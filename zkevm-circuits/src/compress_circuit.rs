//! The compress circuit implementation.

mod table;
use crate::evm_circuit::util::constraint_builder::BaseConstraintBuilder;
use crate::impl_expr;
use crate::util::{Expr, SubCircuitConfig};

use eth_types::Field;
use gadgets::util::select;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn},
    poly::Rotation,
};
use itertools::Itertools;

use std::marker::PhantomData;
use table::{huffman_table, lookup_huffman_table};

const MAX_PARTS: usize = 4;
const WORD_SIZE: u8 = 8;
const MAX_DEGREE: usize = 10;

#[derive(Debug)]
pub(crate) struct Part<F: Field> {
    data: Expression<F>,
    num_bits: Expression<F>,
    r_multi: Expression<F>,
    shift_factor: Expression<F>,
    decode_factor: Expression<F>,
}

#[derive(Debug, Default)]
struct PartValue<F: Field> {
    idx: usize,
    limb_idx: usize,
    input: F,
    data: F,
    data_rlc: F,
    num_bits: F,
    r_multi: F,
    shift_factor: F,
    decode_factor: F,
}

#[derive(Debug)]
enum FixedTableTag {
    Exponent8,
    Exponent32,
    Range32,
    Byte,
    Bool,
}

impl_expr!(FixedTableTag);

impl FixedTableTag {
    pub fn build<F: Field>(&self) -> Box<dyn Iterator<Item = [F; 2]>> {
        let tag = F::from(*self as u64);
        match self {
            FixedTableTag::Exponent8 => Box::new(
                std::iter::once([tag, F::zero()])
                    .chain((0..8).map(move |i| [tag, 2u64.pow(i).into()])),
            ),
            FixedTableTag::Exponent32 => Box::new(
                std::iter::once([tag, F::zero()])
                    .chain((0..32).map(move |i| [tag, 2u64.pow(i).into()])),
            ),
            FixedTableTag::Bool => Box::new(vec![[tag, F::zero()], [tag, F::one()]].into_iter()),
            FixedTableTag::Byte => Box::new((0..256).map(move |i| [tag, i.into()])),
            FixedTableTag::Range32 => Box::new((0..32).map(move |i| [tag, i.into()])),
        }
    }
}

fn compress<F: Field, T: FnMut(PartValue<F>) -> Result<(), Error>>(
    input: &[u8],
    randomness: F,
    mut handle: T,
) -> Result<F, Error> {
    let mut data_rlc = F::zero();
    // how many bits need to be combined into 1 word
    let mut word_remaining = WORD_SIZE;
    let mut r_multi = false;
    for (idx, byte) in input.iter().enumerate() {
        let (code, code_len) = lookup_huffman_table(*byte);
        let mut remaining_code_len = code_len;
        for limb_idx in 0..MAX_PARTS {
            let mut data = 0;
            let mut num_bits = 0;
            let mut shift_factor = 0;
            let mut decode_factor = 0;
            let mut next_byte_begin = false;
            if remaining_code_len != 0 {
                match remaining_code_len.cmp(&word_remaining) {
                    std::cmp::Ordering::Less => {
                        num_bits = remaining_code_len;
                        shift_factor = 2u8.pow((word_remaining - num_bits) as u32);
                        decode_factor = 1;
                        word_remaining -= remaining_code_len;
                        remaining_code_len = 0;
                    }
                    std::cmp::Ordering::Equal => {
                        num_bits = remaining_code_len;
                        shift_factor = 1;
                        decode_factor = 1;
                        word_remaining = WORD_SIZE;
                        next_byte_begin = true;
                        remaining_code_len = 0;
                    }
                    std::cmp::Ordering::Greater => {
                        num_bits = word_remaining;
                        shift_factor = 1;
                        decode_factor = 2u32.pow((remaining_code_len - num_bits) as u32);
                        remaining_code_len -= word_remaining;
                        word_remaining = WORD_SIZE;
                        next_byte_begin = true;
                    }
                }
                data = (code / decode_factor) & (0xff >> (8 - num_bits));
            }
            let randomness = if r_multi { randomness } else { F::one() };
            data_rlc = data_rlc * randomness + F::from((data * shift_factor as u32) as u64);

            handle(PartValue {
                idx,
                limb_idx,
                input: F::from(*byte as u64),
                data: F::from(data as u64),
                data_rlc,
                num_bits: F::from(num_bits as u64),
                r_multi: F::from(r_multi as u64),
                shift_factor: F::from(shift_factor as u64),
                decode_factor: F::from(decode_factor as u64),
            })?;
            r_multi = next_byte_begin;
        }
    }
    Ok(data_rlc)
}

mod decode {
    use super::Part;
    use eth_types::Field;
    use gadgets::util::Expr;
    use halo2_proofs::plonk::Expression;

    // parts data => origin data
    pub(crate) fn data_expr<F: Field>(parts: &[Part<F>]) -> Expression<F> {
        parts.iter().fold(0.expr(), |acc, part| {
            acc + part.data.clone() * part.decode_factor.clone()
        })
    }

    // parts num_bits => origin num_bits
    pub(crate) fn num_bits_expr<F: Field>(parts: &[Part<F>]) -> Expression<F> {
        parts
            .iter()
            .fold(0.expr(), |acc, part| acc + part.num_bits.clone())
    }
}

// input:
//      B = 1011110(7)
//      ~ = 1111111111101(13)
// circuit:
// ```
// input | data     | num_bits | r_multi | shift_factor | decode_factor | data_rlc
// ------|----------|--------- |---------|--------------|---------------|---------------------------------
//  '~'  | 0        | 0        | 0       | 0            | 0             | (10111101*r+11111111)*r+11010000
//  '~'  | 1101     | 4        | 0       | 2^4          | 2^0           | (10111101*r+11111111)*r+11010000
//  '~'  | 11111111 | 8        | 1       | 2^0          | 2^4           | 10111101*r+11111111
//  '~'  | 1        | 1        | 1       | 2^0          | 2^12          | 1011110
//  'B'  | 0        | 0        | 0       | 0            | 0             | 1011110
//  'B'  | 0        | 0        | 0       | 0            | 0             | 1011110
//  'B'  | 0        | 0        | 0       | 0            | 0             | 1011110
//  'B'  | 1011110  | 7        | 0       | 2^1          | 2^0           | 1011110
// ```
#[derive(Debug, Clone)]
pub struct CompressCircuitConfig<F: Field> {
    q_enable: Selector,
    q_end: Selector,
    q_not_end: Selector,
    q_word_end: Selector,  // enable when word starts
    input: Column<Advice>, // input bitstream byte/row
    // output parts:
    // encoded value
    data: Column<Advice>,
    data_rlc: Column<Advice>,
    // encoded bit length
    num_bits: Column<Advice>,
    // randomness multiplier selector
    r_multi: Column<Advice>,
    // the factor with which the part needs to be multiplied
    shift_factor: Column<Advice>,
    // the factor with which the part needs to be multiplied when
    // we decode it
    decode_factor: Column<Advice>,
    // fixed huffman table
    huffman_table: [TableColumn; 3], // [value, code, code_length]
    fixed_table: [TableColumn; 2],   // [tag, or(exponent(2**0..8), exponent(2**0..32), bool(0,1))]

    _marker: PhantomData<F>,
}

/// Circuit configuration arguments
pub struct CompressCircuitConfigArgs<F> {
    // randomness used to do RLC
    pub randomness: Expression<F>,
}

impl<F: Field> SubCircuitConfig<F> for CompressCircuitConfig<F> {
    type ConfigArgs = CompressCircuitConfigArgs<F>;

    fn new(
        meta: &mut ConstraintSystem<F>,
        CompressCircuitConfigArgs { randomness }: Self::ConfigArgs,
    ) -> Self {
        let q_enable = meta.complex_selector();
        let q_end = meta.selector();
        let q_not_end = meta.selector();
        let q_word_end = meta.complex_selector();
        let r_multi = meta.advice_column();
        let input = meta.advice_column();
        let data = meta.advice_column();
        let data_rlc = meta.advice_column();
        let num_bits = meta.advice_column();
        let shift_factor = meta.advice_column();
        let decode_factor = meta.advice_column();
        let huffman_table = array_init::array_init(|_| meta.lookup_table_column());
        let fixed_table = array_init::array_init(|_| meta.lookup_table_column());

        meta.enable_equality(data_rlc);

        // range check
        // input(0..256)
        // data(0..256)
        // num_bits(0..32)
        // r_multi(bool)
        // shift_factor 2.pow(0..8)
        // decode_factor 2.pow(0..32)
        macro_rules! range_check {
            ($column:ident, $range:ident) => {
                meta.lookup(concat!(stringify!($column), " range check"), |meta| {
                    let column = meta.query_advice($column, Rotation::cur());
                    let q_enable = meta.query_selector(q_enable);
                    vec![
                        (
                            q_enable.clone() * FixedTableTag::$range.expr(),
                            fixed_table[0],
                        ),
                        (q_enable * column, fixed_table[1]),
                    ]
                });
            };
        }

        range_check!(input, Byte);
        range_check!(data, Byte);
        range_check!(num_bits, Range32);
        range_check!(r_multi, Bool);
        range_check!(shift_factor, Exponent8);
        range_check!(decode_factor, Exponent32);

        meta.lookup("huffman table", |meta| {
            // lookups:
            //  1. input = huffman_value
            //  2. data0 * decode_factor0 + data1 * decode_factor1 + data2 * decode_factor2
            //      + data3 * decode_factor3 = huffman_code
            //  3. num_bits0 + num_bits1 + num_bits2 + num_bits3 = huffman_code_length

            // next 4 rows as 4 parts
            let parts = (0..MAX_PARTS)
                .map(|i| {
                    let i = i as i32;
                    let data = meta.query_advice(data, Rotation(i));
                    let num_bits = meta.query_advice(num_bits, Rotation(i));
                    let r_multi = meta.query_advice(r_multi, Rotation(i));
                    let shift_factor = meta.query_advice(shift_factor, Rotation(i));
                    let decode_factor = meta.query_advice(decode_factor, Rotation(i));
                    Part {
                        data,
                        num_bits,
                        r_multi,
                        shift_factor,
                        decode_factor,
                    }
                })
                .collect::<Vec<_>>();
            let input = meta.query_advice(input, Rotation::cur());
            let code = decode::data_expr(&parts);
            let q_word_end = meta.query_selector(q_word_end);
            vec![
                (q_word_end.clone() * input, huffman_table[0]),
                (q_word_end.clone() * code, huffman_table[1]),
                (q_word_end * decode::num_bits_expr(&parts), huffman_table[2]),
            ]
        });

        meta.create_gate("data_rlc[last] = data[last] * shift_factor[last]", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let data_rlc = meta.query_advice(data_rlc, Rotation::cur());
            let data = meta.query_advice(data, Rotation::cur());
            let shift_factor = meta.query_advice(shift_factor, Rotation::cur());
            let r_multi = meta.query_advice(r_multi, Rotation::cur());
            cb.require_boolean("r_multi", r_multi);
            cb.require_equal("last data_rlc", data * shift_factor, data_rlc);
            cb.gate(meta.query_selector(q_end))
        });

        meta.create_gate(
            "data_rlc[i] = data_rlc[i+1] * multi[i] + data[i] * shift_factor[i]",
            |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
                let data_rlc_cur = meta.query_advice(data_rlc, Rotation::cur());
                let data_rlc_next = meta.query_advice(data_rlc, Rotation::next());
                let data = meta.query_advice(data, Rotation::cur());
                let shift_factor = meta.query_advice(shift_factor, Rotation::cur());
                let r_multi = meta.query_advice(r_multi, Rotation::cur());
                cb.require_boolean("r_multi", r_multi.clone());
                let multi = select::expr(r_multi, randomness.clone(), 1.expr());
                cb.require_equal(
                    "data_rlc",
                    data_rlc_cur,
                    data_rlc_next * multi + data * shift_factor,
                );

                cb.gate(meta.query_selector(q_not_end))
            },
        );

        Self {
            q_enable,
            q_not_end,
            q_end,
            q_word_end,
            input,
            data,
            data_rlc,
            num_bits,
            r_multi,
            shift_factor,
            decode_factor,
            huffman_table,
            fixed_table,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> CompressCircuitConfig<F> {
    fn load_huffman_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "fixed huffman table",
            |mut table| {
                for (offset, row) in huffman_table::<F>().iter().enumerate() {
                    for (column, value) in self.huffman_table.iter().zip_eq(row) {
                        table.assign_cell(|| "", *column, offset, || Value::known(value))?;
                    }
                }
                Ok(())
            },
        )
    }

    fn load_fixed_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "fixed table",
            |mut table| {
                for (offset, row) in std::iter::once([F::zero(); 2])
                    .chain(
                        [
                            FixedTableTag::Exponent8,
                            FixedTableTag::Exponent32,
                            FixedTableTag::Bool,
                            FixedTableTag::Byte,
                            FixedTableTag::Range32,
                        ]
                        .iter()
                        .flat_map(|tag| tag.build()),
                    )
                    .enumerate()
                {
                    for (column, value) in self.fixed_table.iter().zip_eq(row) {
                        table.assign_cell(|| "", *column, offset, || Value::known(value))?;
                    }
                }
                Ok(())
            },
        )
    }

    /// assign the raw public inputs into compressed columns
    #[allow(clippy::type_complexity)]
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        input: &[u8],
        randomness: F,
    ) -> Result<Option<AssignedCell<F, F>>, Error> {
        self.load_huffman_table(layouter)?;
        self.load_fixed_table(layouter)?;
        layouter.assign_region(
            || "compress data",
            |mut region| {
                let mut rlc_cell = None;
                let last_offset = input.len() * MAX_PARTS - 1;
                let mut offset = last_offset;

                self.q_end.enable(&mut region, offset)?;

                compress(input, randomness, |part| {
                    self.q_enable.enable(&mut region, offset)?;
                    if part.limb_idx == MAX_PARTS - 1 {
                        self.q_word_end.enable(&mut region, offset)?;
                    }
                    if offset != last_offset {
                        self.q_not_end.enable(&mut region, offset)?;
                    }

                    macro_rules! assign_part {
                        ($part:ident) => {
                            region.assign_advice(
                                || concat!("load ", stringify!($part)),
                                self.$part,
                                offset,
                                || Value::known(part.$part),
                            )?
                        };
                    }

                    assign_part!(input);
                    assign_part!(data);
                    assign_part!(num_bits);
                    assign_part!(r_multi);
                    assign_part!(shift_factor);
                    assign_part!(decode_factor);
                    rlc_cell = Some(assign_part!(data_rlc));

                    if offset > 0 {
                        offset -= 1;
                    }
                    Ok(())
                })?;

                Ok(rlc_cell)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, Instance},
    };

    #[derive(Debug, Clone)]
    struct TestCircuitConfig<F: Field> {
        compress: CompressCircuitConfig<F>,
        public_inputs: Column<Instance>,
    }

    struct TestCircuit<F: Field> {
        input: Vec<u8>,
        randomness: F,
    }
    impl<F: Field> TestCircuit<F> {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input,
                randomness: F::from(100),
            }
        }
    }

    impl<F: Field> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig<F>;

        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            todo!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let public_inputs = meta.instance_column();
            meta.enable_equality(public_inputs);
            TestCircuitConfig {
                compress: CompressCircuitConfig::new(
                    meta,
                    CompressCircuitConfigArgs {
                        randomness: 100.expr(),
                    },
                ),
                public_inputs,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let rlc = config
                .compress
                .assign(&mut layouter, &self.input, self.randomness)?;
            layouter.constrain_instance(rlc.unwrap().cell(), config.public_inputs, 0)?;
            Ok(())
        }
    }

    #[test]
    fn test() {
        let input = vec![
            b'H', b'e', b'l', b'l', b'o', b' ', b'W', b'o', b'r', b'l', b'd',
        ];
        let pi = compress(&input, Fr::from(100), |_| Ok(())).unwrap();
        let circuit = TestCircuit::<Fr>::new(input);
        let prover = MockProver::run(17, &circuit, vec![vec![pi]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
