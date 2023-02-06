//! The compress circuit implementation.

mod table;
use crate::evm_circuit::util::constraint_builder::BaseConstraintBuilder;
use crate::util::{Expr, SubCircuitConfig};

use eth_types::Field;
use gadgets::util::select;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn},
    poly::Rotation,
};

use std::marker::PhantomData;
use table::lookup_huffman_table;

const MAX_PARTS: usize = 4;
const WORD_SIZE: usize = 8;
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
pub(crate) struct PartValue {
    data: u8,
    num_bits: u8,
    r_multi: bool,
    shift_factor: u8,
    decode_factor: u32,
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
//      A = 1011101(7)
//      ~ = 1111111111101(13)
// circuit:
// ```
// input | data     | num_bits | r_multi | shift_factor | decode_factor | data_rlc
// ------|----------|--------- |---------|--------------|---------------|---------------------------------
//  'A'  | 1011101  | 7        | 0       | 2^1          | 2^0           | 1011101
//  'A'  |          | 0        | 0       | 0            | 0             | 1011101
//  'A'  |          | 0        | 0       | 0            | 0             | 1011101
//  'A'  |          | 0        | 0       | 0            | 0             | 1011101
//  '~'  | 1        | 1        | 1       | 2^0          | 2^12          | 10111011
//  '~'  | 11111111 | 8        | 1       | 2^0          | 2^4           | 10111011*r+11111111
//  '~'  | 1101     | 4        | 0       | 2^4          | 2^0           | (10111011*r+11111111)*r+11010000
//  '~'  |          | 0        | 0       | 0            | 0             | (10111011*r+11111111)*r+11010000
// ```
// N.B. we can use one row represent all 4 parts
#[derive(Debug, Clone)]
pub struct CompressCircuitConfig<F: Field> {
    q_enable: Selector,
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
        let q_enable = meta.selector();
        let r_multi = meta.advice_column();
        let input = meta.advice_column();
        let data = meta.advice_column();
        let data_rlc = meta.advice_column();
        let num_bits = meta.advice_column();
        let shift_factor = meta.advice_column();
        let decode_factor = meta.advice_column();
        let huffman_table = array_init::array_init(|_| meta.lookup_table_column());

        meta.enable_equality(data_rlc);

        let mut parts = vec![];
        meta.create_gate("split parts", |meta| {
            // next 4 rows as 4 parts
            for i in 0..MAX_PARTS as i32 {
                let data = meta.query_advice(data, Rotation(i));
                let num_bits = meta.query_advice(num_bits, Rotation(i));
                let r_multi = meta.query_advice(r_multi, Rotation(i));
                let shift_factor = meta.query_advice(shift_factor, Rotation(i));
                let decode_factor = meta.query_advice(decode_factor, Rotation(i));

                parts.push(Part {
                    data,
                    num_bits,
                    r_multi,
                    shift_factor,
                    decode_factor,
                });
            }
            vec![0.expr()]
        });

        meta.lookup("huffman table", |meta| {
            // lookups:
            //  1. input = huffman_value
            //  2. data0 * decode_factor0 + data1 * decode_factor1 + data2 * decode_factor2
            //      + data3 * decode_factor3 = huffman_code
            //  3. num_bits0 + num_bits1 + num_bits2 + num_bits3 = huffman_code_length
            let input = meta.query_advice(input, Rotation::cur());
            let code = decode::data_expr(&parts);
            vec![
                (input, huffman_table[0]),
                (code, huffman_table[1]),
                (decode::num_bits_expr(&parts), huffman_table[2]),
            ]
        });

        meta.create_gate("do RLC over parts", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let mut data_rlc_prev = meta.query_advice(data_rlc, Rotation::prev());
            for part in parts.iter() {
                // 1. TODO: range check(lookup):
                //      part.data(0..2^8)
                //      part.num_bits(0..32)
                //      part.r_multi(bool)
                //      part.shift_factor(0..2^32) 2.pow(0..32)
                //      part.decode_factor(0..2^32) 2.pow(0..32)
                cb.require_boolean("r_multi", part.r_multi.clone());
                // 2. Add the part to the rlc
                let multi = select::expr(part.r_multi.clone(), randomness.clone(), 1.expr());
                data_rlc_prev =
                    data_rlc_prev * multi + part.data.clone() * part.shift_factor.clone();
            }
            cb.require_equal(
                "data_rlc",
                data_rlc_prev,
                meta.query_advice(data_rlc, Rotation::cur()),
            );
            cb.gate(meta.query_selector(q_enable))
        });

        Self {
            q_enable,
            input,
            data,
            data_rlc,
            num_bits,
            r_multi,
            shift_factor,
            decode_factor,
            huffman_table,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> CompressCircuitConfig<F> {
    fn load_huffman_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "fixed huffman table",
            |mut table| {
                for value in 0..256 {
                    table.assign_cell(
                        || "huffman table value",
                        self.huffman_table[0],
                        value,
                        || Value::known(F::from(value as u64)),
                    )?;
                    let (code, code_len) = lookup_huffman_table(value as u8);
                    table.assign_cell(
                        || "huffman table code",
                        self.huffman_table[1],
                        value,
                        || Value::known(F::from(code as u64)),
                    )?;
                    table.assign_cell(
                        || "huffman table code length",
                        self.huffman_table[2],
                        value,
                        || Value::known(F::from(code_len as u64)),
                    )?;
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
        layouter.assign_region(
            || "compress public inputs",
            |mut region| {
                // next byte needs bits
                let mut remaining = 8;
                let mut r_multi = false;
                let mut rlc = F::zero();
                let mut rlc_cell = None;

                for (offset, byte) in input.iter().enumerate() {
                    let byte = *byte;
                    region.assign_advice(
                        || "load input",
                        self.input,
                        offset,
                        || Value::known(F::from(byte as u64)),
                    )?;
                    let (code, mut code_len) = lookup_huffman_table(byte);

                    for _ in 0..MAX_PARTS {
                        let mut data = 0;
                        let mut num_bits = 0;
                        let mut next_byte_begin = false;
                        let mut shift_factor = 0;
                        let mut decode_factor = 0;

                        if code_len != 0 {
                            // 1. front part of 1bytes
                            // 2. back part of 1bytes
                            match code_len.cmp(&remaining) {
                                std::cmp::Ordering::Less => {
                                    num_bits = code_len;
                                    shift_factor = 2 ^ (remaining - num_bits);
                                    decode_factor = 1;
                                    remaining -= code_len;
                                    code_len = 0;
                                }
                                std::cmp::Ordering::Equal => {
                                    num_bits = code_len;
                                    shift_factor = 1;
                                    decode_factor = 1;
                                    remaining = 8; // next byte begin
                                    next_byte_begin = true;
                                    code_len = 0;
                                }
                                std::cmp::Ordering::Greater => {
                                    num_bits = remaining;
                                    shift_factor = 1;
                                    decode_factor = 2 ^ (code_len - num_bits) as u32;
                                    remaining = 8; // next byte begin
                                    next_byte_begin = true;
                                    code_len -= remaining;
                                }
                            }
                            data = (code >> decode_factor) & 0xff;
                        }

                        let randomness = if r_multi { randomness } else { F::one() };

                        // if next byte begin combines, then next part needs multiply randomness
                        r_multi = next_byte_begin;

                        rlc = rlc * randomness + F::from((data * shift_factor as u32) as u64);

                        region.assign_advice(
                            || "load data",
                            self.data,
                            offset,
                            || Value::known(F::from(data as u64)),
                        )?;
                        region.assign_advice(
                            || "load num_bits",
                            self.num_bits,
                            offset,
                            || Value::known(F::from(num_bits as u64)),
                        )?;
                        region.assign_advice(
                            || "load r_multi",
                            self.r_multi,
                            offset,
                            || Value::known(F::from(r_multi as u64)),
                        )?;
                        region.assign_advice(
                            || "load shift_factor",
                            self.shift_factor,
                            offset,
                            || Value::known(F::from(shift_factor as u64)),
                        )?;
                        region.assign_advice(
                            || "load decode_factor",
                            self.decode_factor,
                            offset,
                            || Value::known(F::from(decode_factor as u64)),
                        )?;
                        rlc_cell = Some(region.assign_advice(
                            || "load data_rlc",
                            self.data_rlc,
                            offset,
                            || Value::known(rlc),
                        )?);
                        self.q_enable.enable(&mut region, offset)?;
                    }
                }
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

    fn compress_and_rlc<F: Field>(input: &[u8], randomness: F) -> F {
        let mut rlc = F::zero();
        let mut remaining = 8;
        let mut ri_multi = false;
        for byte in input {
            let (code, mut code_len) = lookup_huffman_table(*byte);

            while code_len > 0 {
                let shift_factor;
                let decode_factor;
                let next_byte_begin;

                match code_len.cmp(&remaining) {
                    std::cmp::Ordering::Less => {
                        shift_factor = 2 ^ (remaining - code_len);
                        decode_factor = 1;
                        remaining -= code_len;
                        next_byte_begin = false;
                        code_len = 0;
                    }
                    std::cmp::Ordering::Equal => {
                        shift_factor = 1;
                        decode_factor = 1;
                        remaining = 8; // next byte begin
                        next_byte_begin = true;
                        code_len = 0;
                    }
                    std::cmp::Ordering::Greater => {
                        shift_factor = 1;
                        decode_factor = 2 ^ (code_len - remaining) as u32;
                        remaining = 8; // next byte begin
                        next_byte_begin = true;
                        code_len -= remaining;
                    }
                }
                let data = (code >> decode_factor) & 0xff;

                let randomness = if ri_multi { randomness } else { F::one() };
                rlc = rlc * randomness + F::from((data * shift_factor as u32) as u64);
                ri_multi = next_byte_begin;
            }
        }
        rlc
    }

    #[test]
    fn test() {
        let input = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let pi = compress_and_rlc(&input, Fr::from(100));
        let circuit = TestCircuit::<Fr>::new(input);
        let prover = MockProver::run(10, &circuit, vec![vec![pi]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
