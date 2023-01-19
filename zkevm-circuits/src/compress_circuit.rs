//! The compress circuit implementation.

use crate::evm_circuit::util::{from_bytes, rlc};
use crate::util::{Expr, SubCircuitConfig};
use bit_vec::BitVec;
use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector, TableColumn},
    poly::Rotation,
};
use lazy_static::lazy_static;
use std::marker::PhantomData;

lazy_static! {
    // TODO: maybe fixed huffman table will get from witness
    static ref FIXED_HUFFMAN_TABLE: [BitVec; 256] = [(); 256].map(|_| BitVec::new());
}

mod combine {
    const LEFT_SHIFT_8BITS: u64 = 256;

    use crate::util::Expr;
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;
    pub(crate) fn expr<F: Field>(parts: [Expression<F>; 32]) -> Expression<F> {
        parts
            .into_iter()
            .fold(0.expr(), |acc, part| acc * F::from(LEFT_SHIFT_8BITS) + part)
    }
}

mod compress {
    use super::FIXED_HUFFMAN_TABLE;
    use crate::evm_circuit::util::from_bytes;
    use eth_types::Field;

    pub(crate) fn value<F: Field>(src: F) -> [F; 32] {
        src.to_repr().map(|item| {
            let code = FIXED_HUFFMAN_TABLE[item as usize].to_bytes();
            from_bytes::value::<F>(&code)
        })
    }
}

// mod rlc {
//     use crate::util::Expr;
//     use eth_types::Field;
//     use halo2_proofs::plonk::Expression;

//     pub(crate) fn expr<F: Field>(
//         parts: [Expression<F>; 32],
//         randomness: Expression<F>,
//     ) -> Expression<F> {
//         parts
//             .into_iter()
//             .rev()
//             .fold(0.expr(), |acc, part| acc * randomness.clone() + part)
//     }

//     pub(crate) fn value<F: Field>(src: [F; 32], randomness: F) -> F {
//         src.into_iter()
//             .rev()
//             .fold(F::zero(), |acc, part| acc * randomness + part)
//     }
// }

// layout
// ```
// | q_enable | q_first | q_origin_end |q_end | randomness | origin_rpi_rlc_acc | raw_public_inputs | rpi_rlc_acc      | compressed_public_inputs | cpi_rlc_acc      |cpi_code_length | cpi_rlc_length | huffman_value | huffman_code | code_length |
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// | 1        | 1       | 0            | 0    | rand       | origin_rpi_rlc     | rpi[0]            | rlc = next*r+rpi | cpi[0]                   | rlc = next*r+cpi |   1            |                |      0        |      01      |      2      |
// | 1        | 0       | 1            | 0    | rand       |                    | rpi[1]            | next             | cpi[1]                   | next             |   0            |                |      1        |      110     |      3      |
// ```

/// Config for compress circuit
#[derive(Clone, Debug)]
pub struct CompressCircuitConfig<F: Field> {
    q_enable: Selector,
    q_first: Selector,      // the start row for both origin and split rpi/cpi
    q_origin_end: Selector, // the last row for origin rpi
    q_end: Selector,        // the last row for split rpi/cpi
    origin_rpi_rlc_acc: Column<Advice>, // the raw_public_inputs
    raw_public_inputs: Column<Advice>,
    rpi_rlc_acc: Column<Advice>, // rlc = next*randomness + rpi
    compressed_public_inputs: Column<Advice>,
    cpi_rlc_acc: Column<Advice>,     // rlc = next*randomness + cpi
    cpi_code_length: Column<Advice>, // compressed public inputs's huffman code length
    cpi_rlc_length: Column<Advice>,  // how much bits have been rlc encoded
    randomness: Column<Advice>,
    huffman_table: [TableColumn; 3], // [value, code, code_length]
    _marker: PhantomData<F>,
}

/// Circuit configuration arguments
pub struct CompressCircuitConfigArgs {
    /// uncompressed raw public inputs from pi-circuit
    pub origin_rpi: Column<Advice>,
}

impl<F: Field> SubCircuitConfig<F> for CompressCircuitConfig<F> {
    type ConfigArgs = CompressCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { origin_rpi }: Self::ConfigArgs,
    ) -> Self {
        let q_enable = meta.selector();
        let q_first = meta.selector();
        let q_origin_end = meta.selector();
        let q_end = meta.selector();
        let origin_rpi_rlc_acc = meta.advice_column();
        let raw_public_inputs = meta.advice_column();
        let rpi_rlc_acc = meta.advice_column();
        let compressed_public_inputs = meta.advice_column();
        let cpi_rlc_acc = meta.advice_column();
        let cpi_code_length = meta.advice_column();
        let cpi_rlc_length = meta.advice_column();
        let randomness = meta.advice_column();
        let huffman_table = [(); 3].map(|_| meta.lookup_table_column());

        meta.enable_equality(origin_rpi_rlc_acc);
        meta.enable_equality(rpi_rlc_acc);
        meta.enable_equality(cpi_rlc_acc);
        meta.enable_equality(randomness);
        meta.enable_equality(raw_public_inputs);
        meta.enable_equality(compressed_public_inputs);
        meta.enable_equality(cpi_code_length);

        // lookup huffman table
        meta.lookup("huffman_table", |meta| {
            let raw_public_inputs = meta.query_advice(raw_public_inputs, Rotation::cur());
            let compressed_public_inputs =
                meta.query_advice(compressed_public_inputs, Rotation::cur());
            let cpi_code_length = meta.query_advice(cpi_code_length, Rotation::cur());
            vec![
                (raw_public_inputs, huffman_table[0]),        // value
                (compressed_public_inputs, huffman_table[1]), // code
                (cpi_code_length, huffman_table[2]),          // length
            ]
        });

        // origin_rpi_rlc_acc[0] = rpi_rlc_acc[0]
        meta.create_gate("origin_rpi_rlc_acc[0] = rpi_rlc_acc[i*32]", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let q_first = meta.query_selector(q_first);
            let origin_rpi_rlc_acc = meta.query_advice(origin_rpi_rlc_acc, Rotation::cur());
            let rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
            vec![q_enable * q_first * (origin_rpi_rlc_acc - rpi_rlc_acc)]
        });

        // origin_rpi_rlc_acc = next_origin_rpi_rlc_acc * randomness + origin_rpi
        meta.create_gate(
            "origin_rpi_rlc_acc = next_origin_rpi_rlc_acc * randomness + rlc(orpi0, ..., orpi31)",
            |meta| {
                let q_enable = meta.query_selector(q_enable);
                let q_not_origin_end = 1.expr() - meta.query_selector(q_origin_end);
                let origin_rpi = meta.query_advice(origin_rpi, Rotation::cur());
                let cur_origin_rpi_rlc_acc = meta.query_advice(origin_rpi_rlc_acc, Rotation::cur());
                let next_origin_rpi_rlc_acc =
                    meta.query_advice(origin_rpi_rlc_acc, Rotation::next());
                let randomness = meta.query_advice(randomness, Rotation::cur());

                vec![
                    q_enable
                        * q_not_origin_end
                        * (next_origin_rpi_rlc_acc * randomness + origin_rpi
                            - cur_origin_rpi_rlc_acc),
                ]
            },
        );

        // rpi_rlc_acc = next_rpi_rlc_acc * randomness + rpi
        meta.create_gate(
            "rpi_rlc_acc[0] = next_rpi_rlc_acc * randomness + rpi",
            |meta| {
                let q_enable = meta.query_selector(q_enable);
                let q_not_end = 1.expr() - meta.query_selector(q_end);
                let cur_rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
                let next_rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::next());
                let rpi = meta.query_advice(raw_public_inputs, Rotation::cur());
                let randomness = meta.query_advice(randomness, Rotation::cur());

                vec![q_enable * q_not_end * (next_rpi_rlc_acc * randomness + rpi - cur_rpi_rlc_acc)]
            },
        );

        // cpi_rlc_acc = next_cpi_rlc_acc * randomness + cpi
        meta.create_gate(
            "cpi_rlc_acc[0] = next_cpi_rlc_acc * randomness + cpi",
            |meta| {
                let q_enable = meta.query_selector(q_enable);
                let q_not_end = 1.expr() - meta.query_selector(q_end);
                let cur_cpi_rlc_acc = meta.query_advice(cpi_rlc_acc, Rotation::cur());
                let next_cpi_rlc_acc = meta.query_advice(cpi_rlc_acc, Rotation::next());
                let cpi = meta.query_advice(compressed_public_inputs, Rotation::cur());
                let randomness = meta.query_advice(randomness, Rotation::cur());

                vec![q_enable * q_not_end * (next_cpi_rlc_acc * randomness + cpi - cur_cpi_rlc_acc)]
            },
        );

        // rpi_rlc_acc[last] = rpi
        meta.create_gate("rpi_rlc_acc[last] = rpi", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let q_end = meta.query_selector(q_end);
            let randomness = meta.query_advice(randomness, Rotation::cur());
            let rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
            let rpi = meta.query_advice(raw_public_inputs, Rotation::cur());
            vec![q_enable * q_end * (rpi_rlc_acc - rpi)]
        });

        // cpi_rlc_acc[last] = cpi
        meta.create_gate("cpi_rlc_acc[last] = cpi", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let q_end = meta.query_selector(q_end);
            let randomness = meta.query_advice(randomness, Rotation::cur());
            let cpi_rlc_acc = meta.query_advice(cpi_rlc_acc, Rotation::cur());
            let cpi = meta.query_advice(compressed_public_inputs, Rotation::cur());
            vec![q_enable * q_end * (cpi_rlc_acc - cpi)]
        });

        // rand_rpi[i] == rand_rpi[j]
        meta.create_gate("randomness = randomness.next", |meta| {
            // q_not_end * row.rand_rpi == q_not_end * row_next.rand_rpi
            let q_not_end = 1.expr() - meta.query_selector(q_end);
            let cur_randomness = meta.query_advice(randomness, Rotation::cur());
            let next_randomness = meta.query_advice(randomness, Rotation::next());

            vec![q_not_end * (cur_randomness - next_randomness)]
        });

        Self {
            q_enable,
            q_first,
            q_origin_end,
            q_end,
            origin_rpi_rlc_acc,
            raw_public_inputs,
            rpi_rlc_acc,
            compressed_public_inputs,
            cpi_rlc_acc,
            cpi_code_length,
            cpi_rlc_length,
            randomness,
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
                for (value, code) in FIXED_HUFFMAN_TABLE.iter().enumerate() {
                    table.assign_cell(
                        || "huffman table value",
                        self.huffman_table[0],
                        value,
                        || Value::known(F::from(value as u64)),
                    )?;
                    let code = from_bytes::value::<F>(&code.to_bytes());
                    table.assign_cell(
                        || "huffman table code",
                        self.huffman_table[1],
                        value,
                        || Value::known(code),
                    )?;
                }
                Ok(())
            },
        )
    }

    // 1. compress and assign into 32 columns
    // 2. compute the rlc of compressed_vals
    // 3. return the rlc
    fn assign_cpi(
        &self,
        region: &mut Region<'_, F>,
        raw_pi_vals: &[F],
        offset: usize,
        randomness: F,
    ) -> Result<F, Error> {
        let rpi_val = raw_pi_vals[offset];
        // compress rpi value
        let compressed_vals = compress::value(rpi_val);
        // assign cpi
        for (cpi_value, cpi) in compressed_vals
            .into_iter()
            .zip(self.compressed_public_inputs.into_iter())
        {
            region.assign_advice(
                || "compressed_public_inputs",
                cpi,
                offset,
                || Value::known(cpi_value),
            )?;
        }
        Ok(rlc::value(compressed_vals, randomness))
    }

    /// assign the raw public inputs into compressed columns
    #[allow(clippy::type_complexity)]
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        rand_cpi: F,
        raw_pi_vals: Vec<F>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        self.load_huffman_table(layouter)?;
        layouter.assign_region(
            || "compress public inputs",
            |mut region| {
                // Last row
                let offset = raw_pi_vals.len() - 1;

                let mut cpi_rlc_acc =
                    self.assign_cpi(&mut region, &raw_pi_vals, offset, rand_cpi)?;
                region.assign_advice(
                    || "cpi_rlc_acc",
                    self.cpi_rlc_acc,
                    offset,
                    || Value::known(cpi_rlc_acc),
                )?;
                region.assign_advice(
                    || "rand_cpi",
                    self.rand_cpi,
                    offset,
                    || Value::known(rand_cpi),
                )?;
                self.q_end.enable(&mut region, offset)?;
                self.q_enable.enable(&mut region, offset)?;
                // Next rows
                for offset in (1..offset).rev() {
                    cpi_rlc_acc *= rand_cpi;
                    cpi_rlc_acc += self.assign_cpi(&mut region, &raw_pi_vals, offset, rand_cpi)?;
                    region.assign_advice(
                        || "cpi_rlc_acc",
                        self.cpi_rlc_acc,
                        offset,
                        || Value::known(cpi_rlc_acc),
                    )?;
                    region.assign_advice(
                        || "rand_cpi",
                        self.rand_cpi,
                        offset,
                        || Value::known(rand_cpi),
                    )?;
                    self.q_enable.enable(&mut region, offset)?;
                }

                // First row
                cpi_rlc_acc *= rand_cpi;
                cpi_rlc_acc += self.assign_cpi(&mut region, &raw_pi_vals, 0, rand_cpi)?;
                let cpi_rlc = region.assign_advice(
                    || "cpi_rlc_acc",
                    self.cpi_rlc_acc,
                    0,
                    || Value::known(cpi_rlc_acc),
                )?;
                let cpi_rand = region.assign_advice(
                    || "rand_cpi",
                    self.rand_cpi,
                    0,
                    || Value::known(rand_cpi),
                )?;
                self.q_enable.enable(&mut region, 0)?;
                Ok((cpi_rand, cpi_rlc))
            },
        )
    }
}
