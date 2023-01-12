//! The compress circuit implementation.

use crate::evm_circuit::util::from_bytes;
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

mod rlc {
    use crate::util::Expr;
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field>(
        parts: [Expression<F>; 32],
        randomness: Expression<F>,
    ) -> Expression<F> {
        parts
            .into_iter()
            .rev()
            .fold(0.expr(), |acc, part| acc * randomness.clone() + part)
    }

    pub(crate) fn value<F: Field>(src: [F; 32], randomness: F) -> F {
        src.into_iter()
            .rev()
            .fold(F::zero(), |acc, part| acc * randomness + part)
    }
}

// layout
// ```
// | q_enable | q_end | rand_rpi | rpi0 | rpi1 | ... | rpi31 | cpi0 | cpi1 | ... | cpi31 |  cpi_rlc_acc | huffman_value | huffman_code |
// ------------------------------------------------------------------------------------------------------------------------------------
// | 1        | 0     | rand     |rpi[0]|rpi[1]| ... |rpc[31]|cpi[0]|cpi[1]| ... |cpi[31]| ........... | ............. | ............ |
// | 1        | 1     | rand     |rpi[0]|rpi[1]| ... |rpc[31]|cpi[0]|cpi[1]| ... |cpi[31]| ........... | ............. | ............ |
// ```

/// Config for compress circuit
#[derive(Clone, Debug)]
pub struct CompressCircuitConfig<F: Field> {
    q_enable: Selector,
    q_end: Selector,
    raw_public_inputs: [Column<Advice>; 32],
    compressed_public_inputs: [Column<Advice>; 32],
    cpi_rlc_acc: Column<Advice>,
    rand_cpi: Column<Advice>,
    huffman_table: [TableColumn; 2],
    _marker: PhantomData<F>,
}

/// Circuit configuration arguments
pub struct CompressCircuitConfigArgs {
    /// uncompressed raw public inputs
    pub raw_public_inputs: Column<Advice>,
}

impl<F: Field> SubCircuitConfig<F> for CompressCircuitConfig<F> {
    type ConfigArgs = CompressCircuitConfigArgs;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let q_enable = meta.selector();
        let q_end = meta.selector();
        let raw_public_inputs = [(); 32].map(|_| meta.advice_column());
        let compressed_public_inputs = [(); 32].map(|_| meta.advice_column());
        let cpi_rlc_acc = meta.advice_column();
        let rand_cpi = meta.advice_column();
        let huffman_table = [(); 2].map(|_| meta.lookup_table_column());

        meta.enable_equality(cpi_rlc_acc);
        meta.enable_equality(rand_cpi);

        // lookup huffman table
        for (rpi, cpi) in raw_public_inputs
            .into_iter()
            .zip(compressed_public_inputs.into_iter())
        {
            meta.enable_equality(rpi);
            meta.enable_equality(cpi);

            meta.lookup("huffman_table", |meta| {
                let rpi = meta.query_advice(rpi, Rotation::cur());
                let cpi = meta.query_advice(cpi, Rotation::cur());
                vec![(rpi, huffman_table[0]), (cpi, huffman_table[1])]
            });
        }

        // rpi from pi-circuit will be unfolded into 32 bytes
        meta.create_gate("origin_rpi = rpi0 + rpi1 + ... + rpi31", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let origin_rpi = meta.query_advice(args.raw_public_inputs, Rotation::cur());
            let rpi = raw_public_inputs.map(|rpi| meta.query_advice(rpi, Rotation::cur()));
            vec![q_enable * (origin_rpi - combine::expr(rpi))]
        });

        // cpi_rlc_acc
        // TODO: use 32 bytes per rlc item
        meta.create_gate(
            "cpi_rlc_acc[0] = next_cpi_rlc_acc * rand_rpi + rlc(cpi0, ..., cpi31)",
            |meta| {
                let q_not_end = 1.expr() - meta.query_selector(q_end);
                let cur_cpi_rlc_acc = meta.query_advice(cpi_rlc_acc, Rotation::cur());
                let next_cpi_rlc_acc = meta.query_advice(cpi_rlc_acc, Rotation::next());
                let rand_cpi = meta.query_advice(rand_cpi, Rotation::cur());

                let rlc_cpi = rlc::expr(
                    compressed_public_inputs.map(|cpi| meta.query_advice(cpi, Rotation::cur())),
                    rand_cpi.clone(),
                );

                vec![q_not_end * (next_cpi_rlc_acc * rand_cpi + rlc_cpi - cur_cpi_rlc_acc)]
            },
        );

        meta.create_gate("cpi_rlc_acc[last] = rlc(cpi0, ..., cpi31)", |meta| {
            let q_end = meta.query_selector(q_end);
            let rand_rpi = meta.query_advice(rand_cpi, Rotation::cur());
            let rlc_cpi = rlc::expr(
                compressed_public_inputs.map(|cpi| meta.query_advice(cpi, Rotation::cur())),
                rand_rpi,
            );
            let cpi_rlc_acc = meta.query_advice(cpi_rlc_acc, Rotation::cur());
            vec![q_end * (rlc_cpi - cpi_rlc_acc)]
        });

        // rand_rpi[i] == rand_rpi[j]
        meta.create_gate("rand_pi = rand_rpi.next", |meta| {
            // q_not_end * row.rand_rpi == q_not_end * row_next.rand_rpi
            let q_not_end = 1.expr() - meta.query_selector(q_end);
            let cur_rand_cpi = meta.query_advice(rand_cpi, Rotation::cur());
            let next_rand_cpi = meta.query_advice(rand_cpi, Rotation::next());

            vec![q_not_end * (cur_rand_cpi - next_rand_cpi)]
        });

        Self {
            q_enable,
            q_end,
            raw_public_inputs,
            compressed_public_inputs,
            cpi_rlc_acc,
            rand_cpi,
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
        rand_cpi: F,
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
        Ok(rlc::value(compressed_vals, rand_cpi))
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
                Ok((cpi_rand, cpi_rlc))
            },
        )
    }
}
