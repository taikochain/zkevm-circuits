//! Anchor circuit implementation.

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub use dev::TestAnchorTxCircuit;
mod sign_verify;
#[cfg(any(feature = "test", test))]
mod test;

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{LookupTable, PiFieldTag, PiTable, TxFieldTag, TxTable},
    tx_circuit::TX_LEN,
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, Taiko},
};
use eth_types::{geth_types::Transaction, Field, ToScalar};
use gadgets::util::Expr;
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, Selector},
    poly::Rotation,
};
use sign_verify::SignVerifyConfig;
use std::marker::PhantomData;

use self::sign_verify::GOLDEN_TOUCH_ADDRESS;

// The first of txlist is the anchor tx
const ANCHOR_TX_ID: usize = 0;
const ANCHOR_TX_VALUE: u64 = 0;
const ANCHOR_TX_IS_CREATE: bool = false;
const ANCHOR_TX_GAS_PRICE: u64 = 0;
// TODO: calculate the method_signature
const ANCHOR_TX_METHOD_SIGNATURE: u32 = 0;
const MAX_DEGREE: usize = 9;
const BYTE_POW_BASE: u64 = 1 << 8;

// anchor(bytes32,bytes32,uint64,uint64) = method_signature(4B)+1st(32B)+2nd(32B)+3rd(8B)+4th(8B)
const ANCHOR_CALL_DATA_LEN: usize = 84;

struct CallData {
    start: usize,
    end: usize,
}

/// Config for AnchorTxCircuit
#[derive(Clone, Debug)]
pub struct AnchorTxCircuitConfig<F: Field> {
    tx_table: TxTable,
    pi_table: PiTable,

    q_tag: Selector,
    // the anchor transaction fixed fields
    // Gas, GasPrice, CallerAddress, CalleeAddress, IsCreate, Value, CallDataLength,
    // 2 rows: 0, tag, 0, value
    tag: Column<Fixed>,

    // check: method_signature, l1Hash, l1SignalRoot, l1Height, parentGasUsed
    q_call_data_start: Selector,
    q_call_data_step: Selector,
    q_call_data_end: Selector,
    call_data_rlc_acc: Column<Advice>,
    call_data_tag: Column<Fixed>,

    sign_verify: SignVerifyConfig<F>,
}

/// Circuit configuration arguments
pub struct AnchorTxCircuitConfigArgs<F: Field> {
    /// TxTable
    pub tx_table: TxTable,
    /// PiTable
    pub pi_table: PiTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for AnchorTxCircuitConfig<F> {
    type ConfigArgs = AnchorTxCircuitConfigArgs<F>;

    /// Return a new TxCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            tx_table,
            pi_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_tag = meta.complex_selector();
        let tag = meta.fixed_column();

        let q_call_data_start = meta.complex_selector();
        let q_call_data_step = meta.complex_selector();
        let q_call_data_end = meta.complex_selector();
        let call_data_rlc_acc = meta.advice_column_in(SecondPhase);
        let call_data_tag = meta.fixed_column();
        let sign_verify = SignVerifyConfig::configure(meta, tx_table.clone(), &challenges);

        // anchor transaction constants
        meta.lookup_any("anchor fixed fields", |meta| {
            let q_anchor = meta.query_selector(q_tag);
            let tx_id = ANCHOR_TX_ID.expr();
            let value = meta.query_fixed(tag, Rotation::next());
            let tag = meta.query_fixed(tag, Rotation::cur());
            let index = 0.expr();
            vec![
                (
                    q_anchor.expr() * tx_id,
                    meta.query_advice(tx_table.tx_id, Rotation::cur()),
                ),
                (
                    q_anchor.expr() * tag,
                    meta.query_fixed(tx_table.tag, Rotation::cur()),
                ),
                (
                    q_anchor.expr() * index,
                    meta.query_advice(tx_table.index, Rotation::cur()),
                ),
                (
                    q_anchor * value,
                    meta.query_advice(tx_table.value, Rotation::cur()),
                ),
            ]
        });

        // call data
        meta.create_gate(
            "call_data_rlc_acc[i+1] = call_data_rlc_acc[i] * randomness + call_data[i+1]",
            |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                let q_call_data_step = meta.query_selector(q_call_data_step);
                let call_data_rlc_acc_next = meta.query_advice(call_data_rlc_acc, Rotation::next());
                let call_data_rlc_acc = meta.query_advice(call_data_rlc_acc, Rotation::cur());
                let call_data_next = meta.query_advice(tx_table.value, Rotation::next());
                let randomness = challenges.evm_word();
                cb.require_equal(
                    "call_data_rlc_acc[i+1] = call_data_rlc_acc[i] * randomness + call_data[i+1]",
                    call_data_rlc_acc_next,
                    call_data_rlc_acc * randomness + call_data_next,
                );
                cb.gate(q_call_data_step)
            },
        );
        meta.create_gate("call_data_acc[0] = call_data[0]", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_call_data_start = meta.query_selector(q_call_data_start);
            let call_data_acc = meta.query_advice(call_data_rlc_acc, Rotation::cur());
            let call_data = meta.query_advice(tx_table.value, Rotation::cur());

            cb.require_equal("call_data_acc[0] = call_data[0]", call_data_acc, call_data);
            cb.gate(q_call_data_start)
        });
        meta.lookup_any("call data in pi_table", |meta| {
            let q_call_data_end = meta.query_selector(q_call_data_end);
            let call_data_rlc_acc = meta.query_advice(call_data_rlc_acc, Rotation::cur());
            let call_data_tag = meta.query_fixed(call_data_tag, Rotation::cur());

            [call_data_tag, call_data_rlc_acc]
                .into_iter()
                .zip(pi_table.table_exprs(meta).into_iter())
                .map(|(arg, table)| (q_call_data_end.expr() * arg, table))
                .collect::<Vec<_>>()
        });

        Self {
            tx_table,
            pi_table,

            q_tag,
            tag,

            q_call_data_start,
            q_call_data_step,
            q_call_data_end,
            call_data_rlc_acc,
            call_data_tag,
            sign_verify,
        }
    }
}

impl<F: Field> AnchorTxCircuitConfig<F> {
    fn assign_anchor_tx(
        &self,
        region: &mut Region<'_, F>,
        _anchor_tx: &Transaction,
        taiko: &Taiko,
        _challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        // Gas, GasPrice, CallerAddress, CalleeAddress, IsCreate, Value, CallDataLength,
        let mut offset = 0;
        for (tag, value) in [
            (
                TxFieldTag::Gas,
                Value::known(F::from(taiko.anchor_gas_cost)),
            ),
            (
                TxFieldTag::GasPrice,
                Value::known(F::from(ANCHOR_TX_GAS_PRICE)),
            ),
            (
                TxFieldTag::CallerAddress,
                Value::known(
                    GOLDEN_TOUCH_ADDRESS
                        .to_scalar()
                        .expect("anchor_tx.from too big"),
                ),
            ),
            (
                TxFieldTag::CalleeAddress,
                Value::known(taiko.l2_contract.to_scalar().expect("anchor_tx.to too big")),
            ),
            (
                TxFieldTag::IsCreate,
                Value::known(F::from(ANCHOR_TX_IS_CREATE as u64)),
            ),
            (TxFieldTag::Value, Value::known(F::from(ANCHOR_TX_VALUE))),
            (
                TxFieldTag::CallDataLength,
                Value::known(F::from(ANCHOR_CALL_DATA_LEN as u64)),
            ),
        ] {
            self.q_tag.enable(region, offset)?;
            region.assign_fixed(
                || "tag",
                self.tag,
                offset,
                || Value::known(F::from(tag as u64)),
            )?;
            offset += 1;
            region.assign_fixed(|| "anchor", self.tag, offset, || value)?;
            offset += 1;
        }
        Ok(())
    }

    fn assign_call_data(
        &self,
        region: &mut Region<'_, F>,
        anchor_tx: &Transaction,
        call_data: &CallData,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let mut offset = call_data.start;
        let randomness = challenges.evm_word();
        for (annotation, value, tag) in [
            (
                "method_signature",
                &anchor_tx.call_data[..4],
                PiFieldTag::MethodSign,
            ),
            ("l1_hash", &anchor_tx.call_data[4..36], PiFieldTag::L1Hash),
            (
                "l1_signal_root",
                &anchor_tx.call_data[36..68],
                PiFieldTag::L1SignalRoot,
            ),
            (
                "l1_height",
                &anchor_tx.call_data[68..76],
                PiFieldTag::L1Height,
            ),
            (
                "parent_gas_used",
                &anchor_tx.call_data[76..84],
                PiFieldTag::ParentGasUsed,
            ),
        ] {
            let mut rlc_acc = Value::known(F::ZERO);
            for (idx, byte) in value.iter().enumerate() {
                let row_offset = offset + idx;
                rlc_acc = rlc_acc * randomness + Value::known(F::from(*byte as u64));
                region.assign_advice(
                    || annotation,
                    self.call_data_rlc_acc,
                    row_offset,
                    || rlc_acc,
                )?;
                region.assign_fixed(
                    || annotation,
                    self.call_data_tag,
                    row_offset,
                    || Value::known(F::from(tag as u64)),
                )?;
                // setup selector
                if idx == 0 {
                    self.q_call_data_start.enable(region, row_offset)?;
                }
                // the last offset of field
                if idx == value.len() - 1 {
                    self.q_call_data_end.enable(region, row_offset)?;
                } else {
                    self.q_call_data_step.enable(region, row_offset)?;
                }
            }
            offset += value.len();
        }
        todo!()
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        anchor_tx: &Transaction,
        chain_id: u64,
        taiko: &Taiko,
        call_data: &CallData,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        self.sign_verify
            .assign(layouter, anchor_tx, chain_id, challenges)?;
        layouter.assign_region(
            || "anchor transaction",
            |ref mut region| {
                self.assign_anchor_tx(region, anchor_tx, taiko, challenges)?;
                self.assign_call_data(region, anchor_tx, call_data, challenges)?;
                Ok(())
            },
        )
    }
}

/// Anchor Transaction Circuit for verifying anchor transaction
#[derive(Clone, Default, Debug)]
pub struct AnchorTxCircuit<F: Field> {
    max_txs: usize,
    anchor_tx: Transaction,
    chain_id: u64,
    taiko: Taiko,
    _marker: PhantomData<F>,
}

impl<F: Field> AnchorTxCircuit<F> {
    /// Return a new TxCircuit
    pub fn new(max_txs: usize, anchor_tx: Transaction, chain_id: u64, taiko: Taiko) -> Self {
        AnchorTxCircuit {
            max_txs,
            anchor_tx,
            chain_id,
            taiko,
            _marker: PhantomData,
        }
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    pub(crate) fn min_num_rows() -> usize {
        let rows_sign_verify = SignVerifyConfig::<F>::min_num_rows();
        std::cmp::max(ANCHOR_CALL_DATA_LEN, rows_sign_verify)
    }

    fn call_data_start(&self) -> usize {
        self.max_txs * TX_LEN + 1 // empty row
    }

    fn call_data_end(&self) -> usize {
        self.call_data_start() + ANCHOR_CALL_DATA_LEN
    }
}

impl<F: Field> SubCircuit<F> for AnchorTxCircuit<F> {
    type Config = AnchorTxCircuitConfig<F>;

    fn unusable_rows() -> usize {
        // No column queried at more than 1 distinct rotations, so returns 5 as
        // minimum unusable row.
        5
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(
            block.circuits_params.max_txs,
            block
                .eth_block
                .transactions
                .iter()
                .map(|tx| tx.into())
                .next()
                .unwrap(),
            block.context.chain_id.as_u64(),
            block.taiko.clone(),
        )
    }

    /// Make the assignments to the TxCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let call_data = CallData {
            start: self.call_data_start(),
            end: self.call_data_end(),
        };
        // the first transaction is the anchor transaction
        config.assign(
            layouter,
            &self.anchor_tx,
            self.chain_id,
            &self.taiko,
            &call_data,
            challenges,
        )
    }

    fn min_num_rows_block(_block: &witness::Block<F>) -> (usize, usize) {
        (Self::min_num_rows(), Self::min_num_rows())
    }
}
