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
    table::{LookupTable, PiFieldTag, PiTable, TxContextFieldTag, TxFieldTag, TxTable},
    tx_circuit::TX_LEN,
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, Taiko, Transaction},
};
use eth_types::{Field, ToScalar};
use gadgets::util::{select, Expr};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, Selector},
    poly::Rotation,
};
use sign_verify::SignVerifyConfig;
use std::marker::PhantomData;

use self::sign_verify::GOLDEN_TOUCH_ADDRESS;

// The first of txlist is the anchor tx
const ANCHOR_TX_ID: usize = 1;
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
    use_rlc: Column<Fixed>,

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
        let use_rlc = meta.fixed_column();

        let q_call_data_start = meta.complex_selector();
        let q_call_data_step = meta.complex_selector();
        let q_call_data_end = meta.complex_selector();
        let call_data_rlc_acc = meta.advice_column_in(SecondPhase);
        let call_data_tag = meta.fixed_column();
        let sign_verify = SignVerifyConfig::configure(meta, tx_table.clone(), &challenges);

        // anchor transaction constants
        meta.lookup_any("anchor fixed fields", |meta| {
            let q_tag = meta.query_selector(q_tag);
            [
                ANCHOR_TX_ID.expr(),
                meta.query_fixed(tag, Rotation::cur()),
                0.expr(),
                meta.query_fixed(tag, Rotation::next()),
            ]
            .into_iter()
            .zip(tx_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (q_tag.expr() * arg, table))
            .collect()
        });

        // call data
        meta.create_gate(
            "call_data_rlc_acc[i+1] = call_data_rlc_acc[i] * t + call_data[i+1]",
            |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                let q_call_data_step = meta.query_selector(q_call_data_step);
                let call_data_rlc_acc_next = meta.query_advice(call_data_rlc_acc, Rotation::next());
                let call_data_rlc_acc = meta.query_advice(call_data_rlc_acc, Rotation::cur());
                let call_data_next = meta.query_advice(tx_table.value, Rotation::next());
                let use_rlc = meta.query_fixed(use_rlc, Rotation::cur());
                let randomness = challenges.lookup_input();
                let t = select::expr(use_rlc, randomness, BYTE_POW_BASE.expr());
                cb.require_equal(
                    "call_data_rlc_acc[i+1] = call_data_rlc_acc[i] * t + call_data[i+1]",
                    call_data_rlc_acc_next,
                    call_data_rlc_acc * t + call_data_next,
                );
                cb.gate(q_call_data_step)
            },
        );

        meta.create_gate("call_data_rlc_acc[0] = call_data[0]", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_call_data_start = meta.query_selector(q_call_data_start);
            let call_data_rlc_acc = meta.query_advice(call_data_rlc_acc, Rotation::cur());
            let call_data = meta.query_advice(tx_table.value, Rotation::cur());

            cb.require_equal(
                "call_data_rlc_acc[0] = call_data[0]",
                call_data_rlc_acc,
                call_data,
            );
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
            use_rlc,

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
            let (use_rlc, t) = if value.len() * 8 > F::CAPACITY as usize {
                (Value::known(F::ONE), challenges.evm_word())
            } else {
                (Value::known(F::ZERO), Value::known(F::from(BYTE_POW_BASE)))
            };
            for (idx, byte) in value.iter().enumerate() {
                let row_offset = offset + idx;
                rlc_acc = rlc_acc * t + Value::known(F::from(*byte as u64));
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
                region.assign_fixed(|| annotation, self.use_rlc, row_offset, || use_rlc)?;
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
        Ok(())
    }

    fn load_tx_table(
        &self,
        region: &mut Region<'_, F>,
        txs: &[Transaction],
        max_txs: usize,
        max_calldata: usize,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        assert!(
            txs.len() <= max_txs,
            "txs.len() <= max_txs: txs.len()={}, max_txs={}",
            txs.len(),
            max_txs
        );
        let sum_txs_calldata = txs.iter().map(|tx| tx.call_data.len()).sum();
        assert!(
            sum_txs_calldata <= max_calldata,
            "sum_txs_calldata <= max_calldata: sum_txs_calldata={}, max_calldata={}",
            sum_txs_calldata,
            max_calldata,
        );

        fn assign_row<F: Field>(
            region: &mut Region<'_, F>,
            offset: usize,
            advice_columns: &[Column<Advice>],
            tag: &Column<Fixed>,
            row: &[Value<F>; 4],
            msg: &str,
        ) -> Result<(), Error> {
            for (index, column) in advice_columns.iter().enumerate() {
                region.assign_advice(
                    || format!("tx table {} row {}", msg, offset),
                    *column,
                    offset,
                    || row[if index > 0 { index + 1 } else { index }],
                )?;
            }
            region.assign_fixed(
                || format!("tx table {} row {}", msg, offset),
                *tag,
                offset,
                || row[1],
            )?;
            Ok(())
        }

        let mut offset = 0;
        let advice_columns = [
            self.tx_table.tx_id,
            self.tx_table.index,
            self.tx_table.value,
        ];
        assign_row(
            region,
            offset,
            &advice_columns,
            &self.tx_table.tag,
            &[(); 4].map(|_| Value::known(F::ZERO)),
            "all-zero",
        )?;
        offset += 1;

        // Tx Table contains an initial region that has a size parametrized by max_txs
        // with all the tx data except for calldata, and then a second
        // region that has a size parametrized by max_calldata with all
        // the tx calldata.  This is required to achieve a constant fixed column tag
        // regardless of the number of input txs or the calldata size of each tx.
        let mut calldata_assignments: Vec<[Value<F>; 4]> = Vec::new();
        // Assign Tx data (all tx fields except for calldata)
        let padding_txs: Vec<_> = (txs.len()..max_txs)
            .map(|i| Transaction {
                id: i + 1,
                ..Default::default()
            })
            .collect();
        for tx in txs.iter().chain(padding_txs.iter()) {
            let [tx_data, tx_calldata] = tx.table_assignments(*challenges);
            for row in tx_data {
                assign_row(
                    region,
                    offset,
                    &advice_columns,
                    &self.tx_table.tag,
                    &row,
                    "",
                )?;
                offset += 1;
            }
            calldata_assignments.extend(tx_calldata.iter());
        }
        // Assign Tx calldata
        let padding_calldata = (sum_txs_calldata..max_calldata).map(|_| {
            [
                Value::known(F::ZERO),
                Value::known(F::from(TxContextFieldTag::CallData as u64)),
                Value::known(F::ZERO),
                Value::known(F::ZERO),
            ]
        });
        for row in calldata_assignments.into_iter().chain(padding_calldata) {
            assign_row(
                region,
                offset,
                &advice_columns,
                &self.tx_table.tag,
                &row,
                "",
            )?;
            offset += 1;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        anchor_tx: &Transaction,
        txs: &[Transaction],
        max_txs: usize,
        max_calldata: usize,
        taiko: &Taiko,
        call_data: &CallData,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "anchor transaction",
            |ref mut region| {
                self.load_tx_table(region, txs, max_txs, max_calldata, challenges)?;
                self.assign_anchor_tx(region, anchor_tx, taiko, challenges)?;
                self.assign_call_data(region, anchor_tx, call_data, challenges)?;
                Ok(())
            },
        )?;
        self.sign_verify.assign(layouter, anchor_tx, challenges)
    }
}

/// Anchor Transaction Circuit for verifying anchor transaction
#[derive(Clone, Default, Debug)]
pub struct AnchorTxCircuit<F: Field> {
    max_txs: usize,
    max_calldata: usize,
    anchor_tx: Transaction,
    txs: Vec<Transaction>,
    taiko: Taiko,
    _marker: PhantomData<F>,
}

impl<F: Field> AnchorTxCircuit<F> {
    /// Return a new TxCircuit
    pub fn new(
        max_txs: usize,
        max_calldata: usize,
        anchor_tx: Transaction,
        txs: Vec<Transaction>,
        taiko: Taiko,
    ) -> Self {
        AnchorTxCircuit {
            max_txs,
            max_calldata,
            anchor_tx,
            txs,
            taiko,
            _marker: PhantomData,
        }
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    pub(crate) fn min_num_rows(max_txs: usize) -> usize {
        let rows_sign_verify = SignVerifyConfig::<F>::min_num_rows();
        std::cmp::max(Self::call_data_end(max_txs), rows_sign_verify)
    }

    fn call_data_start(max_txs: usize) -> usize {
        max_txs * TX_LEN + 1 // empty row
    }

    fn call_data_end(max_txs: usize) -> usize {
        Self::call_data_start(max_txs) + ANCHOR_CALL_DATA_LEN
    }
}

impl<F: Field> SubCircuit<F> for AnchorTxCircuit<F> {
    type Config = AnchorTxCircuitConfig<F>;

    fn unusable_rows() -> usize {
        // No column queried at more than 7 distinct rotations, so returns 10 as
        // minimum unusable row.
        10
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            block.txs.first().unwrap().clone(),
            block.txs.clone(),
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
            start: Self::call_data_start(self.max_txs),
            end: Self::call_data_end(self.max_txs),
        };
        // the first transaction is the anchor transaction
        config.assign(
            layouter,
            &self.anchor_tx,
            &self.txs,
            self.max_txs,
            self.max_calldata,
            &self.taiko,
            &call_data,
            challenges,
        )
    }

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        (
            Self::min_num_rows(block.circuits_params.max_txs),
            Self::min_num_rows(block.circuits_params.max_txs),
        )
    }
}
