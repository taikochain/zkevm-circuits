//! Anchor circuit implementation.

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub use dev::TestAnchorTxCircuit;
pub(crate) mod sign_verify;
#[cfg(any(feature = "test", test))]
mod test;
#[cfg(any(feature = "test", test))]
pub(crate) use test::{add_anchor_accounts, add_anchor_tx, sign_tx};

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{byte_table::ByteTable, LookupTable, PiFieldTag, PiTable, TxFieldTag, TxTable},
    tx_circuit::TX_LEN,
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, ProtocolInstance, Transaction},
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

// The anchor tx is the first tx
const ANCHOR_TX_ID: usize = 1;
const ANCHOR_TX_VALUE: u64 = 0;
const ANCHOR_TX_IS_CREATE: bool = false;
const ANCHOR_TX_GAS_PRICE: u64 = 1;
const MAX_DEGREE: usize = 9;
const BYTE_POW_BASE: u64 = 1 << 8;

// function anchor(
//     bytes32 l1Hash,
//     bytes32 l1SignalRoot,
//     uint64 l1Height,
//     uint64 parentGasUsed
// )
// anchor(bytes32,bytes32,uint64,uint64) =
// method_signature(4B)+l1Hash(32B)+l1SignalRoot(32B)+l1Height(32B)+parentGasUsed(32B)
const ANCHOR_CALL_DATA_LEN: usize = 132;

struct CallData {
    start: usize,
    end: usize,
}

/// Config for AnchorTxCircuit
#[derive(Clone, Debug)]
pub struct AnchorTxCircuitConfig<F: Field> {
    tx_table: TxTable,
    pi_table: PiTable,
    byte_table: ByteTable,

    sign_verify: SignVerifyConfig<F>,
}

/// Circuit configuration arguments
pub struct AnchorTxCircuitConfigArgs<F: Field> {
    /// TxTable
    pub tx_table: TxTable,
    /// PiTable
    pub pi_table: PiTable,
    /// ByteTable
    pub byte_table: ByteTable,
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
            byte_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {

        let sign_verify =
            SignVerifyConfig::configure(meta, tx_table.clone(), byte_table.clone(), &challenges);


        Self {
            tx_table,
            pi_table,
            byte_table,

            sign_verify,
        }
    }
}

impl<F: Field> AnchorTxCircuitConfig<F> {
    fn assign_anchor_tx_values(
        &self,
        region: &mut Region<'_, F>,
        _anchor_tx: &Transaction,
        protocol_instance: &ProtocolInstance,
        _challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        // Gas, GasPrice, CallerAddress, CalleeAddress, IsCreate, Value, CallDataLength,
        let mut offset = 0;
        for (tag, value) in [
            (
                TxFieldTag::Gas,
                Value::known(F::from(protocol_instance.anchor_gas_limit)),
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
                Value::known(
                    protocol_instance
                        .l2_contract
                        .to_scalar()
                        .expect("anchor_tx.to too big"),
                ),
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
                &anchor_tx.call_data[68..100],
                PiFieldTag::L1Height,
            ),
            (
                "parent_gas_used",
                &anchor_tx.call_data[100..132],
                PiFieldTag::ParentGasUsed,
            ),
        ] {
            let mut rlc_acc = Value::known(F::ZERO);

            offset += value.len();
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
        protocol_instance: &ProtocolInstance,
        call_data: &CallData,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "anchor transaction",
            |ref mut region| {
                // halo2 doesn't support create gates between different regions,
                // so we need to load TxTable in the same region in order to create
                // gate with TxTable's column
                self.tx_table
                    .load_with_region(region, txs, max_txs, max_calldata, challenges)?;
                self.assign_anchor_tx_values(region, anchor_tx, protocol_instance, challenges)?;
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
    protocol_instance: ProtocolInstance,
    _marker: PhantomData<F>,
}

impl<F: Field> AnchorTxCircuit<F> {
    /// Return a new TxCircuit
    pub fn new(
        max_txs: usize,
        max_calldata: usize,
        anchor_tx: Transaction,
        txs: Vec<Transaction>,
        protocol_instance: ProtocolInstance,
    ) -> Self {
        AnchorTxCircuit {
            max_txs,
            max_calldata,
            anchor_tx,
            txs,
            protocol_instance,
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
            block.protocol_instance.clone(),
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
            &self.protocol_instance,
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
