//! Anchor circuit implementation.

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub use dev::TestAnchorTxCircuit;
pub(crate) mod sign_verify;
#[cfg(any(feature = "test", test))]
mod test;
use ethers_core::types::Res;
#[cfg(any(feature = "test", test))]
pub(crate) use test::{add_anchor_accounts, add_anchor_tx, sign_tx};

use crate::{
    assign,
    evm_circuit::table::Table::*,
    table::{byte_table::ByteTable, LookupTable, PiFieldTag, PiTable, TxFieldTag, TxTable},
    tx_circuit::TX_LEN,
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, ProtocolInstance, Transaction}, 
    circuit_tools::{
        cell_manager::{Cell, CellType, CellManager}, 
        constraint_builder::{ConstraintBuilder, COMPRESS, TO_FIX, RLCable}, cached_region::CachedRegion
    }, evm_circuit::{table::Table, util::rlc}, circuit,
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

///
#[derive(Clone, Debug)]
pub struct AnchorData<F> {
    tx_values: Vec<(TxFieldTag, F)>,
    call_data: Vec<(PiFieldTag, Vec<u8>)>,
}

impl<F: Field> Default for AnchorData<F> {
    fn default() -> Self {
        AnchorData {
            tx_values: vec![
                (TxFieldTag::Gas, F::from(0)),
                (TxFieldTag::GasPrice, F::from(0)),
                (TxFieldTag::CallerAddress, F::from(0)),
                (TxFieldTag::CalleeAddress, F::from(0)),
                (TxFieldTag::IsCreate, F::from(0)),
                (TxFieldTag::Value, F::from(0)),
                (TxFieldTag::CallDataLength, F::from(0)),
            ],
            call_data: vec![
                (PiFieldTag::MethodSign, vec![0; 4]),
                (PiFieldTag::L1Hash, vec![0; 32]),
                (PiFieldTag::L1SignalRoot, vec![0; 32]),
                (PiFieldTag::L1Height, vec![0; 32]),
                (PiFieldTag::ParentGasUsed, vec![0; 32]),
            ],
        }
    }
}

impl<F: Field> AnchorData<F> {
    fn new(protocol_instance: &ProtocolInstance, anchor_tx: &Transaction) -> Self {
        AnchorData { 
            tx_values: [
                (TxFieldTag::Gas, F::from(protocol_instance.anchor_gas_limit)),
                (TxFieldTag::GasPrice, F::from(ANCHOR_TX_GAS_PRICE)),
                (TxFieldTag::CallerAddress, 
                    GOLDEN_TOUCH_ADDRESS.to_scalar()
                    .expect("anchor_tx.from too big")
                ),
                (TxFieldTag::CalleeAddress,
                    protocol_instance
                        .l2_contract
                        .to_scalar()
                        .expect("anchor_tx.to too big"),
                ),
                (TxFieldTag::IsCreate, F::from(ANCHOR_TX_IS_CREATE as u64)),
                (TxFieldTag::Value, F::from(ANCHOR_TX_VALUE)),
                (TxFieldTag::CallDataLength, F::from(ANCHOR_CALL_DATA_LEN as u64))
            ].to_vec(), 
            call_data: [
                (
                    PiFieldTag::MethodSign,
                    anchor_tx.call_data[..4].to_vec(),
                ),
                (PiFieldTag::L1Hash, anchor_tx.call_data[4..36].to_vec()),
                (
                    PiFieldTag::L1SignalRoot,
                    anchor_tx.call_data[36..68].to_vec(),
                ),
                (
                    PiFieldTag::L1Height,
                    anchor_tx.call_data[68..100].to_vec(),
                ),
                (
                    PiFieldTag::ParentGasUsed,
                    anchor_tx.call_data[100..132].to_vec(),
                )
            ].to_vec() 
        }
    }

    fn config(
        &self, cb: &mut ConstraintBuilder<F, AnchorCellType>
    ) -> (Vec<FieldGadget<F>>, Vec<FieldGadget<F>>) {
        let tx_values = self.tx_values
            .iter()
            .map(|(tag, value)| FieldGadget::config(cb, 1))
            .collect::<Vec<_>>();
        let call_data = self.call_data
            .iter()
            .map(|(tag, value)| FieldGadget::config(cb, value.len()))
            .collect::<Vec<_>>();
        (tx_values, call_data)
    }

    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        tx_values: &[FieldGadget<F>],
        call_data: &[FieldGadget<F>],
    )-> Result<(), Error> {
        self.tx_values
            .iter()
            .zip(tx_values.iter())
            .for_each(|((tag, value), gadget)| {
                gadget.assign(region, offset, &[*value]).unwrap();
            });
        self.call_data
            .iter()
            .zip(call_data.iter())
            .for_each(|((tag, value), gadget)| {
                let value = value.iter().map(|v| F::from(*v as u64)).collect::<Vec<_>>();
                gadget.assign(region, offset, value.as_slice()).unwrap();
            });
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AnchorCellType {
    Storage1,
    Byte,
    LookupPi,
    Lookup(Table),

}
impl CellType for AnchorCellType {
    fn byte_type() -> Option<Self> {
        Some(Self::Byte)
    }
    fn storage_for_phase(phase: u8) -> Self {
        match phase {
            1 => AnchorCellType::Storage1,
            _ => unimplemented!()
        }
    }
}
impl Default for AnchorCellType {
    fn default() -> Self {
        Self::Storage1
    }
}


/// Config for AnchorTxCircuit
#[derive(Clone, Debug)]
pub struct AnchorTxCircuitConfig<F: Field> {
    tx_table: TxTable,
    pi_table: PiTable,
    byte_table: ByteTable,

    q_enable: Selector,
    tx_values: Vec<FieldGadget<F>>,
    call_data: Vec<FieldGadget<F>>,

    sign_verify: SignVerifyConfig<F>,
}

/// Circuit configuration arguments
pub struct AnchorTxCircuitConfigArgs<F: Field> {
    /// AnchorData
    pub anchor_data: AnchorData<F>,
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
            anchor_data,
            tx_table,
            pi_table,
            byte_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let cm = CellManager::new(
            meta,
            vec![
                (AnchorCellType::Byte, 1, 1, false),
                (AnchorCellType::Lookup(Tx), 1, 2, false),
                (AnchorCellType::LookupPi, 1, 2, false),
            ],
            0,
            139,
        );
        let mut cb: ConstraintBuilder<F, AnchorCellType> = ConstraintBuilder::new(4,  Some(cm.clone()), Some(challenges.evm_word()));
        cb.preload_tables(meta,
            &[
                    (AnchorCellType::Lookup(Tx), &tx_table), 
                    (AnchorCellType::Lookup(Bytecode), &byte_table), 
                    (AnchorCellType::LookupPi, &pi_table)
               ]
           );
        let q_enable = meta.complex_selector();
        let (tx_values, call_data) = anchor_data.config(&mut cb);
        let sign_verify =
                SignVerifyConfig::configure(meta, tx_table.clone(), byte_table.clone(), &challenges);
        circuit!([meta, cb], {
            tx_values
                .iter()
                .zip(anchor_data.tx_values.iter())
                .for_each(|(value, (tag, _))| {
                    require!(
                        (1.expr(), value.acc(1.expr()), 0.expr(), tag.expr()) =>> @AnchorCellType::Lookup(Tx)
                    )
                });
            call_data
                .iter()
                .zip(anchor_data.call_data.iter())
                .for_each(|(value, (tag, _))| {
                    let r = if value.len * 8 > F::CAPACITY as usize {
                        challenges.evm_word().expr()
                    } else {
                        BYTE_POW_BASE.expr()
                    };
                    require!(
                        (1.expr(), value.acc(r), 0.expr(), tag.expr()) =>> @AnchorCellType::LookupPi 
                    )
                });
            cb.build_constraints(Some(q_enable.expr()));         
        });
        cb.build_lookups(
            meta, 
            &[cm.clone()],
            &[
                (AnchorCellType::Byte, AnchorCellType::Lookup(Bytecode)),
                (AnchorCellType::Lookup(Tx), AnchorCellType::Lookup(Tx)),
                (AnchorCellType::LookupPi, AnchorCellType::LookupPi),
            ],
            Some(q_enable)
        );

        meta.pinned().print_layout_states();
        meta.pinned().print_config_states();

        Self {
            tx_table,
            pi_table,
            byte_table,
            q_enable,
            tx_values,
            call_data,
            sign_verify,
        }
    }
}

impl<F: Field> AnchorTxCircuitConfig<F> {

    #[allow(clippy::too_many_arguments)]
    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        protocol_instance: &ProtocolInstance,
        anchor_tx: &Transaction,
        txs: &[Transaction],
        max_txs: usize,
        max_calldata: usize,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let anchor_data: AnchorData<F> = AnchorData::new(protocol_instance, anchor_tx);
        layouter.assign_region(
            || "anchor transaction",
            |ref mut region| {
                // halo2 doesn't support create gates between different regions,
                // so we need to load TxTable in the same region in order to create
                // gate with TxTable's column
                self.tx_table
                    .load_with_region(region, txs, max_txs, max_calldata, challenges)?;
                let mut region = CachedRegion::new(region);
                anchor_data.assign(&mut region, 0, &self.tx_values, &self.call_data)?;
                Ok(())
            },
        )?;
        self.sign_verify.assign(layouter, anchor_tx, challenges)
    }

}

///
#[derive(Debug, Clone)]
pub struct FieldGadget<F> {
    field: Vec<Cell<F>>,
    len: usize,
}

impl<F: Field> FieldGadget<F> {
    fn config(cb: &mut ConstraintBuilder<F, AnchorCellType>, len: usize) -> Self {
        Self {
            field: cb.query_cells_dyn(AnchorCellType::Byte, len),
            len
        }
    }

    fn bytes_expr(&self) -> Vec<Expression<F>> {
        self.field.iter().map(|f| f.expr()).collect()
    }

    fn acc(&self, r: Expression<F>) -> Expression<F> {
        self.bytes_expr().rlc_rev(&r)
    }

    fn assign(
        &self, 
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        bytes: &[F],
    ) -> Result<(), Error> {
        assert!(bytes.len() == self.len);
        self.field
            .iter()
            .zip(bytes.iter())
            .for_each(|(cell, byte)| {
                assign!(region, cell, offset => *byte);
            });
        Ok(())
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
        // let call_data = CallData {
        //     start: Self::call_data_start(self.max_txs),
        //     end: Self::call_data_end(self.max_txs),
        // };
        // the first transaction is the anchor transaction
        config.assign(
            layouter,
            &self.protocol_instance,
            &self.anchor_tx,
            &self.txs,
            self.max_txs,
            self.max_calldata,
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
