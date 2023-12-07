//! TaikoPiCircuit
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;
mod param;
#[cfg(any(test))]
mod test;
use bus_mapping::circuit_input_builder::ProtocolInstance;

use param::*;

// use bus_mapping::circuit_input_builder::ProtocolInstance;
use eth_types::{Field, U256};

use ethers_core::utils::keccak256;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};

use gadgets::util::{Expr, Scalar};
use halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Expression, Instance, Selector};
use std::marker::PhantomData;

use crate::{
    assign, circuit,
    circuit_tools::{
        cached_region::CachedRegion,
        cell_manager::{Cell, CellColumn, CellManager, CellType},
        constraint_builder::{ConstraintBuilder, RLCable},
    },
    evm_circuit::{table::Table, util::rlc},
    table::{byte_table::ByteTable, BlockContextFieldTag, BlockTable, KeccakTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, BlockContext},
};

use core::result::Result;
use halo2_proofs::plonk::Error;

const S1: PiCellType = PiCellType::StoragePhase1;
const S2: PiCellType = PiCellType::StoragePhase2;
///
#[derive(Debug, Clone, Default)]
pub struct FieldGadget<F> {
    field: Vec<Cell<F>>,
    len: usize,
}

impl<F: Field> FieldGadget<F> {
    fn config(cb: &mut ConstraintBuilder<F, PiCellType>, len: usize) -> Self {
        Self {
            field: cb.query_cells_dyn(PiCellType::Byte, len),
            len,
        }
    }

    fn bytes_expr(&self) -> Vec<Expression<F>> {
        self.field.iter().map(|f| f.expr()).collect()
    }

    fn rlc_acc(&self, r: Expression<F>) -> Expression<F> {
        // 0.expr()
        self.bytes_expr().rlc_rev(&r)
    }

    pub(crate) fn hi_low_field(&self) -> [Expression<F>; 2] {
        assert!(self.len == 32);
        let hi = self.bytes_expr()[..16].to_vec();
        let low = self.bytes_expr()[16..].to_vec();
        [
            hi.rlc_rev(&BYTE_POW_BASE.expr()),
            low.rlc_rev(&BYTE_POW_BASE.expr()),
        ]
    }

    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        bytes: &[F],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        assert!(bytes.len() == self.len);
        let cells = self
            .field
            .iter()
            .zip(bytes.iter())
            .map(|(cell, byte)| assign!(region, cell, offset => *byte).unwrap())
            .collect();
        Ok(cells)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum PiCellType {
    StoragePhase1,
    StoragePhase2,
    Byte,
}

impl CellType for PiCellType {
    type TableType = Table;

    fn create_type(_id: usize) -> Self {
        unreachable!()
    }
    fn lookup_table_type(&self) -> Option<Self::TableType> {
        match self {
            PiCellType::Byte => Some(Table::Bytecode),
            _ => None,
        }
    }
    fn byte_type() -> Option<Self> {
        Some(Self::Byte)
    }
    fn storage_for_phase(phase: u8) -> Self {
        match phase {
            1 => PiCellType::StoragePhase1,
            2 => PiCellType::StoragePhase2,
            _ => unimplemented!(),
        }
    }
}

impl Default for PiCellType {
    fn default() -> Self {
        Self::StoragePhase1
    }
}

/// Public Inputs data known by the verifier
#[derive(Debug, Clone)]
pub struct PublicData<F> {
    pub(crate) protocol_instance: ProtocolInstance,
    pub(crate) block_context: BlockContext,
    _phantom: PhantomData<F>,
}

impl<F: Field> Default for PublicData<F> {
    fn default() -> Self {
        // has to have at least one history hash, block number must start with at least one
        let block = witness::Block::<F> {
            protocol_instance: Some(ProtocolInstance::default()),
            ..Default::default()
        };
        let mut ret = Self::new(&block);
        ret.block_context.history_hashes = vec![U256::default()];
        ret
    }
}

impl<F: Field> PublicData<F> {
    fn new(block: &witness::Block<F>) -> Self {
        Self {
            protocol_instance: block.protocol_instance.clone().unwrap(),
            block_context: block.context.clone(),
            _phantom: PhantomData,
        }
    }

    fn encode_field(&self, idx: usize) -> Vec<u8> {
        match idx {
            0 => self.protocol_instance.parentHash(),
            1 => self.protocol_instance.blockHash(),
            2 => self.protocol_instance.signalRoot(),
            3 => self.protocol_instance.graffiti(),
            4 => self.protocol_instance.meta_hash(),
            5 => self.protocol_instance.prover(),
            6 => self.protocol_instance.tx_list_hash(),
            7 => self.protocol_instance.point_value(),
            _ => unreachable!(),
        }
    }

    fn total_acc(&self, r: Value<F>) -> F {
        let mut rand = F::ZERO;
        r.map(|r| rand = r);
        rlc::value(self.protocol_instance.abi_encode().iter().rev(), rand)
    }

    fn assignment(&self, idx: usize) -> Vec<F> {
        self.encode_field(idx)
            .iter()
            .map(|b| F::from(*b as u64))
            .collect()
    }

    fn assignment_acc(&self, idx: usize, r: Value<F>) -> F {
        let mut rand = F::ZERO;
        r.map(|r| rand = r);
        rlc::value(self.encode_field(idx).iter().rev(), rand)
    }

    fn keccak_hi_low(&self) -> [F; 2] {
        let keccaked_pi = keccak256(self.protocol_instance.abi_encode());
        [
            rlc::value(keccaked_pi[0..16].iter().rev(), BYTE_POW_BASE.scalar()),
            rlc::value(keccaked_pi[16..].iter().rev(), BYTE_POW_BASE.scalar()),
        ]
    }

    fn keccak(&self) -> Vec<u8> {
        keccak256(self.protocol_instance.abi_encode()).to_vec()
    }

    fn keccak_assignment(&self) -> Vec<F> {
        self.keccak().iter().map(|b| F::from(*b as u64)).collect()
    }

    fn total_len(&self) -> usize {
        self.protocol_instance.abi_encode().len()
    }

    fn field_len(&self, idx: usize) -> usize {
        self.encode_field(idx).len()
    }
}

/// PiCircuitConfig
#[derive(Clone, Debug)]
pub struct TaikoPiCircuitConfig<F: Field> {
    q_enable: Selector,
    keccak_instance: Column<Instance>, // equality
    columns: Vec<CellColumn<F, PiCellType>>,

    parent_hash: (Cell<F>, FieldGadget<F>, Cell<F>),
    block_hash: (Cell<F>, FieldGadget<F>, Cell<F>),
    signal_root: FieldGadget<F>,
    graffiti: FieldGadget<F>,
    meta_hash: FieldGadget<F>,
    prover: FieldGadget<F>,
    tx_list_hash: FieldGadget<F>,
    point_value: FieldGadget<F>,

    keccak_bytes: FieldGadget<F>,
    keccak_hi_lo: [Cell<F>; 2],

    total_acc: Cell<F>,
    block_table: BlockTable,
    keccak_table: KeccakTable,
    byte_table: ByteTable,
}

/// PiCircuitConfigArgs
pub struct TaikoPiConfigArgs<F: Field> {
    ///
    pub public_data: PublicData<F>,
    /// BlockTable
    pub block_table: BlockTable,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// ByteTable
    pub byte_table: ByteTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for TaikoPiCircuitConfig<F> {
    type ConfigArgs = TaikoPiConfigArgs<F>;
    /// Return a new TaikoPiCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            public_data,
            block_table,
            keccak_table,
            byte_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let pi = &public_data.protocol_instance;
        let keccak_r = challenges.keccak_input();
        let evm_word = challenges.evm_word();
        let mut cm = CellManager::new(CM_HEIGHT, 0);
        let mut cb: ConstraintBuilder<F, PiCellType> =
            ConstraintBuilder::new(4, Some(cm.clone()), Some(evm_word.expr()));
        cb.load_table(meta, Table::Keccak, &keccak_table);
        cb.load_table(meta, Table::Bytecode, &byte_table);
        cb.load_table(meta, Table::Block, &block_table);
        cm.add_columns(meta, &mut cb, PiCellType::Byte, 0, false, 15);
        cm.add_columns(meta, &mut cb, PiCellType::StoragePhase1, 0, true, 1);
        cm.add_columns(meta, &mut cb, PiCellType::StoragePhase2, 1, true, 1);
        let columns = cm.columns().to_vec();
        cb.set_cell_manager(cm);

        let q_enable = meta.complex_selector();
        let keccak_instance = meta.instance_column();
        meta.enable_equality(keccak_instance);

        let parent_hash = (
            cb.query_one(S1),
            FieldGadget::config(&mut cb, pi.parentHash().len()),
            cb.query_one(S2),
        );
        let block_hash = (
            cb.query_one(S1),
            FieldGadget::config(&mut cb, pi.blockHash().len()),
            cb.query_one(S2),
        );
        let signal_root = FieldGadget::config(&mut cb, pi.signalRoot().len());
        let graffiti = FieldGadget::config(&mut cb, pi.graffiti().len());
        let meta_hash = FieldGadget::config(&mut cb, pi.meta_hash().len());
        let prover = FieldGadget::config(&mut cb, pi.prover().len());
        let tx_list_hash = FieldGadget::config(&mut cb, pi.tx_list_hash().len());
        let point_value = FieldGadget::config(&mut cb, pi.point_value().len());

        let total_acc = cb.query_one(S2);
        let keccak_bytes = FieldGadget::config(&mut cb, DEFAULT_LEN);
        let keccak_hi_lo = [cb.query_one(S1), cb.query_one(S1)];
        meta.create_gate("PI acc constraints", |meta| {
            circuit!([meta, cb], {
                ifx!(q!(q_enable) => {
                    for (block_number, block_hash, block_hash_rlc) in [parent_hash.clone(), block_hash.clone()] {
                        require!(block_hash_rlc.expr() => block_hash.rlc_acc(evm_word.expr()));
                        require!(
                            (
                                BlockContextFieldTag::BlockHash.expr(),
                                block_number.expr(),
                                block_hash_rlc.expr()
                            ) => @cb.table(Table::Block)
                        );
                    }
                    let acc_val = [
                        parent_hash.1.clone(),
                        block_hash.1.clone(),
                        signal_root.clone(),
                        graffiti.clone(),
                        meta_hash.clone(),
                        prover.clone(),
                        tx_list_hash.clone(),
                        point_value.clone(),
                    ]
                    .iter()
                    .fold(0.expr(), |acc, gadget| {
                        let mult = (0..gadget.len).fold(1.expr(), |acc, _| acc * keccak_r.expr());
                        acc * mult + gadget.rlc_acc(keccak_r.expr())
                    });
                    require!(total_acc.expr() => acc_val);
                    require!(
                        (
                            1.expr(),
                            total_acc.expr(),
                            public_data.total_len().expr(),
                            keccak_bytes.rlc_acc(evm_word.expr())
                        )
                        => @cb.table(Table::Keccak)
                    );
                    let hi_lo = keccak_bytes.hi_low_field();
                    keccak_hi_lo
                        .iter()
                        .zip(hi_lo.iter())
                        .for_each(|(cell, epxr)| {
                            require!(cell.expr() => epxr);
                            cb.enable_equality(cell.column());
                        });
                });
            });
            cb.build_constraints()
        });
        cb.build_lookups(meta);

        Self {
            q_enable,
            keccak_instance,
            columns,

            parent_hash,
            block_hash,
            signal_root,
            graffiti,
            meta_hash,
            prover,
            tx_list_hash,
            point_value,

            total_acc,
            keccak_bytes,
            keccak_hi_lo,
            block_table,
            keccak_table,
            byte_table,
        }
    }
}

impl<F: Field> TaikoPiCircuitConfig<F> {
    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        challenge: &Challenges<Value<F>>,
        public_data: &PublicData<F>,
    ) -> Result<(), Error> {
        let evm_word = challenge.evm_word();
        let keccak_r = challenge.keccak_input();
        let hi_lo_cells = layouter.assign_region(
        || "Pi",
        |mut region| {
                self.q_enable.enable(&mut region, 0)?;
                let mut region = CachedRegion::new(&mut region);
                region.annotate_columns(&self.columns);

                assign!(region, self.parent_hash.0, 0 => (public_data.block_context.number - 1).as_u64().scalar())?;
                assign!(region, self.parent_hash.2, 0 => public_data.assignment_acc(PARENT_HASH, evm_word))?;
                assign!(region, self.block_hash.0, 0 => (public_data.block_context.number).as_u64().scalar())?;
                assign!(region, self.block_hash.2, 0 => public_data.assignment_acc(BLOCK_HASH, evm_word))?;

                let mut idx = 0;
                [
                    &self.parent_hash.1,
                    &self.block_hash.1,
                    &self.signal_root,
                    &self.graffiti,
                    &self.meta_hash,
                    &self.prover,
                    &self.tx_list_hash,
                    &self.point_value,
                ].iter().for_each(|gadget| {
                    gadget.assign(&mut region, 0, &public_data.assignment(idx))
                        .expect(&format!("FieldGadget assignment failed at {:?}", idx));
                    idx += 1;
                });

                self.keccak_bytes.assign(&mut region, 0, &public_data.keccak_assignment())
                    .expect("Keccak bytes assignment failed");                
                assign!(region, self.total_acc, 0 => public_data.total_acc(keccak_r))?;
                let hi_low_assignment = public_data.keccak_hi_low();
                let hi = assign!(region, self.keccak_hi_lo[0], 0 => hi_low_assignment[0])?;
                let lo = assign!(region, self.keccak_hi_lo[1], 0 => hi_low_assignment[1])?;

                Ok([hi, lo])
        })?;
        for (i, cell) in hi_lo_cells.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), self.keccak_instance, i)?;
        }
        Ok(())
    }
}
/// Public Inputs Circuit
#[derive(Clone, Debug, Default)]
pub struct TaikoPiCircuit<F: Field> {
    /// PublicInputs data known by the verifier
    pub public_data: PublicData<F>,
}

impl<F: Field> TaikoPiCircuit<F> {
    /// Creates a new TaikoPiCircuit
    pub fn new(public_data: PublicData<F>) -> Self {
        Self { public_data }
    }
}

impl<F: Field> SubCircuit<F> for TaikoPiCircuit<F> {
    type Config = TaikoPiCircuitConfig<F>;

    fn unusable_rows() -> usize {
        // No column queried at more than 3 distinct rotations, so returns 6 as
        // minimum unusable rows.
        CM_HEIGHT + 3
    }

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        (0, PublicData::new(block).total_len())
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        TaikoPiCircuit::new(PublicData::new(block))
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        vec![self.public_data.keccak_hi_low().to_vec()]
    }

    /// Make the assignments to the PiCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign(layouter, challenges, &self.public_data)
    }
}
