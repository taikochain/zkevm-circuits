//! Use the hash value as public input.

use crate::{
    assign,
    evm_circuit::table::Table::*,
    evm_circuit::{util::{constraint_builder::{ConstrainBuilderCommon}}, table::Table},
    table::{byte_table::ByteTable, BlockContextFieldTag, BlockTable, KeccakTable, LookupTable},
    util::{Challenges, SubCircuitConfig, SubCircuit},
    circuit_tools::{
        constraint_builder::{ConstraintBuilder, RLCable, TO_FIX, RLCableValue},
        cell_manager::{CellManager, CellType, Cell, CellColumn}, gadgets::{IsEqualGadget}, cached_region::{CachedRegion},
    },
    
    witness::{self, BlockContext}, circuit,
};

use gadgets::util::{Scalar, not};
use eth_types::{Address, Field, ToBigEndian, ToWord, Word, H256};
use ethers_core::utils::keccak256;
use gadgets::{util::{Expr}};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Circuit, Column, ConstraintSystem, Error, Expression, Instance,
        Selector,
    },
};

use std::{marker::PhantomData, usize, vec};

const BYTE_POW_BASE: u64 = 1 << 8;
const N: usize = 32;
const H: usize = 12;
const RPI_BYTES_LEN: usize = 32 * 10;
const USED_ROWS: usize = RPI_BYTES_LEN + 64;

const L1SIGNAL_IDX: usize = 0;
const PARENT_HASH: usize = 4;
const BLOCK_HASH: usize = 5;
const FIELD9_IDX: usize = 8;
const FIELD10_IDX: usize = 9;
const KECCAK_OUTPUT: usize = 10;


/// PublicData contains all the values that the PiCircuit receives as input
#[derive(Debug, Clone, Default)]
pub struct PublicData {
    /// l1 signal service address
    pub l1_signal_service: Word,
    /// l2 signal service address
    pub l2_signal_service: Word,
    /// l2 contract address
    pub l2_contract: Word,


    /// meta hash
    pub meta_hash: Word,
    /// block hash value
    pub block_hash: Word,
    /// the parent block hash
    pub parent_hash: Word,
    /// signal root
    pub signal_root: Word,
    /// extra message
    pub graffiti: Word,
    /// union field
    pub field9: Word, // prover[96:256]+parentGasUsed[64:96]+gasUsed[32:64]
    /// union field
    pub field10: Word, /* blockMaxGasLimit[192:256]+maxTransactionsPerBlock[128:
                        * 192]+maxBytesPerTxList[64:128] */

    // privates
    // Prover address
    prover: Address,
    // parent block gas used
    parent_gas_used: u32,
    // block gas used
    gas_used: u32,
    // blockMaxGasLimit
    block_max_gas_limit: u64,
    // maxTransactionsPerBlock: u64,
    max_transactions_per_block: u64,
    // maxBytesPerTxList: u64,
    max_bytes_per_tx_list: u64,

    block_context: BlockContext,
    chain_id: Word,
}

impl PublicData {
    fn assignments(&self) -> [(&'static str, Option<Word>, Vec<u8>); 10] {
        [
            (
                "l1_signal_service",
                None,
                self.l1_signal_service.to_be_bytes().to_vec(),
            ),
            (
                "l2_signal_service",
                None,
                self.l2_signal_service.to_be_bytes().to_vec(),
            ),
            ("l2_contract", None, self.l2_contract.to_be_bytes().to_vec()),
            
            ("meta_hash", None, self.meta_hash.to_be_bytes().to_vec()),
            (
                "parent_hash",
                Some(self.block_context.number - 1),
                self.parent_hash.to_be_bytes().to_vec(),
            ),
            (
                "block_hash",
                Some(self.block_context.number),
                self.block_hash.to_be_bytes().to_vec(),
            ),
            ("signal_root", None, self.signal_root.to_be_bytes().to_vec()),
            ("graffiti", None, self.graffiti.to_be_bytes().to_vec()),
            (
                "prover+parentGasUsed+gasUsed",
                None,
                self.field9.to_be_bytes().to_vec(),
            ),
            (
                "blockMaxGasLimit+maxTransactionsPerBlock+maxBytesPerTxList",
                None,
                self.field10.to_be_bytes().to_vec(),
            ),
        ]
    }

    // pub fn abi_encode(&self) -> Vec<u8> {
        
    // }

    /// get rpi bytes
    pub fn rpi_bytes(&self) -> Vec<u8> {
        self.assignments().iter().flat_map(|v| v.2.clone()).collect()
    }

    fn default<F: Default>() -> Self {
        Self::new::<F>(&witness::Block::default())
    }

    /// create PublicData from block and taiko
    pub fn new<F>(block: &witness::Block<F>) -> Self {
        use witness::left_shift;
        let field9 = left_shift(block.protocol_instance.prover, 96)
            + left_shift(block.protocol_instance.parent_gas_used as u64, 64)
            + left_shift(block.protocol_instance.gas_used as u64, 32);

        let field10 = left_shift(block.protocol_instance.block_max_gas_limit, 192)
            + left_shift(block.protocol_instance.max_transactions_per_block, 128)
            + left_shift(block.protocol_instance.max_bytes_per_tx_list, 64);
        PublicData {
            l1_signal_service: block.protocol_instance.l1_signal_service.to_word(),
            l2_signal_service: block.protocol_instance.l2_signal_service.to_word(),
            l2_contract: block.protocol_instance.l2_contract.to_word(),
            meta_hash: block.protocol_instance.meta_hash.hash().to_word(),
            block_hash: block.protocol_instance.block_hash.to_word(),
            parent_hash: block.protocol_instance.parent_hash.to_word(),
            signal_root: block.protocol_instance.signal_root.to_word(),
            graffiti: block.protocol_instance.graffiti.to_word(),
            prover: block.protocol_instance.prover,
            parent_gas_used: block.protocol_instance.parent_gas_used,
            gas_used: block.protocol_instance.gas_used,
            block_max_gas_limit: block.protocol_instance.block_max_gas_limit,
            max_transactions_per_block: block.protocol_instance.max_transactions_per_block,
            max_bytes_per_tx_list: block.protocol_instance.max_bytes_per_tx_list,
            field9,
            field10,
            block_context: block.context.clone(),
            chain_id: block.context.chain_id,
        }
    }

    fn get_pi(&self) -> H256 {
        let rpi_bytes = self.rpi_bytes();
        let rpi_keccak = keccak256(rpi_bytes);
        H256(rpi_keccak)
    }  

    fn get_pi_hi_low<F: Field>(&self) -> (F, F) {
        let keccak_rpi = self.get_pi().to_fixed_bytes();
        (
            keccak_rpi
                .iter()
                .take(16)
                .fold(F::ZERO, |acc, byte| {
                    acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
                }),
            keccak_rpi
                .iter()
                .skip(16)
                .fold(F::ZERO, |acc, byte| {
                    acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
                })
        )
    }
}
/// Config for PiCircuit
#[derive(Clone, Debug)]
pub struct TaikoPiCircuitConfig<F: Field> {
    q_enable: Selector,
    public_input: Column<Instance>, // equality
    field: FieldBytesGadget<F>,
    state: PiState<F>,
    block_acc: Cell<F>, // Phase2
    block_number: Cell<F>, // Phase1
    keccak_input: Cell<F>, // Phase2
    keccak_output:[Cell<F>;2], // Phase2

    block_table: BlockTable,
    keccak_table: KeccakTable,
    byte_table: ByteTable,

    // To annotate columns at assignment for debug purpose 
    col_configs: Vec<CellColumn<F, PiCellType>>,
}

/// Circuit configuration arguments
pub struct TaikoPiCircuitConfigArgs<F: Field> {
    /// BlockTable
    pub block_table: BlockTable,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// ByteTable
    pub byte_table: ByteTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum PiCellType {
    Storage1,
    Storage2,
    Byte,
    Lookup(Table)
}
impl CellType for PiCellType {
    fn byte_type() -> Option<Self> {
        Some(Self::Byte)
    }
    fn storage_for_phase(phase: u8) -> Self {
        match phase {
            1 => PiCellType::Storage1,
            2 => PiCellType::Storage2,
            _ => unimplemented!()
        }
    }
}
impl Default for PiCellType {
    fn default() -> Self {
        Self::Storage1
    }
}


impl<F: Field> SubCircuitConfig<F> for TaikoPiCircuitConfig<F> {
    type ConfigArgs = TaikoPiCircuitConfigArgs<F>;

        /// Return a new TaikoPiCircuitConfig
        fn new(
            meta: &mut ConstraintSystem<F>,
            Self::ConfigArgs {
                block_table,
                keccak_table,
                byte_table,
                challenges,
            }: Self::ConfigArgs,
        ) -> Self {
            let cm = CellManager::new(
                meta,
                vec![
                    (PiCellType::Byte, 1, 1, false),
                    (PiCellType::Storage1, 1, 1, false),
                    (PiCellType::Storage2, 1, 2, true),
                ],
                0,
                32,
            );
            let mut cb: ConstraintBuilder<F, PiCellType> = ConstraintBuilder::new(4,  Some(cm.clone()), Some(challenges.evm_word()));
            cb.preload_tables(meta,
                &[
                        (PiCellType::Lookup(Keccak), &keccak_table), 
                        (PiCellType::Lookup(Bytecode), &byte_table), 
                        (PiCellType::Lookup(Block), &block_table)
                   ]
               );
            let q_enable = meta.complex_selector();
            let public_input = meta.instance_column();
            let field = FieldBytesGadget::config(&mut cb, &challenges);
            let state = PiState::config(&mut cb);
            let block_acc = cb.query_one(PiCellType::Storage2);
            let block_number = cb.query_one(PiCellType::Storage1);
            let keccak_input = cb.query_one(PiCellType::Storage2);
            let keccak_output = [();2].map(|_| cb.query_one(PiCellType::Storage2));
            meta.enable_equality(public_input);
            meta.create_gate(
                "PI acc constraints", 
                |meta| {
                    let keccak_mult = (0..N).fold(1.expr(), |acc, _| acc * challenges.keccak_input());
                    // let evm_mult = (0..N).fold(1.expr(), |acc, _| acc * challenges.evm_word());
                    circuit!([meta, cb], {
                        ifx!(state.increment_step() => {
                            require!(block_acc.rot(meta, 32) => block_acc.expr() * keccak_mult + field.keccak_field());
                        });
                        matchx!((
                            state.is_l1_signal.expr() => {
                                require!(block_acc.expr() => field.keccak_field());
                            },
                            state.lookup_blockhash() => {
                                require!(
                                    (
                                        BlockContextFieldTag::BlockHash.expr(), 
                                        block_number.expr(), 
                                        field.evm_word_field()
                                    ) => @PiCellType::Lookup(Table::Block), (TO_FIX)
                                );
                            },
                            state.is_field_10.expr() => {
                                require!(keccak_input.expr() => block_acc.expr());
                            },
                            state.is_keccak_output.expr() => {
                                require!(
                                    (
                                        1.expr(), 
                                        keccak_input.expr(), 
                                        RPI_BYTES_LEN.expr(), 
                                        field.evm_word_field()
                                    )
                                    => @PiCellType::Lookup(Table::Keccak), (TO_FIX)
                                );
                                let (hi_expr, low_expr) = field.hi_low_field();
                                require!(keccak_output[0].expr() => hi_expr);
                                require!(keccak_output[1].expr() => low_expr);
                                keccak_output.iter().for_each(|c| cb.enable_equality(c.column()));
                            }
                        ));
                    });
                    cb.build_constraints(Some(meta.query_selector(q_enable)))
                }
            );
            cb.build_equalities(meta);
            cb.build_lookups(
                meta, 
                &[cm.clone()],
                &[
                    (PiCellType::Byte, PiCellType::Lookup(Bytecode)),
                    (PiCellType::Lookup(Table::Keccak), PiCellType::Lookup(Table::Keccak)),
                    (PiCellType::Lookup(Table::Block), PiCellType::Lookup(Table::Block)),
                ],
                Some(q_enable)
            );
            // meta.pinned().print_config_states();
            // meta.pinned().print_layout_states();

            let col_configs = cm.columns().to_vec();
            Self {
                q_enable,
                public_input,
                field,
                state,
                block_acc,
                block_number,
                keccak_input,
                keccak_output,
                block_table,
                keccak_table,
                byte_table,
                col_configs,
            }
        }

}

impl<F: Field> TaikoPiCircuitConfig<F> {
    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        public_data: &PublicData,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let pi_cells = layouter.assign_region(
        || "Pi",
        |mut region| {
                
                self.q_enable.enable(&mut region, 0)?;
                let mut region = CachedRegion::new(&mut region);
                region.annotate_columns(&self.col_configs);

                let mut block_acc = F::ZERO;
                let mut keccak_r = F::ZERO;
                challenges.keccak_input().map(|v| keccak_r = v);
                let keccak_mult = (0..N).fold(1.scalar(), |acc: F, _| acc * keccak_r);

                let mut assignments = public_data.assignments().to_vec();
                assignments.append(&mut vec![
                    ("keccak_output", None, public_data.get_pi().to_fixed_bytes().to_vec())
                ]);
                let mut offset = 0;
                let mut state = 0;
                let mut pi_cells = Vec::new();
                for (_annotation, block_number, bytes) in assignments {
                    self.state.assign(&mut region, offset, state)?;
                    if state != KECCAK_OUTPUT {
                        let next = block_acc * keccak_mult 
                            + self.field.assign(&mut region, offset, &bytes, keccak_r)?;
                        assign!(region, self.block_acc, offset => next)?;
                        block_acc = next;
                    }
                    match state {
                        PARENT_HASH | BLOCK_HASH => {
                            let block_number = block_number.expect(&format!("block_number missing at {:?}th row", offset));
                            assign!(region, self.block_number, offset => block_number.as_u64().scalar())?;
                        },
                        FIELD10_IDX => {
                            assign!(region, self.keccak_input, offset => block_acc)?;
                        },
                        KECCAK_OUTPUT => {
                            let (hi, low) = public_data.get_pi_hi_low::<F>();
                            pi_cells.push(assign!(region, self.keccak_output[0], offset => hi)?);
                            pi_cells.push(assign!(region, self.keccak_output[1], offset => low)?);
                        },
                        _ => ()
                    }
                    offset += N;
                    state += 1
                }
                Ok(pi_cells)
            }
        )?;
        for (i, cell) in pi_cells.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), self.public_input, i)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct PiState<F> {
    pub(crate) state: Cell<F>,
    is_l1_signal: IsEqualGadget<F>,
    is_parent_hash: IsEqualGadget<F>,
    is_block_hash: IsEqualGadget<F>,
    is_field_10: IsEqualGadget<F>,
    is_keccak_output: IsEqualGadget<F>,
}
impl<F: Field> PiState<F> {
    pub(crate) fn config(cb: &mut ConstraintBuilder<F, PiCellType>) -> Self {
        let state = cb.query_default();
        Self { 
            state: state.clone(),
            is_l1_signal: IsEqualGadget::construct(cb, state.expr(), L1SIGNAL_IDX.expr()), 
            is_parent_hash:  IsEqualGadget::construct(cb, state.expr(), PARENT_HASH.expr()), 
            is_block_hash: IsEqualGadget::construct(cb, state.expr(), BLOCK_HASH.expr()), 
            is_field_10: IsEqualGadget::construct(cb, state.expr(), FIELD10_IDX.expr()), 
            is_keccak_output: IsEqualGadget::construct(cb, state.expr(), KECCAK_OUTPUT.expr()), 
        }
    }

    pub(crate) fn increment_step(&self) -> Expression<F> {
        not::expr(self.is_field_10.expr()) + not::expr(self.is_keccak_output.expr())
    }

    pub(crate) fn lookup_blockhash(&self) -> Expression<F> {
        self.is_block_hash.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        state: usize
    ) -> Result<(), Error> {
        assign!(region, self.state, offset => state.scalar());
        self.is_l1_signal.assign(region, offset, state.scalar(), L1SIGNAL_IDX.scalar())?;
        self.is_parent_hash.assign(region, offset, state.scalar(), PARENT_HASH.scalar())?;
        self.is_block_hash.assign(region, offset, state.scalar(), BLOCK_HASH.scalar())?;
        self.is_field_10.assign(region, offset, state.scalar(), FIELD10_IDX.scalar())?;
        self.is_keccak_output.assign(region, offset, state.scalar(), KECCAK_OUTPUT.scalar())?;
        Ok(())
    }

}


#[derive(Clone, Debug)]
struct FieldBytesGadget<F> {
    bytes: [Cell<F>; N],
    word_r: Expression<F>,
    keccak_r: Expression<F>,
}
impl<F: Field> FieldBytesGadget<F> {
    pub(crate) fn config(
        cb: &mut ConstraintBuilder<F, PiCellType>, 
        challenges: &Challenges<Expression<F>>
    ) -> Self {
        Self {
            bytes: cb.query_bytes(),
            word_r: challenges.evm_word().expr(),
            keccak_r: challenges.keccak_input().expr(),
        }
    } 

    pub(crate) fn bytes_expr(&self) -> Vec<Expression<F>> {
        self.bytes.iter().map(|b| b.expr()).collect()
    }

    /// RLC of bytes of a field with evm_word 1<<8
    pub(crate) fn hi_low_field(&self) -> (Expression<F>, Expression<F>) {
        let hi = self.bytes_expr()[..16].to_vec();
        let low = self.bytes_expr()[16..].to_vec();
        (hi.rlc_rev(&BYTE_POW_BASE.expr()), low.rlc_rev(&BYTE_POW_BASE.expr()))
    }

    /// RLC of bytes of a field with evm_word
    pub(crate) fn evm_word_field(&self) -> Expression<F> {
        self.bytes_expr().rlc_rev(&self.word_r)
    }

    /// RLC of bytes of a field with keccak_input
    pub(crate) fn keccak_field(&self) -> Expression<F> {
        self.bytes_expr().rlc_rev(&self.keccak_r) // OK!
        // = b0 * r^31 + ... + b31 * r^0
    }

    // ------------------ Assign ------------------

    /// Returns the rlc of given bytes
    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        bytes: &[u8],
        r: F,
    ) -> Result<F, Error> {
        // Assign the bytes
        for (byte, cell) in bytes.iter().zip(self.bytes.iter()) {
            assign!(region, cell, offset => byte.scalar())?;
        }
        Ok(bytes.rlc_rev_value(r))
    }
}


/// Public Inputs Circuit
#[derive(Clone, Default, Debug)]
pub struct TaikoPiCircuit<F: Field> {
    /// PublicInputs data known by the verifier
    pub public_data: PublicData,
    _marker: PhantomData<F>,
}

impl<F: Field> TaikoPiCircuit<F> {
    /// Creates a new TaikoPiCircuit
    pub fn new(public_data: PublicData) -> Self {
        Self {
            public_data,
            _marker: PhantomData,
        }
    }
}


impl<F: Field> SubCircuit<F> for TaikoPiCircuit<F> {
    type Config = TaikoPiCircuitConfig<F>;

    fn unusable_rows() -> usize {
        // No column queried at more than 3 distinct rotations, so returns 6 as
        // minimum unusable rows.
        6
    }

    fn min_num_rows_block(_block: &witness::Block<F>) -> (usize, usize) {
        (USED_ROWS, USED_ROWS)
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        TaikoPiCircuit::new(PublicData::new(block))
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        let (hi, low) = self.public_data.get_pi_hi_low::<F>();
        vec![vec![hi, low]]
    }

    /// Make the assignments to the PiCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.byte_table.load(layouter)?;
        config.assign(layouter, &self.public_data, challenges)
    }
}


// We define the PiTestCircuit as a wrapper over PiCircuit extended to take the
// generic const parameters MAX_TXS and MAX_CALLDATA.  This is necessary because
// the trait Circuit requires an implementation of `configure` that doesn't take
// any circuit parameters, and the PiCircuit defines gates that use rotations
// that depend on MAX_TXS and MAX_CALLDATA, so these two values are required
// during the configuration.
/// Test Circuit for PiCircuit
#[cfg(any(feature = "test", test))]
#[derive(Default, Clone)]
pub struct TaikoPiTestCircuit<F: Field>(pub TaikoPiCircuit<F>);

#[cfg(any(feature = "test", test))]
impl<F: Field> Circuit<F> for TaikoPiTestCircuit<F> {
    type Config = (TaikoPiCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let byte_table = ByteTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            TaikoPiCircuitConfig::new(
                meta,
                TaikoPiCircuitConfigArgs {
                    block_table,
                    keccak_table,
                    byte_table,
                    challenges: challenge_exprs,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);
        let public_data = &self.0.public_data;
        // assign block table
        let randomness = challenges.evm_word();
        config
            .block_table
            .load(&mut layouter, &public_data.block_context, randomness)?;
            // [Tag, 0  (b0*r^31 + ... + b31*r^0)]

        // assign keccak table
        config
            .keccak_table
            .dev_load(&mut layouter, vec![&public_data.rpi_bytes()], &challenges)?;
        config.byte_table.load(&mut layouter)?;

        self.0.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

#[cfg(test)]
mod taiko_pi_circuit_test {

    use super::*;

    use eth_types::ToScalar;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };
    use lazy_static::lazy_static;
    use pretty_assertions::assert_eq;

    lazy_static! {
        static ref OMMERS_HASH: H256 = H256::from_slice(
            &hex::decode("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")
                .unwrap(),
        );
    }

    fn run<F: Field>(
        k: u32,
        public_data: PublicData,
        pi: Option<Vec<Vec<F>>>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = TaikoPiTestCircuit::<F>(TaikoPiCircuit::new(public_data));
        
        let public_inputs = pi.unwrap_or_else(|| circuit.0.instance());
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    fn mock_public_data() -> PublicData {
        let mut public_data = PublicData::default::<Fr>();
        public_data.meta_hash = OMMERS_HASH.to_word();
        public_data.block_hash = OMMERS_HASH.to_word();
        public_data.block_context.block_hash = OMMERS_HASH.to_word();
        public_data.block_context.history_hashes = vec![Default::default(); 256];
        public_data.block_context.number = 300.into();
        public_data
    }

    #[test]
    fn test_default_pi() {
        let public_data = mock_public_data();

        let k = 17;
        assert_eq!(run::<Fr>(k, public_data, None), Ok(()));
    }

    #[test]
    fn test_fail_pi_hash() {
        let public_data = mock_public_data();

        let k = 17;
        match run::<Fr>(k, public_data, Some(vec![vec![Fr::zero(), Fr::one()]])) {
            Ok(_) => unreachable!("this case must fail"),
            Err(errs) => {
                assert_eq!(errs.len(), 4);
                for err in errs {
                    match err {
                        VerifyFailure::Permutation { .. } => return,
                        _ => unreachable!("unexpected error"),
                    }
                }
            }
        }
    }

    #[test]
    fn test_fail_pi_prover() {
        let mut public_data = mock_public_data();
        let address_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        ];

        public_data.prover = Address::from_slice(&address_bytes);

        let prover: Fr = public_data.prover.to_scalar().unwrap();
        let k = 17;
        match run::<Fr>(
            k,
            public_data,
            Some(vec![vec![prover, Fr::zero(), Fr::one()]]),
        ) {
            Ok(_) => unreachable!("this case must fail"),
            Err(errs) => {
                assert_eq!(errs.len(), 4);
                for err in errs {
                    match err {
                        VerifyFailure::Permutation { .. } => return,
                        _ => unreachable!("unexpected error"),
                    }
                }
            }
        }
    }

    #[test]
    fn test_simple_pi() {
        let mut public_data = mock_public_data();
        let chain_id = 1337u64;
        public_data.chain_id = Word::from(chain_id);

        let k = 17;
        assert_eq!(run::<Fr>(k, public_data, None), Ok(()));
    }

    #[test]
    fn test_verify() {
        let mut block = witness::Block::<Fr>::default();

        block.eth_block.parent_hash = *OMMERS_HASH;
        block.eth_block.hash = Some(*OMMERS_HASH);
        block.protocol_instance.block_hash = *OMMERS_HASH;
        block.protocol_instance.parent_hash = *OMMERS_HASH;
        block.context.history_hashes = vec![OMMERS_HASH.to_word()];
        block.context.block_hash = OMMERS_HASH.to_word();
        block.context.number = 300.into();
        
        println!("{:?}\n{:?}", 
            block.protocol_instance.meta_hash.hash(), 
            block.protocol_instance.meta_hash.hash().to_word());

        let public_data = PublicData::new(&block);
        println!("public_data: {:?}\n{:?}", public_data.meta_hash, public_data.meta_hash.to_be_bytes());

        let k = 17;

        // assert_eq!(run::<Fr>(k, public_data, None), Ok(()));
    }
}