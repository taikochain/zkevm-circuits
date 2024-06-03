use eth_types::{Field, ToBigEndian, ToWord, H160, U256};
use ethers_core::abi::*;

use ethers_core::utils::keccak256;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};

use gadgets::util::{Expr, Scalar};
use halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Expression, Instance, Selector};
use std::{convert::TryInto, marker::PhantomData};

use crate::{
    assign, circuit,
    circuit_tools::{
        cached_region::CachedRegion,
        cell_manager::{Cell, CellColumn, CellManager, CellType},
        constraint_builder::{ConstraintBuilder, ExprVec, RLCable, TO_FIX},
    },
    evm_circuit::{table::Table, util::rlc},
    table::{byte_table::ByteTable, BlockContextFieldTag, BlockTable, KeccakTable, LookupTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, BlockContext},
};
use core::result::Result;
use halo2_proofs::plonk::Error;

const BYTE_POW_BASE: u64 = 1 << 8;
const PADDING_LEN: usize = 32;
const META_HASH: usize = 0;
const PARENT_HASH: usize = 1;
const BLOCK_HASH: usize = 2;
const SIGNAL_ROOT: usize = 3;
const GRAFFITI: usize = 4;
const PROVER: usize = 5;
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
    LookupPi,
    Lookup(Table),
}

impl CellType for PiCellType {
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

#[derive(Debug, Clone)]
pub struct PublicData<F> {
    evidence: Token,
    block_context: BlockContext,
    _phantom: PhantomData<F>,
}

impl<F: Field> Default for PublicData<F> {
    fn default() -> Self {
        // has to have at least one history hash, block number must start with at least one
        let mut ret = Self::new(&witness::Block::default());
        ret.block_context.history_hashes = vec![U256::default()];
        ret
    }
}

impl<F: Field> PublicData<F> {
    fn new(block: &witness::Block<F>) -> Self {
        let meta_hash = Token::FixedBytes(
            block
                .protocol_instance
                .meta_hash
                .hash()
                .to_word()
                .to_be_bytes()
                .to_vec(),
        );
        let parent_hash = Token::FixedBytes(
            block
                .protocol_instance
                .parent_hash
                .to_word()
                .to_be_bytes()
                .to_vec(),
        );
        let block_hash = Token::FixedBytes(
            block
                .protocol_instance
                .block_hash
                .to_word()
                .to_be_bytes()
                .to_vec(),
        );
        let signal_root = Token::FixedBytes(
            block
                .protocol_instance
                .signal_root
                .to_word()
                .to_be_bytes()
                .to_vec(),
        );
        let graffiti = Token::FixedBytes(
            block
                .protocol_instance
                .graffiti
                .to_word()
                .to_be_bytes()
                .to_vec(),
        );
        let prover = Token::Address(block.protocol_instance.prover);
        Self {
            evidence: Token::FixedArray(vec![
                meta_hash,
                parent_hash,
                block_hash,
                signal_root,
                graffiti,
                prover,
            ]),
            block_context: block.context.clone(),
            _phantom: PhantomData,
        }
    }

    fn set_field(&mut self, idx: usize, bytes: Vec<u8>) {
        match self.evidence {
            Token::FixedArray(ref mut tokens) => {
                tokens[idx] = match tokens[idx].clone() {
                    Token::Bytes(_) => Token::Bytes(bytes),
                    Token::FixedBytes(_) => Token::FixedBytes(bytes),
                    Token::Address(_) => Token::Address(H160::from(
                        &bytes.try_into().expect("Wrong number of bytes for address"),
                    )),
                    _ => unreachable!(),
                };
            }
            _ => unreachable!(),
        }
    }

    pub fn encode_raw(&self) -> Vec<u8> {
        encode(&[self.evidence.clone()])
    }

    fn encode_field(&self, idx: usize) -> Vec<u8> {
        let field = match self.evidence {
            Token::FixedArray(ref tokens) => tokens[idx].clone(),
            _ => unreachable!(),
        };
        encode(&[field])
    }

    fn total_acc(&self, r: Value<F>) -> F {
        let mut rand = F::ZERO;
        r.map(|r| rand = r);
        rlc::value(self.encode_raw().iter().rev(), rand)
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
        let keccaked_pi = keccak256(self.encode_raw());
        [
            rlc::value(keccaked_pi[0..16].iter().rev(), BYTE_POW_BASE.scalar()),
            rlc::value(keccaked_pi[16..].iter().rev(), BYTE_POW_BASE.scalar()),
        ]
    }

    fn keccak(&self) -> Vec<u8> {
        keccak256(self.encode_raw()).to_vec()
    }

    fn keccak_assignment(&self) -> Vec<F> {
        self.keccak().iter().map(|b| F::from(*b as u64)).collect()
    }

    fn total_len(&self) -> usize {
        self.encode_raw().len()
    }

    fn field_len(&self, idx: usize) -> usize {
        self.encode_field(idx).len()
    }
}

#[derive(Clone, Debug)]
pub struct TaikoPiCircuitConfig<F: Field> {
    q_enable: Selector,
    keccak_instance: Column<Instance>, // equality

    meta_hash: FieldGadget<F>,
    parent_hash: (Cell<F>, FieldGadget<F>, Cell<F>),
    block_hash: (Cell<F>, FieldGadget<F>, Cell<F>),
    signal_root: FieldGadget<F>,
    graffiti: FieldGadget<F>,
    prover: FieldGadget<F>,

    total_acc: Cell<F>,
    keccak_bytes: FieldGadget<F>,
    keccak_hi_lo: [Cell<F>; 2],

    block_table: BlockTable,
    keccak_table: KeccakTable,
    byte_table: ByteTable,

    annotation_configs: Vec<CellColumn<F, PiCellType>>,
}

pub struct TaikoPiCircuitConfigArgs<F: Field> {
    ///
    pub evidence: PublicData<F>,
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
    type ConfigArgs = TaikoPiCircuitConfigArgs<F>;
    /// Return a new TaikoPiCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            evidence,
            block_table,
            keccak_table,
            byte_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let keccak_r = challenges.keccak_input();
        let evm_word = challenges.evm_word();
        let cm = CellManager::new(
            meta,
            vec![
                (PiCellType::Byte, 7, 1, false),
                (PiCellType::StoragePhase1, 1, 1, true),
                (PiCellType::StoragePhase2, 1, 2, true),
            ],
            0,
            32,
        );
        let mut cb: ConstraintBuilder<F, PiCellType> =
            ConstraintBuilder::new(4, Some(cm.clone()), Some(evm_word.expr()));
        cb.preload_tables(
            meta,
            &[
                (PiCellType::Lookup(Table::Keccak), &keccak_table),
                (PiCellType::Lookup(Table::Bytecode), &byte_table),
                (PiCellType::Lookup(Table::Block), &block_table),
            ],
        );
        let q_enable = meta.complex_selector();
        let keccak_instance = meta.instance_column();
        meta.enable_equality(keccak_instance);

        let meta_hash = FieldGadget::config(&mut cb, evidence.field_len(META_HASH));
        let parent_hash = (
            cb.query_one(S1),
            FieldGadget::config(&mut cb, evidence.field_len(PARENT_HASH)),
            cb.query_one(S2),
        );
        let block_hash = (
            cb.query_one(S1),
            FieldGadget::config(&mut cb, evidence.field_len(BLOCK_HASH)),
            cb.query_one(S2),
        );
        let signal_root = FieldGadget::config(&mut cb, evidence.field_len(SIGNAL_ROOT));
        let graffiti = FieldGadget::config(&mut cb, evidence.field_len(GRAFFITI));
        let prover = FieldGadget::config(&mut cb, evidence.field_len(PROVER));

        let total_acc = cb.query_one(S2);
        let keccak_bytes = FieldGadget::config(&mut cb, PADDING_LEN);
        let keccak_hi_lo = [cb.query_one(S1), cb.query_one(S1)];
        meta.create_gate("PI acc constraints", |meta| {
            circuit!([meta, cb], {
                for (block_number, block_hash, block_hash_rlc) in
                    [parent_hash.clone(), block_hash.clone()]
                {
                    require!(block_hash_rlc.expr() => block_hash.rlc_acc(evm_word.expr()));
                    require!(
                        (
                            BlockContextFieldTag::BlockHash.expr(),
                            block_number.expr(),
                            block_hash_rlc.expr()
                        ) => @PiCellType::Lookup(Table::Block), (TO_FIX)
                    );
                }
                let acc_val = [
                    meta_hash.clone(),
                    parent_hash.1.clone(),
                    block_hash.1.clone(),
                    signal_root.clone(),
                    graffiti.clone(),
                    prover.clone(),
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
                        evidence.total_len().expr(),
                        keccak_bytes.rlc_acc(evm_word.expr())
                    )
                    => @PiCellType::Lookup(Table::Keccak), (TO_FIX)
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
            cb.build_constraints(Some(meta.query_selector(q_enable)))
        });
        cb.build_lookups(
            meta,
            &[cm.clone()],
            &[
                (PiCellType::Byte, PiCellType::Lookup(Table::Bytecode)),
                (
                    PiCellType::Lookup(Table::Keccak),
                    PiCellType::Lookup(Table::Keccak),
                ),
                (
                    PiCellType::Lookup(Table::Block),
                    PiCellType::Lookup(Table::Block),
                ),
            ],
            Some(q_enable),
        );
        let annotation_configs = cm.columns().to_vec();
        Self {
            q_enable,
            keccak_instance,
            meta_hash,
            parent_hash,
            block_hash,
            signal_root,
            graffiti,
            prover,
            total_acc,
            keccak_bytes,
            keccak_hi_lo,
            block_table,
            keccak_table,
            byte_table,
            annotation_configs,
        }
    }
}

impl<F: Field> TaikoPiCircuitConfig<F> {
    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        challenge: &Challenges<Value<F>>,
        evidence: &PublicData<F>,
    ) -> Result<(), Error> {
        let evm_word = challenge.evm_word();
        let keccak_r = challenge.keccak_input();
        let hi_lo_cells = layouter.assign_region(
        || "Pi",
        |mut region| {
                self.q_enable.enable(&mut region, 0)?;
                let mut region = CachedRegion::new(&mut region);
                region.annotate_columns(&self.annotation_configs);

                assign!(region, self.parent_hash.0, 0 => (evidence.block_context.number - 1).as_u64().scalar());
                assign!(region, self.parent_hash.2, 0 => evidence.assignment_acc(PARENT_HASH, evm_word));
                assign!(region, self.block_hash.0, 0 => (evidence.block_context.number).as_u64().scalar());
                assign!(region, self.block_hash.2, 0 => evidence.assignment_acc(BLOCK_HASH, evm_word));

                let _acc = F::ZERO;
                let mut idx = 0;
                [
                    &self.meta_hash,
                    &self.parent_hash.1,
                    &self.block_hash.1,
                    &self.signal_root,
                    &self.graffiti,
                    &self.prover,
                ].iter().for_each(|gadget| {
                    gadget.assign(&mut region, 0, &evidence.assignment(idx))
                        .expect(&format!("FieldGadget assignment failed at {:?}", idx));
                    idx += 1;
                });
                self.keccak_bytes.assign(&mut region, 0, &evidence.keccak_assignment())
                    .expect("Keccak bytes assignment failed");
                assign!(region, self.total_acc, 0 => evidence.total_acc(keccak_r))?;
                let hi_low_assignment = evidence.keccak_hi_low();
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
    pub evidence: PublicData<F>,
}

impl<F: Field> TaikoPiCircuit<F> {
    /// Creates a new TaikoPiCircuit
    pub fn new(evidence: PublicData<F>) -> Self {
        Self { evidence }
    }
}

impl<F: Field> SubCircuit<F> for TaikoPiCircuit<F> {
    type Config = TaikoPiCircuitConfig<F>;

    fn unusable_rows() -> usize {
        // No column queried at more than 3 distinct rotations, so returns 6 as
        // minimum unusable rows.
        PublicData::<F>::default().total_len() + 3
    }

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        // TODO(Cecilia): what is the first field?
        (0, PublicData::new(block).total_len())
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        TaikoPiCircuit::new(PublicData::new(block))
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        vec![self.evidence.keccak_hi_low().to_vec()]
    }

    /// Make the assignments to the PiCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.byte_table.load(layouter)?;
        config.assign(layouter, challenges, &self.evidence)
    }
}

#[cfg(any(feature = "test", test))]
impl<F: Field> Circuit<F> for TaikoPiCircuit<F> {
    type Config = (TaikoPiCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = PublicData<F>;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn params(&self) -> Self::Params {
        self.evidence.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, PublicData::default())
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let byte_table = ByteTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            TaikoPiCircuitConfig::new(
                meta,
                TaikoPiCircuitConfigArgs {
                    evidence: params,
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
        let evidance = self.params();
        let randomness = challenges.evm_word();
        // assign block table
        config
            .block_table
            .load(&mut layouter, &evidance.block_context, randomness)?;
        // assign keccak table
        config
            .keccak_table
            .dev_load(&mut layouter, vec![&evidance.encode_raw()], &challenges)?;
        config.byte_table.load(&mut layouter)?;

        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

#[cfg(test)]
mod taiko_pi_circuit_test {

    use std::vec;

    use super::*;

    use eth_types::H256;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };
    use lazy_static::lazy_static;
    use pretty_assertions::assert_eq;

    lazy_static! {
        static ref LAST_HASH: H256 = H256::from_slice(
            &hex::decode("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")
                .unwrap(),
        );
        static ref THIS_HASH: H256 = H256::from_slice(
            &hex::decode("1dcc4de8dec751111b85b567b6cc12fea12451b9480000000a142fd40d493111")
                .unwrap(),
        );
        static ref PROVER_ADDR: H160 =
            H160::from_slice(&hex::decode("8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199").unwrap(),);
    }

    fn run<F: Field>(
        k: u32,
        evidence: PublicData<F>,
        pi: Option<Vec<Vec<F>>>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = TaikoPiCircuit::new(evidence);
        let keccak_instance = pi.unwrap_or_else(|| circuit.instance());
        let prover = match MockProver::run(k, &circuit, keccak_instance) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    fn mock_public_data() -> PublicData<Fr> {
        let mut evidence = PublicData::default();
        evidence.set_field(PARENT_HASH, LAST_HASH.to_fixed_bytes().to_vec());
        evidence.set_field(BLOCK_HASH, THIS_HASH.to_fixed_bytes().to_vec());
        evidence.block_context.number = 300.into();
        evidence.block_context.block_hash = THIS_HASH.to_word();
        // has to have at least one history block
        evidence.block_context.history_hashes = vec![LAST_HASH.to_word()];
        evidence
    }

    #[test]
    fn test_default_pi() {
        let evidence = mock_public_data();

        let k = 17;
        assert_eq!(run::<Fr>(k, evidence, None), Ok(()));
    }

    #[test]
    fn test_fail_hi_lo() {
        let evidence = mock_public_data();

        let k = 17;
        match run::<Fr>(k, evidence, Some(vec![vec![Fr::zero(), Fr::one()]])) {
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
    fn test_fail_historical_hash() {
        let mut block = witness::Block::<Fr>::default();

        block.eth_block.parent_hash = *LAST_HASH;
        block.eth_block.hash = Some(*THIS_HASH);
        block.protocol_instance.block_hash = *THIS_HASH;
        block.protocol_instance.parent_hash = *LAST_HASH;

        // parent hash doesn't exist in table!
        block.context.history_hashes = vec![THIS_HASH.to_word(), THIS_HASH.to_word()];
        block.context.block_hash = THIS_HASH.to_word();
        block.context.number = 300.into();

        let evidence = PublicData::new(&block);

        let k = 17;
        match run::<Fr>(k, evidence, None) {
            Ok(_) => unreachable!("this case must fail"),
            Err(errs) => {
                assert_eq!(errs.len(), 1);
                for err in errs {
                    match err {
                        VerifyFailure::Lookup { .. } => return,
                        _ => unreachable!("unexpected error"),
                    }
                }
            }
        }
    }

    #[test]
    fn test_simple_pi() {
        let mut evidence = mock_public_data();
        let block_number = 1337u64;
        evidence.block_context.number = block_number.into();
        evidence.block_context.history_hashes = vec![LAST_HASH.to_word()];
        evidence.set_field(PROVER, PROVER_ADDR.to_fixed_bytes().to_vec());

        let k = 17;
        assert_eq!(run::<Fr>(k, evidence, None), Ok(()));
    }

    #[test]
    fn test_verify() {
        let mut block = witness::Block::<Fr>::default();

        block.eth_block.parent_hash = *LAST_HASH;
        block.eth_block.hash = Some(*THIS_HASH);
        block.protocol_instance.block_hash = *THIS_HASH;
        block.protocol_instance.parent_hash = *LAST_HASH;
        block.context.history_hashes = vec![LAST_HASH.to_word()];
        block.context.block_hash = THIS_HASH.to_word();
        block.context.number = 300.into();

        let evidence = PublicData::new(&block);

        let k = 17;

        assert_eq!(run::<Fr>(k, evidence, None), Ok(()));
    }
}
