

use bus_mapping::evm;
use eth_types::{Address, Field, ToBigEndian, ToWord, Word, H256, H160};
use ethers_core::abi::*;
use ethers_core::abi::FixedBytes;
use ethers_core::utils::keccak256;
use halo2_proofs::circuit::{Value, Layouter, SimpleFloorPlanner, AssignedCell};
use itertools::Itertools;
use std::convert::TryInto;
use std::marker::PhantomData;
use gadgets::util::{Expr, Scalar};
use halo2_proofs::plonk::{Expression, ConstraintSystem, Selector, Instance, Column, Circuit};
use keccak256::keccak_arith::Keccak;
use halo2_proofs::plonk::Error;
use core::result::Result;
use crate::circuit_tools::cached_region::CachedRegion;
use crate::circuit_tools::cell_manager::{Cell, CellType, CellManager, CellColumn};
use crate::circuit_tools::constraint_builder::{ConstraintBuilder, TO_FIX, RLCable, ExprVec};
use crate::evm_circuit::table::Table;
use crate::evm_circuit::util::rlc;
use crate::util::{Challenges, SubCircuitConfig, SubCircuit};
use crate::witness::{self, Bytecode, BlockContext};
use crate::{circuit, assign};
use crate::table::{byte_table::ByteTable, BlockContextFieldTag, BlockTable, KeccakTable, LookupTable};

const BYTE_POW_BASE: u64 = 1 << 8;
const PADDING_LEN: usize = 32;


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
            len
        }
    }

    fn bytes_expr(&self) -> Vec<Expression<F>> {
        self.field.iter().map(|f| f.expr()).collect()
    }

    fn acc(&self, r: Expression<F>) -> Expression<F> {
        //0.expr()
        self.bytes_expr().rlc_rev(&r)
    }

    pub(crate) fn hi_low_field(&self) -> [Expression<F>; 2] {
        assert!(self.len == 32);
        let hi = self.bytes_expr()[..16].to_vec();
        let low = self.bytes_expr()[16..].to_vec();
        [hi.rlc_rev(&BYTE_POW_BASE.expr()), low.rlc_rev(&BYTE_POW_BASE.expr())]
    }

    fn assign(
        &self, 
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        bytes: &[F],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        assert!(bytes.len() == self.len);
        let cells = self.field.iter().zip(bytes.iter()).map(
            |(cell, byte)| {
                assign!(region, cell, offset => *byte).unwrap()
            }
        ).collect();
        Ok(cells)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum PiCellType {
    Storage1,
    Storage2,
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



#[derive(Debug, Clone)]
pub struct PublicData<F> {
    evidence: Token,
    block_context: BlockContext,
    _phantom: PhantomData<F>,
}

impl<F: Field> Default for PublicData<F> {
    fn default() -> Self {
        Self::new(&witness::Block::default())
    }
}

impl<F: Field> PublicData<F> {
    fn new(block: &witness::Block<F>) -> Self {
        let block_hash = Token::FixedBytes(block.protocol_instance.block_hash.to_word().to_be_bytes().to_vec());
        let signal_root = Token::FixedBytes(block.protocol_instance.signal_root.to_word().to_be_bytes().to_vec());
        Self { 
            evidence: Token::FixedArray(vec![
                block_hash,
                signal_root,
                ]),
            block_context: block.context.clone(),
            _phantom: PhantomData
        }
    }

    fn set_field(&mut self, idx: usize, bytes: Vec<u8>) {
        match self.evidence {
            Token::FixedArray(ref mut tokens) => {
                tokens[idx] = match tokens[idx].clone() {
                    Token::Bytes(_) => Token::Bytes(bytes),
                    Token::FixedBytes(_) => Token::FixedBytes(bytes),
                    Token::Address(_) => Token::Address(
                        H160::from(&bytes.try_into().expect("Wrong number of bytes for address")
                    )),
                    _ => unreachable!(),
                };
            }
            _ => unreachable!(),
        }
    }

    fn encode_raw(&self) -> Vec<u8> {
        encode(&[self.evidence.clone()])
    }

    fn encode_field(&self, idx: usize) -> Vec<u8> {
        let field = match self.evidence {
            Token::FixedArray(ref tokens) => tokens[idx].clone(),
            _ => unreachable!(),
        };
        encode(&[field])
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
            keccaked_pi
                .iter()
                .take(16)
                .fold(F::ZERO, |acc: F, byte| {
                    acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
                }),
                keccaked_pi
                .iter()
                .skip(16)
                .fold(F::ZERO, |acc: F, byte| {
                    acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
                })
        ]
    }

    fn keccak(&self) -> Vec<u8> {
        keccak256(self.encode_raw()).to_vec()
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
    public_input: Column<Instance>, // equality
    block_hash: (Cell<F>, FieldGadget<F>, Cell<F>),
    signal_root: FieldGadget<F>,
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
                (PiCellType::Byte, 1, 1, false),
                (PiCellType::Storage1, 1, 1, true),
                (PiCellType::Storage2, 1, 1, true),
            ],
            0,
            evidence.total_len() + PADDING_LEN,
        );
        let mut cb: ConstraintBuilder<F, PiCellType> = ConstraintBuilder::new(4,  Some(cm.clone()), Some(evm_word.expr()));
        cb.preload_tables(meta,
            &[
                    (PiCellType::Lookup(Table::Keccak), &keccak_table), 
                    (PiCellType::Lookup(Table::Bytecode), &byte_table), 
                    (PiCellType::Lookup(Table::Block), &block_table)
               ]
           );
        let q_enable = meta.complex_selector();
        let public_input = meta.instance_column();
        let block_hash =(
            cb.query_one(PiCellType::Storage1),
            FieldGadget::config(&mut cb, evidence.field_len(0)),
            cb.query_one(PiCellType::Storage2)
        );
        let signal_root = FieldGadget::config(&mut cb, evidence.field_len(1));

        meta.create_gate(
            "PI acc constraints", 
            |meta| {
                circuit!([meta, cb], {
                    for (n, b, acc) in [/* parent_hash.clone() , */ block_hash.clone()] {
                        require!(acc.expr() => b.acc(evm_word.expr()));
                        require!(
                            (
                                BlockContextFieldTag::BlockHash.expr(), 
                                n.expr(), 
                                acc.expr()
                            ) => @PiCellType::Lookup(Table::Block), (TO_FIX)
                        );
                        println!(
                            "require ({:?}, {:?}, {:?})", 
                            BlockContextFieldTag::BlockHash,
                            n.expr().identifier(),
                            b.acc(evm_word.expr()).identifier()
                        );
                    }
                });
                cb.build_constraints(Some(meta.query_selector(q_enable)))
            }
        );
        cb.build_lookups(
            meta, 
            &[cm.clone()],
            &[
                (PiCellType::Byte, PiCellType::Lookup(Table::Bytecode)),
                (PiCellType::Lookup(Table::Keccak), PiCellType::Lookup(Table::Keccak)),
                (PiCellType::Lookup(Table::Block), PiCellType::Lookup(Table::Block)),
            ],
            Some(q_enable)
        );
        let annotation_configs = cm.columns().to_vec();
        Self {
            q_enable, 
            public_input,
            block_hash,
            signal_root,
            block_table,
            keccak_table,
            byte_table,
            annotation_configs 
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
        let pi_cells = layouter.assign_region(
        || "Pi",
        |mut region| {
                self.q_enable.enable(&mut region, 0)?;
                let mut region = CachedRegion::new(&mut region);
                region.annotate_columns(&self.annotation_configs);

                let mut acc = F::ZERO;
                let mut offset = 0;
                let mut idx = 0;
                [
                    &self.block_hash.1,
                    &self.signal_root,
                ].iter().for_each(|gadget| {
                    println!("assignment {:?}: {:?}, {:?}", idx, offset, evidence.encode_field(idx));
                    gadget.assign(&mut region, offset, &evidence.assignment(idx))
                        .expect(&format!("FieldGadget assignment failed at {:?}", idx));
                    offset += evidence.field_len(idx);
                    idx += 1;
                });

                println!("evidence.block_context.number: {:?}\n", evidence.block_context.number);
                assign!(region, self.block_hash.0, 0 => (evidence.block_context.number).as_u64().scalar());
                assign!(region, self.block_hash.2, 0 => evidence.assignment_acc(0, evm_word));

                Ok(())
        });
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
        Self {
            evidence: evidence,
        }
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
        vec![ self.evidence.keccak_hi_low().to_vec()]
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
    type Config =  (TaikoPiCircuitConfig<F>, Challenges);
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

    fn configure_with_params(
        meta: &mut ConstraintSystem<F>,
        params: Self::Params,
    ) -> Self::Config {
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
                }
            ),
            challenges
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
        evidence: PublicData<F>,
        pi: Option<Vec<Vec<F>>>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = TaikoPiCircuit::new(evidence);
        let public_inputs = pi.unwrap_or_else(|| circuit.instance());
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    fn mock_public_data() -> PublicData<Fr> {
        let A = OMMERS_HASH.clone()/* H256::default() */;
        let mut evidence = PublicData::default();
        evidence.set_field(0, A.to_fixed_bytes().to_vec());
        evidence.block_context.number = 300.into();
        evidence.block_context.block_hash = A.to_word();
        evidence
    }

    #[test]
    fn test_default_pi() {
        let evidence = mock_public_data();

        let k = 17;
        assert_eq!(run::<Fr>(k, evidence, None), Ok(()));
    }

    #[test]
    fn test(){
        println!("test");
        let mut evidence = PublicData::<Fr>::default();
        let data = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
        evidence.set_field(0, data.clone());
        // evidence.set_field(1, vec![0u8; 32]);
        // evidence.set_field(2, data.clone());
        // evidence.set_field(3, vec![0u8; 32]);
        // evidence.set_field(4, vec![0u8; 32]);
        // evidence.set_field(5, vec![0u8; 20]);

        // evidence.parent_hash = Token::FixedBytes(vec![0u8; 32]);
        // evidence.block_hash = Token::FixedBytes(data);
        // evidence.signal_root = Token::FixedBytes(vec![0u8; 32]);
        // evidence.graffiti = Token::FixedBytes(vec![0u8; 32]);
        // evidence.prover = Token::Address([0x22u8; 20].into());
        let encode_raw = evidence.encode_raw();
        println!("abi.encode {:?}\nkeccak {:?}\nhi-lo {:?}", encode_raw.clone(), keccak256(encode_raw), evidence.keccak_hi_low());
    }

}


