// function getInstance(TaikoData.BlockEvidence memory evidence)
    // internal
    // pure
    // returns (bytes32 instance)
// {
    // uint256[6] memory inputs;
    // inputs[0] = uint256(evidence.metaHash);
    // inputs[1] = uint256(evidence.parentHash);
    // inputs[2] = uint256(evidence.blockHash);
    // inputs[3] = uint256(evidence.signalRoot);
    // inputs[4] = uint256(evidence.graffiti);
    // inputs[5] = (uint256(uint160(evidence.prover)) << 96)
    //     | (uint256(evidence.parentGasUsed) << 64)
    //     | (uint256(evidence.gasUsed) << 32);



        // @dev Struct representing block evidence.
        // struct BlockEvidence {
        //     bytes32 metaHash;
        //     bytes32 parentHash;
        //     bytes32 blockHash;
        //     bytes32 signalRoot;
        //     bytes32 graffiti;
        //     address prover;
        //     bytes proofs;
        // }

    // if (evidence.prover != address(1)) return 0;
    // else return keccak256(abi.encode(evidence));

    // evidence.proofs = bytes.concat(
    //     bytes2(verifierId),
    //     bytes16(0),
    //     bytes16(instance),
    //     bytes16(0),
    //     bytes16(uint128(uint256(instance))),
    //     new bytes(100)
    // );
// }

use eth_types::{ToWord, ToBigEndian, Field};
use ethers_core::abi::*;
use ethers_core::abi::FixedBytes;
use ethers_core::utils::keccak256;
use halo2_proofs::circuit::{Value, Layouter};
use std::convert::TryInto;
use std::marker::PhantomData;
use gadgets::util::{Expr, Scalar};
use halo2_proofs::plonk::{Expression, ConstraintSystem, Selector, Instance, Column};
use keccak256::keccak_arith::Keccak;
use halo2_proofs::plonk::Error;
use core::result::Result;
use crate::circuit_tools::cached_region::CachedRegion;
use crate::circuit_tools::cell_manager::{Cell, CellType, CellManager, CellColumn};
use crate::circuit_tools::constraint_builder::{ConstraintBuilder, TO_FIX, RLCable};
use crate::evm_circuit::table::Table;
use crate::util::{Challenges, SubCircuitConfig, SubCircuit};
use crate::witness::{self, Bytecode};
use crate::{circuit, assign};
use crate::table::{byte_table::ByteTable, BlockContextFieldTag, BlockTable, KeccakTable, LookupTable};

const PADDING_LEN: usize = 32;
const PROOF_LEN: usize = 102;
const BYTE_POW_BASE: u64 = 1 << 8;

#[derive(Debug, Clone)]
pub struct PublicData {
    meta_hash: Token,
    parent_hash: Token,
    block_hash: Token,
    signal_root: Token,
    graffiti: Token,
    prover: Token,
}

impl PublicData {
    fn new<F>(block: &witness::Block<F>) -> Self {
        let meta_hash = Token::FixedBytes(block.protocol_instance.meta_hash.hash().to_word().to_be_bytes().to_vec());
        let parent_hash = Token::FixedBytes(block.protocol_instance.parent_hash.to_word().to_be_bytes().to_vec());
        let block_hash = Token::FixedBytes(block.protocol_instance.block_hash.to_word().to_be_bytes().to_vec());
        let signal_root = Token::FixedBytes(block.protocol_instance.signal_root.to_word().to_be_bytes().to_vec());
        let graffiti = Token::FixedBytes(block.protocol_instance.graffiti.to_word().to_be_bytes().to_vec());
        let prover = Token::Address(block.protocol_instance.prover);

        Self {
            meta_hash,
            parent_hash,
            block_hash,
            signal_root,
            graffiti,
            prover,
        }
    }

    fn default<F: Default>() -> Self {
        Self::new::<F>(&witness::Block::default())
    }

    fn encode_raw(&self) -> Vec<u8> {
        // Fixed bytes are directly concat
        //  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        //  0000000000000000000000000000000000000000000000000000000000000000
        //  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        //  0000000000000000000000000000000000000000000000000000000000000000
        //  0000000000000000000000000000000000000000000000000000000000000000
        //  0000000000000000000000002222222222222222222222222222222222222222
        // Second padding happens right before dyn bytes
        //  00000000000000000000000000000000000000000000000000000000000000e0
        // Proofs: new bytes(102), 0x66 = 102
        //  0000000000000000000000000000000000000000000000000000000000000066
        //  0000000000000000000000000000000000000000000000000000000000000000
        //  0000000000000000000000000000000000000000000000000000000000000000
        //  0000000000000000000000000000000000000000000000000000000000000000
        //  0000000000000000000000000000000000000000000000000000000000000000
        encode(&[
            Token::FixedArray(vec![
                self.meta_hash.clone(),
                self.parent_hash.clone(),
                self.block_hash.clone(),
                self.signal_root.clone(),
                self.graffiti.clone(),
                self.prover.clone(),
            ])
        ])
    }


    fn get_pi_hi_low(&self) -> (u64, u64) {
        let keccaked_pi = keccak256(self.encode_raw());
        (
            keccaked_pi
                .iter()
                .take(16)
                .fold(0u64, |acc: u64, byte| {
                    acc * BYTE_POW_BASE + *byte as u64
                }),
                keccaked_pi
                .iter()
                .skip(16)
                .fold(0u64, |acc: u64, byte| {
                    acc * BYTE_POW_BASE + *byte as u64
                })
        )
    }

    fn max_height(&self) -> usize {
        self.encode_raw().len()
    }

}

trait AbiLength {
    fn len(&self) -> usize;
}
impl AbiLength for Token {
    fn len(&self) -> usize {
        // TODO(Cecilia): handle padding for dyn data 
        match self {
            // Solidity fixed type: bytes8, bytes32, bytes64, bytes1024,...
            Token::FixedBytes(bytes) => ((bytes.len() + 31) / 32) * 32,
            // Solidity dyn type: bytes, encoded with one more word representing the length
            Token::Bytes(bytes) => (((bytes.len() + 31) / 32) + 1) * 32,
            Token::Int(_) | Token::Uint(_) | Token::Bool(_) | Token::Address(_) => 32,
            _ => unimplemented!()
        }
    }
}

#[derive(Clone, Debug)]
pub struct TaikoPiCircuitConfig<F: Field> {
    q_enable: Selector,
    public_input: Column<Instance>, // equality
    keccak_output: Vec<Cell<F>>, // hi, lo
    block_numbers: Vec<Cell<F>>, 
    public_input_bytes: FieldGadget<F>,

    meta_hash: FieldGadget<F>,
    parent_hash: FieldGadget<F>,
    block_hash: FieldGadget<F>,
    signal_root: FieldGadget<F>,
    graffiti: FieldGadget<F>,
    prover: FieldGadget<F>,

    block_table: BlockTable,
    keccak_table: KeccakTable,
    byte_table: ByteTable,

    annotation_configs: Vec<CellColumn<F, PiCellType>>,
}

pub struct TaikoPiCircuitConfigArgs<F: Field> {
    /// 
    pub evidence: PublicData,
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
                (PiCellType::Storage2, 1, 2, true),
            ],
            0,
            32,
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
       
        let keccak_output =  [(); 2].iter().map(|_| cb.query_one(PiCellType::Storage2)).collect::<Vec<_>>();
        let block_numbers = [(); 2].iter().map(|_| cb.query_one(PiCellType::Storage1)).collect::<Vec<_>>();
        let public_input_bytes = FieldGadget::config(&mut cb, PADDING_LEN);

        let meta_hash = FieldGadget::config(&mut cb, evidence.meta_hash.len());
        let parent_hash = FieldGadget::config(&mut cb, evidence.parent_hash.len());
        let block_hash = FieldGadget::config(&mut cb, evidence.block_hash.len());
        let signal_root = FieldGadget::config(&mut cb, evidence.signal_root.len());
        let graffiti = FieldGadget::config(&mut cb, evidence.graffiti.len());
        let prover = FieldGadget::config(&mut cb, evidence.prover.len());

        meta.create_gate(
            "PI acc constraints", 
            |meta| {
                circuit!([meta, cb], {
                    for (b, n) in [parent_hash.clone(), block_hash.clone()].iter().zip(block_numbers.clone().iter()) {
                        require!(
                            (
                                BlockContextFieldTag::BlockHash.expr(), 
                                n.expr(), 
                                b.acc(evm_word.expr())
                            ) => @PiCellType::Lookup(Table::Block), (TO_FIX)
                        );
                    }
                    let keccak_input = [
                            meta_hash.clone(), 
                            parent_hash.clone(), 
                            block_hash.clone(), 
                            signal_root.clone(), 
                            graffiti.clone(), 
                            prover.clone(), 
                        ].iter().fold(0.expr(), |acc, gadget| {
                            let mult = (0..gadget.len).fold(1.expr(), |acc, _| acc * keccak_r.expr());
                            acc * mult + gadget.acc(keccak_r.expr())
                        });
                    require!(
                        (
                            1.expr(), 
                            keccak_input, 
                            evidence.max_height().expr(), 
                            public_input_bytes.acc(evm_word.expr())
                        )
                        => @PiCellType::Lookup(Table::Keccak), (TO_FIX)
                    );
                    let hi_lo = public_input_bytes.hi_low_field();
                    keccak_output.iter().zip(hi_lo.iter()).for_each(|(output, epxr)| {
                        require!(output.expr() => epxr);
                        cb.enable_equality(output.column());
                    });
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
            keccak_output,
            block_numbers,
            public_input_bytes,
            meta_hash,
            parent_hash,
            block_hash,
            signal_root,
            graffiti,
            prover,
            block_table,
            keccak_table,
            byte_table,
            annotation_configs 
        }
    }
}

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


/// Public Inputs Circuit
#[derive(Clone, Debug)]
pub struct TaikoPiCircuit<F: Field> {
    /// PublicInputs data known by the verifier
    pub evidence: PublicData,
    _marker: PhantomData<F>,
}

impl<F: Field> Default for TaikoPiCircuit<F> {
    fn default() -> Self {
        Self::new(PublicData::default::<F>())
    }
}

impl<F: Field> TaikoPiCircuit<F> {
    /// Creates a new TaikoPiCircuit
    pub fn new(evidence: PublicData) -> Self {
        Self {
            evidence: evidence,
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

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        // TODO(Cecilia): what is the first field?
        (0, PublicData::new(block).max_height())
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        TaikoPiCircuit::new(PublicData::new(block))
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        let (hi, low) = self.evidence.get_pi_hi_low();
        vec![vec![hi.scalar(), low.scalar()]]
    }

    /// Make the assignments to the PiCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.byte_table.load(layouter)?;
        // config.assign(layouter, &self.evidence, challenges)
        Ok(())
    }
}

#[test]
fn test(){
    println!("test");
}
