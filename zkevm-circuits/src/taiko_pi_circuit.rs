//! Use the hash value as public input.
use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{byte_table::ByteTable, BlockContextFieldTag, BlockTable, KeccakTable, keccak_table::KeccakTable2, LookupTable},
    util::{random_linear_combine_word as rlc, Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, BlockContext},
};
use gadgets::{
    is_zero::IsZeroChip,
    less_than::{LtChip, LtConfig, LtInstruction},
};
use gadgets::util::{and, not, or, select, Expr};
use eth_types::{Address, Field, ToBigEndian, ToWord, Word, H256, H160, Bytes, ToScalar, ToLittleEndian,};
use ethers_core::utils::keccak256;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, SecondPhase,
        Selector,
    },
    poly::Rotation,
};
use std::marker::PhantomData;
use ethers_core::{types::U256, utils::rlp::{RlpStream, Encodable}};
use itertools::Itertools;

use lazy_static::lazy_static;
lazy_static! {
    static ref OMMERS_HASH: H256 = H256::from_slice(
        &hex::decode("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")
            .unwrap(),
    );
}

/// BlockValues
#[derive(Clone, Default, Debug)]
pub struct BlockValues {
    coinbase: Address,
    gas_limit: u64,
    number: u64,
    timestamp: u64,
    difficulty: Word,
    base_fee: Word, // NOTE: BaseFee was added by EIP-1559 and is ignored in legacy headers.
    chain_id: u64,
    history_hashes: Vec<Word>,
}

const MAX_DEGREE: usize = 9;
const RPI_CELL_IDX: usize = 0;
const RPI_RLC_ACC_CELL_IDX: usize = 1;
const BYTE_POW_BASE: u64 = 1 << 8;
const RPI_BYTES_LEN: usize = 32 * 10;
// 10 fields * 32B + lo(16B) + hi(16B) + keccak(32B)
const USED_ROWS: usize = RPI_BYTES_LEN + 64; // TODO(George)

/// Fixed by the spec
// pub(super) const BLOCK_LEN: usize = 7 + 256;
const EXTRA_LEN: usize = 2; // TODO(George) is this needed?
const ZERO_BYTE_GAS_COST: u64 = 4;
const NONZERO_BYTE_GAS_COST: u64 = 16;

// The total number of previous blocks for which to check the hash chain
const PREVIOUS_BLOCKS_NUM: usize = 1; // TODO(George) 256;
// This is the number of entries each block occupies in the block_table, which
// is equal to the number of header fields per block (coinbase, timestamp,
// number, difficulty, gas_limit, base_fee, blockhash, beneficiary, state_root,
// transactions_root, receipts_root, gas_used, mix_hash, withdrawals_root)
const BLOCK_LEN_IN_TABLE: usize = 15;
// previous hashes in rlc, lo and hi
// + zero
const BLOCK_TABLE_MISC_LEN: usize = PREVIOUS_BLOCKS_NUM * 3 + 1;
// Total number of entries in the block table:
// + (block fields num) * (total number of blocks)
// + misc entries
const TOTAL_BLOCK_TABLE_LEN: usize =
    (BLOCK_LEN_IN_TABLE * (PREVIOUS_BLOCKS_NUM + 1)) + BLOCK_TABLE_MISC_LEN;

const OLDEST_BLOCK_NUM: usize = 0; // TODO(George) = 0;
const CURRENT_BLOCK_NUM: usize = PREVIOUS_BLOCKS_NUM; // TODO(George) = 256;

const WORD_SIZE: usize = 32;
const U64_SIZE: usize = 8;
const ADDRESS_SIZE: usize = 20;

const RLP_HDR_NOT_SHORT: u64 = 0x81;

// Maximum size of block header fields in bytes
const PARENT_HASH_SIZE: usize = WORD_SIZE;
const OMMERS_HASH_SIZE: usize = WORD_SIZE;
const BENEFICIARY_SIZE: usize = ADDRESS_SIZE;
const STATE_ROOT_SIZE: usize = WORD_SIZE;
const TX_ROOT_SIZE: usize = WORD_SIZE;
const RECEIPTS_ROOT_SIZE: usize = WORD_SIZE;
const LOGS_BLOOM_SIZE: usize = 256;
const DIFFICULTY_SIZE: usize = 1;
const NUMBER_SIZE: usize = U64_SIZE;
const GAS_LIMIT_SIZE: usize = WORD_SIZE;
const GAS_USED_SIZE: usize = WORD_SIZE;
const TIMESTAMP_SIZE: usize = WORD_SIZE;
const EXTRA_DATA_SIZE: usize = 1;
const MIX_HASH_SIZE: usize = WORD_SIZE;
const NONCE_SIZE: usize = U64_SIZE;
const BASE_FEE_SIZE: usize = WORD_SIZE;
const WITHDRAWALS_ROOT_SIZE: usize = WORD_SIZE;

// Helper contants for the offset calculations below
const PARENT_HASH_RLP_LEN: usize = PARENT_HASH_SIZE + 1;
const OMMERS_HASH_RLP_LEN: usize = OMMERS_HASH_SIZE + 1;
const BENEFICIARY_RLP_LEN: usize = BENEFICIARY_SIZE + 1;
const STATE_ROOT_RLP_LEN: usize = STATE_ROOT_SIZE + 1;
const TX_ROOT_RLP_LEN: usize = TX_ROOT_SIZE + 1;
const RECEIPTS_ROOT_RLP_LEN: usize = RECEIPTS_ROOT_SIZE + 1;
const LOGS_BLOOM_RLP_LEN: usize = LOGS_BLOOM_SIZE + 3;
const DIFFICULTY_RLP_LEN: usize = DIFFICULTY_SIZE;
const NUMBER_RLP_LEN: usize = NUMBER_SIZE + 1;
const GAS_LIMIT_RLP_LEN: usize = GAS_LIMIT_SIZE + 1;
const GAS_USED_RLP_LEN: usize = GAS_USED_SIZE + 1;
const TIMESTAMP_RLP_LEN: usize = TIMESTAMP_SIZE + 1;
const EXTRA_DATA_RLP_LEN: usize = EXTRA_DATA_SIZE;
const MIX_HASH_RLP_LEN: usize = MIX_HASH_SIZE + 1;
const NONCE_RLP_LEN: usize = NONCE_SIZE + 1;
const BASE_FEE_RLP_LEN: usize = BASE_FEE_SIZE + 1;
const WITHDRAWALS_ROOT_RLP_LEN: usize = WITHDRAWALS_ROOT_SIZE;

// Row offsets where the value of block header fields start (after their RLP
// header)
const PARENT_HASH_RLP_OFFSET: usize = 4;
const BENEFICIARY_RLP_OFFSET: usize =
    PARENT_HASH_RLP_OFFSET + PARENT_HASH_RLP_LEN + OMMERS_HASH_RLP_LEN;
const STATE_ROOT_RLP_OFFSET: usize = BENEFICIARY_RLP_OFFSET + BENEFICIARY_RLP_LEN;
const TX_ROOT_RLP_OFFSET: usize = STATE_ROOT_RLP_OFFSET + STATE_ROOT_RLP_LEN;
const RECEIPTS_ROOT_RLP_OFFSET: usize = TX_ROOT_RLP_OFFSET + TX_ROOT_RLP_LEN;
const NUMBER_RLP_OFFSET: usize =
    RECEIPTS_ROOT_RLP_OFFSET + RECEIPTS_ROOT_RLP_LEN + LOGS_BLOOM_RLP_LEN + DIFFICULTY_RLP_LEN;
const GAS_LIMIT_RLP_OFFSET: usize = NUMBER_RLP_OFFSET + NUMBER_RLP_LEN;
const GAS_USED_RLP_OFFSET: usize = GAS_LIMIT_RLP_OFFSET + GAS_LIMIT_RLP_LEN;
const TIMESTAMP_RLP_OFFSET: usize = GAS_USED_RLP_OFFSET + GAS_USED_RLP_LEN;
const MIX_HASH_RLP_OFFSET: usize = TIMESTAMP_RLP_OFFSET + TIMESTAMP_RLP_LEN + EXTRA_DATA_RLP_LEN;
const BASE_FEE_RLP_OFFSET: usize = MIX_HASH_RLP_OFFSET + MIX_HASH_RLP_LEN + NONCE_RLP_LEN;
const WITHDRAWALS_ROOT_RLP_OFFSET: usize = BASE_FEE_RLP_OFFSET + BASE_FEE_RLP_LEN;
const BLOCKHASH_TOTAL_ROWS: usize = WITHDRAWALS_ROOT_RLP_OFFSET + WITHDRAWALS_ROOT_RLP_LEN;

// Absolute row number of the row where the LSB of the total RLP length is
// located
const TOTAL_LENGTH_OFFSET: i32 = 2;


/// PublicData contains all the values that the PiCircuit receives as input
#[derive(Debug, Clone)]
pub struct PublicData<F: Field> {
    /// l1 signal service address
    pub l1_signal_service: Word,
    /// l2 signal service address
    pub l2_signal_service: Word,
    /// l2 contract address
    pub l2_contract: Word,
    /// meta hash
    pub meta_hash: Word,
    /// block hash value
    pub block_hash: H256,
    /// the parent block hash
    pub parent_hash: H256,
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
    /// block gas used
    pub gas_used: u32,
    // blockMaxGasLimit
    block_max_gas_limit: u64,
    // maxTransactionsPerBlock: u64,
    max_transactions_per_block: u64,
    // maxBytesPerTxList: u64,
    max_bytes_per_tx_list: u64,
    /// block_context
    pub block_context: BlockContext,
    chain_id: Word,

    /// Block State Root
    pub state_root: H256,
    /// The author
    pub beneficiary: Address,
    /// Transactions Root
    pub transactions_root: H256,
    /// Receipts Root
    pub receipts_root: H256,
    /// Mix Hash
    pub mix_hash: H256,
    /// Withdrawals Root
    pub withdrawals_root: H256,

    /// All data of the past 256 blocks
    pub previous_blocks: Vec<witness::Block<F>>,
    /// RLPs of the past 256 blocks
    pub previous_blocks_rlp: Vec<Bytes>,
    /// History hashes contains the most recent 256 block hashes in history,
    /// where the latest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,

    blockhash_blk_hdr_rlp: Bytes,
    blockhash_rlp_hash_hi: F,
    blockhash_rlp_hash_lo: F,
}

fn rlp_opt<T: Encodable>(rlp: &mut RlpStream, opt: &Option<T>) {
    if let Some(inner) = opt {
        rlp.append(inner);
    } else {
        rlp.append(&"");
    }
}

impl<F:Field> Default for PublicData<F> {
    fn default() -> Self {
        PublicData {
            parent_hash: H256::default(),
            beneficiary: Address::default(),
            transactions_root: H256::default(),
            receipts_root: H256::default(),
            gas_used: u32::default(),
            mix_hash: H256::default(),
            withdrawals_root: H256::default(),
            previous_blocks: vec![],
            previous_blocks_rlp: vec![],
            block_hash: H256::default(),
            blockhash_blk_hdr_rlp: Bytes::default(),
            blockhash_rlp_hash_hi: F::default(),
            blockhash_rlp_hash_lo: F::default(),

            l1_signal_service: U256::default(),
            l2_signal_service: U256::default(),
            l2_contract: U256::default(),
            meta_hash: U256::default(),
            signal_root: U256::default(),
            graffiti: U256::default(),
            field9: U256::default(),
            field10: U256::default(),
            prover: H160::default(),
            parent_gas_used: u32::default(),
            block_max_gas_limit: u64::default(),
            max_transactions_per_block: u64::default(),
            max_bytes_per_tx_list: u64::default(),
            block_context: BlockContext::default(),
            chain_id: U256::default(),
            history_hashes: vec![],
            state_root: H256::default(),
        }
    }
}

impl<F: Field> PublicData<F> {
    fn assignments(&self) -> [(&'static str, Option<Word>, [u8; 32]); 10] {
        [
            (
                "l1_signal_service",
                None,
                self.l1_signal_service.to_be_bytes(),
            ),
            (
                "l2_signal_service",
                None,
                self.l2_signal_service.to_be_bytes(),
            ),
            ("l2_contract", None, self.l2_contract.to_be_bytes()),
            ("meta_hash", None, self.meta_hash.to_be_bytes()),
            (
                "parent_hash",
                Some(self.block_context.number - 1),
                self.parent_hash.to_fixed_bytes(),
            ),
            (
                "block_hash",
                Some(self.block_context.number),
                self.block_hash.to_fixed_bytes(),
            ),
            ("signal_root", None, self.signal_root.to_be_bytes()),
            ("graffiti", None, self.graffiti.to_be_bytes()),
            (
                "prover+parentGasUsed+gasUsed",
                None,
                self.field9.to_be_bytes(),
            ),
            (
                "blockMaxGasLimit+maxTransactionsPerBlock+maxBytesPerTxList",
                None,
                self.field10.to_be_bytes(),
            ),
        ]
    }

    /// get rpi bytes
    pub fn rpi_bytes(&self) -> Vec<u8> {
        self.assignments().iter().flat_map(|v| v.2).collect()
    }

    fn default() -> Self {
        Self::new(&witness::Block::default())
    }

    /// create PublicData from block and taiko
    pub fn new(block: &witness::Block<F>) -> Self {
        assert!(block.context.number >= U256::from(0x100));
        let (blockhash_blk_hdr_rlp, blockhash_rlp_hash_hi, blockhash_rlp_hash_lo, block_hash) =
            Self::get_block_header_rlp_from_block(block);

        // Only initializing `previous_blocks` and `previous_blocks_rlp` here
        // these values are set outside of `new`
        let previous_blocks = vec![witness::Block::<F>::default(); PREVIOUS_BLOCKS_NUM];
        let previous_blocks_rlp = vec![Bytes::default(); PREVIOUS_BLOCKS_NUM];

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
            block_hash: block.protocol_instance.block_hash,//.to_word(),
            parent_hash: block.protocol_instance.parent_hash,//.to_word(),
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
            // parent_hash: block.eth_block.parent_hash,
            beneficiary: block.eth_block.author.unwrap_or_else(H160::zero),
            transactions_root: block.eth_block.transactions_root,
            receipts_root: block.eth_block.receipts_root,
            // gas_used: block.eth_block.gas_used,
            mix_hash: block.eth_block.mix_hash.unwrap_or_else(H256::zero),
            withdrawals_root: block.eth_block.withdrawals_root.unwrap_or_else(H256::zero),
            previous_blocks,
            previous_blocks_rlp,
            blockhash_blk_hdr_rlp,
            blockhash_rlp_hash_hi,
            blockhash_rlp_hash_lo,
            history_hashes: block.context.history_hashes.clone(),
            state_root: block.eth_block.state_root,
        }
    }

       /// Returns struct with values for the block table
       pub fn get_block_table_values(&self) -> BlockValues {
        const PREVIOUS_BLOCKS_NUM:usize = 256; // TODO(George): remove shadow
        let history_hashes = [
            vec![U256::zero(); PREVIOUS_BLOCKS_NUM - self.history_hashes.len()],
            self.history_hashes.to_vec(),]
        .concat();
        BlockValues {
            coinbase: self.block_context.coinbase,
            gas_limit: self.block_context.gas_limit,
            number: self.block_context.number.as_u64(),
            timestamp: self.block_context.timestamp.as_u64(),
            difficulty: self.block_context.difficulty,
            base_fee: self.block_context.base_fee,
            chain_id: self.chain_id.as_u64(),
            history_hashes,
        }
    }

    fn get_pi(&self) -> H256 {
        let rpi_bytes = self.rpi_bytes();
        let rpi_keccak = keccak256(rpi_bytes);
        H256(rpi_keccak)
    }

    fn split_hash(hash: [u8; 32]) -> (F, F) {
        let hi = hash.iter().take(16).fold(F::ZERO, |acc, byte| {
            acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
        });

        let lo = hash.iter().skip(16).fold(F::ZERO, |acc, byte| {
            acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
        });
        (hi, lo)
    }

    fn get_block_header_rlp_from_block(block: &witness::Block<F>) -> (Bytes, F, F, H256) {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream
            .append(&block.eth_block.parent_hash)
            .append(&*OMMERS_HASH)
            .append(&block.eth_block.author.unwrap_or_else(H160::zero))
            .append(&block.eth_block.state_root)
            .append(&block.eth_block.transactions_root)
            .append(&block.eth_block.receipts_root)
            .append(&vec![0u8; LOGS_BLOOM_SIZE]) // logs_bloom is all zeros
            .append(&block.context.difficulty)
            .append(&block.context.number.low_u64())
            // .append(&block.context.gas_limit)
            .append(&U256::from(block.context.gas_limit))
            .append(&U256::from(block.protocol_instance.gas_used))
            .append(&block.context.timestamp);
        rlp_opt(&mut stream, &None::<u8>); // extra_data = ""
        stream
            .append(&block.eth_block.mix_hash.unwrap_or_else(H256::zero))
            .append(&vec![0u8; NONCE_SIZE]) // nonce = 0
            .append(&block.context.base_fee)
            .append(&block.eth_block.withdrawals_root.unwrap_or_else(H256::zero));

        stream.finalize_unbounded_list();
        let out: bytes::Bytes = stream.out().into();
        let rlp_bytes: Bytes = out.into();
        let hash = keccak256(&rlp_bytes);
        let (hi, lo) = Self::split_hash(hash);
        let hash_res = H256::from(hash);
        (rlp_bytes, hi, lo, hash_res)
    }
}

#[derive(Debug, Clone)]
struct BlockhashColumns {
    blk_hdr_rlp: Column<Advice>,
    blk_hdr_rlp_inv: Column<Advice>,
    blk_hdr_rlp_const: Column<Fixed>,
    q_blk_hdr_rlp: Selector,
    q_blk_hdr_rlp_const: Selector,
    blk_hdr_rlp_len_calc: Column<Advice>,
    blk_hdr_rlp_len_calc_inv: Column<Advice>,
    blk_hdr_reconstruct_value: Column<Advice>,
    blk_hdr_reconstruct_hi_lo: Column<Advice>,
    q_hi: Column<Fixed>,
    q_lo: Column<Fixed>,
    block_table_tag: Column<Fixed>,
    block_table_index: Column<Fixed>,
    q_reconstruct: Column<Fixed>,
    q_number: Column<Fixed>,
    q_parent_hash: Selector,
    q_var_field_256: Column<Fixed>,
    q_blk_hdr_rlc_start: Selector,
    q_blk_hdr_rlp_end: Selector,
    blk_hdr_rlc_acc: Column<Advice>,
    blk_hdr_do_rlc_acc: Column<Advice>,
    q_lookup_blockhash: Selector,
    blk_hdr_is_leading_zero: Column<Advice>,
    blk_hdr_blockhash: Column<Advice>,
}

/// Config for PiCircuit
#[derive(Clone, Debug)]
pub struct TaikoPiCircuitConfig<F: Field> {
    rpi_field_bytes: Column<Advice>,
    rpi_field_bytes_acc: Column<Advice>,
    rpi_rlc_acc: Column<Advice>,
    q_field_start: Selector,
    q_field_step: Selector,
    q_field_end: Selector,
    is_field_rlc: Column<Fixed>,

    byte_table: ByteTable,

    pi: Column<Instance>, // keccak_hi, keccak_lo

    q_keccak: Selector,
    keccak_table: KeccakTable, // TODO(George): merge Keccak Tables
    keccak_table2: KeccakTable2,

    // External tables
    q_block_table: Selector,
    block_index: Column<Advice>,
    block_table: BlockTable,
    block_table_blockhash: BlockTable,

    q_start: Selector,
    fixed_u8: Column<Fixed>,
    rlp_is_short: LtConfig<F, 1>,
    blockhash_cols: BlockhashColumns,
    _marker: PhantomData<F>,
}

/// Circuit configuration arguments
pub struct TaikoPiCircuitConfigArgs<F: Field> {
    /// BlockTable
    pub block_table: BlockTable,
    /// BlockTable for blockhash
    pub block_table_blockhash: BlockTable, // TODO(George): merge the block tables
    /// ByteTable
    pub byte_table: ByteTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
    /// KeccakTable
    pub keccak_table: KeccakTable, // TODO(George): merge the keccak tables
    /// KeccakTable
    pub keccak_table2: KeccakTable2
}

impl<F: Field> SubCircuitConfig<F> for TaikoPiCircuitConfig<F> {
    type ConfigArgs = TaikoPiCircuitConfigArgs<F>;

    /// Return a new TaikoPiCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            block_table,
            block_table_blockhash,
            keccak_table,
            keccak_table2,
            byte_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let rpi_field_bytes = meta.advice_column();
        let rpi_field_bytes_acc = meta.advice_column_in(SecondPhase);
        let rpi_rlc_acc = meta.advice_column_in(SecondPhase);
        let q_field_start = meta.complex_selector();
        let q_field_step = meta.complex_selector();
        let q_field_end = meta.complex_selector();
        let is_field_rlc = meta.fixed_column();

        let pi = meta.instance_column();

        let q_keccak = meta.complex_selector();
        let q_block_table = meta.complex_selector();
        let block_index = meta.advice_column();

        let q_start = meta.complex_selector();
        let fixed_u8 = meta.fixed_column();
        // Block hash
        let blk_hdr_rlp = meta.advice_column();
        let blk_hdr_rlp_inv = meta.advice_column();
        let blk_hdr_rlp_const = meta.fixed_column();
        let q_blk_hdr_rlp = meta.complex_selector();
        let q_blk_hdr_rlp_end = meta.complex_selector();
        let q_blk_hdr_rlp_const = meta.complex_selector();

        let blk_hdr_rlp_len_calc = meta.advice_column();
        let blk_hdr_rlp_len_calc_inv = meta.advice_column();
        let blk_hdr_reconstruct_value = meta.advice_column_in(SecondPhase);
        let blk_hdr_reconstruct_hi_lo = meta.advice_column();
        let block_table_tag_blockhash = meta.fixed_column();
        let block_table_index_blockhash = meta.fixed_column();
        let q_reconstruct = meta.fixed_column();
        let blk_hdr_is_leading_zero = meta.advice_column();

        // Selectors for header fields.
        let q_number = meta.fixed_column();
        let q_parent_hash = meta.complex_selector();
        let q_var_field_256 = meta.fixed_column();
        let q_hi = meta.fixed_column();
        let q_lo = meta.fixed_column();

        let q_blk_hdr_rlc_start = meta.complex_selector();
        let blk_hdr_do_rlc_acc = meta.advice_column_in(SecondPhase);
        let blk_hdr_rlc_acc = meta.advice_column_in(SecondPhase);
        let q_lookup_blockhash = meta.complex_selector();
        let blk_hdr_blockhash = meta.advice_column();
        // self.blockhash_cols.block_table_tag
        let blockhash_cols = BlockhashColumns {
            blk_hdr_rlp,
            blk_hdr_rlp_inv,
            blk_hdr_rlp_const,
            q_blk_hdr_rlp,
            q_blk_hdr_rlp_const,
            blk_hdr_rlp_len_calc,
            blk_hdr_rlp_len_calc_inv,
            blk_hdr_reconstruct_value,
            blk_hdr_reconstruct_hi_lo,
            q_hi,
            q_lo,
            q_reconstruct,
            block_table_tag: block_table_tag_blockhash,
            block_table_index: block_table_index_blockhash,
            q_number,
            q_parent_hash,
            q_var_field_256,
            q_blk_hdr_rlc_start,
            q_blk_hdr_rlp_end,
            blk_hdr_rlc_acc,
            blk_hdr_do_rlc_acc,
            q_lookup_blockhash,
            blk_hdr_is_leading_zero,
            blk_hdr_blockhash,

        };

        meta.enable_equality(rpi_field_bytes);
        meta.enable_equality(rpi_field_bytes_acc);
        meta.enable_equality(rpi_rlc_acc);
        meta.enable_equality(block_table.value);
        meta.enable_equality(pi);

        // field bytes
        meta.create_gate(
            "rpi_field_bytes_acc[i+1] = rpi_field_bytes_acc[i] * t + rpi_bytes[i+1]",
            |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                let q_field_step = meta.query_selector(q_field_step);
                let rpi_field_bytes_acc_next =
                    meta.query_advice(rpi_field_bytes_acc, Rotation::next());
                let rpi_field_bytes_acc = meta.query_advice(rpi_field_bytes_acc, Rotation::cur());
                let rpi_field_bytes_next = meta.query_advice(rpi_field_bytes, Rotation::next());
                let is_field_rlc = meta.query_fixed(is_field_rlc, Rotation::next());
                let randomness = challenges.evm_word();
                let t = select::expr(is_field_rlc, randomness, BYTE_POW_BASE.expr());
                cb.require_equal(
                    "rpi_field_bytes_acc[i+1] = rpi_field_bytes_acc[i] * t + rpi_bytes[i+1]",
                    rpi_field_bytes_acc_next,
                    rpi_field_bytes_acc * t + rpi_field_bytes_next,
                );
                cb.gate(q_field_step)
            },
        );
        meta.create_gate("rpi_field_bytes_acc[0] = rpi_field_bytes[0]", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_field_start = meta.query_selector(q_field_start);
            let rpi_field_bytes_acc = meta.query_advice(rpi_field_bytes_acc, Rotation::cur());
            let rpi_field_bytes = meta.query_advice(rpi_field_bytes, Rotation::cur());

            cb.require_equal(
                "rpi_field_bytes_acc[0] = rpi_field_bytes[0]",
                rpi_field_bytes_acc,
                rpi_field_bytes,
            );
            cb.gate(q_field_start)
        });

        // keccak in rpi
        meta.lookup_any("keccak(rpi)", |meta| {
            let q_keccak = meta.query_selector(q_keccak);
            let rpi_rlc = meta.query_advice(rpi_field_bytes_acc, Rotation::cur());
            let output = meta.query_advice(rpi_rlc_acc, Rotation::cur());
            [1.expr(), rpi_rlc, RPI_BYTES_LEN.expr(), output]
                .into_iter()
                .zip(keccak_table.table_exprs(meta).into_iter())
                .map(|(arg, table)| (q_keccak.expr() * arg, table))
                .collect::<Vec<_>>()
        });

        // TODO(GEORGE): do we need this, we  already check block hash in another lookup
        // in block table
        /*
        meta.lookup_any("in block table", |meta| {
            let q_block_table = meta.query_selector(q_block_table);
            let block_index = meta.query_advice(block_index, Rotation::cur());
            let block_hash = meta.query_advice(rpi_field_bytes_acc, Rotation::cur());
            [
                BlockContextFieldTag::BlockHash.expr(),
                block_index,
                block_hash,
            ]
            .into_iter()
            .zip(block_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (q_block_table.expr() * arg, table))
            .collect::<Vec<_>>()
        });
        */
        // is byte
        meta.lookup_any("is_byte", |meta| {
            let q_field_step = meta.query_selector(q_field_start);
            let q_field_end = meta.query_selector(q_field_end);
            let is_field = or::expr([q_field_step, q_field_end]);
            let rpi_field_bytes = meta.query_advice(rpi_field_bytes, Rotation::cur());
            [rpi_field_bytes]
                .into_iter()
                .zip(byte_table.table_exprs(meta).into_iter())
                .map(|(arg, table)| (is_field.expr() * arg, table))
                .collect::<Vec<_>>()
        });

        let offset = TOTAL_BLOCK_TABLE_LEN + EXTRA_LEN;

        // Block hash checks in three parts:
        // 1. RLP checks
        // 2. RLC calculation
        // 3. Keccak lookup

        // Check if the RLP byte is 0
        let rlp_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_blk_hdr_rlp),
            |meta| meta.query_advice(blk_hdr_rlp, Rotation::cur()),
            blk_hdr_rlp_inv,
        );

        // Check if the length is 0
        let length_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_blk_hdr_rlp),
            |meta| meta.query_advice(blk_hdr_rlp_len_calc, Rotation::cur()),
            blk_hdr_rlp_len_calc_inv,
        );

        // Check if the RLP byte is short (byte < 81)
        let rlp_is_short = LtChip::configure(
            meta,
            |meta| meta.query_selector(q_blk_hdr_rlp),
            |meta| meta.query_advice(blk_hdr_rlp, Rotation::cur()),
            |_| RLP_HDR_NOT_SHORT.expr(),
        );

        // Check that all RLP bytes are within [0, 255]
        meta.lookup_any("Block header RLP: byte range checks", |meta| {
            let block_header_rlp_byte = meta.query_advice(blk_hdr_rlp, Rotation::cur());
            let fixed_u8_table = meta.query_fixed(fixed_u8, Rotation::cur());

            vec![(block_header_rlp_byte, fixed_u8_table)]
        });

        meta.create_gate("Block header", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_enabled = meta.query_selector(q_blk_hdr_rlp);
            let q_const = meta.query_selector(q_blk_hdr_rlp_const);
            let q_rlc_start = meta.query_selector(q_blk_hdr_rlc_start);
            let q_rlc_end = meta.query_selector(q_blk_hdr_rlp_end);
            let byte = meta.query_advice(blk_hdr_rlp, Rotation::cur());
            let byte_next = meta.query_advice(blk_hdr_rlp, Rotation::next());
            let const_byte = meta.query_fixed(blk_hdr_rlp_const, Rotation::cur());
            let length = meta.query_advice(blk_hdr_rlp_len_calc, Rotation::cur());
            let length_next = meta.query_advice(blk_hdr_rlp_len_calc, Rotation::next());
            let is_leading_zero = meta.query_advice(blk_hdr_is_leading_zero, Rotation::cur());
            let is_leading_zero_next = meta.query_advice(blk_hdr_is_leading_zero, Rotation::next());
            let q_reconstruct_cur = meta.query_fixed(q_reconstruct, Rotation::cur());
            let q_reconstruct_next = meta.query_fixed(q_reconstruct, Rotation::next());
            let do_rlc_acc = meta.query_advice(blk_hdr_do_rlc_acc, Rotation::cur());
            let rlc_acc = meta.query_advice(blk_hdr_rlc_acc, Rotation::cur());
            let rlc_acc_next = meta.query_advice(blk_hdr_rlc_acc, Rotation::next());
            let q_hi_next = meta.query_fixed(q_hi, Rotation::next());
            let q_lo_cur = meta.query_fixed(q_lo, Rotation::cur());
            let q_lo_next = meta.query_fixed(q_lo, Rotation::next());

            // Check all RLP bytes that are constant against their expected value
            cb.condition(q_const, |cb| {
                cb.require_equal(
                    "RLP constant byte values are correct",
                    byte.expr(),
                    const_byte.expr(),
                );
            });

            // 1. Block header RLP

            cb.condition(q_enabled.expr(), |cb| {
                // Make sure that the length starts from 0
                let q_number_or_field_256 = or::expr([
                    meta.query_fixed(q_number, Rotation::cur()),
                    meta.query_fixed(q_var_field_256, Rotation::cur()),
                ]);
                cb.condition(not::expr(q_number_or_field_256), |cb| {
                    cb.require_zero("length default value is zero", length.expr());
                });

                // `is_leading_zero` needs to be boolean
                cb.require_boolean("is_leading_zero boolean", is_leading_zero.expr());
                // `q_rlc_acc` needs to be boolean
                cb.require_boolean("q_rlc_acc boolean", do_rlc_acc.expr());

                // Covers a corner case where MSB bytes can be skipped by annotating them as
                // leading zeroes. This can occur when `blk_hdr_is_leading_zero`
                // is set to 0 wrongly (the actual byte value is non-zero)
                cb.condition(not::expr(rlp_is_zero.expr()), |cb| {
                    cb.require_zero("Leading zeros cannot be skipped", is_leading_zero.expr());
                });
            });

            // Check leading zeros are actually leading zeros
            for q_field in [q_number, q_var_field_256] {
                let q_field_prev = meta.query_fixed(q_field, Rotation::prev());
                let q_field = meta.query_fixed(q_field, Rotation::cur());
                cb.condition(and::expr([is_leading_zero.expr(), q_field]), |cb| {
                    // Leading byte is actually zero
                    cb.require_zero("Leading zero is actually zero", byte.expr());

                    // Loading zeros needs to be continuous, except at the beginning of the field
                    let is_leading_zero_prev =
                        meta.query_advice(blk_hdr_is_leading_zero, Rotation::prev());
                    cb.require_equal(
                        "Leading zeros must be continuous or we are at the begining of the field",
                        1.expr(),
                        or::expr([is_leading_zero_prev, not::expr(q_field_prev)]),
                    );
                });
            }

            // Length checks for all variable length fields:
            // 1. len = 0 for leading zeros
            // 2. len = len_prev + 1 otherwise
            // 3. total_len = 0 if value <= 0x80
            let rlp_is_short_next = rlp_is_short.is_lt(meta, Some(Rotation::next()));
            for (q_value, var_size) in [(q_number, NUMBER_SIZE), (q_var_field_256, WORD_SIZE)] {
                let q_field = meta.query_fixed(q_value, Rotation::cur());
                let q_field_next = meta.query_fixed(q_value, Rotation::next());
                // Only check while we're processing the field
                cb.condition(q_field.expr(), |cb| {
                    // Length needs to remain zero when skipping over leading zeros
                    cb.condition(is_leading_zero.expr(), |cb| {
                        cb.require_zero("Length is zero on a leading zero", length.expr());
                    });

                    // The length needs to increment when
                    // - not a leading zero
                    // - the total length is not 0
                    // We know the total length is 0 when the length is currently 0 and the field
                    // ends on the next row
                    let is_total_len_zero =
                        and::expr([not::expr(q_field_next.expr()), length_is_zero.expr()]);
                    let do_increment_length = and::expr([
                        not::expr(is_leading_zero.expr()),
                        not::expr(is_total_len_zero.expr()),
                    ]);
                    cb.condition(do_increment_length, |cb| {
                        let length_prev = meta.query_advice(blk_hdr_rlp_len_calc, Rotation::prev());
                        cb.require_equal(
                            "len = len_prev + 1",
                            length.expr(),
                            length_prev.expr() + 1.expr(),
                        );
                    });

                    // The length is also set to 0 when the RLP encoding is short (single RLP byte
                    // encoding)
                    cb.condition(
                        and::expr([rlp_is_short_next.clone(), length_is_zero.expr(), not::expr(q_field_next.expr())]),
                        |cb| {
                            cb.require_zero(
                                "Length is set to zero for short values",
                                length_next.expr(),
                            );
                        },
                    );
                });

                // Check RLP encoding
                cb.condition(
                    and::expr([not::expr(q_field.clone()), q_field_next.expr()]),
                    |cb| {
                        let length =
                            meta.query_advice(blk_hdr_rlp_len_calc, Rotation(var_size as i32));
                        cb.require_equal("RLP length", byte.expr(), 0x80.expr() + length.expr());
                    },
                );
            }

            // Check total length of RLP stream.
            // For the block header, the total RLP length is always two bytes long and only
            // the LSB fluctuates:
            // - Minimum total length: lengths of all the fixed size fields + all the RLP
            //   headers = 527 bytes (0x020F)
            // - Maximum total length: minimum total length + (maximum length of variable
            //   size field) = 527 + 4*32+1*8 = 663 (0x0297)
            // - Actual total length: minimum total length + length of all variable size
            //   fields (number, gas_limit, gas_used, timestamp, base fee).
            cb.condition(q_rlc_start.expr(), |cb| {
                let mut get_len = |offset: usize| {
                    meta.query_advice(
                        blk_hdr_rlp_len_calc,
                        // The length of a field is located at its last row
                        // Since the `offset` given is the first byte of the next field, we need to
                        // remove 1 row to target the last byte of the actual field
                        Rotation((offset - 1).try_into().unwrap()),
                    )
                };
                let number_len = get_len(NUMBER_RLP_OFFSET + NUMBER_SIZE);
                let gas_limit_len = get_len(GAS_LIMIT_RLP_OFFSET + GAS_LIMIT_SIZE);
                let gas_used_len = get_len(GAS_USED_RLP_OFFSET + GAS_USED_SIZE);
                let timestamp_len = get_len(TIMESTAMP_RLP_OFFSET + TIMESTAMP_SIZE);
                let base_fee_len = get_len(BASE_FEE_RLP_OFFSET + BASE_FEE_SIZE);
                // Only check the LSB of the length (the MSB is always 0x02!).
                cb.require_equal(
                    "total_len",
                    meta.query_advice(blk_hdr_rlp, Rotation(TOTAL_LENGTH_OFFSET)),
                    0x0F.expr()
                        + number_len
                        + gas_limit_len
                        + gas_used_len
                        + timestamp_len
                        + base_fee_len,
                );
            });

            // Leading zeros artificical headers are not part of the RLC calculation
            let q_number_next = meta.query_fixed(q_number, Rotation::next());
            let q_number_after_next = meta.query_fixed(q_number, Rotation(2));
            let q_var_field_256_next = meta.query_fixed(q_var_field_256, Rotation::next());
            let q_var_field_256_after_next = meta.query_fixed(q_var_field_256, Rotation(2));
            let is_number_header =
                and::expr([not::expr(q_number_next.expr()), q_number_after_next.expr()]);
            let is_var_field_header = and::expr([
                not::expr(q_var_field_256_next.expr()),
                q_var_field_256_after_next.expr(),
            ]);
            let is_number_zero =
                meta.query_advice(blk_hdr_is_leading_zero, Rotation((NUMBER_SIZE + 1) as i32));
            let is_var_field_zero =
                meta.query_advice(blk_hdr_is_leading_zero, Rotation((WORD_SIZE + 1) as i32));
            let rlp_short_or_zero = rlp_is_short.is_lt(meta, Some(Rotation::next()));
            // Artificial headers exist for header fields with short values greater than
            // zero
            let is_artificial_header = and::expr([
                rlp_short_or_zero.expr(),
                or::expr([
                    and::expr([is_number_header, not::expr(is_number_zero.expr())]),
                    and::expr([is_var_field_header, not::expr(is_var_field_zero.expr())]),
                ]),
            ]);
            let no_rlc = or::expr([is_leading_zero_next.expr(), is_artificial_header]);

            let do_rlc_val = select::expr(no_rlc, 0.expr(), 1.expr());
            cb.condition(q_enabled.expr(), |cb| {
                cb.require_equal(
                    "skip leading zeros and artifical headers in RLC ",
                    meta.query_advice(blk_hdr_do_rlc_acc, Rotation::cur()),
                    do_rlc_val,
                );
            });

            // Decode RLC field values
            cb.condition(
                and::expr([
                    q_reconstruct_next.expr(),
                    not::expr(q_hi_next.expr()),
                    not::expr(q_lo_next.expr()),
                ]),
                |cb| {
                    let decode = meta.query_advice(blk_hdr_reconstruct_value, Rotation::cur());
                    let decode_next =
                        meta.query_advice(blk_hdr_reconstruct_value, Rotation::next());
                    // For the first byte start from scratch and just copy over the next byte
                    let r = select::expr(q_reconstruct_cur.expr(), challenges.evm_word().expr(), 0.expr());
                    cb.require_equal("decode", decode_next, decode * r + byte_next.expr());
                },
            );

            // Decode Hi/Lo field values
            cb.condition(q_hi_next.expr(), |cb| {
                let decode = meta.query_advice(blk_hdr_reconstruct_value, Rotation::cur());
                let decode_next = meta.query_advice(blk_hdr_reconstruct_value, Rotation::next());
                // For the first byte start from scratch and just copy over the next byte
                let r = select::expr(q_reconstruct_cur.expr(), 2_u64.pow(8).expr(), 0.expr());
                cb.require_equal("hi value", decode_next, decode * r + byte_next.expr());
            });
            cb.condition(q_lo_next.expr(), |cb| {
                let decode = meta.query_advice(blk_hdr_reconstruct_value, Rotation::cur());
                let decode_next = meta.query_advice(blk_hdr_reconstruct_value, Rotation::next());
                // For the first byte start from scratch and just copy over the next byte
                let r = select::expr(q_lo_cur.expr(), 2_u64.pow(8).expr(), 0.expr());
                cb.require_equal("lo value", decode_next, decode * r + byte_next.expr());
            });

            // 2. Check RLC of RLP'd block header
            // Accumulate only bytes that have q_blk_hdr_rlp AND
            // NOT(blk_hdr_is_leading_zero) and skip RLP headers if value is <0x80
            cb.condition(q_rlc_start.expr(), |cb| {
                cb.require_equal("rlc_acc = byte", rlc_acc.expr(), byte.expr());
            });
            cb.condition(
                and::expr([q_enabled.expr(), not::expr(q_rlc_end.expr())]),
                |cb| {
                    // RLC encode the bytes, but skip over leading zeros
                    let r = select::expr(do_rlc_acc.expr(), challenges.keccak_input().expr(), 1.expr());
                    let byte_value = select::expr(do_rlc_acc.expr(), byte_next.expr(), 0.expr());
                    cb.require_equal(
                        "rlc_acc_next = rlc_acc * r + next_byte",
                        rlc_acc_next.expr(),
                        rlc_acc.expr() * r + byte_value,
                    );
                },
            );

            cb.gate(1.expr())
        });

        meta.lookup_any(
            "Block header: Check RLC of field values except of `q_parent_hash`",
            |meta| {
                let q_sel = and::expr([
                    meta.query_fixed(q_reconstruct, Rotation::cur()),
                    not::expr(meta.query_fixed(q_reconstruct, Rotation::next())),
                    // We exclude `parent_hash` as it is dealt with in its own lookup
                    not::expr(meta.query_selector(q_parent_hash)),
                ]);
                vec![
                    (
                        q_sel.expr() * meta.query_fixed(block_table_tag_blockhash, Rotation::cur()),
                        meta.query_advice(block_table.tag, Rotation::cur()),
                    ),
                    (
                        q_sel.expr() * meta.query_fixed(block_table_index_blockhash, Rotation::cur()),
                        meta.query_advice(block_table.index, Rotation::cur()),
                    ),
                    (
                        q_sel.expr()
                            * meta.query_advice(blk_hdr_reconstruct_value, Rotation::cur()),
                        meta.query_advice(block_table.value, Rotation::cur()),
                    ),
                ]
            },
        );

        // 3. Check block header hash
        meta.lookup_any("blockhash lookup keccak", |meta| {
            let q_blk_hdr_rlp_end = meta.query_selector(q_blk_hdr_rlp_end);
            let blk_hdr_rlc = meta.query_advice(blk_hdr_rlc_acc, Rotation::cur());
            // The total RLP length is the RLP list length (0x200 + blk_hdr_rlp[2])
            //  + 3 bytes for the RLP list header
            let blk_hdr_rlp_num_bytes = 0x200.expr()
                + meta.query_advice(
                    blk_hdr_rlp,
                    Rotation(-(BLOCKHASH_TOTAL_ROWS as i32) + 1 + 2),
                )
                + 3.expr();
            let blk_hdr_hash_hi = meta.query_advice(blk_hdr_blockhash, Rotation::cur());
            let blk_hdr_hash_lo = meta.query_advice(blk_hdr_blockhash, Rotation::prev());
            vec![
                (
                    q_blk_hdr_rlp_end.expr(),
                    meta.query_advice(keccak_table2.is_enabled, Rotation::cur()),
                ),
                (
                    q_blk_hdr_rlp_end.expr() * blk_hdr_rlc,
                    meta.query_advice(keccak_table2.input_rlc, Rotation::cur()),
                ),
                (
                    q_blk_hdr_rlp_end.expr() * blk_hdr_rlp_num_bytes,
                    meta.query_advice(keccak_table2.input_len, Rotation::cur()),
                ),
                (
                    q_blk_hdr_rlp_end.expr() * blk_hdr_hash_hi,
                    meta.query_advice(keccak_table2.output_hi, Rotation::cur()),
                ),
                (
                    q_blk_hdr_rlp_end * blk_hdr_hash_lo,
                    meta.query_advice(keccak_table2.output_lo, Rotation::cur()),
                ),
            ]
        });

        meta.lookup_any(
            "Block header: Check hi parts of block hashes against previous hashes",
            |meta| {
                let q_blk_hdr_rlp_end = meta.query_selector(q_blk_hdr_rlp_end);
                let blk_hdr_hash_hi = meta.query_advice(blk_hdr_blockhash, Rotation::cur());
                let q_lookup_blockhash = meta.query_selector(q_lookup_blockhash);
                let tag = meta.query_fixed(block_table_tag_blockhash, Rotation::prev());
                let index = meta.query_fixed(block_table_index_blockhash, Rotation::cur());
                let q_sel = and::expr([q_blk_hdr_rlp_end, q_lookup_blockhash]);
                vec![
                    (
                        q_sel.expr() * tag,
                        meta.query_advice(block_table.tag, Rotation::cur()),
                    ),
                    (
                        q_sel.expr() * index,
                        meta.query_advice(block_table.index, Rotation::cur()),
                    ),
                    (
                        q_sel.expr() * blk_hdr_hash_hi,
                        meta.query_advice(block_table.value, Rotation::cur()),
                    ),
                ]
            },
        );
        meta.lookup_any(
            "Block header: Check lo parts of block hashes against previous hashes",
            |meta| {
                let q_blk_hdr_rlp_end = meta.query_selector(q_blk_hdr_rlp_end);
                let blk_hdr_hash_lo = meta.query_advice(blk_hdr_blockhash, Rotation::prev());
                let q_lookup_blockhash = meta.query_selector(q_lookup_blockhash);
                let tag = meta.query_fixed(block_table_tag_blockhash, Rotation(-2));
                let index = meta.query_fixed(block_table_index_blockhash, Rotation::cur());
                let q_sel = and::expr([q_blk_hdr_rlp_end, q_lookup_blockhash]);
                vec![
                    (
                        q_sel.expr() * tag,
                        meta.query_advice(block_table.tag, Rotation::cur()),
                    ),
                    (
                        q_sel.expr() * index,
                        meta.query_advice(block_table.index, Rotation::cur()),
                    ),
                    (
                        q_sel.expr() * blk_hdr_hash_lo,
                        meta.query_advice(block_table.value, Rotation::cur()),
                    ),
                ]
            },
        );

        // Check all parent_hash fields against previous_hashes in block table
        meta.lookup_any("Block header: Check parent hashes hi", |meta| {
            let tag = meta.query_fixed(block_table_tag_blockhash, Rotation::cur());
            let index = meta.query_fixed(block_table_index_blockhash, Rotation::cur()) - 1.expr();
            let q_hi = meta.query_fixed(q_hi, Rotation::cur());
            let q_lo_next = meta.query_fixed(q_lo, Rotation::next());

            let q_sel = and::expr([
                // meta.query_fixed(q_reconstruct, Rotation::cur()),
                // not::expr(meta.query_fixed(q_reconstruct, Rotation::next())),
                q_hi,
                q_lo_next,
                meta.query_selector(q_parent_hash),
            ]);

            vec![
                (
                    q_sel.expr() * tag,
                    meta.query_advice(block_table.tag, Rotation::cur()),
                ),
                // (
                //     q_sel.expr() * index,
                //     meta.query_advice(block_table.index, Rotation::cur()),
                // ),
                (
                    q_sel.expr() * meta.query_advice(blk_hdr_reconstruct_value, Rotation::cur()),
                    meta.query_advice(block_table.value, Rotation::cur()),
                ),
            ]
        });
        meta.lookup_any("Block header: Check parent hashes lo", |meta| {
            let tag = meta.query_fixed(block_table_tag_blockhash, Rotation::cur());
            let index = meta.query_fixed(block_table_index_blockhash, Rotation::cur()) - 1.expr();
            let q_lo_cur = meta.query_fixed(q_lo, Rotation::cur());
            let q_lo_next = meta.query_fixed(q_lo, Rotation::next());

            let q_sel = and::expr([
                q_lo_cur,
                not::expr(q_lo_next),
                meta.query_selector(q_parent_hash),
            ]);

            vec![
                (
                    q_sel.expr() * tag,
                    meta.query_advice(block_table.tag, Rotation::cur()),
                ),
                // (
                //     q_sel.expr() * index,
                //     meta.query_advice(block_table.index, Rotation::cur()),
                // ),
                (
                    q_sel.expr() * meta.query_advice(blk_hdr_reconstruct_value, Rotation::cur()),
                    meta.query_advice(block_table.value, Rotation::cur()),
                ),
            ]
        });

        Self {
            rpi_field_bytes,
            rpi_field_bytes_acc,
            rpi_rlc_acc,
            q_field_start,
            q_field_step,
            q_field_end,

            byte_table,
            is_field_rlc,

            pi, // keccak_hi, keccak_lo

            q_keccak,
            keccak_table,
            keccak_table2,

            q_block_table,
            block_index,
            block_table,

            _marker: PhantomData,
            q_start,
            fixed_u8,
            rlp_is_short,
            blockhash_cols,
            block_table_blockhash,
        }
    }
}

impl<F: Field> TaikoPiCircuitConfig<F> {
    #[allow(clippy::too_many_arguments)]
    fn assign_pi_field(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        _annotation: &'static str,
        field_bytes: &[u8],
        rpi_rlc_acc: &mut Value<F>,
        challenges: &Challenges<Value<F>>,
        keccak_hi_lo: bool,
        block_number: Option<Word>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let len = field_bytes.len();
        let mut field_rlc_acc = Value::known(F::ZERO);
        let (use_rlc, t) = if len * 8 > F::CAPACITY as usize {
            (F::ONE, challenges.evm_word())
        } else {
            (F::ZERO, Value::known(F::from(BYTE_POW_BASE)))
        };

        let randomness = if keccak_hi_lo {
            challenges.evm_word()
        } else {
            challenges.keccak_input()
        };
        let mut cells = vec![None; field_bytes.len() + 2];
        for (i, byte) in field_bytes.iter().enumerate() {
            let row_offset = *offset + i;

            region.assign_fixed(
                || "is_field_rlc",
                self.is_field_rlc,
                row_offset,
                || Value::known(use_rlc),
            )?;

            // assign field bytes
            let field_byte_cell = region.assign_advice(
                || "field bytes",
                self.rpi_field_bytes,
                row_offset,
                || Value::known(F::from(*byte as u64)),
            )?;

            field_rlc_acc = field_rlc_acc * t + Value::known(F::from(*byte as u64));
            let rpi_cell = region.assign_advice(
                || "field bytes acc",
                self.rpi_field_bytes_acc,
                row_offset,
                || field_rlc_acc,
            )?;
            *rpi_rlc_acc = *rpi_rlc_acc * randomness + Value::known(F::from(*byte as u64));
            let rpi_rlc_acc_cell = region.assign_advice(
                || "rpi_rlc_acc",
                self.rpi_rlc_acc,
                row_offset,
                || *rpi_rlc_acc,
            )?;
            // setup selector
            if i == 0 {
                self.q_field_start.enable(region, row_offset)?;
            }
            // the last offset of field
            if i == field_bytes.len() - 1 {
                self.q_field_end.enable(region, row_offset)?;
                cells[RPI_CELL_IDX] = Some(rpi_cell);
                cells[RPI_RLC_ACC_CELL_IDX] = Some(rpi_rlc_acc_cell);
                if let Some(block_number) = block_number {
                    self.q_block_table.enable(region, row_offset)?;
                    region.assign_advice(
                        || "block_index",
                        self.block_index,
                        row_offset,
                        || Value::known(F::from(block_number.as_u64())),
                    )?;
                }
            } else {
                self.q_field_step.enable(region, row_offset)?;
            }
            cells[2 + i] = Some(field_byte_cell);
        }
        *offset += field_bytes.len();
        Ok(cells.into_iter().map(|cell| cell.unwrap()).collect())
    }

    #[allow(clippy::type_complexity)]
    fn get_block_header_rlp_from_public_data(
        public_data: &PublicData<F>,
        randomness: Value<F>,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<Value<F>>, Value<F>, Value<F>) {
        // RLP encode the block header data
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        // println!("public data = {:?}", public_data);
        stream
            .append(&public_data.parent_hash)
            .append(&*OMMERS_HASH)
            .append(&public_data.beneficiary)
            .append(&public_data.state_root)
            .append(&public_data.transactions_root)
            .append(&public_data.receipts_root)
            .append(&vec![0u8; LOGS_BLOOM_SIZE]) // logs_bloom is all zeros
            .append(&public_data.block_context.difficulty)
            .append(&public_data.block_context.number.as_u64())
            .append(&U256::from(public_data.block_context.gas_limit))
            // .append(&(public_data.block_context.gas_limit))
            .append(&public_data.gas_used)
            .append(&public_data.block_context.timestamp);
        rlp_opt(&mut stream, &None::<u8>); // extra_data = ""
        stream
            .append(&public_data.mix_hash)
            .append(&vec![0u8; 8]) // nonce = 0
            .append(&public_data.block_context.base_fee)
            .append(&public_data.withdrawals_root);
        stream.finalize_unbounded_list();
        let mut bytes: Vec<u8> = stream.out().into();

        // Calculate the block hash
        let hash = keccak256(&bytes);
        let hash_hi = hash.iter().take(16).fold(F::ZERO, |acc, byte| {
            acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
        });
        let hash_lo = hash.iter().skip(16).fold(F::ZERO, |acc, byte| {
            acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
        });

        let mut leading_zeros: Vec<u8> = vec![0; bytes.len()];
        let mut blk_hdr_do_rlc_acc: Vec<u8> = vec![1; bytes.len()];
        let mut blk_hdr_rlc_acc: Vec<Value<F>> = vec![];

        // Calculate the RLC of the bytes
        bytes.iter().map(|b| Value::known(F::from(*b as u64))).fold(
            Value::known(F::ZERO),
            |mut rlc_acc, byte| {
                rlc_acc = rlc_acc * randomness + byte;
                // println!("rlc_acc = {:?}\nrandomness = {:?}\nbyte = {:?}", rlc_acc, randomness, byte);
                blk_hdr_rlc_acc.push(rlc_acc);
                rlc_acc
            },
        );

        // Handles leading zeros, short values and calculates the values for
        // `blk_hdr_is_leading_zero` and `blk_hdr_rlc_acc`
        let block = &public_data.block_context;
        for (field, offset, zeros_bias) in [
            (U256::from(block.number.as_u64()), NUMBER_RLP_OFFSET, 32 - 8),
            (block.gas_limit.into(), GAS_LIMIT_RLP_OFFSET, 0),
            (public_data.gas_used.into(), GAS_USED_RLP_OFFSET, 0),
            (U256::from(block.timestamp), TIMESTAMP_RLP_OFFSET, 0),
            (block.base_fee, BASE_FEE_RLP_OFFSET, 0),
        ]
        .iter()
        {
            // If the field has a short value then there is no RLP header.
            // We need add an artificial RLP header with field length of one (0x80) to align
            // the field.
            // When the field is zero, it is represented by 0x80,
            // which just so happens to be the value of the artificial header we need,
            // thus we skip adding it.
            // The field's value for the circuit will still be zero due to
            // the leading zeros padding filling up the whole field.
            if *field <= U256::from(0x80) {
                if *field != U256::zero() {
                    bytes.insert(offset - 1, 0x80);
                    // Skipping artificial header for RLC. Since we accumulate the next byte in
                    // gates, we denote the skip one row earlier
                    blk_hdr_do_rlc_acc.insert(offset - 2, 0);
                    // Copy the current RLC when skipping
                    blk_hdr_rlc_acc.insert(offset - 1, blk_hdr_rlc_acc[offset - 2]);
                }
                leading_zeros.insert(offset - 1, 0);
            }

            // Pad the field with the required amount of leading zeros
            let num_leading_zeros = ((field.leading_zeros() / 8) - zeros_bias) as usize;
            bytes.splice(offset..offset, vec![0; num_leading_zeros]);
            leading_zeros.splice(offset..offset, vec![1; num_leading_zeros]);
            // Skipping leading zeros for RLC. Since we accumulate the next byte in gates,
            // we denote the skip one row earlier
            blk_hdr_do_rlc_acc.splice(offset - 1..offset - 1, vec![0; num_leading_zeros]);
            // Copy the current RLC when skipping
            blk_hdr_rlc_acc.splice(
                offset..offset,
                vec![blk_hdr_rlc_acc[*offset - 1]; num_leading_zeros],
            );
        }

        // println!("assign: bytes = {:x?}", bytes);
        // println!("assign: blk_hdr_rlc_acc = {:?}", blk_hdr_rlc_acc);
        // println!("assign: blk_hdr_do_rlc_acc = {:?}", blk_hdr_do_rlc_acc);
        // println!("assign: randomness = {:?}", randomness);

        (
            bytes,
            leading_zeros,
            blk_hdr_do_rlc_acc,
            blk_hdr_rlc_acc,
            Value::known(hash_hi),
            Value::known(hash_lo),
        )
    }

        // Assigns all columns relevant to the blockhash checks
        fn assign_block_hash_calc(
            &self,
            region: &mut Region<'_, F>,
            public_data: &PublicData<F>,
            block_number: usize,
            challenges: &Challenges<Value<F>>,
        ) {
            let randomness = challenges.evm_word();
            // Current block is the exception, it sits on offset zero but hash block number
            // = CURRENT_BLOCK_NUM The rest blocks are following, with their block
            // number being one less from their position
            let block_offset = if block_number == CURRENT_BLOCK_NUM {
                0
            } else {
                (block_number + 1) * BLOCKHASH_TOTAL_ROWS
            };

            self.blockhash_cols
                .q_blk_hdr_rlc_start
                .enable(region, block_offset)
                .unwrap();
            self.blockhash_cols
                .q_blk_hdr_rlp_end
                .enable(region, block_offset + BLOCKHASH_TOTAL_ROWS - 1)
                .unwrap();

            region
                .assign_fixed(
                    || "block_table_index",
                    self.blockhash_cols.block_table_index,
                    block_offset + BLOCKHASH_TOTAL_ROWS - 1,
                    || Value::known(F::from(block_number as u64)),
                )
                .unwrap();

            // We use the previous row for the `PreviousHashHi` tag as in this row
            // `WithdrawalRoot` is set too
            region
                .assign_fixed(
                    || "block_table_tag",
                    self.blockhash_cols.block_table_tag,
                    block_offset + BLOCKHASH_TOTAL_ROWS - 2,
                    || Value::known(F::from(BlockContextFieldTag::PreviousHashHi as u64)),
                )
                .unwrap();

            region
                .assign_fixed(
                    || "block_table_index",
                    self.blockhash_cols.block_table_index,
                    block_offset + BLOCKHASH_TOTAL_ROWS - 2,
                    || Value::known(F::from(block_number as u64)),
                )
                .unwrap();

            // We need to push `PreviousHashLo` tag up one row since `PreviousHashHi`
            // uses the current row
            region
                .assign_fixed(
                    || "block_table_tag",
                    self.blockhash_cols.block_table_tag,
                    block_offset + BLOCKHASH_TOTAL_ROWS - 3, // TODO(Geoge): was -3 originally
                    || Value::known(F::from(BlockContextFieldTag::PreviousHashLo as u64)),
                )
                .unwrap();
            if block_number != CURRENT_BLOCK_NUM {
                self.blockhash_cols
                    .q_lookup_blockhash
                    .enable(region, block_offset + BLOCKHASH_TOTAL_ROWS - 1)
                    .unwrap();
            }

            let (
                block_header_rlp_byte,
                leading_zeros,
                blk_hdr_do_rlc_acc,
                blk_hdr_rlc_acc,
                blk_hdr_hash_hi,
                blk_hdr_hash_lo,
            ) = Self::get_block_header_rlp_from_public_data(public_data, challenges.keccak_input());
            // println!("blk_hdr_rlc_acc = {:?}", blk_hdr_rlc_acc);
            // println!("blk_hdr_do_rlc_acc = {:?}", blk_hdr_do_rlc_acc);
            // println!("leading_zeros = {:?}", leading_zeros);

            // Construct all the constant values of the block header.
            // `c()` is for constant values, `v()` is for variable values.
            let c = |value| (true, value);
            let v = || (false, 123456);
            let rlp_const: Vec<(bool, u64)> = [
                vec![c(0xF9), c(0x02), v()], // RLP list header
                vec![c(0xA0)],
                vec![v(); PARENT_HASH_SIZE], // Parent hash
                vec![c(0xA0)],
                (*OMMERS_HASH)
                    .as_bytes()
                    .iter()
                    .map(|b| c(*b as u64))
                    .collect(), // Ommers hash
                vec![c(0x94)],
                vec![v(); BENEFICIARY_SIZE], // Beneficiary
                vec![c(0xA0)],
                vec![v(); STATE_ROOT_SIZE], // State root
                vec![c(0xA0)],
                vec![v(); TX_ROOT_SIZE], // Tx root
                vec![c(0xA0)],
                vec![v(); RECEIPTS_ROOT_SIZE], // Receipt root
                vec![c(0xB9), c(0x01), c(0x00)],
                vec![v(); LOGS_BLOOM_SIZE],    // Bloom filter
                vec![c(0x80)],                 // Difficulty
                vec![v(); 1 + NUMBER_SIZE],    // number
                vec![v(); 1 + GAS_LIMIT_SIZE], // Gas limit
                vec![v(); 1 + GAS_USED_SIZE],  // Gas used
                vec![v(); 1 + TIMESTAMP_SIZE], // Timestamp
                vec![c(0x80)],                 // Extra data
                vec![c(0xA0)],
                vec![v(); MIX_HASH_SIZE], // Mix hash
                vec![c(0x88)],
                vec![v(); NONCE_SIZE],        // Nonce
                vec![v(); 1 + BASE_FEE_SIZE], // Base fee
                vec![c(0xA0)],
                vec![v(); WITHDRAWALS_ROOT_SIZE], // Withdrawals Root
            ]
            .concat();

            println!("block_header_rlp_byte = {:x?}", block_header_rlp_byte);
            for (offset, rlp_byte) in block_header_rlp_byte.iter().enumerate() {
                let absolute_offset = block_offset + offset;
                region
                    .assign_advice(
                        || "blk_hdr_rlp",
                        self.blockhash_cols.blk_hdr_rlp,
                        absolute_offset,
                        || Value::known(F::from(*rlp_byte as u64)),
                    )
                    .unwrap();
                region
                    .assign_advice(
                        || "blk_hdr_rlp_inv",
                        self.blockhash_cols.blk_hdr_rlp_inv,
                        absolute_offset,
                        || Value::known(F::from((*rlp_byte) as u64).invert().unwrap_or(F::ZERO)),
                    )
                    .unwrap();
                region
                    .assign_advice(
                        || "blk_hdr_do_rlc_acc",
                        self.blockhash_cols.blk_hdr_do_rlc_acc,
                        absolute_offset,
                        || Value::known(F::from(blk_hdr_do_rlc_acc[offset] as u64)),
                    )
                    .unwrap();
                region
                    .assign_advice(
                        || "blk_hdr_rlc_acc",
                        self.blockhash_cols.blk_hdr_rlc_acc,
                        absolute_offset,
                        || blk_hdr_rlc_acc[offset],
                    )
                    .unwrap();
                region
                    .assign_advice(
                        || "blk_hdr_is_leading_zero",
                        self.blockhash_cols.blk_hdr_is_leading_zero,
                        absolute_offset,
                        || Value::known(F::from(leading_zeros[offset] as u64)),
                    )
                    .unwrap();

                self.blockhash_cols
                    .q_blk_hdr_rlp
                    .enable(region, absolute_offset)
                    .unwrap();
            }

            // Calculate reconstructed values
            let mut reconstructed_values: Vec<Vec<Value<F>>> = vec![];
            for (index, value) in [
                // parent_hash hi
                public_data.parent_hash.as_fixed_bytes()[0..PARENT_HASH_SIZE / 2].iter(),
                // parent_hash lo
                public_data.parent_hash.as_fixed_bytes()[PARENT_HASH_SIZE / 2..PARENT_HASH_SIZE].iter(),
                public_data.beneficiary.as_fixed_bytes().iter(),
                public_data.state_root.as_fixed_bytes().iter(),
                public_data.transactions_root.as_fixed_bytes().iter(),
                public_data.receipts_root.as_fixed_bytes().iter(),
                public_data
                    .block_context
                    .number
                    .as_u64()
                    .to_be_bytes()
                    .iter(),
                U256::from(public_data.block_context.gas_limit).to_be_bytes().iter(),
                U256::from(public_data.gas_used).to_be_bytes().iter(),
                public_data.block_context.timestamp.to_be_bytes().iter(),
                public_data.mix_hash.as_fixed_bytes().iter(),
                public_data.block_context.base_fee.to_be_bytes().iter(),
                public_data.withdrawals_root.as_fixed_bytes().iter(),
            ]
            .iter()
            .enumerate()
            {
                // reconstructed_values.push(
                //     value
                //         .clone()
                //         .scan(Value::known(F::ZERO), |acc, &x| {
                //             *acc = if index <= 1 {
                //                 let mut acc_shifted = *acc;
                //                 for _ in 0..8 {
                //                     acc_shifted = acc_shifted * Value::known(F::from(2));
                //                 }
                //                 acc_shifted
                //             } else {
                //                 *acc * Value::known(randomness)
                //             } + Value::known(F::from(x as u64));
                //             Some(*acc)
                //         })
                //         .collect::<Vec<Value<F>>>(),
                // );

                reconstructed_values.push(
                    value
                        .clone()
                        .scan(Value::known(F::ZERO), |acc, &x| {
                            *acc = if index <= 1 {
                                let mut acc_shifted = *acc;
                                for _ in 0..8 {
                                    acc_shifted = acc_shifted * Value::known(F::from(2));
                                }
                                acc_shifted
                            } else {
                                *acc * randomness
                            } + Value::known(F::from(x as u64));
                            Some(*acc)
                        })
                        .collect::<Vec<Value<F>>>(),
                );
            }

            for (offset, (v, q)) in rlp_const.iter().enumerate() {
                let absolute_offset = block_offset + offset;
                region
                    .assign_fixed(
                        || "blk_hdr_rlp_const",
                        self.blockhash_cols.blk_hdr_rlp_const,
                        absolute_offset,
                        || Value::known(F::from(*v as u64)),
                    )
                    .unwrap();
                if *q == 1 {
                    self.blockhash_cols
                        .q_blk_hdr_rlp_const
                        .enable(region, absolute_offset)
                        .unwrap();
                }
            }

            let mut length_calc = F::ZERO;
            for (field_num, (name, base_offset, is_reconstruct)) in [
                ("parent_hash hi", PARENT_HASH_RLP_OFFSET, true),
                (
                    "parent_hash lo",
                    PARENT_HASH_RLP_OFFSET + PARENT_HASH_SIZE / 2,
                    true,
                ),
                ("beneficiary", BENEFICIARY_RLP_OFFSET, true),
                ("state_root", STATE_ROOT_RLP_OFFSET, true),
                ("tx_root", TX_ROOT_RLP_OFFSET, true),
                ("receipts_root", RECEIPTS_ROOT_RLP_OFFSET, true),
                ("number", NUMBER_RLP_OFFSET, true),
                ("gas_limit", GAS_LIMIT_RLP_OFFSET, false),
                ("gas_used", GAS_USED_RLP_OFFSET, false),
                ("timestamp", TIMESTAMP_RLP_OFFSET, false),
                ("mix_hash", MIX_HASH_RLP_OFFSET, true),
                ("base_fee_per_gas", BASE_FEE_RLP_OFFSET, false),
                ("withdrawals_root", WITHDRAWALS_ROOT_RLP_OFFSET, true),
            ]
            .iter()
            .enumerate()
            {
                for (offset, val) in reconstructed_values[field_num].iter().enumerate() {
                    let absolute_offset = block_offset + base_offset + offset;
                    let is_parent_hash_hi = *name == "parent_hash hi";
                    let is_parent_hash_lo = *name == "parent_hash lo";
                    let is_parent_hash = is_parent_hash_hi || is_parent_hash_lo;

                    // `q_parent_hash` enables the lookup of parent_hash against the past 256 block
                    // hashes We skip this check for the oldest block as we don't
                    // have its parent block hash to compare it with
                    if block_number != OLDEST_BLOCK_NUM {
                        if is_parent_hash {
                            self.blockhash_cols
                                .q_parent_hash
                                .enable(region, absolute_offset)
                                .unwrap();
                        }
                        if is_parent_hash_hi {
                            region
                                .assign_fixed(
                                    || "parent hash q_hi",
                                    self.blockhash_cols.q_hi,
                                    absolute_offset,
                                    || Value::known(F::ONE),
                                )
                                .unwrap();
                        } else if is_parent_hash_lo {
                            region
                                .assign_fixed(
                                    || "parent hash q_lo",
                                    self.blockhash_cols.q_lo,
                                    absolute_offset,
                                    || Value::known(F::ONE),
                                )
                                .unwrap();
                        }
                    }

                    region
                        .assign_advice(
                            || "reconstruct_value for ".to_string() + name,
                            self.blockhash_cols.blk_hdr_reconstruct_value,
                            absolute_offset,
                            || *val,
                        )
                        .unwrap();
                    // println!("blk_hdr_reconstruct_value[{}] = {:?}", absolute_offset, val);

                    if *is_reconstruct && !(is_parent_hash && block_number == OLDEST_BLOCK_NUM) {
                        region
                            .assign_fixed(
                                || "q_reconstruct for ".to_string() + name,
                                self.blockhash_cols.q_reconstruct,
                                absolute_offset,
                                || Value::known(F::ONE),
                            )
                            .unwrap();
                    }

                    if [
                        GAS_LIMIT_RLP_OFFSET,
                        GAS_USED_RLP_OFFSET,
                        TIMESTAMP_RLP_OFFSET,
                        BASE_FEE_RLP_OFFSET,
                        NUMBER_RLP_OFFSET,
                    ]
                    .contains(base_offset)
                    {
                        let field_size: usize;
                        let field_lead_zeros_num: u32;
                        let gas_limit = &U256::from(public_data.block_context.gas_limit);
                        let gas_used = &U256::from(public_data.gas_used);

                        // println!("public_data = {:?}", public_data);
                        match *base_offset {
                            GAS_LIMIT_RLP_OFFSET => {
                                (field_size, field_lead_zeros_num) = (
                                    GAS_LIMIT_RLP_LEN - 1,
                                    gas_limit.leading_zeros() / 8,
                                )
                            }
                            GAS_USED_RLP_OFFSET => {
                                (field_size, field_lead_zeros_num) = (GAS_USED_RLP_LEN - 1, gas_used.leading_zeros() / 8)
                            }
                            TIMESTAMP_RLP_OFFSET => {
                                (field_size, field_lead_zeros_num) = (
                                    TIMESTAMP_RLP_LEN - 1,
                                    &public_data.block_context.timestamp.leading_zeros() / 8,
                                )
                            }
                            BASE_FEE_RLP_OFFSET => {
                                (field_size, field_lead_zeros_num) =
                                    (BASE_FEE_RLP_LEN - 1, &public_data.block_context.base_fee.leading_zeros() / 8)
                            }
                            _ => {
                                (field_size, field_lead_zeros_num) =
                                    (NUMBER_RLP_LEN - 1, &public_data.block_context.number.as_u64().leading_zeros() / 8)
                            }
                        }

                        if (offset < field_lead_zeros_num as usize)
                            || // short RLP values have 0 length
                                (offset == field_size - 1
                                && length_calc == F::ZERO
                                && block_header_rlp_byte[base_offset + offset] <= 0x80)
                        {
                            length_calc = F::ZERO;
                        } else {
                            length_calc = F::from(offset as u64 - field_lead_zeros_num as u64 + 1);
                        }

                        region
                            .assign_advice(
                                || "length of ".to_string() + name,
                                self.blockhash_cols.blk_hdr_rlp_len_calc,
                                absolute_offset,
                                || Value::known(length_calc),
                            )
                            .unwrap();
                        // println!("length[{}] = {:?}", absolute_offset, length_calc);
                        region
                            .assign_advice(
                                || "inverse length of ".to_string() + name,
                                self.blockhash_cols.blk_hdr_rlp_len_calc_inv,
                                absolute_offset,
                                || Value::known(length_calc.invert().unwrap_or(F::ZERO)),
                            )
                            .unwrap();

                        let selector = if *base_offset == NUMBER_RLP_OFFSET {
                            // println!("q_number[{}] = 1", absolute_offset);
                            self.blockhash_cols.q_number
                        } else {
                            // println!("q_var_field_256[{}] = 1", absolute_offset);
                            self.blockhash_cols.q_var_field_256
                        };
                        region
                            .assign_fixed(
                                || "q_number and q_var_field_256",
                                selector,
                                absolute_offset,
                                || Value::known(F::ONE),
                            )
                            .unwrap();
                    }
                }
            }

            // Set the block table tags for fields with only one index
            for (offset, tag) in [
                (
                    PARENT_HASH_RLP_OFFSET + PARENT_HASH_SIZE / 2,
                    BlockContextFieldTag::PreviousHashHi,
                ),
                (
                    PARENT_HASH_RLP_OFFSET + PARENT_HASH_SIZE,
                    BlockContextFieldTag::PreviousHashLo,
                ),
                (
                    BENEFICIARY_RLP_OFFSET + BENEFICIARY_SIZE,
                    BlockContextFieldTag::Beneficiary,
                ),
                (
                    STATE_ROOT_RLP_OFFSET + STATE_ROOT_SIZE,
                    BlockContextFieldTag::StateRoot,
                ),
                (
                    TX_ROOT_RLP_OFFSET + TX_ROOT_SIZE,
                    BlockContextFieldTag::TransactionsRoot,
                ),
                (
                    RECEIPTS_ROOT_RLP_OFFSET + RECEIPTS_ROOT_SIZE,
                    BlockContextFieldTag::ReceiptsRoot,
                ),
                (
                    NUMBER_RLP_OFFSET + NUMBER_SIZE,
                    BlockContextFieldTag::Number,
                ),
                (
                    GAS_LIMIT_RLP_OFFSET + GAS_LIMIT_SIZE,
                    BlockContextFieldTag::GasLimit,
                ),
                (
                    GAS_USED_RLP_OFFSET + GAS_USED_SIZE,
                    BlockContextFieldTag::GasUsed,
                ),
                (
                    TIMESTAMP_RLP_OFFSET + TIMESTAMP_SIZE,
                    BlockContextFieldTag::Timestamp,
                ),
                (
                    MIX_HASH_RLP_OFFSET + MIX_HASH_SIZE,
                    BlockContextFieldTag::MixHash,
                ),
                (
                    BASE_FEE_RLP_OFFSET + BASE_FEE_SIZE,
                    BlockContextFieldTag::BaseFee,
                ),
                (
                    WITHDRAWALS_ROOT_RLP_OFFSET + WITHDRAWALS_ROOT_SIZE,
                    BlockContextFieldTag::WithdrawalsRoot,
                ),
            ]
            .iter()
            {
                let absolute_offset = block_offset + offset - 1;
                region
                    .assign_fixed(
                        || "block_table_tag",
                        self.blockhash_cols.block_table_tag,
                        absolute_offset,
                        || Value::known(F::from(*tag as u64)),
                    )
                    .unwrap();
                println!("block_table_tag[{}] = {:?}", absolute_offset, tag);

                // let idx2 = if (block_number == CURRENT_BLOCK_NUM) && (*tag == BlockContextFieldTag::PreviousHashLo) {
                //     255
                // } else {
                //     block_number
                // };
                region
                    .assign_fixed(
                        || "block_table_index",
                        self.blockhash_cols.block_table_index,
                        absolute_offset,
                        || Value::known(F::from(block_number as u64)),
                        // || Value::known(F::from((idx2) as u64)),
                    )
                    .unwrap();
                // println!("block_table_index[{}] = {:?}", absolute_offset, idx2);
                println!("block_table_index[{}] = {:?}", absolute_offset, block_number);
            }

            // Determines if it is a short RLP value
            let lt_chip = LtChip::construct(self.rlp_is_short);
            for (offset, &byte) in block_header_rlp_byte.iter().enumerate() {
                lt_chip
                    .assign(
                        region,
                        block_offset + offset,
                        F::from(byte as u64),
                        F::from(RLP_HDR_NOT_SHORT),
                    )
                    .unwrap();
            }


            // Set the block header hash parts
            region
                .assign_advice(
                    || "blk_hdr_hash_hi",
                    self.blockhash_cols.blk_hdr_blockhash,
                    block_offset + BLOCKHASH_TOTAL_ROWS - 1,
                    || blk_hdr_hash_hi,
                )
                .unwrap();
            region
                .assign_advice(
                    || "blk_hdr_hash_lo",
                    self.blockhash_cols.blk_hdr_blockhash,
                    block_offset + BLOCKHASH_TOTAL_ROWS - 2,
                    || blk_hdr_hash_lo,
                )
                .unwrap();

        }

    // TODO(George): migrate this to block_table.rs
    #[allow(clippy::type_complexity)]
    fn assign_block_table(
        &self,
        region: &mut Region<'_, F>,
        public_data: &PublicData<F>,
        block_number: usize,
        test_public_data: &Option<PublicData<F>>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<AssignedCell<F, F>, Error> {
        // When in negative testing, we need to bypass the actual public_data with some
        // wrong test data
        let pb = test_public_data.as_ref().unwrap_or(public_data);
        let block_values = pb.get_block_table_values();
        let randomness = challenges.evm_word();
        self.q_start.enable(region, 0)?;

        let base_offset = if block_number == CURRENT_BLOCK_NUM {
            0
        } else {
            BLOCK_LEN_IN_TABLE * (block_number + 1) + BLOCK_TABLE_MISC_LEN
        };

        let mut block_data: Vec<(&str, BlockContextFieldTag, usize, Value<F>, bool)> = vec![
            (
                "coinbase",
                BlockContextFieldTag::Coinbase,
                block_number,
                Value::known(
                    block_values.coinbase.to_scalar().unwrap()
                )
                ,
                false,
            ),
            (
                "timestamp",
                BlockContextFieldTag::Timestamp,
                block_number,
                Value::known(F::from(block_values.timestamp)),
                false,
            ),
            (
                "number",
                BlockContextFieldTag::Number,
                block_number,
                randomness.map(|randomness|
                    rlc(
                        [0; 32 - NUMBER_SIZE]
                            .into_iter()
                            .chain(block_values.number.to_be_bytes().into_iter())
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness,)
                    ),
                false,
            ),
            (
                "difficulty",
                BlockContextFieldTag::Difficulty,
                block_number,
                randomness.map(|randomness| rlc(block_values.difficulty.to_le_bytes(), randomness)),
                false,
            ),
            (
                "gas_limit",
                BlockContextFieldTag::GasLimit,
                block_number,
                Value::known(
                    F::from(block_values.gas_limit)
                )
                ,
                false,
            ),
            (
                "base_fee",
                BlockContextFieldTag::BaseFee,
                block_number,
                randomness.map(|randomness| rlc(block_values.base_fee.to_le_bytes(), randomness)),
                false,
            ),
            // TODO(George)
            /*
            (
                "blockhash",
                BlockContextFieldTag::BlockHash,
                block_number,
                randomness.map(|randomness| rlc(pb.block_context.base_fee.to_le_bytes().into_iter()
                .rev()
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(), randomness)),
                false,
            ),
             */
            (
                "chain_id",
                BlockContextFieldTag::ChainId,
                block_number,
                Value::known(
                    F::from(block_values.chain_id)
                )
                ,
                false,
            ),
            (
                "beneficiary",
                BlockContextFieldTag::Beneficiary,
                block_number,
                randomness.map(|randomness|
                    rlc(([0u8; 32 - BENEFICIARY_SIZE]
                            .into_iter()
                            .chain(pb.beneficiary.to_fixed_bytes().into_iter()))
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                    randomness)),
                false,
            ),
            (
                "state_root",
                BlockContextFieldTag::StateRoot,
                block_number,
                randomness.map(|randomness|
                    rlc(
                        pb.state_root
                            .to_fixed_bytes()
                            .into_iter()
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness)
                    ),
                false,
            ),
            (
                "transactions_root",
                BlockContextFieldTag::TransactionsRoot,
                block_number,
                randomness.map(|randomness|
                    rlc(
                        pb.transactions_root
                            .to_fixed_bytes()
                            .into_iter()
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness,)
                    ),
                false,
            ),
            (
                "receipts_root",
                BlockContextFieldTag::ReceiptsRoot,
                block_number,
                randomness.map(|randomness|
                    rlc(
                        pb.receipts_root
                            .to_fixed_bytes()
                            .into_iter()
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness,)
                    ),
                false,
            ),
            (
                "gas_used",
                BlockContextFieldTag::GasUsed,
                block_number,
                Value::known(
                    F::from(pb.gas_used as u64),
                ),
                false,
            ),
            (
                "mix_hash",
                BlockContextFieldTag::MixHash,
                block_number,
                randomness.map(|randomness|
                    rlc(
                        pb.mix_hash
                            .to_fixed_bytes()
                            .into_iter()
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness,)
                    ),
                false,
            ),
            (
                "withdrawals_root",
                BlockContextFieldTag::WithdrawalsRoot,
                block_number,
                randomness.map(|randomness|
                    rlc(
                        pb.withdrawals_root
                            .to_fixed_bytes()
                            .into_iter()
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness,)
                    ),
                false,
            ),
        ];

        // println!("history_hashes = {:x?}", block_values.history_hashes);

        // The following need to be added only once in block table
        if block_number == CURRENT_BLOCK_NUM {
            block_data.extend_from_slice(
                block_values
                    .history_hashes
                    .iter()
                    .enumerate()
                    .map(|(i, h)| {
                        (
                            "prev_hash",
                            BlockContextFieldTag::PreviousHash,
                            i,
                            randomness.map(|randomness| rlc(h.to_le_bytes(), randomness),),
                            false,
                        )
                    })
                    .collect_vec()
                    .as_slice(),
            );
            block_data.extend_from_slice(
                block_values
                    .history_hashes
                    .iter()
                    .enumerate()
                    .map(|(i, h)| {
                        (
                            "prev_hash hi",
                            BlockContextFieldTag::PreviousHashHi,
                            i,
                            Value::known(
                                h.to_be_bytes()
                                    .iter()
                                    .take(16)
                                    .fold(F::ZERO, |acc, byte| {
                                        acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
                                    }),
                            ),
                            false,
                        )
                    })
                    .collect_vec()
                    .as_slice(),
            );
            block_data.extend_from_slice(
                block_values
                    .history_hashes
                    .iter()
                    .enumerate()
                    .map(|(i, h)| {
                        (
                            "prev_hash lo",
                            BlockContextFieldTag::PreviousHashLo,
                            i,
                            Value::known(
                                h.to_be_bytes()
                                    .iter()
                                    .skip(16)
                                    .fold(F::ZERO, |acc, byte| {
                                        acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
                                    }),
                            ),
                            false,
                        )
                    })
                    .collect_vec()
                    .as_slice(),
            );
            block_data.extend_from_slice(&[
                (
                    "zero",
                    BlockContextFieldTag::None,
                    0,
                    Value::known(
                        F::ZERO
                    )
                    ,
                    false,
                ),
            ]);
        }

        // let mut cells = vec![];
        // Continue computing RLC from where we left off
        // let mut rlc_acc = prev_rlc_acc;

        println!("BLOCK TABLE");
        // let mut cell;
        let mut chain_id_cell = vec![];
        for (offset, (name, tag, idx, val, not_in_table)) in block_data.into_iter().enumerate() {
            let absolute_offset = base_offset + offset;
            // if absolute_offset < TOTAL_BLOCK_TABLE_LEN - 1 {
            //     self.q_not_end.enable(region, absolute_offset)?;
            // }
            // let val_cell = region.assign_advice(|| name, self.raw_public_inputs, absolute_offset, || Value::known(val))?;
            // rlc_acc = rlc_acc * randomness + val;
            // region.assign_advice(|| name, self.rpi_rlc_acc, absolute_offset, || rlc_acc)?;
            // raw_pi_vals[absolute_offset] = val;
            if not_in_table {
                // cells.push(val_cell);
            } else {
                self.q_block_table.enable(region, absolute_offset)?;
                region.assign_advice(
                    || name,
                    self.block_table.tag,
                    absolute_offset,
                    || Value::known(F::from(tag as u64)),
                )?;
                region.assign_advice(
                    || name,
                    self.block_table.index,
                    absolute_offset,
                    || Value::known(F::from(idx as u64)),
                )?;

                println!("block table name [{}] = {}", absolute_offset, name);
                println!("block table tag  [{}] = {:?}", absolute_offset, tag);
                println!("block table index[{}] = {}", absolute_offset, idx);
                println!("block table value[{}] = {:?}", absolute_offset, val);

                let cell = region.assign_advice(|| name, self.block_table.value, absolute_offset, || val)?;
                if name == "chain_id" {
                    chain_id_cell.push(cell);
                }
            }
        }

        // let txs_hash_hi;
        // let txs_hash_lo;

        // if cells.is_empty() {
        //     txs_hash_hi = None;
        //     txs_hash_lo = None;
        // } else {
        //     txs_hash_hi = Some(cells[1].clone());
        //     txs_hash_lo = Some(cells[2].clone());
        // };

        // Ok((txs_hash_hi, txs_hash_lo, rlc_acc))
        Ok(chain_id_cell.pop().unwrap())
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        public_data: &PublicData<F>,
        test_public_data: &Option<PublicData<F>>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let lt_chip: LtChip<F, 1> = LtChip::construct(self.rlp_is_short);
        lt_chip.load(layouter)?;

        let pi = layouter.assign_region(
            || "region 0",
            |ref mut region| {
                // Annotate columns
                self.block_table.annotate_columns_in_region(region);
                self.rlp_is_short.annotate_columns_in_region(region);
                region.name_column(|| "rpi_field_bytes", self.rpi_field_bytes);
                region.name_column(|| "rpi_field_bytes_acc", self.rpi_field_bytes_acc);
                region.name_column(|| "is_field_rlc", self.is_field_rlc);
                region.name_column(|| "block_index", self.block_index);
                region.name_column(|| "blockhash_cols.blk_hdr_rlp_len_calc", self.blockhash_cols.blk_hdr_rlp_len_calc);
                region.name_column(|| "blockhash_cols.blk_hdr_rlp_len_calc_inv", self.blockhash_cols.blk_hdr_rlp_len_calc_inv);
                region.name_column(|| "blockhash_cols.blk_hdr_reconstruct_value", self.blockhash_cols.blk_hdr_reconstruct_value);
                region.name_column(|| "blockhash_cols.blk_hdr_reconstruct_hi_lo", self.blockhash_cols.blk_hdr_reconstruct_hi_lo);
                region.name_column(|| "blockhash_cols.blk_hdr_rlc_acc", self.blockhash_cols.blk_hdr_rlc_acc);
                region.name_column(|| "blockhash_cols.blk_hdr_do_rlc_acc", self.blockhash_cols.blk_hdr_do_rlc_acc);
                region.name_column(|| "blockhash_cols.blk_hdr_is_leading_zero", self.blockhash_cols.blk_hdr_is_leading_zero);
                region.name_column(|| "rpi_rlc_acc", self.rpi_rlc_acc);
                region.name_column(|| "Public_Inputs", self.pi);
                region.name_column(|| "fixed_u8", self.fixed_u8);

                // Assign current block
                println!("assigning block #{} (CURRENT_BLOCK_NUM)", CURRENT_BLOCK_NUM);
                self.assign_block_hash_calc(
                    region,
                    public_data,
                    CURRENT_BLOCK_NUM,
                    challenges,
                );
                self.assign_block_table(
                    region,
                    public_data,
                    CURRENT_BLOCK_NUM,
                    test_public_data,
                    challenges,
                )?;

                for (block_number, prev_block) in public_data.previous_blocks
                    [0..PREVIOUS_BLOCKS_NUM]
                    .iter()
                    .enumerate()
                {
                    println!("assigning block #{}", block_number);
                    let prev_public_data =
                        PublicData::new(prev_block);
                    self.assign_block_hash_calc(
                        region,
                        &prev_public_data,
                        block_number,
                        challenges,
                    );
                    self.assign_block_table(
                        region,
                        public_data,
                        block_number,
                        test_public_data,
                        challenges,
                    )?;
                }

                let mut rpi_rlc_acc = Value::known(F::ZERO);
                let mut offset = 0;
                let mut rpi_rlc_acc_cell = None;
                for (annotation, block_number, field_bytes) in public_data.assignments() {
                    let cells = self.assign_pi_field(
                        region,
                        &mut offset,
                        annotation,
                        &field_bytes,
                        &mut rpi_rlc_acc,
                        challenges,
                        false, // TODO(George): keccak_hi_lo option
                        block_number,
                    )?;
                    rpi_rlc_acc_cell = Some(cells[RPI_RLC_ACC_CELL_IDX].clone());
                }

                // input_rlc in self.rpi_field_bytes_acc
                // input_len in self.rpi_len_acc
                // output_rlc in self.rpi_rlc_acc
                let keccak_row = offset;
                let rpi_rlc_acc_cell = rpi_rlc_acc_cell.unwrap();
                rpi_rlc_acc_cell.copy_advice(
                    || "keccak(rpi)_input",
                    region,
                    self.rpi_field_bytes_acc,
                    keccak_row,
                )?;
                let keccak = public_data.get_pi();
                let mut keccak_input = keccak.to_fixed_bytes();
                keccak_input.reverse();
                let keccak_rlc = challenges
                    .evm_word()
                    .map(|randomness| rlc(keccak_input, randomness));
                let keccak_output_cell = region.assign_advice(
                    || "keccak(rpi)_output",
                    self.rpi_rlc_acc,
                    keccak_row,
                    || keccak_rlc,
                )?;
                self.q_keccak.enable(region, keccak_row)?;

                rpi_rlc_acc = Value::known(F::ZERO);
                offset += 1;
                let mut pi = Vec::with_capacity(2);

                for (idx, (annotation, field_bytes)) in [
                    (
                        "high_16_bytes_of_keccak_rpi",
                        &keccak.to_fixed_bytes()[..16],
                    ),
                    ("low_16_bytes_of_keccak_rpi", &keccak.to_fixed_bytes()[16..]),
                ]
                .into_iter()
                .enumerate()
                {
                    let cells = self.assign_pi_field(
                        region,
                        &mut offset,
                        annotation,
                        field_bytes,
                        &mut rpi_rlc_acc,
                        challenges,
                        true,
                        None,
                    )?;
                    pi.push(cells[RPI_CELL_IDX].clone());
                    if idx == 1 {
                        region.constrain_equal(
                            keccak_output_cell.cell(),
                            cells[RPI_RLC_ACC_CELL_IDX].cell(),
                        )?;
                    }
                }

                Ok(pi)
            },
        )?;
        for (idx, cell) in pi.into_iter().enumerate() {
            layouter.constrain_instance(cell.cell(), self.pi, idx)?;
        }
        Ok(())
    }
}

/// Public Inputs Circuit
#[derive(Clone, Default, Debug)]
pub struct TaikoPiCircuit<F: Field> {
    /// PublicInputs data known by the verifier
    pub public_data: PublicData<F>,
    ///Test public data
    pub test_public_data: Option<PublicData<F>>,
    _marker: PhantomData<F>,
}

impl<F: Field> TaikoPiCircuit<F> {
    /// Creates a new TaikoPiCircuit
    pub fn new(public_data: PublicData<F>, test_public_data: Option<PublicData<F>>) -> Self {
        Self {
            public_data,
            test_public_data,
            _marker: PhantomData,
        }
    }

    fn split_hash(hash: [u8; 32]) -> (F, F) {
        let hi = hash.iter().take(16).fold(F::ZERO, |acc, byte| {
            acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
        });

        let lo = hash.iter().skip(16).fold(F::ZERO, |acc, byte| {
            acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
        });
        (hi, lo)
    }

    fn get_block_header_rlp_from_block(block: &witness::Block<F>) -> (Bytes, F, F, H256) {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream
            .append(&block.eth_block.parent_hash)
            .append(&*OMMERS_HASH)
            .append(&block.eth_block.author.unwrap_or_else(H160::zero))
            .append(&block.eth_block.state_root)
            .append(&block.eth_block.transactions_root)
            .append(&block.eth_block.receipts_root)
            .append(&vec![0u8; LOGS_BLOOM_SIZE]) // logs_bloom is all zeros
            .append(&block.context.difficulty)
            .append(&block.context.number.low_u64())
            // .append(&block.context.gas_limit)
            .append(&U256::from(block.context.gas_limit))
            .append(&U256::from(block.protocol_instance.gas_used))
            .append(&block.context.timestamp);
        rlp_opt(&mut stream, &None::<u8>); // extra_data = ""
        stream
            .append(&block.eth_block.mix_hash.unwrap_or_else(H256::zero))
            .append(&vec![0u8; NONCE_SIZE]) // nonce = 0
            .append(&block.context.base_fee)
            .append(&block.eth_block.withdrawals_root.unwrap_or_else(H256::zero));

        stream.finalize_unbounded_list();
        let out: bytes::Bytes = stream.out().into();
        let rlp_bytes: Bytes = out.into();
        let hash = keccak256(&rlp_bytes);
        // let (hi, lo) = Self::split_hash(hash);
        let (hi, lo) = Self::split_hash(hash);
        let hash_res = H256::from(hash);
        (rlp_bytes, hi, lo, hash_res)
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

    /// TODO(George)
    // fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
    //     let row_num = |tx_num, calldata_len| {
    //         TOTAL_BLOCK_TABLE_LEN + EXTRA_LEN + 3 * (TX_LEN * tx_num + 1) + calldata_len
    //     };
    //     let calldata_len = block.txs.iter().map(|tx| tx.call_data.len()).sum();
    //     (
    //         row_num(block.txs.len(), calldata_len),
    //         row_num(
    //             block.circuits_params.max_txs,
    //             block.circuits_params.max_calldata,
    //         ),
    //     )
    // }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        TaikoPiCircuit::new(PublicData::new(block), None)
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        let keccak_rpi = self.public_data.get_pi();
        let keccak_hi = keccak_rpi
            .to_fixed_bytes()
            .iter()
            .take(16)
            .fold(F::ZERO, |acc, byte| {
                acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
            });

        let keccak_lo = keccak_rpi
            .to_fixed_bytes()
            .iter()
            .skip(16)
            .fold(F::ZERO, |acc, byte| {
                acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
            });

        let public_inputs = vec![keccak_hi, keccak_lo];
        vec![public_inputs]
    }

    /// Make the assignments to the PiCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed u8 table",
            |mut region| {
                for i in 0..(1 << 8) {
                    region.assign_fixed(
                        || format!("row_{}", i),
                        config.fixed_u8,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }

                Ok(())
            },
        )?;

        config.byte_table.load(layouter)?;
        config.assign(layouter, &self.public_data, &self.test_public_data, challenges)
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
        let block_table_blockhash = BlockTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta); // TODO(George): merge keccak tables
        let keccak_table2 = KeccakTable2::construct(meta);
        let byte_table = ByteTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            TaikoPiCircuitConfig::new(
                meta,
                TaikoPiCircuitConfigArgs {
                    block_table,
                    block_table_blockhash,
                    keccak_table,
                    keccak_table2,
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
        // assign keccak table
        config
            .keccak_table
            .dev_load(&mut layouter, vec![&public_data.rpi_bytes()], &challenges)?;
        config.byte_table.load(&mut layouter)?;

        // println!("public_data.blockhash_blk_hdr_rlp = {:x?}", public_data.blockhash_blk_hdr_rlp);
        let pr_bl:Vec<Vec<u8>> = public_data.previous_blocks_rlp.iter().map(|a| a.to_vec()).collect();
        let cur_bl = public_data.blockhash_blk_hdr_rlp.to_vec();
        let all = pr_bl.iter().chain(vec![&cur_bl]);
        println!("all block rlp = {:?}", all);
        config.keccak_table2.dev_load(
            &mut layouter,
            all,
            &challenges,
        )?;

        self.0.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

#[cfg(test)]
mod taiko_pi_circuit_test {

    use super::*;

    use eth_types::{ToScalar, H64, U64};
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
        public_data: PublicData<F>,
        pi: Option<Vec<Vec<F>>>,
        test_public_data: Option<PublicData<F>>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = TaikoPiTestCircuit::<F>(TaikoPiCircuit::new(public_data, test_public_data));
        let public_inputs = pi.unwrap_or_else(|| circuit.0.instance());

        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        // prover.verify()
        let res: Result<(), Vec<VerifyFailure>> = prover.verify();
        let mut curated_res = Vec::new();
        if res.is_err() {
            let errors = res.as_ref().err().unwrap();
            for error in errors.iter() {
                match error {
                    VerifyFailure::CellNotAssigned { .. } => (),
                    _ => curated_res.push(<&halo2_proofs::dev::VerifyFailure>::clone(&error)),
                };
            }
            if !curated_res.is_empty() {
                return res;
            }
        }
        Ok(())
    }

    fn mock_public_data<F: Field>() -> PublicData<F> {
        let mut public_data = PublicData::default();
        public_data.meta_hash = OMMERS_HASH.to_word();
        public_data.block_hash = *OMMERS_HASH;
        public_data.block_context.block_hash = OMMERS_HASH.to_word();
        public_data.block_context.history_hashes = vec![Default::default(); 256];
        public_data.block_context.number = 300.into();
        public_data
    }

    #[test]
    fn test_default_pi() {
        let public_data = mock_public_data();

        let k = 17;
        assert_eq!(run::<Fr>(k, public_data, None, None), Ok(()));
    }

    #[test]
    fn test_fail_pi_hash() {
        let public_data = mock_public_data();

        let k = 17;
        match run::<Fr>(k, public_data, Some(vec![vec![Fr::zero(), Fr::one()]]), None) {
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
            None,
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
        assert_eq!(run::<Fr>(k, public_data, None, None), Ok(()));
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

        let public_data = PublicData::new(&block);

        let k = 17;

        assert_eq!(run::<Fr>(k, public_data, None, None), Ok(()));
    }

    fn get_block_header_rlp_from_block(block: &witness::Block<Fr>) -> (H256, Bytes) {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream
            .append(&block.eth_block.parent_hash)
            .append(&*OMMERS_HASH)
            .append(&block.eth_block.author.unwrap_or_else(H160::zero))
            .append(&block.eth_block.state_root)
            .append(&block.eth_block.transactions_root)
            .append(&block.eth_block.receipts_root)
            .append(&vec![0u8; LOGS_BLOOM_SIZE]) // logs_bloom is all zeros
            .append(&block.context.difficulty)
            .append(&block.context.number.low_u64())
            .append(&block.context.gas_limit)
            // .append(&U256::from(block.context.gas_limit))
            .append(&U256::from(block.protocol_instance.gas_used))
            .append(&block.context.timestamp);
        rlp_opt(&mut stream, &None::<u8>); // extra_data = ""
        stream
            .append(&block.eth_block.mix_hash.unwrap_or_else(H256::zero))
            .append(&vec![0u8; NONCE_SIZE]) // nonce = 0
            .append(&block.context.base_fee)
            .append(&block.eth_block.withdrawals_root.unwrap_or_else(H256::zero));

        stream.finalize_unbounded_list();
        let out: bytes::Bytes = stream.out().into();
        let rlp_bytes: Bytes = out.into();
        let hash = keccak256(&rlp_bytes);
        (hash.into(), rlp_bytes)
    }

    fn default_test_block() -> (
        witness::Block<Fr>,
        Address,
        Vec<witness::Block<Fr>>,
        Vec<Bytes>,
    ) {
        let mut current_block = witness::Block::<Fr>::default();

        const PREVIOUS_BLOCKS_NUM:usize = 256; // TODO(George): remove shadow var
        current_block.context.history_hashes = vec![U256::zero(); PREVIOUS_BLOCKS_NUM];
        let mut previous_blocks: Vec<witness::Block<Fr>> =
            vec![witness::Block::<Fr>::default(); PREVIOUS_BLOCKS_NUM];
        let mut previous_blocks_rlp: Vec<Bytes> = vec![Bytes::default(); PREVIOUS_BLOCKS_NUM];
        let mut past_block_hash = H256::zero();
        let mut past_block_rlp: Bytes;
        for i in 0..256 { // TODO(George): replace 256 with `PREVIOUS_BLOCKS_NUM`
            let mut past_block = witness::Block::<Fr>::default();
            past_block.eth_block.parent_hash = past_block_hash;
            (past_block_hash, past_block_rlp) = get_block_header_rlp_from_block(&past_block);

            current_block.context.history_hashes[i] = U256::from(past_block_hash.as_bytes());
            previous_blocks[i] = past_block.clone();
            previous_blocks[i].context.number = U256::from(0x100);
            previous_blocks_rlp[i] = past_block_rlp.clone();
            // println!("past_block_hash[{}] = {:x?}", i, past_block_hash);
        }

        let prover = current_block.protocol_instance.prover;
        // Populate current block
        current_block.eth_block.parent_hash = past_block_hash;
        current_block.protocol_instance.parent_hash = past_block_hash;
        current_block.eth_block.author = Some(prover); //Some(prover);
        current_block.eth_block.state_root = H256::zero();
        current_block.eth_block.transactions_root = H256::zero();
        current_block.eth_block.receipts_root = H256::zero();
        current_block.eth_block.logs_bloom = Some([0; LOGS_BLOOM_SIZE].into());
        current_block.eth_block.difficulty = U256::from(0);
        current_block.eth_block.number = Some(U64::from(0));
        current_block.eth_block.gas_limit = U256::from(0);
        current_block.eth_block.gas_used = U256::from(0);
        current_block.protocol_instance.gas_used = 0;
        current_block.eth_block.timestamp = U256::from(0);
        current_block.context.timestamp = U256::from(0);
        current_block.eth_block.extra_data = eth_types::Bytes::from([0; 0]);
        current_block.eth_block.mix_hash = Some(H256::zero());
        current_block.eth_block.nonce = Some(H64::from([0, 0, 0, 0, 0, 0, 0, 0]));
        current_block.eth_block.base_fee_per_gas = Some(U256::from(0));
        current_block.eth_block.withdrawals_root = Some(H256::zero());

        (current_block, prover, previous_blocks, previous_blocks_rlp)
    }

    #[test]
    fn test_blockhash_verify() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        let mut public_data = PublicData::new(&block);
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr>(k, public_data, None, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_short_values() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(0x100);
        block.context.gas_limit = 0x76;
        block.protocol_instance.gas_used = 0x77; //U256::from(0x77);
        block.context.timestamp = U256::from(0x78);
        block.context.base_fee = U256::from(0x79);

        let mut public_data = PublicData::new(&block);
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr>(k, public_data, None, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_one_byte_non_short_values() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(0x100);
        block.context.gas_limit = RLP_HDR_NOT_SHORT;
        block.protocol_instance.gas_used = RLP_HDR_NOT_SHORT as u32; //U256::from(RLP_HDR_NOT_SHORT);
        block.context.timestamp = U256::from(RLP_HDR_NOT_SHORT);
        block.context.base_fee = U256::from(RLP_HDR_NOT_SHORT);

        let mut public_data = PublicData::new(&block);
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr>(k, public_data, None, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_one_byte_non_short_values_2() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(0x100);
        block.context.gas_limit = 0xFF;
        block.protocol_instance.gas_used = 0xff; //U256::from(0xFF);
        block.context.timestamp = U256::from(0xFF);
        block.context.base_fee = U256::from(0xFF);

        let mut public_data = PublicData::new(&block);
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr>(k, public_data, None, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_leading_zeros() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(0x0090909090909090_u128);
        block.context.gas_limit = 0x0000919191919191;
        block.protocol_instance.gas_used = 0x92 << 2*8; //U256::from(0x92) << (28 * 8);
        block.context.timestamp = U256::from(0x93) << (7 * 8);
        block.context.base_fee = U256::from(0x94) << (26 * 8);

        let mut public_data = PublicData::new(&block);
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr>(k, public_data, None, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_max_lengths() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();

        block.context.number = U256::from(0x9090909090909090_u128);
        block.context.gas_limit = 0x9191919191919191;
        block.protocol_instance.gas_used = 0x92;// << (31 * 8);
        block.context.timestamp = U256::from(0x93);// << (31 * 8);
        block.context.base_fee = U256::from(0x94) << (31 * 8);

        let mut public_data = PublicData::new(&block);
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr>(k, public_data, None, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_fail_lookups() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();

        block.eth_block.state_root = H256::from_slice(
            &hex::decode("21223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49349")
                .unwrap(),
        );
        block.eth_block.transactions_root = H256::from_slice(
            &hex::decode("31223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49350")
                .unwrap(),
        );
        block.eth_block.receipts_root = H256::from_slice(
            &hex::decode("41223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49351")
                .unwrap(),
        );
        block.eth_block.logs_bloom = Some([0; LOGS_BLOOM_SIZE].into());
        block.eth_block.extra_data = eth_types::Bytes::from([0; 0]);
        block.eth_block.mix_hash = Some(H256::from_slice(
            &hex::decode("51223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49352")
                .unwrap(),
        ));
        block.context.number = U256::from(0x9090909090909090_u128);
        block.context.gas_limit = 0x9191919191919191;
        block.protocol_instance.gas_used = 0x92 << (3 * 8);
        block.context.timestamp = U256::from(0x93) << (31 * 8);
        block.context.base_fee = U256::from(0x94) << (31 * 8);
        block.eth_block.withdrawals_root = Some(H256::from_slice(
            &hex::decode("61223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49353")
                .unwrap(),
        ));

        let mut public_data = PublicData::new(&block);
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        let (mut test_block, _, test_previous_blocks, previous_blocks_rlp) = default_test_block();
        test_block.context.number = U256::from(0x100);
        let test_public_data = PublicData::new(&test_block);
        public_data.previous_blocks = test_previous_blocks;

        match run::<Fr>(k, public_data, None, Some(test_public_data)) {
            Ok(_) => unreachable!("this case must fail"),
            Err(errs) => {
                //assert_eq!(errs.len(), 14);
                for err in errs {
                    match err {
                        VerifyFailure::Lookup { .. } => return,
                        VerifyFailure::CellNotAssigned { .. } => return,
                        _ => unreachable!("unexpected error"),
                    }
                }
            }
        }
    }
}
