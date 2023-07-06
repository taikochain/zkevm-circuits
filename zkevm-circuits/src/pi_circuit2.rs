//! Use the hash value as public input.
//!
//! We will use three lookup tables to implement the circuit.
//! 1. rlp_table: txs -> rlp
//! 2. compress_table: rlp -> compress
//! 3. hash_table: compress -> hash
//!
//! The dataflow:
//! ```
//! +----------+         +-----------+       +------------+
//! |   txs    +---------> compress? +------->   hash     |
//! |          |         |           |       |            |
//! +----------+         +-----------+       +------------+
//! ```

use crate::evm_circuit::util::constraint_builder::BaseConstraintBuilder;
use eth_types::{geth_types::BlockConstants, H160, H256};
use eth_types::{
    geth_types::Transaction, Address, BigEndianHash, Field, ToBigEndian, ToLittleEndian, ToScalar,
    Word,
};
use eth_types::{sign_types::SignData, Bytes};
use ethers_core::types::U256;
use ethers_core::utils::keccak256;
use halo2_proofs::plonk::{Expression, Instance};
use itertools::Itertools;
use rlp::{Rlp, RlpStream};
use std::marker::PhantomData;

use crate::table::TxTable;
use crate::table::{BlockContextFieldTag, TxFieldTag};
use crate::table::{BlockTable, KeccakTable2};
use crate::util::{random_linear_combine_word as rlc, Challenges, SubCircuit, SubCircuitConfig};
use crate::witness;
use gadgets::util::{and, not, or, select, Expr};
use gadgets::{
    is_zero::IsZeroChip,
    less_than::{LtChip, LtConfig, LtInstruction},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};
use lazy_static::lazy_static;

// The total number of previous blocks for which to check the hash chain
const PREVIOUS_BLOCKS_NUM: usize = 256;
/// Fixed by the spec
const TX_LEN: usize = 10;
// This is the number of entries each block occupies in the block_table, which
// is equal to the number of header fields per block (coinbase, timestamp,
// number, difficulty, gas_limit, base_fee, blockhash, beneficiary, state_root,
// transactions_root, receipts_root, gas_used, mix_hash, withdrawals_root)
const BLOCK_LEN_IN_TABLE: usize = 15;
// previous hashes in rlc, lo and hi
// + zero, prover, txs_hash_hi, txs_hash_lo fields
const BLOCK_TABLE_MISC_LEN: usize = PREVIOUS_BLOCKS_NUM * 3 + 4;
// Total number of entries in the block table:
// + (block fields num) * (total number of blocks)
// + misc entries
const TOTAL_BLOCK_TABLE_LEN: usize =
    (BLOCK_LEN_IN_TABLE * (PREVIOUS_BLOCKS_NUM + 1)) + BLOCK_TABLE_MISC_LEN;

const ZERO_BYTE_GAS_COST: u64 = 4;
const NONZERO_BYTE_GAS_COST: u64 = 16;
const MAX_DEGREE: usize = 9;
const BYTE_POW_BASE: u64 = 1 << 8;

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

const OLDEST_BLOCK_NUM: usize = 0;
const CURRENT_BLOCK_NUM: usize = 256;

// Absolute row number of the row where the LSB of the total RLP length is
// located
const TOTAL_LENGTH_OFFSET: i32 = 2;

lazy_static! {
    static ref OMMERS_HASH: H256 = H256::from_slice(
        &hex::decode("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
    );
}

/// Values of the block table (as in the spec)
#[derive(Clone, Default, Debug)]
pub struct BlockValues {
    coinbase: Address,
    gas_limit: u64,
    number: u64,
    timestamp: Word,
    difficulty: Word,
    base_fee: Word, // NOTE: BaseFee was added by EIP-1559 and is ignored in legacy headers.
    chain_id: u64,
    history_hashes: Vec<Word>,
}

/// Values of the tx table (as in the spec)
#[derive(Default, Debug, Clone)]
pub struct TxValues {
    nonce: Word,
    gas: Word, //gas limit
    gas_price: Word,
    from_addr: Address,
    to_addr: Address,
    is_create: u64,
    value: Word,
    call_data_len: u64,
    call_data_gas_cost: u64,
    tx_sign_hash: [u8; 32],
}

/// Extra values (not contained in block or tx tables)
#[derive(Default, Debug, Clone)]
pub struct ExtraValues {
    // block_hash: H256,
    state_root: H256,
    prev_state_root: H256,
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
}

/// PublicData contains all the values that the PiCircuit recieves as input
#[derive(Debug, Clone, Default)]
pub struct PublicData<F: Field> {
    /// chain id
    pub chain_id: Word,
    /// History hashes contains the most recent 256 block hashes in history,
    /// where the latest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// Block Transactions
    pub transactions: Vec<eth_types::Transaction>,
    /// Block State Root
    pub state_root: H256,
    /// Previous block root
    pub prev_state_root: H256,
    /// Constants related to Ethereum block
    pub block_constants: BlockConstants,

    /// Prover address
    pub prover: Address,

    /// Parent hash
    pub parent_hash: H256,
    /// The author
    pub beneficiary: Address,
    /// Transactions Root
    pub transactions_root: H256,
    /// Receipts Root
    pub receipts_root: H256,
    /// Logs Bloom
    // pub logs_bloom: Bloom,
    /// Gas Used
    pub gas_used: U256,
    /// Mix Hash
    pub mix_hash: H256,
    /// Withdrawals Root
    pub withdrawals_root: H256,

    /// All data of the past 256 blocks
    pub previous_blocks: Vec<witness::Block<F>>,
    /// RLPs of the past 256 blocks
    pub previous_blocks_rlp: Vec<Bytes>,

    // private values
    block_rlp: Bytes,
    block_hash: H256,
    block_hash_hi: F,
    block_hash_lo: F,

    txs_rlp: Bytes,
    txs_hash: H256,
    txs_hash_hi: F,
    txs_hash_lo: F,

    blockhash_blk_hdr_rlp: Bytes,
    blockhash_rlp_hash_hi: F,
    blockhash_rlp_hash_lo: F,
}

pub(super) fn rlp_opt<T: rlp::Encodable>(rlp: &mut rlp::RlpStream, opt: &Option<T>) {
    if let Some(inner) = opt {
        rlp.append(inner);
    } else {
        rlp.append(&"");
    }
}

impl<F: Field> PublicData<F> {
    fn get_block_rlp_rlc(&self, challenges: &Challenges<Value<F>>) -> Value<F> {
        use crate::evm_circuit::util::rlc;
        let randomness = challenges.keccak_input();
        randomness.map(|randomness| rlc::value(self.block_rlp.iter().rev(), randomness))
    }

    fn get_txs_rlp_rlc(&self, challenges: &Challenges<Value<F>>) -> Value<F> {
        use crate::evm_circuit::util::rlc;
        let randomness = challenges.keccak_input();
        randomness.map(|randomness| rlc::value(self.txs_rlp.iter().rev(), randomness))
    }

    fn split_hash(hash: [u8; 32]) -> (F, F) {
        let hi = hash.iter().take(16).fold(F::zero(), |acc, byte| {
            acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
        });

        let lo = hash.iter().skip(16).fold(F::zero(), |acc, byte| {
            acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
        });
        (hi, lo)
    }

    fn get_txs_hash(txs_rlp: &Bytes) -> (H256, F, F) {
        let hash = keccak256(&txs_rlp);
        let (hi, lo) = Self::split_hash(hash);
        (hash.into(), hi, lo)
    }

    fn get_block_hash(
        block: &witness::Block<F>,
        prover: Address,
        txs_hash: H256,
    ) -> (Bytes, H256, F, F) {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream
            .append(&block.eth_block.parent_hash)
            .append(&*OMMERS_HASH);
        rlp_opt(&mut stream, &block.eth_block.author);
        stream
            .append(&block.eth_block.state_root)
            .append(&block.eth_block.transactions_root)
            .append(&block.eth_block.receipts_root);
        rlp_opt(&mut stream, &block.eth_block.logs_bloom);
        stream.append(&block.eth_block.difficulty);
        rlp_opt(&mut stream, &block.eth_block.number);
        stream
            .append(&block.eth_block.gas_limit)
            .append(&block.eth_block.gas_used)
            .append(&block.eth_block.timestamp)
            .append(&block.eth_block.extra_data.as_ref());
        rlp_opt(&mut stream, &block.eth_block.mix_hash);
        rlp_opt(&mut stream, &block.eth_block.nonce);
        // rlp_opt(&mut stream, &block.eth_block.base_fee_per_gas);
        // append prover and txs_hash
        stream.append(&prover).append(&txs_hash);
        stream.finalize_unbounded_list();
        let out: bytes::Bytes = stream.out().into();
        let rlp = out.into();
        let hash = keccak256(&rlp);
        let (hi, lo) = Self::split_hash(hash);
        (rlp, hash.into(), hi, lo)
    }

    fn decode_txs_rlp(txs_rlp: &Bytes) -> Vec<eth_types::Transaction> {
        Rlp::new(txs_rlp).as_list().expect("invalid txs rlp")
    }

    fn default() -> Self {
        Self::new(
            &witness::Block::default(),
            Address::default(),
            Bytes::default(),
        )
    }

    fn get_block_header_rlp_from_block(block: &witness::Block<F>) -> (Bytes, F, F) {
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
            .append(&block.eth_block.gas_used)
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
        (rlp_bytes, hi, lo)
    }

    /// create PublicData from block and prover
    pub fn new(block: &witness::Block<F>, prover: Address, txs_rlp: Bytes) -> Self {
        let txs = Self::decode_txs_rlp(&txs_rlp);
        let (txs_hash, txs_hash_hi, txs_hash_lo) = Self::get_txs_hash(&txs_rlp);
        let (block_rlp, block_hash, block_hash_hi, block_hash_lo) =
            Self::get_block_hash(block, prover, txs_hash);
        let (blockhash_blk_hdr_rlp, blockhash_rlp_hash_hi, blockhash_rlp_hash_lo) =
            Self::get_block_header_rlp_from_block(block);

        // Only initializing `previous_blocks` and `previous_blocks_rlp` here
        // these values are set outside of `new`
        let previous_blocks = vec![witness::Block::<F>::default(); PREVIOUS_BLOCKS_NUM];
        let previous_blocks_rlp = vec![Bytes::default(); PREVIOUS_BLOCKS_NUM];

        PublicData {
            chain_id: block.context.chain_id,
            history_hashes: block.context.history_hashes.clone(),
            transactions: txs,
            state_root: block.eth_block.state_root,
            prev_state_root: H256::from_uint(&block.prev_state_root),
            block_constants: BlockConstants {
                coinbase: block.context.coinbase,
                timestamp: block.context.timestamp,
                number: block.context.number.low_u64().into(),
                difficulty: block.context.difficulty,
                gas_limit: block.context.gas_limit.into(),
                base_fee: block.context.base_fee,
            },
            blockhash_blk_hdr_rlp,
            blockhash_rlp_hash_hi,
            blockhash_rlp_hash_lo,
            block_rlp,
            block_hash,
            block_hash_hi,
            block_hash_lo,
            txs_rlp,
            txs_hash,
            txs_hash_hi,
            txs_hash_lo,
            prover,
            parent_hash: block.eth_block.parent_hash,
            beneficiary: block.eth_block.author.unwrap_or_else(H160::zero),
            transactions_root: block.eth_block.transactions_root,
            receipts_root: block.eth_block.receipts_root,
            gas_used: block.eth_block.gas_used,
            mix_hash: block.eth_block.mix_hash.unwrap_or_else(H256::zero),
            withdrawals_root: block.eth_block.withdrawals_root.unwrap_or_else(H256::zero),
            previous_blocks,
            previous_blocks_rlp,
        }
    }

    /// Returns struct with values for the block table
    pub fn get_block_table_values(&self) -> BlockValues {
        let history_hashes = [
            vec![U256::zero(); PREVIOUS_BLOCKS_NUM - self.history_hashes.len()],
            self.history_hashes.to_vec(),
        ]
        .concat();
        BlockValues {
            coinbase: self.block_constants.coinbase,
            gas_limit: self.block_constants.gas_limit.as_u64(),
            number: self.block_constants.number.as_u64(),
            timestamp: self.block_constants.timestamp,
            difficulty: self.block_constants.difficulty,
            base_fee: self.block_constants.base_fee,
            chain_id: self.chain_id.as_u64(),
            history_hashes,
        }
    }

    /// Returns struct with values for the tx table
    pub fn get_tx_table_values(&self) -> Vec<TxValues> {
        let chain_id: u64 = self
            .chain_id
            .try_into()
            .expect("Error converting chain_id to u64");
        let mut tx_vals = vec![];
        for tx in &self.txs() {
            let sign_data: SignData = tx
                .sign_data(chain_id)
                .expect("Error computing tx_sign_hash");
            let mut msg_hash_le = [0u8; 32];
            msg_hash_le.copy_from_slice(sign_data.msg_hash.to_bytes().as_slice());
            tx_vals.push(TxValues {
                nonce: tx.nonce,
                gas_price: tx.gas_price,
                gas: tx.gas_limit,
                from_addr: tx.from,
                to_addr: tx.to.unwrap_or_else(Address::zero),
                is_create: (tx.to.is_none() as u64),
                value: tx.value,
                call_data_len: tx.call_data.0.len() as u64,
                call_data_gas_cost: tx.call_data.0.iter().fold(0, |acc, byte| {
                    acc + if *byte == 0 {
                        ZERO_BYTE_GAS_COST
                    } else {
                        NONZERO_BYTE_GAS_COST
                    }
                }),
                tx_sign_hash: msg_hash_le,
            });
        }
        tx_vals
    }

    /// Returns struct with the extra values
    pub fn get_extra_values(&self) -> ExtraValues {
        ExtraValues {
            // block_hash: self.hash.unwrap_or_else(H256::zero),
            state_root: self.state_root,
            prev_state_root: self.prev_state_root,
        }
    }

    fn txs(&self) -> Vec<Transaction> {
        self.transactions.iter().map(Transaction::from).collect()
    }
}

/// Config for PiCircuit
#[derive(Clone, Debug)]
pub struct PiCircuitConfig<F: Field> {
    /// Max number of supported transactions
    max_txs: usize,
    /// Max number of supported calldata bytes
    max_calldata: usize,

    rpi: Column<Advice>,
    rpi_rlc_acc: Column<Advice>, // rlp input
    q_start: Selector,
    q_not_end: Selector,

    rpi_encoding: Column<Advice>, // rlc_acc, rlp_rlc, rlp_len, hash_hi, hash_lo
    q_rpi_encoding: Selector,

    pi: Column<Instance>, // keccak_hi, keccak_lo
    // rlp_table
    // rlc(txlist) -> rlc(rlp(txlist))
    rlp_table: [Column<Advice>; 3], // [input, len, output]
    // keccak_table
    // rlc(compressed) -> rlc(keccak(compressed)
    keccak_table: KeccakTable2,

    // External tables
    q_block_table: Selector,
    block_table: BlockTable,

    // tx table
    q_tx_table: Selector,
    tx_table: TxTable, // txlist hash, pi hash
    q_tx_calldata: Selector,
    q_calldata_start: Selector,
    tx_id_inv: Column<Advice>,
    tx_value_inv: Column<Advice>,
    tx_id_diff_inv: Column<Advice>,
    fixed_u8: Column<Fixed>,
    fixed_u16: Column<Fixed>,
    calldata_gas_cost: Column<Advice>,
    is_final: Column<Advice>,

    blk_hdr_rlp_is_short: LtConfig<F, 1>,
    // blockhash columns
    blockhash_cols: BlockhashColumns,

    _marker: PhantomData<F>,
}

/// Circuit configuration arguments
pub struct PiCircuitConfigArgs<F: Field> {
    /// Max number of supported transactions
    pub max_txs: usize,
    /// Max number of supported calldata bytes
    pub max_calldata: usize,
    /// TxTable
    pub tx_table: TxTable,
    /// BlockTable
    pub block_table: BlockTable,
    /// RlpTable
    pub rlp_table: [Column<Advice>; 3],
    /// KeccakTable
    pub keccak_table: KeccakTable2,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for PiCircuitConfig<F> {
    type ConfigArgs = PiCircuitConfigArgs<F>;

    /// Return a new PiCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            max_txs,
            max_calldata,
            block_table,
            tx_table,
            rlp_table,
            keccak_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_block_table = meta.selector();
        let q_tx_table = meta.complex_selector();
        let q_tx_calldata = meta.complex_selector();
        let q_calldata_start = meta.complex_selector();

        let rpi = meta.advice_column();
        let rpi_rlc_acc = meta.advice_column();
        let rpi_encoding = meta.advice_column();
        let q_rpi_encoding = meta.complex_selector();
        let q_start = meta.complex_selector();
        let q_not_end = meta.complex_selector();

        // Tx Table
        let tx_id = tx_table.tx_id;
        let tx_value = tx_table.value;
        let tag = tx_table.tag;
        let index = tx_table.index;
        let tx_id_inv = meta.advice_column();
        let tx_value_inv = meta.advice_column();
        let tx_id_diff_inv = meta.advice_column();
        let fixed_u8 = meta.fixed_column();
        // The difference of tx_id of adjacent rows in calldata part of tx table
        // lies in the interval [0, 2^16] if their tx_id both do not equal to zero.
        // We do not use 2^8 for the reason that a large block may have more than
        // 2^8 transfer transactions which have 21000*2^8 (~ 5.376M) gas.
        let fixed_u16 = meta.fixed_column();
        let calldata_gas_cost = meta.advice_column();
        let is_final = meta.advice_column();

        // Block hash
        let blk_hdr_rlp = meta.advice_column();
        let blk_hdr_rlp_inv = meta.advice_column();
        let blk_hdr_rlp_const = meta.fixed_column();
        let q_blk_hdr_rlp = meta.complex_selector();
        let q_blk_hdr_rlp_end = meta.complex_selector();
        let q_blk_hdr_rlp_const = meta.complex_selector();

        let blk_hdr_rlp_len_calc = meta.advice_column();
        let blk_hdr_rlp_len_calc_inv = meta.advice_column();
        let blk_hdr_reconstruct_value = meta.advice_column();
        let blk_hdr_reconstruct_hi_lo = meta.advice_column();
        let block_table_tag = meta.fixed_column();
        let block_table_index = meta.fixed_column();
        let q_reconstruct = meta.fixed_column();
        let blk_hdr_is_leading_zero = meta.advice_column();

        // Selectors for header fields.
        let q_number = meta.fixed_column();
        let q_parent_hash = meta.complex_selector();
        let q_var_field_256 = meta.fixed_column();
        let q_hi = meta.fixed_column();
        let q_lo = meta.fixed_column();

        let q_blk_hdr_rlc_start = meta.complex_selector();
        let blk_hdr_do_rlc_acc = meta.advice_column();
        let blk_hdr_rlc_acc = meta.advice_column();
        let q_lookup_blockhash = meta.complex_selector();

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
            block_table_tag,
            block_table_index,
            q_number,
            q_parent_hash,
            q_var_field_256,
            q_blk_hdr_rlc_start,
            q_blk_hdr_rlp_end,
            blk_hdr_rlc_acc,
            blk_hdr_do_rlc_acc,
            q_lookup_blockhash,
            blk_hdr_is_leading_zero,
        };

        let pi = meta.instance_column();

        meta.enable_equality(rpi);
        meta.enable_equality(rpi_rlc_acc);
        meta.enable_equality(rpi_encoding);
        meta.enable_equality(pi);
        // TODO(George): is this needed?
        meta.enable_equality(blk_hdr_reconstruct_value);

        // rlc_acc
        meta.create_gate("rpi_rlc_acc_next = rpi_rlc_acc * r + rpi_next", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_not_end = meta.query_selector(q_not_end);
            let rpi_rlc_acc_next = meta.query_advice(rpi_rlc_acc, Rotation::next());
            let rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
            let rpi_next = meta.query_advice(rpi, Rotation::next());
            let r = challenges.evm_word();

            cb.require_equal("left=right", rpi_rlc_acc_next, rpi_rlc_acc * r + rpi_next);
            cb.gate(q_not_end)
        });

        meta.create_gate("rpi_rlc_acc[0] = rpi[0]", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_start = meta.query_selector(q_start);
            let rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
            let rpi = meta.query_advice(rpi, Rotation::cur());

            cb.require_equal("", rpi_rlc_acc, rpi);

            cb.gate(q_start)
        });

        meta.lookup_any("lookup rlp", |meta| {
            let q_rpi_encoding = meta.query_selector(q_rpi_encoding);
            let rpi_rlc_acc = meta.query_advice(rpi_encoding, Rotation(0));
            let rpi_rlp_rlc = meta.query_advice(rpi_encoding, Rotation(1));
            let rpi_rlp_len = meta.query_advice(rpi_encoding, Rotation(2));
            vec![
                (
                    q_rpi_encoding.expr() * rpi_rlc_acc,
                    meta.query_advice(rlp_table[0], Rotation::cur()),
                ),
                (
                    q_rpi_encoding.expr() * rpi_rlp_rlc,
                    meta.query_advice(rlp_table[1], Rotation::cur()),
                ),
                (
                    q_rpi_encoding * rpi_rlp_len,
                    meta.query_advice(rlp_table[2], Rotation::cur()),
                ),
            ]
        });

        meta.lookup_any("lookup keccak", |meta| {
            let q_rpi_encoding = meta.query_selector(q_rpi_encoding);

            let rpi_rlp_rlc = meta.query_advice(rpi_encoding, Rotation(1));
            let rpi_rlp_len = meta.query_advice(rpi_encoding, Rotation(2));
            let rpi_hash_hi = meta.query_advice(rpi_encoding, Rotation(3));
            let rpi_hash_lo = meta.query_advice(rpi_encoding, Rotation(4));
            vec![
                (
                    q_rpi_encoding.expr(),
                    meta.query_advice(keccak_table.is_enabled, Rotation::cur()),
                ),
                (
                    q_rpi_encoding.expr() * rpi_rlp_rlc,
                    meta.query_advice(keccak_table.input_rlc, Rotation::cur()),
                ),
                (
                    q_rpi_encoding.expr() * rpi_rlp_len,
                    meta.query_advice(keccak_table.input_len, Rotation::cur()),
                ),
                (
                    q_rpi_encoding.expr() * rpi_hash_hi,
                    meta.query_advice(keccak_table.output_hi, Rotation::cur()),
                ),
                (
                    q_rpi_encoding * rpi_hash_lo,
                    meta.query_advice(keccak_table.output_lo, Rotation::cur()),
                ),
            ]
        });

        // 0.2 Block table -> value column match with raw_public_inputs at expected
        // offset
        meta.create_gate("block_table[i] = block[i]", |meta| {
            let q_block_table = meta.query_selector(q_block_table);
            let block_value = meta.query_advice(block_table.value, Rotation::cur());
            let rpi_block_value = meta.query_advice(rpi, Rotation::cur());
            vec![q_block_table * (block_value - rpi_block_value)]
        });

        let offset = TOTAL_BLOCK_TABLE_LEN;
        let tx_table_len = max_txs * TX_LEN + 1;

        //  0.3 Tx table -> {tx_id, index, value} column match with raw_public_inputs
        // at expected offset
        meta.create_gate("tx_table.tx_id[i] == rpi[i]", |meta| {
            // row.q_tx_table * row.tx_table.tx_id
            // == row.q_tx_table * row_offset_tx_table_tx_id.raw_public_inputs
            let q_tx_table = meta.query_selector(q_tx_table);
            let tx_id = meta.query_advice(tx_table.tx_id, Rotation::cur());
            let rpi_tx_id = meta.query_advice(rpi, Rotation(offset as i32));

            vec![q_tx_table * (tx_id - rpi_tx_id)]
        });

        meta.create_gate("tx_table.index[i] == rpi[tx_table_len + i]", |meta| {
            // row.q_tx_table * row.tx_table.tx_index
            // == row.q_tx_table * row_offset_tx_table_tx_index.raw_public_inputs
            let q_tx_table = meta.query_selector(q_tx_table);
            let tx_index = meta.query_advice(tx_table.index, Rotation::cur());
            let rpi_tx_index = meta.query_advice(rpi, Rotation((offset + tx_table_len) as i32));

            vec![q_tx_table * (tx_index - rpi_tx_index)]
        });

        meta.create_gate("tx_table.tx_value[i] == rpi[2* tx_table_len + i]", |meta| {
            // (row.q_tx_calldata | row.q_tx_table) * row.tx_table.tx_value
            // == (row.q_tx_calldata | row.q_tx_table) *
            // row_offset_tx_table_tx_value.raw_public_inputs
            let q_tx_table = meta.query_selector(q_tx_table);
            let tx_value = meta.query_advice(tx_value, Rotation::cur());
            let q_tx_calldata = meta.query_selector(q_tx_calldata);
            let rpi_tx_value = meta.query_advice(rpi, Rotation((offset + 2 * tx_table_len) as i32));

            vec![or::expr([q_tx_table, q_tx_calldata]) * (tx_value - rpi_tx_value)]
        });

        let tx_id_is_zero_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_tx_calldata),
            |meta| meta.query_advice(tx_table.tx_id, Rotation::cur()),
            tx_id_inv,
        );
        let tx_value_is_zero_config = IsZeroChip::configure(
            meta,
            |meta| {
                or::expr([
                    meta.query_selector(q_tx_table),
                    meta.query_selector(q_tx_calldata),
                ])
            },
            |meta| meta.query_advice(tx_value, Rotation::cur()),
            tx_value_inv,
        );
        let _tx_id_diff_is_zero_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_tx_calldata),
            |meta| {
                meta.query_advice(tx_table.tx_id, Rotation::next())
                    - meta.query_advice(tx_table.tx_id, Rotation::cur())
            },
            tx_id_diff_inv,
        );

        meta.lookup_any("tx_id_diff", |meta| {
            let tx_id_next = meta.query_advice(tx_id, Rotation::next());
            let tx_id = meta.query_advice(tx_id, Rotation::cur());
            let tx_id_inv_next = meta.query_advice(tx_id_inv, Rotation::next());
            let tx_id_diff_inv = meta.query_advice(tx_id_diff_inv, Rotation::cur());
            let fixed_u16_table = meta.query_fixed(fixed_u16, Rotation::cur());

            let tx_id_next_nonzero = tx_id_next.expr() * tx_id_inv_next;
            let tx_id_not_equal_to_next = (tx_id_next.expr() - tx_id.expr()) * tx_id_diff_inv;
            let tx_id_diff_minus_one = tx_id_next - tx_id - 1.expr();

            vec![(
                tx_id_diff_minus_one * tx_id_next_nonzero * tx_id_not_equal_to_next,
                fixed_u16_table,
            )]
        });

        meta.create_gate("calldata constraints", |meta| {
            let q_is_calldata = meta.query_selector(q_tx_calldata);
            let q_calldata_start = meta.query_selector(q_calldata_start);
            let tx_idx = meta.query_advice(tx_id, Rotation::cur());
            let tx_idx_next = meta.query_advice(tx_id, Rotation::next());
            let tx_idx_inv_next = meta.query_advice(tx_id_inv, Rotation::next());
            let tx_idx_diff_inv = meta.query_advice(tx_id_diff_inv, Rotation::cur());
            let idx = meta.query_advice(index, Rotation::cur());
            let idx_next = meta.query_advice(index, Rotation::next());
            let value_next = meta.query_advice(tx_value, Rotation::next());
            let value_next_inv = meta.query_advice(tx_value_inv, Rotation::next());

            let gas_cost = meta.query_advice(calldata_gas_cost, Rotation::cur());
            let gas_cost_next = meta.query_advice(calldata_gas_cost, Rotation::next());
            let is_final = meta.query_advice(is_final, Rotation::cur());

            let is_tx_id_nonzero = not::expr(tx_id_is_zero_config.expr());
            let is_tx_id_next_nonzero = tx_idx_next.expr() * tx_idx_inv_next.expr();

            let is_value_zero = tx_value_is_zero_config.expr();
            let is_value_nonzero = not::expr(tx_value_is_zero_config.expr());

            let is_value_next_nonzero = value_next.expr() * value_next_inv.expr();
            let is_value_next_zero = not::expr(is_value_next_nonzero.expr());

            // gas = value == 0 ? 4 : 16
            let gas = ZERO_BYTE_GAS_COST.expr() * is_value_zero.expr()
                + NONZERO_BYTE_GAS_COST.expr() * is_value_nonzero.expr();
            let gas_next = ZERO_BYTE_GAS_COST.expr() * is_value_next_zero
                + NONZERO_BYTE_GAS_COST.expr() * is_value_next_nonzero;

            // if tx_id == 0 then idx == 0, tx_id_next == 0
            let default_calldata_row_constraint1 = tx_id_is_zero_config.expr() * idx.expr();
            let default_calldata_row_constraint2 = tx_id_is_zero_config.expr() * tx_idx_next.expr();
            let default_calldata_row_constraint3 = tx_id_is_zero_config.expr() * is_final.expr();
            let default_calldata_row_constraint4 = tx_id_is_zero_config.expr() * gas_cost.expr();

            // if tx_id != 0 then
            //    1. tx_id_next == tx_id: idx_next == idx + 1, gas_cost_next == gas_cost +
            //       gas_next, is_final == false;
            //    2. tx_id_next == tx_id + 1 + x (where x is in [0, 2^16)): idx_next == 0,
            //       gas_cost_next == gas_next, is_final == true;
            //    3. tx_id_next == 0: is_final == true, idx_next == 0, gas_cost_next == 0;
            // either case 1, case 2 or case 3 holds.

            let tx_id_equal_to_next =
                1.expr() - (tx_idx_next.expr() - tx_idx.expr()) * tx_idx_diff_inv.expr();
            let idx_of_same_tx_constraint =
                tx_id_equal_to_next.clone() * (idx_next.expr() - idx.expr() - 1.expr());
            let idx_of_next_tx_constraint = (tx_idx_next.expr() - tx_idx.expr()) * idx_next.expr();

            let gas_cost_of_same_tx_constraint = tx_id_equal_to_next.clone()
                * (gas_cost_next.expr() - gas_cost.expr() - gas_next.expr());
            let gas_cost_of_next_tx_constraint = is_tx_id_next_nonzero.expr()
                * (tx_idx_next.expr() - tx_idx.expr())
                * (gas_cost_next.expr() - gas_next.expr());

            let is_final_of_same_tx_constraint = tx_id_equal_to_next * is_final.expr();
            let is_final_of_next_tx_constraint =
                (tx_idx_next.expr() - tx_idx.expr()) * (is_final.expr() - 1.expr());

            // if tx_id != 0 then
            //    1. q_calldata_start * (index - 0) == 0 and
            //    2. q_calldata_start * (gas_cost - gas) == 0.

            vec![
                q_is_calldata.expr() * default_calldata_row_constraint1,
                q_is_calldata.expr() * default_calldata_row_constraint2,
                q_is_calldata.expr() * default_calldata_row_constraint3,
                q_is_calldata.expr() * default_calldata_row_constraint4,
                q_is_calldata.expr() * is_tx_id_nonzero.expr() * idx_of_same_tx_constraint,
                q_is_calldata.expr() * is_tx_id_nonzero.expr() * idx_of_next_tx_constraint,
                q_is_calldata.expr() * is_tx_id_nonzero.expr() * gas_cost_of_same_tx_constraint,
                q_is_calldata.expr() * is_tx_id_nonzero.expr() * gas_cost_of_next_tx_constraint,
                q_is_calldata.expr() * is_tx_id_nonzero.expr() * is_final_of_same_tx_constraint,
                q_is_calldata.expr() * is_tx_id_nonzero.expr() * is_final_of_next_tx_constraint,
                q_calldata_start.expr() * is_tx_id_nonzero.expr() * (idx - 0.expr()),
                q_calldata_start.expr() * is_tx_id_nonzero.expr() * (gas_cost - gas),
            ]
        });

        // Test if tx tag equals to CallDataLength
        let tx_tag_is_cdl_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_tx_table),
            |meta| meta.query_fixed(tag, Rotation::cur()) - TxFieldTag::CallDataLength.expr(),
            tx_id_inv,
        );

        meta.create_gate(
            "call_data_gas_cost should be zero if call_data_length is zero",
            |meta| {
                let q_tx_table = meta.query_selector(q_tx_table);

                let is_calldata_length_zero = tx_value_is_zero_config.expr();
                let is_calldata_length_row = tx_tag_is_cdl_config.expr();
                let calldata_cost = meta.query_advice(tx_value, Rotation::next());

                vec![q_tx_table * is_calldata_length_row * is_calldata_length_zero * calldata_cost]
            },
        );

        meta.lookup_any("gas_cost in tx table", |meta| {
            let q_tx_table = meta.query_selector(q_tx_table);
            let is_final = meta.query_advice(is_final, Rotation::cur());

            let tx_id = meta.query_advice(tx_id, Rotation::cur());

            // calldata gas cost assigned in the tx table
            // CallDataGasCost is on the next row of CallDataLength
            let calldata_cost_assigned = meta.query_advice(tx_value, Rotation::next());
            // calldata gas cost calculated in call data
            let calldata_cost_calc = meta.query_advice(calldata_gas_cost, Rotation::cur());

            let is_calldata_length_row = tx_tag_is_cdl_config.expr();
            let is_calldata_length_nonzero = not::expr(tx_value_is_zero_config.expr());

            // lookup (tx_id, true, is_calldata_length_nonzero * is_calldata_cost *
            // gas_cost) in the table (tx_id, is_final, gas_cost)
            // if q_tx_table is true
            let condition = q_tx_table * is_calldata_length_nonzero * is_calldata_length_row;

            vec![
                (condition.expr() * tx_id.expr(), tx_id),
                (condition.expr() * 1.expr(), is_final),
                (
                    condition.expr() * calldata_cost_assigned,
                    calldata_cost_calc,
                ),
            ]
        });

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
                        and::expr([rlp_is_short_next.clone(), length_is_zero.expr()]),
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
                    let r = select::expr(q_reconstruct_cur.expr(), challenges.evm_word(), 0.expr());
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
                    let r = select::expr(do_rlc_acc.expr(), challenges.keccak_input(), 1.expr());
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
                        q_sel.expr() * meta.query_fixed(block_table_tag, Rotation::cur()),
                        meta.query_advice(block_table.tag, Rotation::cur()),
                    ),
                    (
                        q_sel.expr() * meta.query_fixed(block_table_index, Rotation::cur()),
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
            // The total RLP length is the RLP list length (0x200 + blk_hdr_rlp[2]) + 3
            // bytes for the RLP list header
            let blk_hdr_rlp_num_bytes = 0x200.expr()
                + meta.query_advice(
                    blk_hdr_rlp,
                    Rotation(-(BLOCKHASH_TOTAL_ROWS as i32) + 1 + 2),
                )
                + 3.expr();
            let blk_hdr_hash_hi = meta.query_advice(rpi_encoding, Rotation::cur());
            let blk_hdr_hash_lo = meta.query_advice(rpi_encoding, Rotation::prev());

            vec![
                (
                    q_blk_hdr_rlp_end.expr(),
                    meta.query_advice(keccak_table.is_enabled, Rotation::cur()),
                ),
                (
                    q_blk_hdr_rlp_end.expr() * blk_hdr_rlc,
                    meta.query_advice(keccak_table.input_rlc, Rotation::cur()),
                ),
                (
                    q_blk_hdr_rlp_end.expr() * blk_hdr_rlp_num_bytes,
                    meta.query_advice(keccak_table.input_len, Rotation::cur()),
                ),
                (
                    q_blk_hdr_rlp_end.expr() * blk_hdr_hash_hi,
                    meta.query_advice(keccak_table.output_hi, Rotation::cur()),
                ),
                (
                    q_blk_hdr_rlp_end * blk_hdr_hash_lo,
                    meta.query_advice(keccak_table.output_lo, Rotation::cur()),
                ),
            ]
        });

        meta.lookup_any(
            "Block header: Check hi parts of block hashes against previous hashes",
            |meta| {
                let q_blk_hdr_rlp_end = meta.query_selector(q_blk_hdr_rlp_end);
                let blk_hdr_hash_hi = meta.query_advice(rpi_encoding, Rotation::cur());
                let q_lookup_blockhash = meta.query_selector(q_lookup_blockhash);
                let tag = meta.query_fixed(block_table_tag, Rotation::prev());
                let index = meta.query_fixed(block_table_index, Rotation::cur());
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
                let blk_hdr_hash_lo = meta.query_advice(rpi_encoding, Rotation::prev());
                let q_lookup_blockhash = meta.query_selector(q_lookup_blockhash);
                let tag = meta.query_fixed(block_table_tag, Rotation(-2));
                let index = meta.query_fixed(block_table_index, Rotation::cur());
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
            let tag = meta.query_fixed(block_table_tag, Rotation::cur());
            let index = meta.query_fixed(block_table_index, Rotation::cur()) - 1.expr();
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
                (
                    q_sel.expr() * index,
                    meta.query_advice(block_table.index, Rotation::cur()),
                ),
                (
                    q_sel.expr() * meta.query_advice(blk_hdr_reconstruct_value, Rotation::cur()),
                    meta.query_advice(block_table.value, Rotation::cur()),
                ),
            ]
        });
        meta.lookup_any("Block header: Check parent hashes lo", |meta| {
            let tag = meta.query_fixed(block_table_tag, Rotation::cur());
            let index = meta.query_fixed(block_table_index, Rotation::cur()) - 1.expr();
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
                (
                    q_sel.expr() * index,
                    meta.query_advice(block_table.index, Rotation::cur()),
                ),
                (
                    q_sel.expr() * meta.query_advice(blk_hdr_reconstruct_value, Rotation::cur()),
                    meta.query_advice(block_table.value, Rotation::cur()),
                ),
            ]
        });

        Self {
            max_txs,
            max_calldata,
            block_table,
            q_block_table,
            q_tx_table,
            q_tx_calldata,
            q_calldata_start,
            tx_table,
            tx_id_inv,
            tx_value_inv,
            tx_id_diff_inv,
            fixed_u8,
            fixed_u16,
            calldata_gas_cost,
            is_final,
            pi,

            rpi,
            rpi_rlc_acc,
            rpi_encoding,
            q_rpi_encoding,
            q_start,
            q_not_end,

            rlp_table,
            keccak_table,

            blk_hdr_rlp_is_short: rlp_is_short,
            blockhash_cols,

            _marker: PhantomData,
        }
    }
}

impl<F: Field> PiCircuitConfig<F> {
    #[inline]
    fn circuit_txs_len(&self) -> usize {
        3 * (TX_LEN * self.max_txs + 1) + self.max_calldata
    }

    fn assign_tx_empty_row(&self, region: &mut Region<'_, F>, offset: usize) -> Result<(), Error> {
        region.assign_advice(
            || "tx_id",
            self.tx_table.tx_id,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "tx_id_inv",
            self.tx_id_inv,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_fixed(
            || "tag",
            self.tx_table.tag,
            offset,
            || Value::known(F::from(TxFieldTag::Null as u64)),
        )?;
        region.assign_advice(
            || "index",
            self.tx_table.index,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "tx_value",
            self.tx_table.value,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "tx_value_inv",
            self.tx_value_inv,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "is_final",
            self.is_final,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "gas_cost",
            self.calldata_gas_cost,
            offset,
            || Value::known(F::zero()),
        )?;
        Ok(())
    }

    /// Assigns a tx_table row and stores the values in a vec for the
    /// raw_public_inputs column
    #[allow(clippy::too_many_arguments)]
    fn assign_tx_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        tx_id: usize,
        tag: TxFieldTag,
        index: usize,
        tx_value: Value<F>,
        rpi_vals: &mut [Value<F>],
    ) -> Result<(), Error> {
        let tx_id = F::from(tx_id as u64);
        // tx_id_inv = (tag - CallDataLength)^(-1)
        let tx_id_inv = if tag != TxFieldTag::CallDataLength {
            let x = F::from(tag as u64) - F::from(TxFieldTag::CallDataLength as u64);
            x.invert().unwrap_or(F::zero())
        } else {
            F::zero()
        };
        let tag = F::from(tag as u64);
        let index = F::from(index as u64);
        let tx_value = tx_value;
        let tx_value_inv = tx_value.map(|v| v.invert().unwrap_or(F::zero()));

        self.q_tx_table.enable(region, offset)?;

        // Assign vals to Tx_table
        region.assign_advice(
            || "tx_id",
            self.tx_table.tx_id,
            offset,
            || Value::known(tx_id),
        )?;
        region.assign_fixed(|| "tag", self.tx_table.tag, offset, || Value::known(tag))?;
        region.assign_advice(
            || "index",
            self.tx_table.index,
            offset,
            || Value::known(index),
        )?;
        region.assign_advice(|| "tx_value", self.tx_table.value, offset, || tx_value)?;
        region.assign_advice(
            || "tx_id_inv",
            self.tx_id_inv,
            offset,
            || Value::known(tx_id_inv),
        )?;
        region.assign_advice(
            || "tx_value_inverse",
            self.tx_value_inv,
            offset,
            || tx_value_inv,
        )?;

        // Assign vals to raw_public_inputs column
        let tx_table_len = TX_LEN * self.max_txs + 1;

        let id_offset = TOTAL_BLOCK_TABLE_LEN;
        let index_offset = id_offset + tx_table_len;
        let value_offset = index_offset + tx_table_len;

        region.assign_advice(
            || "txlist.tx_id",
            self.rpi,
            offset + id_offset,
            || Value::known(tx_id),
        )?;

        region.assign_advice(
            || "txlist.tx_index",
            self.rpi,
            offset + index_offset,
            || Value::known(index),
        )?;

        region.assign_advice(
            || "txlist.tx_value",
            self.rpi,
            offset + value_offset,
            || tx_value,
        )?;

        // Add copy to vec
        rpi_vals[offset] = Value::known(tx_id);
        rpi_vals[offset + tx_table_len] = Value::known(index);
        rpi_vals[offset + 2 * tx_table_len] = tx_value;

        Ok(())
    }

    /// Assigns one calldata row
    #[allow(clippy::too_many_arguments)]
    fn assign_tx_calldata_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        tx_id: usize,
        tx_id_next: usize,
        index: usize,
        tx_value: F,
        is_final: bool,
        gas_cost: F,
        rpi_vals: &mut [Value<F>],
    ) -> Result<(), Error> {
        let tx_id = F::from(tx_id as u64);
        let tx_id_inv = tx_id.invert().unwrap_or(F::zero());
        let tx_id_diff = F::from(tx_id_next as u64) - tx_id;
        let tx_id_diff_inv = tx_id_diff.invert().unwrap_or(F::zero());
        let tag = F::from(TxFieldTag::CallData as u64);
        let index = F::from(index as u64);
        let tx_value = tx_value;
        let tx_value_inv = tx_value.invert().unwrap_or(F::zero());
        let is_final = if is_final { F::one() } else { F::zero() };

        // Assign vals to raw_public_inputs column
        let tx_table_len = TX_LEN * self.max_txs + 1;
        let calldata_offset = tx_table_len + offset;

        self.q_tx_calldata.enable(region, calldata_offset)?;

        // Assign vals to Tx_table
        region.assign_advice(
            || "tx_id",
            self.tx_table.tx_id,
            calldata_offset,
            || Value::known(tx_id),
        )?;
        region.assign_advice(
            || "tx_id_inv",
            self.tx_id_inv,
            calldata_offset,
            || Value::known(tx_id_inv),
        )?;
        region.assign_fixed(
            || "tag",
            self.tx_table.tag,
            calldata_offset,
            || Value::known(tag),
        )?;
        region.assign_advice(
            || "index",
            self.tx_table.index,
            calldata_offset,
            || Value::known(index),
        )?;
        region.assign_advice(
            || "tx_value",
            self.tx_table.value,
            calldata_offset,
            || Value::known(tx_value),
        )?;
        region.assign_advice(
            || "tx_value_inv",
            self.tx_value_inv,
            calldata_offset,
            || Value::known(tx_value_inv),
        )?;
        region.assign_advice(
            || "tx_id_diff_inv",
            self.tx_id_diff_inv,
            calldata_offset,
            || Value::known(tx_id_diff_inv),
        )?;
        region.assign_advice(
            || "is_final",
            self.is_final,
            calldata_offset,
            || Value::known(is_final),
        )?;
        region.assign_advice(
            || "gas_cost",
            self.calldata_gas_cost,
            calldata_offset,
            || Value::known(gas_cost),
        )?;

        let value_offset = 3 * tx_table_len;

        region.assign_advice(
            || "raw_pi.tx_value",
            self.rpi,
            offset + value_offset + TOTAL_BLOCK_TABLE_LEN,
            || Value::known(tx_value),
        )?;

        // Add copy to vec
        rpi_vals[offset + value_offset] = Value::known(tx_value);

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn assign_block(
        &self,
        region: &mut Region<'_, F>,
        public_data: &PublicData<F>,
        block_number: usize,
        prev_rlc_acc: Value<F>,
        test_public_data: &Option<PublicData<F>>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<
        (
            Option<AssignedCell<F, F>>, // txs hash hi
            Option<AssignedCell<F, F>>, // txs hash lo
            Value<F>,                   // block_rlc_acc
        ),
        Error,
    > {
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
                Value::known(block_values.coinbase.to_scalar().unwrap()),
                false,
            ),
            (
                "timestamp",
                BlockContextFieldTag::Timestamp,
                block_number,
                randomness.map(|randomness| rlc(block_values.timestamp.to_le_bytes(), randomness)),
                false,
            ),
            (
                "number",
                BlockContextFieldTag::Number,
                block_number,
                randomness.map(|randomness| {
                    rlc(
                        [0; 32 - NUMBER_SIZE]
                            .into_iter()
                            .chain(block_values.number.to_be_bytes().into_iter())
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness,
                    )
                }),
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
                Value::known(F::from(block_values.gas_limit)),
                false,
            ),
            (
                "base_fee",
                BlockContextFieldTag::BaseFee,
                block_number,
                randomness.map(|randomness| rlc(block_values.base_fee.to_be_bytes(), randomness)),
                false,
            ),
            (
                "blockhash",
                BlockContextFieldTag::BlockHash,
                block_number,
                randomness.map(|randomness| {
                    rlc(
                        pb.block_hash
                            .to_fixed_bytes()
                            .into_iter()
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness,
                    )
                }),
                false,
            ),
            (
                "chain_id",
                BlockContextFieldTag::ChainId,
                block_number,
                Value::known(F::from(block_values.chain_id)),
                false,
            ),
            (
                "beneficiary",
                BlockContextFieldTag::Beneficiary,
                block_number,
                randomness.map(|randomness| {
                    rlc(
                        ([0u8; 32 - BENEFICIARY_SIZE]
                            .into_iter()
                            .chain(pb.beneficiary.to_fixed_bytes().into_iter()))
                        .rev()
                        .collect::<Vec<u8>>()
                        .try_into()
                        .unwrap(),
                        randomness,
                    )
                }),
                false,
            ),
            (
                "state_root",
                BlockContextFieldTag::StateRoot,
                block_number,
                randomness.map(|randomness| {
                    rlc(
                        pb.state_root
                            .to_fixed_bytes()
                            .into_iter()
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness,
                    )
                }),
                false,
            ),
            (
                "transactions_root",
                BlockContextFieldTag::TransactionsRoot,
                block_number,
                randomness.map(|randomness| {
                    rlc(
                        pb.transactions_root
                            .to_fixed_bytes()
                            .into_iter()
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness,
                    )
                }),
                false,
            ),
            (
                "receipts_root",
                BlockContextFieldTag::ReceiptsRoot,
                block_number,
                randomness.map(|randomness| {
                    rlc(
                        pb.receipts_root
                            .to_fixed_bytes()
                            .into_iter()
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness,
                    )
                }),
                false,
            ),
            (
                "gas_used",
                BlockContextFieldTag::GasUsed,
                block_number,
                randomness.map(|randomness| rlc(pb.gas_used.to_be_bytes(), randomness)),
                false,
            ),
            (
                "mix_hash",
                BlockContextFieldTag::MixHash,
                block_number,
                randomness.map(|randomness| {
                    rlc(
                        pb.mix_hash
                            .to_fixed_bytes()
                            .into_iter()
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness,
                    )
                }),
                false,
            ),
            (
                "withdrawals_root",
                BlockContextFieldTag::WithdrawalsRoot,
                block_number,
                randomness.map(|randomness| {
                    rlc(
                        pb.withdrawals_root
                            .to_fixed_bytes()
                            .into_iter()
                            .rev()
                            .collect::<Vec<u8>>()
                            .try_into()
                            .unwrap(),
                        randomness,
                    )
                }),
                false,
            ),
        ];

        if block_number == CURRENT_BLOCK_NUM {
            // The following need to be added only once in block table
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
                            randomness.map(|randomness| rlc(h.to_le_bytes(), randomness)),
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
                                    .fold(F::zero(), |acc, byte| {
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
                                    .fold(F::zero(), |acc, byte| {
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
                    Value::known(F::zero()),
                    false,
                ),
                (
                    "prover",
                    BlockContextFieldTag::None,
                    0,
                    Value::known(pb.prover.to_scalar().unwrap()),
                    true,
                ),
                (
                    "txs_hash_hi",
                    BlockContextFieldTag::None,
                    0,
                    Value::known(pb.txs_hash_hi),
                    true,
                ),
                (
                    "txs_hash_lo",
                    BlockContextFieldTag::None,
                    0,
                    Value::known(pb.txs_hash_lo),
                    true,
                ),
            ]);
        }

        let mut cells = vec![];
        // Continue computing RLC from where we left off
        let mut rlc_acc = prev_rlc_acc;

        for (offset, (name, tag, idx, val, not_in_table)) in block_data.into_iter().enumerate() {
            let absolute_offset = base_offset + offset;
            if absolute_offset < TOTAL_BLOCK_TABLE_LEN - 1 {
                self.q_not_end.enable(region, absolute_offset)?;
            }
            let val_cell = region.assign_advice(|| name, self.rpi, absolute_offset, || val)?;
            rlc_acc = rlc_acc * randomness + val;
            region.assign_advice(|| name, self.rpi_rlc_acc, absolute_offset, || rlc_acc)?;
            if not_in_table {
                cells.push(val_cell);
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
                region.assign_advice(|| name, self.block_table.value, absolute_offset, || val)?;
            }
        }

        let txs_hash_hi;
        let txs_hash_lo;

        if cells.is_empty() {
            txs_hash_hi = None;
            txs_hash_lo = None;
        } else {
            txs_hash_hi = Some(cells[1].clone());
            txs_hash_lo = Some(cells[2].clone());
        };

        Ok((txs_hash_hi, txs_hash_lo, rlc_acc))
    }

    #[allow(clippy::type_complexity)]
    fn assign_txs(
        &self,
        region: &mut Region<'_, F>,
        public_data: &PublicData<F>,
        challenges: &Challenges<Value<F>>,
        rpi_vals: Vec<Value<F>>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>, Value<F>), Error> {
        self.q_start.enable(region, 0)?;

        let r = challenges.evm_word();

        let last = rpi_vals.len() - 1;
        let mut rlc_acc = Value::known(F::zero());
        for (offset, val) in rpi_vals.iter().enumerate() {
            if offset != last {
                self.q_not_end
                    .enable(region, offset + TOTAL_BLOCK_TABLE_LEN)?;
            }
            rlc_acc = rlc_acc * r + val;
            region.assign_advice(
                || "txs_rlc_acc",
                self.rpi_rlc_acc,
                offset + TOTAL_BLOCK_TABLE_LEN,
                || rlc_acc,
            )?;
        }

        let mut offset = 5;
        self.q_rpi_encoding.enable(region, offset)?;
        region.assign_advice(|| "txs_rlc_acc", self.rpi_encoding, offset, || rlc_acc)?;
        offset += 1;
        let txs_rlp_rlc = public_data.get_txs_rlp_rlc(challenges);
        region.assign_advice(|| "txs_rlp_rlc", self.rpi_encoding, offset, || txs_rlp_rlc)?;
        offset += 1;
        region.assign_advice(
            || "txs_rlp_len",
            self.rpi_encoding,
            offset,
            || Value::known(F::from(public_data.txs_rlp.len() as u64)),
        )?;
        offset += 1;
        let txs_hash_hi_cell = region.assign_advice(
            || "txs_hash_hi",
            self.rpi_encoding,
            offset,
            || Value::known(public_data.txs_hash_hi),
        )?;
        offset += 1;
        let txs_hash_lo_cell = region.assign_advice(
            || "txs_hash_lo",
            self.rpi_encoding,
            offset,
            || Value::known(public_data.txs_hash_lo),
        )?;

        Ok((txs_hash_hi_cell, txs_hash_lo_cell, rlc_acc))
    }

    fn assign_rlp_table(
        &self,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
        txs_rlc_acc: Value<F>,
        block_rlc_acc: Value<F>,
        public_data: &PublicData<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "rlp table",
            |mut region| {
                let block_rlp_rlc = public_data.get_block_rlp_rlc(challenges);
                let txs_rlp_rlc = public_data.get_txs_rlp_rlc(challenges);
                for (offset, vals) in [
                    [
                        Value::known(F::zero()),
                        Value::known(F::zero()),
                        Value::known(F::zero()),
                    ],
                    [
                        txs_rlc_acc,
                        txs_rlp_rlc,
                        Value::known(F::from(public_data.txs_rlp.len() as u64)),
                    ],
                    [
                        block_rlc_acc,
                        block_rlp_rlc,
                        Value::known(F::from(public_data.block_rlp.len() as u64)),
                    ],
                ]
                .iter()
                .enumerate()
                {
                    for (val, row) in vals.iter().zip_eq(self.rlp_table.iter()) {
                        region.assign_advice(|| "", *row, offset, || *val)?;
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    fn assign_fixed_u8(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed u8 table",
            |mut region| {
                for i in 0..(1 << 8) {
                    region.assign_fixed(
                        || format!("row_{}", i),
                        self.fixed_u8,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }

    fn assign_fixed_u16(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed u16 table",
            |mut region| {
                for i in 0..(1 << 16) {
                    region.assign_fixed(
                        || format!("row_{}", i),
                        self.fixed_u16,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }

    #[allow(clippy::type_complexity)]
    fn get_block_header_rlp_from_public_data(
        public_data: &PublicData<F>,
        challenges: &Challenges<Value<F>>,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<Value<F>>, Value<F>, Value<F>) {
        // RLP encode the block header data
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream
            .append(&public_data.parent_hash)
            .append(&*OMMERS_HASH)
            .append(&public_data.beneficiary)
            .append(&public_data.state_root)
            .append(&public_data.transactions_root)
            .append(&public_data.receipts_root)
            .append(&vec![0u8; LOGS_BLOOM_SIZE]) // logs_bloom is all zeros
            .append(&public_data.block_constants.difficulty)
            .append(&public_data.block_constants.number)
            .append(&public_data.block_constants.gas_limit)
            .append(&public_data.gas_used)
            .append(&public_data.block_constants.timestamp);
        rlp_opt(&mut stream, &None::<u8>); // extra_data = ""
        stream
            .append(&public_data.mix_hash)
            .append(&vec![0u8; 8]) // nonce = 0
            .append(&public_data.block_constants.base_fee)
            .append(&public_data.withdrawals_root);
        stream.finalize_unbounded_list();
        let mut bytes: Vec<u8> = stream.out().into();

        // Calculate the block hash
        let hash = keccak256(&bytes);
        let hash_hi = hash.iter().take(16).fold(F::zero(), |acc, byte| {
            acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
        });
        let hash_lo = hash.iter().skip(16).fold(F::zero(), |acc, byte| {
            acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
        });

        let mut leading_zeros: Vec<u8> = vec![0; bytes.len()];
        let mut blk_hdr_do_rlc_acc: Vec<u8> = vec![1; bytes.len()];
        let mut blk_hdr_rlc_acc: Vec<Value<F>> = vec![];

        // Calculate the RLC of the bytes
        bytes.iter().map(|b| Value::known(F::from(*b as u64))).fold(
            Value::known(F::zero()),
            |mut rlc_acc, byte| {
                rlc_acc = rlc_acc * challenges.keccak_input() + byte;
                blk_hdr_rlc_acc.push(rlc_acc);
                rlc_acc
            },
        );

        // Handles leading zeros, short values and calculates the values for
        // `blk_hdr_is_leading_zero` and `blk_hdr_rlc_acc`
        let block = &public_data.block_constants;
        for (field, offset, zeros_bias) in [
            (U256::from(block.number.as_u64()), NUMBER_RLP_OFFSET, 32 - 8),
            (block.gas_limit, GAS_LIMIT_RLP_OFFSET, 0),
            (public_data.gas_used, GAS_USED_RLP_OFFSET, 0),
            (block.timestamp, TIMESTAMP_RLP_OFFSET, 0),
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
                || Value::known(F::from((block_number) as u64)),
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
                || Value::known(F::from((block_number) as u64)),
            )
            .unwrap();

        // We need to push `PreviousHashLo` tag up one row since we `PreviousHashHi`
        // uses the current row
        region
            .assign_fixed(
                || "block_table_tag",
                self.blockhash_cols.block_table_tag,
                block_offset + BLOCKHASH_TOTAL_ROWS - 3,
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
        ) = Self::get_block_header_rlp_from_public_data(public_data, challenges);

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
                    || Value::known(F::from((*rlp_byte) as u64).invert().unwrap_or(F::zero())),
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
        let randomness = challenges.evm_word();
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
                .block_constants
                .number
                .as_u64()
                .to_be_bytes()
                .iter(),
            public_data.block_constants.gas_limit.to_be_bytes().iter(),
            public_data.gas_used.to_be_bytes().iter(),
            public_data.block_constants.timestamp.to_be_bytes().iter(),
            public_data.mix_hash.as_fixed_bytes().iter(),
            public_data.block_constants.base_fee.to_be_bytes().iter(),
            public_data.withdrawals_root.as_fixed_bytes().iter(),
        ]
        .iter()
        .enumerate()
        {
            reconstructed_values.push(
                value
                    .clone()
                    .scan(Value::known(F::zero()), |acc, &x| {
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
                    || Value::known(F::from(*v)),
                )
                .unwrap();
            if *q == 1 {
                self.blockhash_cols
                    .q_blk_hdr_rlp_const
                    .enable(region, absolute_offset)
                    .unwrap();
            }
        }

        let mut length_calc = F::zero();
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
                                || Value::known(F::one()),
                            )
                            .unwrap();
                    } else if is_parent_hash_lo {
                        region
                            .assign_fixed(
                                || "parent hash q_lo",
                                self.blockhash_cols.q_lo,
                                absolute_offset,
                                || Value::known(F::one()),
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

                if *is_reconstruct && !(is_parent_hash && block_number == OLDEST_BLOCK_NUM) {
                    region
                        .assign_fixed(
                            || "q_reconstruct for ".to_string() + name,
                            self.blockhash_cols.q_reconstruct,
                            absolute_offset,
                            || Value::known(F::one()),
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
                    let field: &U256;
                    match *base_offset {
                        GAS_LIMIT_RLP_OFFSET => {
                            (field_size, field) = (
                                GAS_LIMIT_RLP_LEN - 1,
                                &public_data.block_constants.gas_limit,
                            )
                        }
                        GAS_USED_RLP_OFFSET => {
                            (field_size, field) = (GAS_USED_RLP_LEN - 1, &public_data.gas_used)
                        }
                        TIMESTAMP_RLP_OFFSET => {
                            (field_size, field) = (
                                TIMESTAMP_RLP_LEN - 1,
                                &public_data.block_constants.timestamp,
                            )
                        }
                        BASE_FEE_RLP_OFFSET => {
                            (field_size, field) =
                                (BASE_FEE_RLP_LEN - 1, &public_data.block_constants.base_fee)
                        }
                        _ => {
                            (field_size, field) =
                                (NUMBER_RLP_LEN - 1, &public_data.block_constants.base_fee)
                        } // `field` doesn't matter in this case
                    }

                    let field_lead_zeros_num = if *base_offset == NUMBER_RLP_OFFSET {
                        public_data.block_constants.number.leading_zeros() / 8
                    } else {
                        field.leading_zeros() / 8
                    } as usize;

                    if (offset < field_lead_zeros_num)
                        || // short RLP values have 0 length
                            (offset == field_size - 1
                            && length_calc == F::zero()
                            && block_header_rlp_byte[base_offset + offset] <= 0x80)
                    {
                        length_calc = F::zero();
                    } else {
                        length_calc = F::from((offset - field_lead_zeros_num + 1) as u64);
                    }

                    region
                        .assign_advice(
                            || "length of ".to_string() + name,
                            self.blockhash_cols.blk_hdr_rlp_len_calc,
                            absolute_offset,
                            || Value::known(length_calc),
                        )
                        .unwrap();
                    region
                        .assign_advice(
                            || "inverse length of ".to_string() + name,
                            self.blockhash_cols.blk_hdr_rlp_len_calc_inv,
                            absolute_offset,
                            || Value::known(length_calc.invert().unwrap_or(F::zero())),
                        )
                        .unwrap();

                    let selector = if *base_offset == NUMBER_RLP_OFFSET {
                        self.blockhash_cols.q_number
                    } else {
                        self.blockhash_cols.q_var_field_256
                    };
                    region
                        .assign_fixed(
                            || "q_number and q_var_field_256",
                            selector,
                            absolute_offset,
                            || Value::known(F::one()),
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

            region
                .assign_fixed(
                    || "block_table_index",
                    self.blockhash_cols.block_table_index,
                    absolute_offset,
                    || Value::known(F::from((block_number) as u64)),
                )
                .unwrap();
        }

        // Determines if it is a short RLP value
        let lt_chip = LtChip::construct(self.blk_hdr_rlp_is_short);
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
                self.rpi_encoding,
                block_offset + BLOCKHASH_TOTAL_ROWS - 1,
                || blk_hdr_hash_hi,
            )
            .unwrap();
        region
            .assign_advice(
                || "blk_hdr_hash_lo",
                self.rpi_encoding,
                block_offset + BLOCKHASH_TOTAL_ROWS - 2,
                || blk_hdr_hash_lo,
            )
            .unwrap();
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        public_data: &PublicData<F>,
        test_public_data: &Option<PublicData<F>>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        self.assign_fixed_u8(layouter)?;
        self.assign_fixed_u16(layouter)?;

        let (public_inputs, txs_rlc_acc, block_rlc_acc) = layouter.assign_region(
            || "region 0",
            |mut region| {
                // Assign current block
                self.assign_block_hash_calc(
                    &mut region,
                    public_data,
                    CURRENT_BLOCK_NUM,
                    challenges,
                );
                let (txs_hash_hi_cell, txs_hash_lo_cell, first_block_rlc_acc) = self.assign_block(
                    &mut region,
                    public_data,
                    CURRENT_BLOCK_NUM,
                    Value::known(F::zero()),
                    test_public_data,
                    challenges,
                )?;

                // Assign previous blocks
                let mut prev_block_rlc_acc = first_block_rlc_acc;
                for (block_number, prev_block) in public_data.previous_blocks
                    [0..PREVIOUS_BLOCKS_NUM]
                    .iter()
                    .enumerate()
                {
                    let prev_public_data =
                        PublicData::new(prev_block, public_data.prover, Bytes::default());
                    self.assign_block_hash_calc(
                        &mut region,
                        &prev_public_data,
                        block_number,
                        challenges,
                    );
                    // Assign block table for previous blocks
                    let (_, _, block_rlc_acc) = self.assign_block(
                        &mut region,
                        &prev_public_data,
                        block_number,
                        prev_block_rlc_acc,
                        test_public_data,
                        challenges,
                    )?;
                    prev_block_rlc_acc = block_rlc_acc;
                }

                let mut offset = 0;
                self.q_rpi_encoding.enable(&mut region, offset)?;
                region.assign_advice(
                    || "block_rlc_acc",
                    self.rpi_encoding,
                    offset,
                    || prev_block_rlc_acc,
                )?;
                offset += 1;
                let block_rlp_rlc = public_data.get_block_rlp_rlc(challenges);
                region.assign_advice(
                    || "block_rlp_rlc",
                    self.rpi_encoding,
                    offset,
                    || block_rlp_rlc,
                )?;
                offset += 1;
                region.assign_advice(
                    || "block_rlp_len",
                    self.rpi_encoding,
                    offset,
                    || Value::known(F::from(public_data.block_rlp.len() as u64)),
                )?;
                offset += 1;
                let block_hash_hi_cell = region.assign_advice(
                    || "block_hash_hi",
                    self.rpi_encoding,
                    offset,
                    || Value::known(public_data.block_hash_hi),
                )?;
                offset += 1;
                let block_hash_lo_cell = region.assign_advice(
                    || "block_hash_lo",
                    self.rpi_encoding,
                    offset,
                    || Value::known(public_data.block_hash_lo),
                )?;

                // Assign Tx table
                let mut offset = 0;
                let txs = public_data.get_tx_table_values();
                assert!(txs.len() <= self.max_txs);
                let tx_default = TxValues::default();

                let circuit_txs_len = self.circuit_txs_len();
                let mut rpi_vals = vec![Value::known(F::zero()); circuit_txs_len];

                // Add empty row
                self.assign_tx_row(
                    &mut region,
                    offset,
                    0,
                    TxFieldTag::Null,
                    0,
                    Value::known(F::zero()),
                    &mut rpi_vals,
                )?;
                offset += 1;

                let randomness = challenges.evm_word();

                for i in 0..self.max_txs {
                    let tx = if i < txs.len() { &txs[i] } else { &tx_default };

                    for (tag, value) in &[
                        (
                            TxFieldTag::Nonce,
                            randomness.map(|randomness| rlc(tx.nonce.to_le_bytes(), randomness)),
                        ),
                        (
                            TxFieldTag::Gas,
                            randomness.map(|randomness| rlc(tx.gas.to_le_bytes(), randomness)),
                        ),
                        (
                            TxFieldTag::GasPrice,
                            randomness.map(|v| rlc(tx.gas_price.to_le_bytes(), v)),
                        ),
                        (
                            TxFieldTag::CallerAddress,
                            Value::known(tx.from_addr.to_scalar().expect("tx.from too big")),
                        ),
                        (
                            TxFieldTag::CalleeAddress,
                            Value::known(tx.to_addr.to_scalar().expect("tx.to too big")),
                        ),
                        (TxFieldTag::IsCreate, Value::known(F::from(tx.is_create))),
                        (
                            TxFieldTag::Value,
                            randomness.map(|randomness| rlc(tx.value.to_le_bytes(), randomness)),
                        ),
                        (
                            TxFieldTag::CallDataLength,
                            Value::known(F::from(tx.call_data_len)),
                        ),
                        (
                            TxFieldTag::CallDataGasCost,
                            Value::known(F::from(tx.call_data_gas_cost)),
                        ),
                        (
                            TxFieldTag::TxSignHash,
                            randomness.map(|randomness| rlc(tx.tx_sign_hash, randomness)),
                        ),
                    ] {
                        self.assign_tx_row(
                            &mut region,
                            offset,
                            i + 1,
                            *tag,
                            0,
                            *value,
                            &mut rpi_vals,
                        )?;
                        offset += 1;
                    }
                }
                // Tx Table CallData
                let mut calldata_count = 0;
                self.q_calldata_start.enable(&mut region, offset)?;
                // the call data bytes assignment starts at offset 0
                offset = 0;
                let txs = public_data.txs();
                for (i, tx) in public_data.txs().iter().enumerate() {
                    let call_data_length = tx.call_data.0.len();
                    let mut gas_cost = F::zero();
                    for (index, byte) in tx.call_data.0.iter().enumerate() {
                        assert!(calldata_count < self.max_calldata);
                        let is_final = index == call_data_length - 1;
                        gas_cost += if *byte == 0 {
                            F::from(ZERO_BYTE_GAS_COST)
                        } else {
                            F::from(NONZERO_BYTE_GAS_COST)
                        };
                        let tx_id_next = if is_final {
                            let mut j = i + 1;
                            while j < txs.len() && txs[j].call_data.0.is_empty() {
                                j += 1;
                            }
                            if j >= txs.len() {
                                0
                            } else {
                                j + 1
                            }
                        } else {
                            i + 1
                        };

                        self.assign_tx_calldata_row(
                            &mut region,
                            offset,
                            i + 1,
                            tx_id_next as usize,
                            index,
                            F::from(*byte as u64),
                            is_final,
                            gas_cost,
                            &mut rpi_vals,
                        )?;
                        offset += 1;
                        calldata_count += 1;
                    }
                }
                for _ in calldata_count..self.max_calldata {
                    self.assign_tx_calldata_row(
                        &mut region,
                        offset,
                        0, // tx_id
                        0,
                        0,
                        F::zero(),
                        false,
                        F::zero(),
                        &mut rpi_vals,
                    )?;
                    offset += 1;
                }

                // NOTE: we add this empty row so as to pass mock prover's check
                //      otherwise it will emit CellNotAssigned Error
                let tx_table_len = TX_LEN * self.max_txs + 1;
                self.assign_tx_empty_row(&mut region, tx_table_len + offset)?;

                let (origin_txs_hash_hi_cell, origin_txs_hash_lo_cell, txs_rlc_acc) =
                    self.assign_txs(&mut region, public_data, challenges, rpi_vals)?;
                // assert two txs hash are equal

                if txs_hash_hi_cell.is_some() {
                    region.constrain_equal(
                        txs_hash_hi_cell.unwrap().cell(),
                        origin_txs_hash_hi_cell.cell(),
                    )?;
                    region.constrain_equal(
                        txs_hash_lo_cell.unwrap().cell(),
                        origin_txs_hash_lo_cell.cell(),
                    )?;
                }
                Ok((
                    [block_hash_hi_cell, block_hash_lo_cell],
                    txs_rlc_acc,
                    prev_block_rlc_acc,
                ))
            },
        )?;
        // assign rlp table
        self.assign_rlp_table(
            layouter,
            challenges,
            txs_rlc_acc,
            block_rlc_acc,
            public_data,
        )?;

        // constraint public inputs
        for (offset, cell) in public_inputs.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), self.pi, offset)?;
        }
        Ok(())
    }
}

/// Public Inputs Circuit
#[derive(Clone, Default, Debug)]
pub struct PiCircuit<F: Field> {
    max_txs: usize,
    max_calldata: usize,
    /// PublicInputs data known by the verifier
    pub public_data: PublicData<F>,
    test_public_data: Option<PublicData<F>>,

    _marker: PhantomData<F>,
}

impl<F: Field> PiCircuit<F> {
    /// Creates a new PiCircuit
    pub fn new(
        max_txs: usize,
        max_calldata: usize,
        public_data: PublicData<F>,
        test_public_data: Option<PublicData<F>>,
    ) -> Self {
        Self {
            max_txs,
            max_calldata,
            public_data,
            test_public_data,
            _marker: PhantomData,
        }
    }

    /// create a new PiCircuit with extra data
    /// prover: for l2
    /// txs_rlp: get from l1 contract
    pub fn new_from_block_with_extra(
        block: &witness::Block<F>,
        prover: Address,
        txs_rlp: Bytes,
    ) -> Self {
        PiCircuit::new(
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            PublicData::new(block, prover, txs_rlp),
            None,
        )
    }
}

impl<F: Field> SubCircuit<F> for PiCircuit<F> {
    type Config = PiCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        PiCircuit::new(
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            PublicData::new(block, Address::default(), Bytes::default()),
            None,
        )
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        vec![vec![
            self.public_data.block_hash_hi,
            self.public_data.block_hash_lo,
        ]]
    }

    /// Make the assignments to the PiCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign(
            layouter,
            &self.public_data,
            &self.test_public_data,
            challenges,
        )
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
pub struct PiTestCircuit<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
    pub PiCircuit<F>,
);

#[cfg(any(feature = "test", test))]
impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> Circuit<F>
    for PiTestCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    type Config = PiCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let tx_table = TxTable::construct(meta);
        let rlp_table = array_init::array_init(|_| meta.advice_column());
        let keccak_table = KeccakTable2::construct(meta);
        let challenges = Challenges::mock(100.expr(), 110.expr());
        PiCircuitConfig::new(
            meta,
            PiCircuitConfigArgs {
                max_txs: MAX_TXS,
                max_calldata: MAX_CALLDATA,
                block_table,
                tx_table,
                rlp_table,
                keccak_table,
                challenges,
            },
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // let challenges = challenges.values(&mut layouter);
        let challenges = Challenges::mock(Value::known(F::from(100)), Value::known(F::from(110)));
        let public_data = &self.0.public_data;

        // Include all previous block RLP hashes
        let previous_blocks_rlp: Vec<Vec<u8>> = public_data
            .previous_blocks_rlp
            .clone()
            .into_iter()
            .map(|r| r.to_vec())
            .collect();

        // assign keccak table
        config.keccak_table.dev_load(
            &mut layouter,
            previous_blocks_rlp.iter().chain(
                vec![
                    &public_data.txs_rlp.to_vec(),
                    &public_data.block_rlp.to_vec(),
                    &public_data.blockhash_blk_hdr_rlp.to_vec(),
                ]
                .into_iter(),
            ),
            &challenges,
        )?;

        self.0.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

#[cfg(test)]
mod pi_circuit_test {

    use super::*;

    use crate::test_util::rand_tx;
    use eth_types::{H64, U256, U64};
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };
    use pretty_assertions::assert_eq;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn run<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
        k: u32,
        public_data: PublicData<F>,
        test_public_data: Option<PublicData<F>>,
        pi: Option<Vec<Vec<F>>>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA>(PiCircuit::new(
            MAX_TXS,
            MAX_CALLDATA,
            public_data,
            test_public_data,
        ));
        let public_inputs = pi.unwrap_or_else(|| circuit.0.instance());

        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
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
        let hash_byte_hi: Vec<u8> = circuit
            .0
            .public_data
            .block_hash
            .as_bytes()
            .iter()
            .take(16)
            .copied()
            .collect();
        let hash_byte_lo: Vec<u8> = circuit
            .0
            .public_data
            .block_hash
            .as_bytes()
            .iter()
            .skip(16)
            .copied()
            .collect();
        let _s1 = hex::encode(hash_byte_hi);
        let _s2 = hex::encode(hash_byte_lo);
        Ok(())
    }

    #[test]
    fn test_default_pi() {
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 8;
        let public_data = PublicData::default();

        let k = 18;
        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None),
            Ok(())
        );
    }

    #[test]
    fn test_fail_pi_hash() {
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 8;
        let public_data = PublicData::default();

        let k = 18;
        match run::<Fr, MAX_TXS, MAX_CALLDATA>(
            k,
            public_data,
            None,
            Some(vec![vec![Fr::zero(), Fr::one()]]),
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
    fn test_fail_pi_prover() {
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 8;
        let mut public_data = PublicData::default();
        let address_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        ];

        public_data.prover = Address::from_slice(&address_bytes);

        let prover: Fr = public_data.prover.to_scalar().unwrap();
        let k = 18;
        match run::<Fr, MAX_TXS, MAX_CALLDATA>(
            k,
            public_data,
            None,
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
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;

        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let mut public_data = PublicData::default();
        let chain_id = 1337u64;
        public_data.chain_id = Word::from(chain_id);

        let n_tx = 4;
        for i in 0..n_tx {
            let eth_tx = eth_types::Transaction::from(&rand_tx(&mut rng, chain_id, i & 2 == 0));
            public_data.transactions.push(eth_tx);
        }

        let k = 18;
        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None),
            Ok(())
        );
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
            .append(&block.eth_block.gas_used)
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
        let prover =
            Address::from_slice(&hex::decode("Df08F82De32B8d460adbE8D72043E3a7e25A3B39").unwrap());

        let mut current_block = witness::Block::<Fr>::default();

        current_block.context.history_hashes = vec![U256::zero(); PREVIOUS_BLOCKS_NUM];
        let mut previous_blocks: Vec<witness::Block<Fr>> =
            vec![witness::Block::<Fr>::default(); PREVIOUS_BLOCKS_NUM];
        let mut previous_blocks_rlp: Vec<Bytes> = vec![Bytes::default(); PREVIOUS_BLOCKS_NUM];
        let mut past_block_hash = H256::zero();
        let mut past_block_rlp: Bytes;
        for i in 0..PREVIOUS_BLOCKS_NUM {
            let mut past_block = witness::Block::<Fr>::default();
            past_block.eth_block.parent_hash = past_block_hash;
            (past_block_hash, past_block_rlp) = get_block_header_rlp_from_block(&past_block);

            current_block.context.history_hashes[i] = U256::from(past_block_hash.as_bytes());
            previous_blocks[i] = past_block.clone();
            previous_blocks_rlp[i] = past_block_rlp.clone();
        }

        // Populate current block
        current_block.eth_block.parent_hash = past_block_hash;
        current_block.eth_block.author = Some(prover);
        current_block.eth_block.state_root = H256::zero();
        current_block.eth_block.transactions_root = H256::zero();
        current_block.eth_block.receipts_root = H256::zero();
        current_block.eth_block.logs_bloom = Some([0; LOGS_BLOOM_SIZE].into());
        current_block.eth_block.difficulty = U256::from(0);
        current_block.eth_block.number = Some(U64::from(0));
        current_block.eth_block.gas_limit = U256::from(0);
        current_block.eth_block.gas_used = U256::from(0);
        current_block.eth_block.timestamp = U256::from(0);
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
        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_short_values() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(0x75);
        block.context.gas_limit = 0x76;
        block.eth_block.gas_used = U256::from(0x77);
        block.context.timestamp = U256::from(0x78);
        block.context.base_fee = U256::from(0x79);

        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_one_byte_non_short_values() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(RLP_HDR_NOT_SHORT);
        block.context.gas_limit = RLP_HDR_NOT_SHORT;
        block.eth_block.gas_used = U256::from(RLP_HDR_NOT_SHORT);
        block.context.timestamp = U256::from(RLP_HDR_NOT_SHORT);
        block.context.base_fee = U256::from(RLP_HDR_NOT_SHORT);

        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_one_byte_non_short_values_2() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(0xFF);
        block.context.gas_limit = 0xFF;
        block.eth_block.gas_used = U256::from(0xFF);
        block.context.timestamp = U256::from(0xFF);
        block.context.base_fee = U256::from(0xFF);

        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None),
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
        block.eth_block.gas_used = U256::from(0x92) << (28 * 8);
        block.context.timestamp = U256::from(0x93) << (27 * 8);
        block.context.base_fee = U256::from(0x94) << (26 * 8);

        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None),
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
        block.eth_block.gas_used = U256::from(0x92) << (31 * 8);
        block.context.timestamp = U256::from(0x93) << (31 * 8);
        block.context.base_fee = U256::from(0x94) << (31 * 8);

        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None),
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
        block.eth_block.gas_used = U256::from(0x92) << (31 * 8);
        block.context.timestamp = U256::from(0x93) << (31 * 8);
        block.context.base_fee = U256::from(0x94) << (31 * 8);
        block.eth_block.withdrawals_root = Some(H256::from_slice(
            &hex::decode("61223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49353")
                .unwrap(),
        ));

        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        let (test_block, _, test_previous_blocks, previous_blocks_rlp) = default_test_block();
        let test_public_data = PublicData::new(&test_block, H160::default(), Default::default());
        public_data.previous_blocks = test_previous_blocks;

        match run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, Some(test_public_data), None) {
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
