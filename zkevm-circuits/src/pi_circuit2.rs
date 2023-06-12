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
use eth_types::U64;
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

use crate::table::TxFieldTag;
use crate::table::TxTable;
use crate::table::{BlockTable, KeccakTable2};
use crate::util::{random_linear_combine_word as rlc, Challenges, SubCircuit, SubCircuitConfig};
use crate::witness;
use gadgets::is_zero::IsZeroChip;
use gadgets::util::{and, not, or, Expr};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};
use lazy_static::lazy_static;

/// Fixed by the spec
const TX_LEN: usize = 10;
const BLOCK_LEN: usize = 7 + 256*2 + 16;
const EXTRA_LEN: usize = 2;
const ZERO_BYTE_GAS_COST: u64 = 4;
const NONZERO_BYTE_GAS_COST: u64 = 16;
const MAX_DEGREE: usize = 8;
const BYTE_POW_BASE: u64 = 1 << 8;

const Q_PARENT_HASH_OFFSET: usize = 4;
const Q_BENEFICIARY_OFFSET: usize = Q_PARENT_HASH_OFFSET + 32 + 1 + 32 + 1;
const Q_STATE_ROOT_OFFSET: usize = Q_BENEFICIARY_OFFSET + 20 + 1;
const Q_TX_ROOT_OFFSET: usize = Q_STATE_ROOT_OFFSET + 32 + 1;
const Q_RECEIPTS_ROOT_OFFSET: usize = Q_TX_ROOT_OFFSET + 32 + 1;
const Q_NUMBER_OFFSET: usize = Q_RECEIPTS_ROOT_OFFSET + 32 + 1 + 256 + 3 + 1;
const Q_GAS_LIMIT_OFFSET: usize = Q_NUMBER_OFFSET + 8 + 1;
const Q_GAS_USED_OFFSET: usize = Q_GAS_LIMIT_OFFSET + 32 + 1;
const Q_TIMESTAMP_OFFSET: usize = Q_GAS_USED_OFFSET + 32 + 1;
const Q_MIX_HASH_OFFSET: usize = Q_TIMESTAMP_OFFSET + 32 + 1 + 1;
const Q_BASE_FEE_OFFSET: usize = Q_MIX_HASH_OFFSET + 32 + 1 + 8 + 1;
const Q_WITHDRAWALS_ROOT_OFFSET: usize = Q_BASE_FEE_OFFSET + 32 + 1;
const BLOCKHASH_TOTAL_ROWS: usize = 666;

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
    q_blk_hdr_total_len: Selector,
    blk_hdr_reconstruct_value: Column<Advice>,
    q_parent_hash: Column<Fixed>,
    q_beneficiary: Column<Fixed>,
    q_state_root: Column<Fixed>,
    q_transactions_root: Column<Fixed>,
    q_receipts_root: Column<Fixed>,
    q_number: Column<Fixed>,
    // TODO(George) gas limit is u64 and not u256
    q_gas_limit: Column<Fixed>,
    q_gas_used: Column<Fixed>,
    q_timestamp: Column<Fixed>,
    q_mix_hash: Column<Fixed>,
    q_base_fee_per_gas: Column<Fixed>,
    q_withdrawals_root: Column<Fixed>,
    q_hi: Selector,
    q_lo: Column<Fixed>,
    q_blk_hdr_rlc_start: Selector,
    q_blk_hdr_rlp_end: Selector,
    blk_hdr_rlc_acc: Column<Advice>,
    q_blk_hdr_rlc_acc: Column<Advice>,
    blk_hdr_is_leading_zero: Column<Advice>,
    blk_hdr_rlp_is_short: Column<Advice>,
    blk_hdr_rlp_diff_0x81: Column<Advice>,
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

    // pub withdrawalsRoot: H256,

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

    fn get_block_header_rlp_from_block(block: &witness::Block<F>) -> (Bytes, F, F)
    {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream
            .append(&block.eth_block.parent_hash)
            .append(&*OMMERS_HASH)
            .append(&block.eth_block.author.unwrap_or_else(H160::zero))
            .append(&block.eth_block.state_root)
            .append(&block.eth_block.transactions_root)
            .append(&block.eth_block.receipts_root)
            .append(&vec![0u8; 256]) // logs_bloom is all zeros
            .append(&block.context.difficulty)
            .append(&block.context.number.low_u64())
            .append(&block.context.gas_limit)
            .append(&block.eth_block.gas_used)
            .append(&block.context.timestamp);
        rlp_opt(&mut stream, &None::<u8>); // extra_data = ""
        stream
            .append(&block.eth_block.mix_hash.unwrap_or_else(H256::zero))
            .append(&vec![0u8; 8]) // nonce = 0
            .append(&block.context.base_fee);

        // TODO(George): can't find withdrawals_root in eth_block, use zeros for now
        // rlp_opt(&mut stream, &block.withdrawals_root);
        stream.append(&vec![0; 32]);

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
        let (blockhash_blk_hdr_rlp, blockhash_rlp_hash_hi, blockhash_rlp_hash_lo) = Self::get_block_header_rlp_from_block(block);

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
            blockhash_blk_hdr_rlp: blockhash_blk_hdr_rlp,
            blockhash_rlp_hash_hi: blockhash_rlp_hash_hi,
            blockhash_rlp_hash_lo: blockhash_rlp_hash_lo,
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
            // TODO(George): withdrawalsRoot: block.eth_block.,
        }
    }

    /// Returns struct with values for the block table
    pub fn get_block_table_values(&self) -> BlockValues {
        let history_hashes = [
            vec![U256::zero(); 256 - self.history_hashes.len()],
            self.history_hashes
                .iter()
                .map(|&hash| hash)
                .collect(),
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
            history_hashes: history_hashes
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
        let q_blk_hdr_total_len = meta.complex_selector();
        let blk_hdr_reconstruct_value = meta.advice_column();
        let blk_hdr_is_leading_zero = meta.advice_column();
        let blk_hdr_rlp_is_short = meta.advice_column();
        let blk_hdr_rlp_diff_0x81 = meta.advice_column();

        // Enum for selecting header fields. The cases are:
        // let blk_hdr_field_select = meta.fixed_column();
        // Selectors for each header field.
        let q_parent_hash = meta.fixed_column();
        let q_beneficiary = meta.fixed_column();
        let q_state_root = meta.fixed_column();
        let q_transactions_root = meta.fixed_column();
        let q_receipts_root = meta.fixed_column();
        let q_number = meta.fixed_column();
        let q_gas_limit = meta.fixed_column();
        let q_gas_used = meta.fixed_column();
        let q_timestamp = meta.fixed_column();
        let q_mix_hash = meta.fixed_column();
        let q_base_fee_per_gas = meta.fixed_column();
        let q_withdrawals_root = meta.fixed_column();
        // We use `q_hi` and `q_lo` to distinguish the 16 MSB from the 16 LSB for fields with length of 32 bytes
        let q_hi = meta.complex_selector();
        let q_lo = meta.fixed_column();

        let q_blk_hdr_rlc_start = meta.complex_selector();
        let q_blk_hdr_rlc_acc = meta.advice_column();
        let blk_hdr_rlc_acc = meta.advice_column();

        let blockhash_cols = BlockhashColumns {
            blk_hdr_rlp,
            blk_hdr_rlp_inv,
            blk_hdr_rlp_const,
            q_blk_hdr_rlp,
            q_blk_hdr_rlp_const,
            blk_hdr_rlp_len_calc,
            blk_hdr_rlp_len_calc_inv,
            q_blk_hdr_total_len,
            blk_hdr_reconstruct_value,
            q_parent_hash,
            q_beneficiary,
            q_state_root,
            q_transactions_root,
            q_receipts_root,
            q_number,
            q_gas_limit,
            q_gas_used,
            q_timestamp,
            q_mix_hash,
            q_base_fee_per_gas,
            q_withdrawals_root,
            q_hi,
            q_lo,
            q_blk_hdr_rlc_start,
            q_blk_hdr_rlp_end,
            blk_hdr_rlc_acc,
            q_blk_hdr_rlc_acc,
            blk_hdr_is_leading_zero,
            blk_hdr_rlp_is_short,
            blk_hdr_rlp_diff_0x81,
        };

        let pi = meta.instance_column();

        meta.enable_equality(rpi);
        meta.enable_equality(rpi_rlc_acc);
        meta.enable_equality(rpi_encoding);
        meta.enable_equality(pi);
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

        let offset = BLOCK_LEN + 1 + EXTRA_LEN + 3;
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

        // 1. Block header RLP
        meta.lookup_any("Block header RLP: byte range checks", |meta| {
            let block_header_rlp = meta.query_advice(blk_hdr_rlp, Rotation::cur());
            let fixed_u8_table = meta.query_fixed(fixed_u8, Rotation::cur());

            vec![(block_header_rlp, fixed_u8_table)]
        });

        meta.create_gate("Block header RLP: constant checks", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_blk_hdr_rlp = meta.query_selector(q_blk_hdr_rlp);
            let q_blk_hdr_rlp_const = meta.query_selector(q_blk_hdr_rlp_const);
            let blk_hdr_rlp = meta.query_advice(blk_hdr_rlp, Rotation::cur());
            let blk_hdr_rlp_const = meta.query_fixed(blk_hdr_rlp_const, Rotation::cur());

            cb.require_equal("RLP hdr costants are correct", blk_hdr_rlp, blk_hdr_rlp_const);
            cb.gate(and::expr([q_blk_hdr_rlp, q_blk_hdr_rlp_const]))
        });

        // Make sure that length starts from 0
        meta.create_gate("Block header RLP: length default value = 0", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let length = meta.query_advice(blk_hdr_rlp_len_calc, Rotation::cur());
            cb.require_zero("length default value is zero", length);

            cb.gate(and::expr([
                not::expr(or::expr([
                    meta.query_fixed(q_number, Rotation::cur()),
                    meta.query_fixed(q_gas_limit, Rotation::cur()),
                    meta.query_fixed(q_gas_used, Rotation::cur()),
                    meta.query_fixed(q_timestamp, Rotation::cur()),
                    meta.query_fixed(q_base_fee_per_gas, Rotation::cur()),
                ])),
                meta.query_selector(q_blk_hdr_rlp),
            ]))
        });

        meta.create_gate("Block header RLP: leading zeros column is boolean", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let blk_hdr_is_leading_zero = meta.query_advice(blk_hdr_is_leading_zero, Rotation::cur());
            cb.require_boolean("blk_hdr_is_leading_zero is boolean", blk_hdr_is_leading_zero);

            cb.gate(meta.query_selector(q_blk_hdr_rlp))
        });

        let blk_hdr_rlp_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_blk_hdr_rlp),
            |meta| meta.query_advice(blk_hdr_rlp, Rotation::cur()),
            blk_hdr_rlp_inv,
        );

        let blk_hdr_rlp_length_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_blk_hdr_rlp),
            |meta| meta.query_advice(blk_hdr_rlp_len_calc, Rotation::cur()),
            blk_hdr_rlp_len_calc_inv,
        );

        for q_field in [
            q_number,
            q_gas_limit,
            q_gas_used,
            q_timestamp,
            q_base_fee_per_gas,
        ] {
            meta.create_gate("Block header RLP: leading zeros checks", |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                let blk_hdr_rlp_cur = meta.query_advice(blk_hdr_rlp, Rotation::cur());
                let blk_hdr_is_leading_zero_cur = meta.query_advice(blk_hdr_is_leading_zero, Rotation::cur());
                let blk_hdr_is_leading_zero_prev = meta.query_advice(blk_hdr_is_leading_zero, Rotation::prev());

                let q_field_cur = meta.query_fixed(q_field, Rotation::cur());
                let q_number_prev = meta.query_fixed(q_number, Rotation::prev());
                let q_gas_limit_prev = meta.query_fixed(q_gas_limit, Rotation::prev());
                let q_gas_used_prev = meta.query_fixed(q_gas_used, Rotation::prev());
                let q_timestamp_prev = meta.query_fixed(q_timestamp, Rotation::prev());
                let q_base_fee_per_gas_prev = meta.query_fixed(q_base_fee_per_gas, Rotation::prev());

                cb.require_zero("Leading zero is actually zero", blk_hdr_rlp_cur);
                cb.require_equal("Leading zeros must be continuous or we are at the begining of the field",
                                1.expr(),
                                or::expr([
                                    blk_hdr_is_leading_zero_prev,
                                    or::expr([not::expr(q_number_prev),
                                              not::expr(q_gas_limit_prev),
                                              not::expr(q_gas_used_prev),
                                              not::expr(q_timestamp_prev),
                                              not::expr(q_base_fee_per_gas_prev),
                                        ])]));

                cb.gate(and::expr([
                                blk_hdr_is_leading_zero_cur,
                                q_field_cur,
                            ]))
            });
        }

        // Covers a corner case where LSB leading zeros can be skipped.
        // This can occur when `blk_hdr_is_leading_zero` is set to 0 wrongly (the actual byte value is non-zero)
        meta.create_gate("Block header RLP: last leading zeros check", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let blk_hdr_is_leading_zero = meta.query_advice(blk_hdr_is_leading_zero, Rotation::cur());

            cb.condition(not::expr(blk_hdr_rlp_is_zero.expr()),
                    |cb| {
                        cb.require_zero("Leading zeros cannot be skipped",blk_hdr_is_leading_zero);
            });

            cb.gate(meta.query_selector(q_blk_hdr_rlp))
        });

        // Length calc checks for all variable length fields:
        // 1. len = 0 for leading zeros
        // 2. len = len_prev + 1 otherwise
        // 3. total_len = 0 if value <= 0x80
        for q_value in [q_number, q_gas_limit, q_gas_used, q_timestamp, q_base_fee_per_gas] {
            meta.create_gate("Block header RLP: length calculation", |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                let length = meta.query_advice(blk_hdr_rlp_len_calc, Rotation::cur());
                let length_prev = meta.query_advice(blk_hdr_rlp_len_calc, Rotation::prev());
                let blk_hdr_is_leading_zero = meta.query_advice(blk_hdr_is_leading_zero, Rotation::cur());
                let field_sel = meta.query_fixed(q_value, Rotation::cur());
                let field_sel_next = meta.query_fixed(q_value, Rotation::next());
                let total_len_is_zero = and::expr([not::expr(field_sel_next), blk_hdr_rlp_length_is_zero.expr()]);

                let rlp_is_short = meta.query_advice(blk_hdr_rlp_is_short, Rotation::cur());

                cb.condition(blk_hdr_is_leading_zero.expr(),
                    |cb| {
                        cb.require_zero("Length is zero on a leading zero", length.clone());
                });

                cb.condition(and::expr([not::expr(blk_hdr_is_leading_zero.clone()),
                                        not::expr(total_len_is_zero.clone())]),
                    |cb| {
                        cb.require_equal("len = len_prev + 1", length.clone(), length_prev + 1.expr());
                });

                cb.condition(rlp_is_short,
                    |cb| {
                        cb.require_zero("Length is zero on a leading zero", length.clone());
                });

                cb.gate(field_sel)
            });
        }

        for q_value in [q_number, q_gas_limit, q_gas_used, q_timestamp, q_base_fee_per_gas] {
            meta.create_gate("Block header RLP: rlp_is_short checks", |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
                let field_sel = meta.query_fixed(q_value, Rotation::cur());
                let field_sel_next = meta.query_fixed(q_value, Rotation::next());
                let rlp_is_short = meta.query_advice(blk_hdr_rlp_is_short, Rotation::cur());
                let rlp_diff_0x81 = meta.query_advice(blk_hdr_rlp_diff_0x81, Rotation::cur());
                let blk_hdr_rlp = meta.query_advice(blk_hdr_rlp, Rotation::cur());
                let prev_length_is_zero = 1.expr() - meta.query_advice(blk_hdr_rlp_len_calc, Rotation::prev()) * meta.query_advice(blk_hdr_rlp_len_calc_inv, Rotation::prev());

                cb.condition(field_sel_next.clone(),
                    |cb| {
                        cb.require_zero("rlp_is_short can only be enabled at the last byte of the field", rlp_is_short.clone());
                });

                cb.condition(and::expr([not::expr(field_sel_next),
                                        prev_length_is_zero]),
                    |cb| {
                        cb.require_equal("rlp byte <= 0x80 -> rlp_is_short, else NOT(rlp_is_short)",
                                         0x81.expr() - blk_hdr_rlp,
                                         rlp_diff_0x81 - (1.expr() - rlp_is_short)*((2<<8)-1).expr());
                });

                cb.gate(field_sel)
            });
        }

        meta.lookup_any("Block header RLP: rlp_diff_0x81 is byte", |meta| {
            let rlp_diff_0x81 = meta.query_advice(blk_hdr_rlp_diff_0x81, Rotation::cur());
            let fixed_u8_table = meta.query_fixed(fixed_u8, Rotation::cur());
            vec![(rlp_diff_0x81, fixed_u8_table)]
        });

        meta.create_gate("Block header RLP: rlp_is_short is boolean", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let rlp_is_short = meta.query_advice(blk_hdr_rlp_is_short, Rotation::cur());
            cb.require_boolean("rlp_is_short is boolean", rlp_is_short);
            cb.gate(meta.query_selector(q_blk_hdr_rlp))
        });

        meta.create_gate("Block header RLP: check RLP header for `number`", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_number_cur = meta.query_fixed(q_number, Rotation::cur());
            let q_number_next = meta.query_fixed(q_number, Rotation::next());
            let total_length = meta.query_advice(blk_hdr_rlp_len_calc, Rotation(8));
            let cur_byte = meta.query_advice(blk_hdr_rlp, Rotation::cur());

            cb.require_equal("blk_hdr_rlp = 0x80 + Len(number)", cur_byte, 0x80.expr() + total_length);

            cb.gate(and::expr([q_number_next, not::expr(q_number_cur)]))
        });

        for q_field in [
                        q_gas_limit,
                        q_gas_used,
                        q_timestamp,
                        q_base_fee_per_gas] {
            meta.create_gate("Block header RLP: check RLP headers for `gas_limit`, `gas_used`, `timestamp`, `base_fee`", |meta| {
                let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                let blk_hdr_rlp = meta.query_advice(blk_hdr_rlp, Rotation::cur());
                let q_field_cur = meta.query_fixed(q_field, Rotation::cur());
                let q_field_next = meta.query_fixed(q_field, Rotation::next());

                // All these fields have their lengths calculated 32 rows away
                cb.condition(q_field_next.clone(),
                    |cb| {
                        cb.require_equal("blk_hdr_rlp = 0x80 + Len(<field>)", blk_hdr_rlp, 0x80.expr() + meta.query_advice(blk_hdr_rlp_len_calc, Rotation(32)));
                    }
                );
                // Enable when the selectors switch from 0 to 1
                cb.gate(and::expr([q_field_next, not::expr(q_field_cur)]))
            });
        }

        meta.create_gate("Block header RLP: check total length", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let total_len = meta.query_advice(blk_hdr_rlp, Rotation::cur());
            let number_len = meta.query_advice(blk_hdr_rlp_len_calc, Rotation((Q_NUMBER_OFFSET +8 -3).try_into().unwrap()));
            let gas_limit_len = meta.query_advice(blk_hdr_rlp_len_calc, Rotation((Q_GAS_LIMIT_OFFSET +32 -3).try_into().unwrap()));
            let gas_used_len = meta.query_advice(blk_hdr_rlp_len_calc, Rotation((Q_GAS_USED_OFFSET +32-3).try_into().unwrap()));
            let timestamp_len = meta.query_advice(blk_hdr_rlp_len_calc, Rotation((Q_TIMESTAMP_OFFSET +32 -3).try_into().unwrap()));
            let base_fee_len = meta.query_advice(blk_hdr_rlp_len_calc, Rotation((Q_BASE_FEE_OFFSET +32 -3).try_into().unwrap()));

            // For the block header, the total RLP length is always two bytes long and only
            // the LSB fluctuates: Minimum total length: lengths of all the
            // fixed size fields + all the RLP headers = 527 bytes (0x020F)
            // Maximum total length: minimum total length + (maximum length of variable zize
            // field) = 527 + 4*32+1*8 = 663 (0x0297) Actual total length:
            // minimum total length + length of all variable size fields (number, gas_limit,
            // gas_used, timestamp, base fee)
            cb.require_equal(
                "LSB(total_len) = min(LSB(total_len)) + sum(Len(<var field>))",
                total_len,
                0x0F.expr()
                    + number_len
                    + gas_limit_len
                    + gas_used_len
                    + timestamp_len
                    + base_fee_len,
            );

            cb.gate(meta.query_selector(q_blk_hdr_total_len))
        });

        // Reconstruct field values
        for selector in [q_parent_hash,
                         q_beneficiary,
                         q_state_root,
                         q_transactions_root,
                         q_receipts_root,
                         q_number,
                         q_gas_limit,
                         q_gas_used,
                         q_timestamp,
                         q_mix_hash,
                         q_base_fee_per_gas,
                         q_withdrawals_root] {
            meta.create_gate(
                "Block header RLP: reconstructing header field values from RLP",
                |meta| {
                    let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                    let q_hi = meta.query_selector(q_hi);
                    let q_lo_cur = meta.query_fixed(q_lo, Rotation::cur());
                    let q_lo_prev = meta.query_fixed(q_lo, Rotation::prev());

                    let selector = meta.query_fixed(selector, Rotation::cur());
                    let blk_hdr_rlp = meta.query_advice(blk_hdr_rlp, Rotation::cur());
                    let blk_hdr_reconstruct_value_cur = meta.query_advice(blk_hdr_reconstruct_value, Rotation::cur());
                    let blk_hdr_reconstruct_value_prev = meta.query_advice(blk_hdr_reconstruct_value, Rotation::prev());

                    cb.condition(and::expr([selector.clone(), q_hi.clone()]),
                        |cb| {
                            cb.require_equal(
                                "byte_hi[n]*2^8 + byte_hi[n+1]",
                                blk_hdr_reconstruct_value_cur.clone(),
                                blk_hdr_reconstruct_value_prev.clone() * 256.expr() + blk_hdr_rlp.clone(),
                            )
                        },
                    );

                    // At the start of the value reconstruction for the lo parts, the previous value
                    // in `blk_hdr_reconstruct_value` is not zero. We need to explicitly set the first value here
                    cb.condition(
                        and::expr([q_lo_cur.clone(), not::expr(q_lo_prev.clone())]),
                        |cb| {
                            cb.require_equal(
                                "byte_lo[0] == rlp_byte",
                                blk_hdr_reconstruct_value_cur.clone(),
                                blk_hdr_rlp.clone(),
                            )
                        },
                    );

                    cb.condition(and::expr([q_lo_cur, q_lo_prev]), |cb| {
                        cb.require_equal(
                            "byte_lo[n]*2^8 + byte_lo[n+1]",
                            blk_hdr_reconstruct_value_cur,
                            blk_hdr_reconstruct_value_prev * 256.expr() + blk_hdr_rlp,
                        )
                    });

                    cb.gate(and::expr([meta.query_selector(q_blk_hdr_total_len), selector]))
            });
        }

        for q_field in [q_parent_hash,
                        q_beneficiary,
                        q_state_root,
                        q_transactions_root,
                        q_receipts_root,
                        q_number,
                        q_gas_limit,
                        q_gas_used,
                        q_timestamp,
                        q_mix_hash,
                        q_base_fee_per_gas,
                        q_withdrawals_root] {
            meta.create_gate(
                "Block header RLP: reconstructing value starts from 0",
                |meta| {
                    let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

                    cb.require_zero(
                        "blk_hdr_reconstruct_value defaults to 0",
                        meta.query_advice(blk_hdr_reconstruct_value, Rotation::cur()),
                    );

                    cb.gate(and::expr([meta.query_selector(q_blk_hdr_total_len), not::expr(meta.query_fixed(q_field, Rotation::cur()))]))
            });
        };

        // TODO(George): add withdrawals_root
        // TODO(George): check q_parent_hash
        for sel in [q_beneficiary, q_number, q_gas_limit, q_parent_hash, q_state_root, q_transactions_root, q_receipts_root, q_gas_used, q_timestamp, q_mix_hash, q_base_fee_per_gas] {
            meta.lookup_any("Block header: Check reconstructed values for the lo parts of fields and for fields without hi/lo", |meta| {
                let q_sel = and::expr([
                                meta.query_fixed(sel, Rotation::cur()),
                                not::expr(meta.query_fixed(sel, Rotation::next())),
                ]);
                vec![
                    (
                        q_sel.clone().expr() * meta.query_advice(blk_hdr_reconstruct_value, Rotation::cur()),
                        meta.query_advice(block_table.value, Rotation::cur()),
                    ),
                ]
            });
        }

        // TODO(George): add withdrawals_root
        // TODO(George): check q_parent_hash
        for sel in [q_parent_hash, q_state_root, q_transactions_root, q_receipts_root, q_gas_used, q_timestamp, q_mix_hash, q_base_fee_per_gas] {
            meta.lookup_any("Block header: check reconstructed values for the hi parts of fields", |meta| {
                let q_sel = and::expr([
                                meta.query_fixed(sel, Rotation::cur()),
                                meta.query_selector(q_hi),
                                meta.query_fixed(q_lo, Rotation::next()),
                ]);
                vec![
                    (
                        q_sel.expr() * meta.query_advice(blk_hdr_reconstruct_value, Rotation::cur()),
                        meta.query_advice(block_table.value, Rotation::cur()),
                    )
                ]
            });
        }

        // 2. Check RLC of RLP'd block header
        // Accumulate only bytes that have q_blk_hdr_rlp AND NOT(blk_hdr_is_leading_zero) and skip RLP headers if value is <0x80

        meta.create_gate("Block header RLC: `q_blk_hdr_rlp` is boolean", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_blk_hdr_rlp = meta.query_selector(q_blk_hdr_rlp);
            let q_blk_hdr_rlc_acc = meta.query_advice(q_blk_hdr_rlc_acc, Rotation::cur());

            cb.require_boolean("`q_blk_hdr_rlc_acc` is boolean", q_blk_hdr_rlc_acc);

            cb.gate(q_blk_hdr_rlp)
        });

        meta.create_gate("Block header RLC: initialize accumulator", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_blk_hdr_rlc_start = meta.query_selector(q_blk_hdr_rlc_start);
            let blk_hdr_rlp_rlc_acc = meta.query_advice(blk_hdr_rlc_acc, Rotation::cur());
            let blk_hdr_rlp = meta.query_advice(blk_hdr_rlp, Rotation::cur());

            cb.require_equal("blk_hdr_rlp_rlc_acc[0] = blk_hdr_rlp[0]", blk_hdr_rlp_rlc_acc, blk_hdr_rlp);

            cb.gate(q_blk_hdr_rlc_start)
        });

        meta.create_gate("Block header RLC: RLC calculation", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_blk_hdr_rlp = meta.query_selector(q_blk_hdr_rlp);
            let q_blk_hdr_rlc_acc = meta.query_advice(q_blk_hdr_rlc_acc, Rotation::cur());
            let q_blk_hdr_rlp_end = meta.query_selector(q_blk_hdr_rlp_end);
            let blk_hdr_rlc_acc_next = meta.query_advice(blk_hdr_rlc_acc, Rotation::next());
            let blk_hdr_rlc_acc = meta.query_advice(blk_hdr_rlc_acc, Rotation::cur());
            let blk_hdr_rlp_next = meta.query_advice(blk_hdr_rlp, Rotation::next());

            let r = challenges.evm_word();

            cb.require_equal("rlc_acc_next = rlc_acc * r + next_byte", blk_hdr_rlc_acc_next, blk_hdr_rlc_acc * r + blk_hdr_rlp_next);

            cb.gate(and::expr([q_blk_hdr_rlp, q_blk_hdr_rlc_acc, not::expr(q_blk_hdr_rlp_end)]))
        });

        meta.create_gate("Block header RLC: skip leading zeros and artificial RLP headers", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_blk_hdr_rlp = meta.query_selector(q_blk_hdr_rlp);
            let q_blk_hdr_rlp_end = meta.query_selector(q_blk_hdr_rlp_end);
            let q_blk_hdr_rlc_acc = meta.query_advice(q_blk_hdr_rlc_acc, Rotation::cur());
            let blk_hdr_rlp_rlc_acc_next = meta.query_advice(blk_hdr_rlc_acc, Rotation::next());
            let blk_hdr_rlp_rlc_acc = meta.query_advice(blk_hdr_rlc_acc, Rotation::cur());

            cb.require_equal("rlc_acc_next = rlc_acc", blk_hdr_rlp_rlc_acc_next, blk_hdr_rlp_rlc_acc);

            cb.gate(and::expr([q_blk_hdr_rlp, not::expr(q_blk_hdr_rlc_acc), not::expr(q_blk_hdr_rlp_end)]))
        });

        // 3. Check block header hash
        meta.lookup_any("blockhash lookup keccak", |meta| {
            let q_blk_hdr_rlp_end = meta.query_selector(q_blk_hdr_rlp_end);

            let blk_hdr_rlc = meta.query_advice(blk_hdr_rlc_acc, Rotation::cur());
            // The total RLP lenght is the RLP list length (0x200 + blk_hdr_rlp[2]) + 3 bytes for the RLP list header
            let blk_hdr_rlp_len = 0x200.expr() + meta.query_advice(blk_hdr_rlp, Rotation(-(BLOCKHASH_TOTAL_ROWS as i32)+1+2)) + 0x03.expr();
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
                    q_blk_hdr_rlp_end.expr() * blk_hdr_rlp_len,
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

            blockhash_cols,

            _marker: PhantomData,
        }
    }
}

impl<F: Field> PiCircuitConfig<F> {
    /// Return the number of rows in the circuit
    #[inline]
    fn circuit_block_len(&self) -> usize {
        // +1 empty row in block table
        // +3 prover, txs_hash_hi, txs_hash_lo
        // EXTRA_LEN: state_root, prev_root
        // total = 269
        BLOCK_LEN + 1 + EXTRA_LEN + 3
    }

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

        let id_offset = self.circuit_block_len();
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
            offset + value_offset + self.circuit_block_len(),
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
        challenges: &Challenges<Value<F>>,
    ) -> Result<
        (
            AssignedCell<F, F>, // block hash hi
            AssignedCell<F, F>, // block hash lo
            AssignedCell<F, F>, // txs hash hi
            AssignedCell<F, F>, // txs hash lo
            Value<F>,           // block_rlc_acc
        ),
        Error,
    > {
        let block_values = public_data.get_block_table_values();
        let extra_values = public_data.get_extra_values();
        let randomness = challenges.evm_word();
        self.q_start.enable(region, 0)?;
        let mut rlc_acc = Value::known(F::zero());
        let mut cells = vec![];
        let beneficiary_value = Value::known(public_data.beneficiary.as_fixed_bytes().iter().fold(F::zero(),
                                |mut acc, &x| {
                                    for _ in 0..8 {
                                        acc = acc.double();
                                    }
                                    acc += F::from(x as u64);
                                    acc
                                }));

        for (offset, (name, val, not_in_table)) in [
            ("zero", Value::known(F::zero()), false),
            (
                "coinbase",
                Value::known(block_values.coinbase.to_scalar().unwrap()),
                false,
            ),
            (
                "gas_limit",
                Value::known(F::from(block_values.gas_limit)),
                false,
            ),
            ("number", Value::known(F::from(block_values.number)), false),
            (
                "timestamp",
                randomness.map(|randomness| rlc(block_values.timestamp.to_le_bytes(), randomness)),
                false,
            ),
            (
                "difficulty",
                randomness.map(|randomness| rlc(block_values.difficulty.to_le_bytes(), randomness)),
                false,
            ),
            (
                "base_fee",
                randomness.map(|randomness| rlc(block_values.base_fee.to_le_bytes(), randomness)),
                false,
            ),
            (
                "chain_id",
                Value::known(F::from(block_values.chain_id)),
                false,
            ),
        ]
        .into_iter()
        .chain(block_values.history_hashes.iter().map(|h| {
            (
                "prev_hash_hi",
                Value::known(F::from_u128(u128::from_be_bytes(h.to_be_bytes()[0..16].try_into().unwrap()))),
                false,
            )
        }))
        .chain(block_values.history_hashes.iter().map(|h| {
            (
                "prev_hash_lo",
                Value::known(F::from_u128(u128::from_be_bytes(h.to_be_bytes()[16..32].try_into().unwrap()))),
                false,
            )
        }))
        .chain([
            (
                "beneficiary",
                beneficiary_value,
                false,
            ),
            (
                "state_root_hi",
                Value::known(F::from_u128(u128::from_be_bytes(public_data.state_root.to_fixed_bytes()[0..16].try_into().unwrap()))),
                false,
            ),
            (
                "state_root_lo",
                Value::known(F::from_u128(u128::from_be_bytes(public_data.state_root.to_fixed_bytes()[16..32].try_into().unwrap()))),
                false,
            ),
            (
                "transactions_root_hi",
                Value::known(F::from_u128(u128::from_be_bytes(public_data.transactions_root.to_fixed_bytes()[0..16].try_into().unwrap()))),
                false,
            ),
            (
                "transactions_root_lo",
                Value::known(F::from_u128(u128::from_be_bytes(public_data.transactions_root.to_fixed_bytes()[16..32].try_into().unwrap()))),
                false,
            ),
            (
                "receipts_root_hi",
                Value::known(F::from_u128(u128::from_be_bytes(public_data.receipts_root.to_fixed_bytes()[0..16].try_into().unwrap()))),
                false,
            ),
            (
                "receipts_root_lo",
                Value::known(F::from_u128(u128::from_be_bytes(public_data.receipts_root.to_fixed_bytes()[16..32].try_into().unwrap()))),
                false,
            ),
            (
                "number",
                Value::known(F::from(block_values.number)),
                false,
            ),
            (
                "gas_used_hi",
                Value::known(F::from_u128(u128::from_be_bytes(public_data.gas_used.to_be_bytes()[0..16].try_into().unwrap()))),
                false,
            ),
            (
                "gas_used_lo",
                Value::known(F::from_u128(u128::from_be_bytes(public_data.gas_used.to_be_bytes()[16..32].try_into().unwrap()))),
                false,
            ),
            (
                "timestamp_hi",
                Value::known(F::from_u128(u128::from_be_bytes(block_values.timestamp.to_be_bytes()[0..16].try_into().unwrap()))),
                false,
            ),
            (
                "timestamp_lo",
                Value::known(F::from_u128(u128::from_be_bytes(block_values.timestamp.to_be_bytes()[16..32].try_into().unwrap()))),
                false,
            ),
            (
                "mix_hash_hi",
                Value::known(F::from_u128(u128::from_be_bytes(public_data.mix_hash.to_fixed_bytes()[0..16].try_into().unwrap()))),
                false,
            ),
            (
                "mix_hash_lo",
                Value::known(F::from_u128(u128::from_be_bytes(public_data.mix_hash.to_fixed_bytes()[16..32].try_into().unwrap()))),
                false,
            ),
            (
                "base_fee_hi",
                Value::known(F::from_u128(u128::from_be_bytes(block_values.base_fee.to_be_bytes()[0..16].try_into().unwrap()))),
                false,
            ),
            (
                "base_fee_lo",
                Value::known(F::from_u128(u128::from_be_bytes(block_values.base_fee.to_be_bytes()[16..32].try_into().unwrap()))),
                false,
            ),
            // TODO(George): add withdrawals root
            // (
            //     "withdrawals_root_hi",
            //     Value::known(F::from_u128(u128::from_be_bytes(public_data.withdrawals_root.to_fixed_bytes()[0..16].try_into().unwrap()))),
            //     false,
            // ),
            // (
            //     "withdrawals_root_lo",
            //     Value::known(F::from_u128(u128::from_be_bytes(public_data.withdrawals_root.to_fixed_bytes()[16..32].try_into().unwrap()))),
            //     false,
            // ),
        ])
        .chain([
            (
                "state.root",
                randomness.map(|v| rlc(extra_values.state_root.to_fixed_bytes(), v)),
                false,
            ),
            (
                "parent_block.hash",
                randomness.map(|v| rlc(extra_values.prev_state_root.to_fixed_bytes(), v)),
                false,
            ),
            (
                "prover",
                Value::known(public_data.prover.to_scalar().unwrap()),
                true,
            ),
            ("txs_hash_hi", Value::known(public_data.txs_hash_hi), true),
            ("txs_hash_lo", Value::known(public_data.txs_hash_lo), true),
        ])
        .enumerate()
        {
            if offset < self.circuit_block_len() - 1 {
                self.q_not_end.enable(region, offset)?;
            }
            let val_cell = region.assign_advice(|| name, self.rpi, offset, || val)?;
            rlc_acc = rlc_acc * randomness + val;
            region.assign_advice(|| name, self.rpi_rlc_acc, offset, || rlc_acc)?;
            if not_in_table {
                cells.push(val_cell);
            } else {
                self.q_block_table.enable(region, offset)?;
                region.assign_advice(|| name, self.block_table.value, offset, || val)?;
            }
        }

        let mut offset = 0;
        self.q_rpi_encoding.enable(region, offset)?;
        region.assign_advice(|| "block_rlc_acc", self.rpi_encoding, offset, || rlc_acc)?;
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

        Ok((
            block_hash_hi_cell,
            block_hash_lo_cell,
            cells[1].clone(),
            cells[2].clone(),
            rlc_acc,
        ))
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
                    .enable(region, offset + self.circuit_block_len())?;
            }
            rlc_acc = rlc_acc * r + val;
            region.assign_advice(
                || "txs_rlc_acc",
                self.rpi_rlc_acc,
                offset + self.circuit_block_len(),
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

    fn get_block_header_rlp_from_public_data(
        public_data: &PublicData<F>,
        challenges: &Challenges<Value<F>>,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<Value<F>>, Value<F>, Value<F>) {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream
            .append(&public_data.parent_hash)
            .append(&*OMMERS_HASH)
            .append(&public_data.beneficiary)
            .append(&public_data.state_root)
            .append(&public_data.transactions_root)
            .append(&public_data.receipts_root)
            .append(&vec![0u8; 256]) // logs_bloom is all zeros
            .append(&public_data.block_constants.difficulty)
            .append(&public_data.block_constants.number)
            .append(&public_data.block_constants.gas_limit)
            .append(&public_data.gas_used)
            .append(&public_data.block_constants.timestamp);
        rlp_opt(&mut stream, &None::<u8>); // extra_data = ""
        stream
            .append(&public_data.mix_hash)
            .append(&vec![0u8; 8]) // nonce = 0
            .append(&public_data.block_constants.base_fee);

        // TODO(George): can't find withdrawals_root in eth_block, use zeros for now
        // rlp_opt(&mut stream, &block.withdrawals_root);
        stream.append(&vec![0; 32]);

        stream.finalize_unbounded_list();
        let out: bytes::Bytes = stream.out().into();

        // Calculate hash
        let rlp: Bytes = out.clone().into();
        let hash = keccak256(&rlp);
        let hash_hi = hash.iter().take(16).fold(F::zero(), |acc, byte| {
            acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
        });
        let hash_lo = hash.iter().skip(16).fold(F::zero(), |acc, byte| {
            acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
        });

        let mut out_vec: Vec<u8> = out.into();
        let mut leading_zeros: Vec<u8> = vec![0; out_vec.len()];
        let mut q_blk_hdr_rlc_acc: Vec<u8> = vec![1; out_vec.len()];
        let mut blk_hdr_rlc_acc: Vec<Value<F>> = vec![];

        let randomness = challenges.evm_word();
        out_vec.iter().map(|b| Value::known(F::from(*b as u64)))
                      .fold(Value::known(F::zero()), |mut rlc_acc, byte| {
                              rlc_acc = rlc_acc * randomness + byte;
                              blk_hdr_rlc_acc.push(rlc_acc);
                              rlc_acc
                          });

        // We handle `number` outside of the for due to the type difference
        // For explanation of the below refer to the following for loop documentation
        if public_data.block_constants.number <= U64::from(0x80) {
            if public_data.block_constants.number != U64::zero() {
                out_vec.splice(Q_NUMBER_OFFSET-1..Q_NUMBER_OFFSET-1, [0x80]);
                q_blk_hdr_rlc_acc.splice(Q_NUMBER_OFFSET-2..Q_NUMBER_OFFSET-2, [0]);
                blk_hdr_rlc_acc.splice(Q_NUMBER_OFFSET-1..Q_NUMBER_OFFSET-1, [blk_hdr_rlc_acc[Q_NUMBER_OFFSET-2]]);
            }
            leading_zeros.splice(Q_NUMBER_OFFSET-1..Q_NUMBER_OFFSET-1, [0]);
        }
        out_vec.splice(Q_NUMBER_OFFSET..Q_NUMBER_OFFSET, vec![0; (public_data.block_constants.number.leading_zeros() / 8) as usize]);
        leading_zeros.splice(Q_NUMBER_OFFSET..Q_NUMBER_OFFSET, vec![1; (public_data.block_constants.number.leading_zeros() / 8) as usize]);
        q_blk_hdr_rlc_acc.splice(Q_NUMBER_OFFSET-1..Q_NUMBER_OFFSET-1, vec![0; (public_data.block_constants.number.leading_zeros() / 8) as usize]);
        blk_hdr_rlc_acc.splice(Q_NUMBER_OFFSET..Q_NUMBER_OFFSET, vec![blk_hdr_rlc_acc[Q_NUMBER_OFFSET-1]; (public_data.block_constants.number.leading_zeros() / 8) as usize]);

        // Handles leading zeros, short values and calculates the values for `blk_hdr_is_leading_zero` and `blk_hdr_rlc_acc`
        for (field, offset) in [(public_data.block_constants.gas_limit, Q_GAS_LIMIT_OFFSET),
                                (public_data.gas_used, Q_GAS_USED_OFFSET),
                                (public_data.block_constants.timestamp, Q_TIMESTAMP_OFFSET),
                                (public_data.block_constants.base_fee, Q_BASE_FEE_OFFSET)].iter() {
            // If the field has a short value then there is no RLP header.
            // We need add an artificial RLP header with field length of one (0x80) to align the field
            //
            // When the field is zero, it is represented by 0x80,
            // which just so happens to be the value of the artificial header we need,
            // thus we skip adding it.
            // The field's value for the circuit will still be zero due to
            // the leading zeros padding filling up the whole field
            //
            if *field <= U256::from(0x80) {
                if *field != U256::zero() {
                    out_vec.splice(offset-1..offset-1, [0x80]);
                    // Skipping artificial header for RLC. Since we accumulate the next byte in gates, we denote the skip one row earlier
                    q_blk_hdr_rlc_acc.splice(offset-2..offset-2, [0]);
                    // Copy the current RLC when skipping
                    blk_hdr_rlc_acc.splice(offset-1..offset-1, [blk_hdr_rlc_acc[offset-2]]);
                }
                leading_zeros.splice(offset-1..offset-1, [0]);
            }

            // Pad the field at the start with the needed amount leading zeros
            out_vec.splice(offset..offset, vec![0; (field.leading_zeros() / 8) as usize]);
            leading_zeros.splice(offset..offset, vec![1; (field.leading_zeros() / 8) as usize]);
            // Skipping leading zeros for RLC. Since we accumulate the next byte in gates, we denote the skip one row earlier
            q_blk_hdr_rlc_acc.splice(offset-1..offset-1, vec![0; (field.leading_zeros() / 8) as usize]);
            // Copy the current RLC when skipping
            blk_hdr_rlc_acc.splice(offset..offset, vec![blk_hdr_rlc_acc[*offset-1]; (field.leading_zeros() / 8) as usize]);
        }

        (out_vec, leading_zeros, q_blk_hdr_rlc_acc, blk_hdr_rlc_acc, Value::known(hash_hi), Value::known(hash_lo))
    }

    // Assigns all columns relevant to the blockhash checks
    fn assign_block_hash_calc(
        &self,
        region: &mut Region<'_, F>,
        public_data: &PublicData<F>,
        challenges: &Challenges<Value<F>>,
    ) {
        self.blockhash_cols.q_blk_hdr_rlc_start.enable(region, 0).unwrap();
        self.blockhash_cols.q_blk_hdr_rlp_end.enable(region, BLOCKHASH_TOTAL_ROWS-1).unwrap();
        let (block_header_rlp, leading_zeros, q_blk_hdr_rlc_acc, blk_hdr_rlc_acc, blk_hdr_hash_hi, blk_hdr_hash_lo) = Self::get_block_header_rlp_from_public_data(public_data, challenges);
        assert_eq!(block_header_rlp.len(), BLOCKHASH_TOTAL_ROWS);

        // Initialize columns to zero
        for i in 0..BLOCKHASH_TOTAL_ROWS {
            for col in [self.blockhash_cols.q_parent_hash, self.blockhash_cols.q_beneficiary,
                        self.blockhash_cols.q_state_root, self.blockhash_cols.q_transactions_root,
                        self.blockhash_cols.q_receipts_root, self.blockhash_cols.q_number,
                        self.blockhash_cols.q_gas_limit, self.blockhash_cols.q_gas_used,
                        self.blockhash_cols.q_timestamp, self.blockhash_cols.q_mix_hash,
                        self.blockhash_cols.q_base_fee_per_gas, self.blockhash_cols.q_withdrawals_root,
                        self.blockhash_cols.q_lo, self.blockhash_cols.q_lo,
                        self.blockhash_cols.q_lo, self.blockhash_cols.q_lo,
                        self.blockhash_cols.q_lo, self.blockhash_cols.q_lo,
                        self.blockhash_cols.q_lo, self.blockhash_cols.q_lo,
                        self.blockhash_cols.q_lo, self.blockhash_cols.q_lo,]
            {
                region.assign_fixed(|| "initializing column", col, i, || Value::known(F::zero()),).unwrap();
            }
            for col in [self.blockhash_cols.blk_hdr_rlp_len_calc, self.blockhash_cols.blk_hdr_rlp_len_calc_inv,
                       self.blockhash_cols.blk_hdr_reconstruct_value, self.blockhash_cols.blk_hdr_rlp_is_short] {
                region.assign_advice(|| "initializing column", col, i, || Value::known(F::zero()),).unwrap();
            }
        }

        let rlp_const: Vec<u64> = [
            vec![0xF9, 0x02, 0x00],  // RLP list header
            vec![0xA0], vec![0; 32], // Parent hash
            vec![0xA0], (*OMMERS_HASH).as_bytes().iter().map(|b| *b as u64).collect(), // Ommers hash
            vec![0x94], vec![0; 20], // Beneficiary
            vec![0xA0], vec![0; 32], // State root
            vec![0xA0], vec![0; 32], // Tx root
            vec![0xA0], vec![0; 32], // Receipt root
            vec![0xB9, 0x01, 0x00], vec![0; 256], // Bloom filter
            vec![0x80],              // Difficulty
            vec![0x00], vec![0; 8],  // number
            vec![0x00], vec![0; 32], // Gas limit
            vec![0x00], vec![0; 32], // Gas used
            vec![0x00], vec![0; 32], // Timestamp
            vec![0x80],              // Extra data
            vec![0xA0], vec![0; 32], // Mix hash
            vec![0x88], vec![0; 8],  // Nonce
            vec![0x00], vec![0; 32], // Base fee
            vec![0xA0], vec![0; 32], // Withdrawals Root
        ].concat();

        let q_rlp_const: Vec<u64> = [
            vec![1, 1, 0],               // RLP list header
            vec![1], vec![0; 32],        // Parent hash
            vec![1], vec![1; 32],        // Ommers hash header and value
            vec![1], vec![0; 20],        // Beneficiary
            vec![1], vec![0; 32],        // State root
            vec![1], vec![0; 32],        // Tx root
            vec![1], vec![0; 32],        // Receipt root
            vec![1, 1, 1], vec![1; 256], // Bloom filter
            vec![1],                     // Difficulty
            vec![0], vec![0; 8],         // number
            vec![0], vec![0; 32],        // Gas limit
            vec![0], vec![0; 32],        // Gas used
            vec![0], vec![0; 32],        // Timestamp
            vec![1],                     // Extra data
            vec![1], vec![0; 32],        // Mix hash
            vec![1], vec![0; 8],         // Nonce
            vec![0], vec![0; 32],        // Base fee
            vec![1], vec![0; 32],        // Withdrawals Root
        ].concat();

        for (offset, rlp_byte) in block_header_rlp.iter().enumerate() {
            region.assign_advice(|| "blk_hdr_rlp", self.blockhash_cols.blk_hdr_rlp, offset, || Value::known(F::from(*rlp_byte as u64)),).unwrap();
            region.assign_advice(|| "blk_hdr_rlp_inv", self.blockhash_cols.blk_hdr_rlp_inv, offset, || Value::known(F::from((*rlp_byte) as u64).invert().unwrap_or(F::zero())),).unwrap();

            let diff: u64 = if *rlp_byte < 0x81 { 0x81u64 - *rlp_byte as u64 } else { 0xFFu64 - (*rlp_byte as u64 - 0x81u64) };
            region.assign_advice(|| "blk_hdr_rlp_diff_0x81", self.blockhash_cols.blk_hdr_rlp_diff_0x81, offset, || Value::known(F::from(diff as u64))).unwrap();
            region.assign_advice(|| "q_blk_hdr_rlc_acc", self.blockhash_cols.q_blk_hdr_rlc_acc, offset, || Value::known(F::from(q_blk_hdr_rlc_acc[offset] as u64))).unwrap();
            region.assign_advice(|| "blk_hdr_rlc_acc", self.blockhash_cols.blk_hdr_rlc_acc, offset, || blk_hdr_rlc_acc[offset]).unwrap();

            region.assign_advice(|| "blk_hdr_is_leading_zero", self.blockhash_cols.blk_hdr_is_leading_zero, offset, || Value::known(F::from(leading_zeros[offset] as u64))).unwrap();

            self.blockhash_cols
                .q_blk_hdr_rlp
                .enable(region, offset)
                .unwrap();
        }

        // Gets rid of CellNotAssigned occuring in the last row
        region.assign_advice(|| "blk_hdr_rlc_acc", self.blockhash_cols.blk_hdr_rlc_acc, BLOCKHASH_TOTAL_ROWS, || Value::known(F::zero())).unwrap();
        region.assign_advice(|| "blk_hdr_rlp", self.blockhash_cols.blk_hdr_rlp, BLOCKHASH_TOTAL_ROWS, || Value::known(F::zero())).unwrap();

        // Calculate reconstructed values
        let mut reconstructed_values: Vec<Vec<Value<F>>> = vec![];
        for value in [
            public_data.parent_hash.as_fixed_bytes()[0..16].iter(),
            public_data.parent_hash.as_fixed_bytes()[16..32].iter(),
            public_data.beneficiary.as_fixed_bytes().iter(),
            public_data.state_root.as_fixed_bytes()[0..16].iter(),
            public_data.state_root.as_fixed_bytes()[16..32].iter(),
            public_data.transactions_root.as_fixed_bytes()[0..16].iter(),
            public_data.transactions_root.as_fixed_bytes()[16..32].iter(),
            public_data.receipts_root.as_fixed_bytes()[0..16].iter(),
            public_data.receipts_root.as_fixed_bytes()[16..32].iter(),
            public_data.block_constants.number.as_u64().to_be_bytes().iter(),
            public_data.block_constants.gas_limit.to_be_bytes()[0..16].iter(),
            public_data.block_constants.gas_limit.to_be_bytes()[16..32].iter(),
            public_data.gas_used.to_be_bytes()[0..16].iter(),
            public_data.gas_used.to_be_bytes()[16..32].iter(),
            public_data.block_constants.timestamp.to_be_bytes()[0..16].iter(),
            public_data.block_constants.timestamp.to_be_bytes()[16..32].iter(),
            public_data.mix_hash.as_fixed_bytes()[0..16].iter(),
            public_data.mix_hash.as_fixed_bytes()[16..32].iter(),
            public_data.block_constants.base_fee.to_be_bytes()[0..16].iter(),
            public_data.block_constants.base_fee.to_be_bytes()[16..32].iter(),
            // TODO(George): cannot find withdrawals_root in eth_block, use zeros for now
            // &block.withdrawals_root.as_fixed_bytes()[0..16],
            // &block.withdrawals_root.as_fixed_bytes()[16..32],
            [0u8; 16].iter(),
            [0u8; 16].iter(),
        ] {
            reconstructed_values.push(
                value.clone()
                    .scan(F::zero(), |acc, &x| {
                        for _ in 0..8 {
                            *acc = (*acc).double();
                        }
                        *acc += F::from(x as u64);
                        Some(Value::known(acc.clone()))
                    })
                    .collect::<Vec<Value<F>>>(),
            );
        }

        for (offset, (v, q)) in rlp_const.iter().zip(q_rlp_const.iter()).enumerate() {
            region.assign_fixed(|| "blk_hdr_rlp_const", self.blockhash_cols.blk_hdr_rlp_const, offset, || Value::known(F::from(*v)),).unwrap();
            if *q == 1 {
                self.blockhash_cols
                    .q_blk_hdr_rlp_const
                    .enable(region, offset)
                    .unwrap();
            }
        }

        self.blockhash_cols
            .q_blk_hdr_total_len
            .enable(region, 2)
            .unwrap();

        let number_lead_zeros_num: usize = (public_data.block_constants.number.leading_zeros() / 8) as usize;
        let mut length_calc = F::zero();
        let mut length_calc_inv = F::zero();
        for i in 0..32 {
            region.assign_fixed(|| "q_parent_hash", self.blockhash_cols.q_parent_hash, Q_PARENT_HASH_OFFSET + i, || Value::known(F::one()),).unwrap();
            region.assign_fixed(|| "q_state_root",self.blockhash_cols.q_state_root, Q_STATE_ROOT_OFFSET + i,|| Value::known(F::one()),).unwrap();
            region.assign_fixed(|| "q_transactions_root",self.blockhash_cols.q_transactions_root, Q_TX_ROOT_OFFSET + i,|| Value::known(F::one()),).unwrap();
            region.assign_fixed(|| "q_receipts_root",self.blockhash_cols.q_receipts_root, Q_RECEIPTS_ROOT_OFFSET + i,|| Value::known(F::one()),).unwrap();
            region.assign_fixed(|| "q_mix_hash", self.blockhash_cols.q_mix_hash, Q_MIX_HASH_OFFSET + i, || Value::known(F::one()),).unwrap();
            region.assign_fixed(|| "q_withdrawals_root",self.blockhash_cols.q_withdrawals_root, Q_WITHDRAWALS_ROOT_OFFSET + i,|| Value::known(F::one()),).unwrap();

            if i < 20 {
                region.assign_fixed(|| "q_beneficiary",self.blockhash_cols.q_beneficiary, Q_BENEFICIARY_OFFSET + i,|| Value::known(F::one()),).unwrap();
                region.assign_advice(|| "reconstruct_value for beneficiary",self.blockhash_cols.blk_hdr_reconstruct_value, Q_BENEFICIARY_OFFSET + i,|| reconstructed_values[2][i],).unwrap();
                self.blockhash_cols.q_hi.enable(region, Q_BENEFICIARY_OFFSET + i).unwrap(); // No actual use, Only for convenience in generating some gates elegantly
            }

            if i < 8 {
                region.assign_fixed(|| "q_number",self.blockhash_cols.q_number, Q_NUMBER_OFFSET + i,|| Value::known(F::one()),).unwrap();
                if i < number_lead_zeros_num{
                    length_calc = F::zero();
                    length_calc_inv = F::zero();
                } else {
                    length_calc = F::from((i - number_lead_zeros_num + 1) as u64);
                    length_calc_inv = F::from((i - number_lead_zeros_num + 1) as u64).invert().unwrap_or(F::zero());
                }
                if i==7 &&
                   (length_calc == F::one() || length_calc == F::zero()) &&
                   block_header_rlp[Q_NUMBER_OFFSET+i] <= 0x80
                {
                    length_calc = F::zero();
                    length_calc_inv = F::zero();
                    region.assign_advice(|| "number length",self.blockhash_cols.blk_hdr_rlp_is_short, Q_NUMBER_OFFSET + i,|| Value::known(F::one())).unwrap();
                }
                region.assign_advice(|| "number length",self.blockhash_cols.blk_hdr_rlp_len_calc, Q_NUMBER_OFFSET + i,|| Value::known(length_calc)).unwrap();
                region.assign_advice(|| "number length inverse",self.blockhash_cols.blk_hdr_rlp_len_calc_inv, Q_NUMBER_OFFSET + i,|| Value::known(length_calc_inv)).unwrap();
                region.assign_advice(|| "reconstruct_value for number",self.blockhash_cols.blk_hdr_reconstruct_value, Q_NUMBER_OFFSET + i,|| reconstructed_values[9][i],).unwrap();
                self.blockhash_cols.q_hi.enable(region, Q_NUMBER_OFFSET + i).unwrap(); // No actual use, Only for convenience in generating some gates elegantly
            }

            for (str, field, selector, offset) in
                    [("gas_limit", public_data.block_constants.gas_limit, self.blockhash_cols.q_gas_limit,        Q_GAS_LIMIT_OFFSET),
                     ("gas_used",  public_data.gas_used,                  self.blockhash_cols.q_gas_used,         Q_GAS_USED_OFFSET),
                     ("timestamp", public_data.block_constants.timestamp, self.blockhash_cols.q_timestamp,        Q_TIMESTAMP_OFFSET),
                     ("base_fee",  public_data.block_constants.base_fee,  self.blockhash_cols.q_base_fee_per_gas, Q_BASE_FEE_OFFSET)].iter() {

                let field_lead_zeros_num: usize = (field.leading_zeros() / 8) as usize;
                region.assign_fixed(|| "q_".to_string() + *str, *selector, offset + i,|| Value::known(F::one()),).unwrap();
                if i < field_lead_zeros_num {
                    length_calc = F::zero();
                    length_calc_inv = F::zero();
                } else {
                    length_calc = F::from((i - field_lead_zeros_num + 1) as u64);
                    length_calc_inv = F::from((i - field_lead_zeros_num + 1) as u64).invert().unwrap_or(F::zero());
                }
                if i==31 &&
                    (length_calc == F::one() || length_calc == F::zero()) &&
                    block_header_rlp[offset+i] <= 0x80
                {
                    length_calc = F::zero();
                    length_calc_inv = F::zero();
                    region.assign_advice(|| String::from(*str) + " length",self.blockhash_cols.blk_hdr_rlp_is_short, offset + i,|| Value::known(F::one())).unwrap();
                }
                region.assign_advice(|| String::from(*str) + " length", self.blockhash_cols.blk_hdr_rlp_len_calc, offset + i, || Value::known(length_calc)).unwrap();
                region.assign_advice(|| String::from(*str) + " length inverse", self.blockhash_cols.blk_hdr_rlp_len_calc_inv, offset + i,|| Value::known(length_calc_inv)).unwrap();
            }

            if i < 16 {
                // q_hi for all fields
                for offset in [Q_PARENT_HASH_OFFSET, Q_STATE_ROOT_OFFSET,
                               Q_TX_ROOT_OFFSET, Q_RECEIPTS_ROOT_OFFSET,
                               Q_GAS_LIMIT_OFFSET, Q_GAS_USED_OFFSET,
                               Q_TIMESTAMP_OFFSET, Q_MIX_HASH_OFFSET,
                               Q_BASE_FEE_OFFSET, Q_WITHDRAWALS_ROOT_OFFSET] {
                    self.blockhash_cols.q_hi.enable(region, offset + i).unwrap();
                }

                // reconstructing values for the _hi parts
                region.assign_advice(|| "reconstruct_value for parent_hash_hi", self.blockhash_cols.blk_hdr_reconstruct_value, Q_PARENT_HASH_OFFSET + i, || reconstructed_values[0][i],).unwrap();
                region.assign_advice(|| "reconstruct_value for state_root_hi", self.blockhash_cols.blk_hdr_reconstruct_value, Q_STATE_ROOT_OFFSET + i, || reconstructed_values[3][i],).unwrap();
                region.assign_advice(|| "reconstruct_value for tx_root_hi", self.blockhash_cols.blk_hdr_reconstruct_value, Q_TX_ROOT_OFFSET + i, || reconstructed_values[5][i],).unwrap();
                region.assign_advice(|| "reconstruct_value for receipts_root_hi", self.blockhash_cols.blk_hdr_reconstruct_value, Q_RECEIPTS_ROOT_OFFSET + i, || reconstructed_values[7][i],).unwrap();
                region.assign_advice(|| "reconstruct_value for gas_limit_hi", self.blockhash_cols.blk_hdr_reconstruct_value, Q_GAS_LIMIT_OFFSET + i, || reconstructed_values[10][i],).unwrap();
                region.assign_advice(|| "reconstruct_value for gas_used_hi", self.blockhash_cols.blk_hdr_reconstruct_value, Q_GAS_USED_OFFSET + i, || reconstructed_values[12][i],).unwrap();
                region.assign_advice(|| "reconstruct_value for timestamp_hi", self.blockhash_cols.blk_hdr_reconstruct_value, Q_TIMESTAMP_OFFSET + i, || reconstructed_values[14][i],).unwrap();
                region.assign_advice(|| "reconstruct_value for mix_hash_hi", self.blockhash_cols.blk_hdr_reconstruct_value, Q_MIX_HASH_OFFSET + i, || reconstructed_values[16][i],).unwrap();
                region.assign_advice(|| "reconstruct_value for base_fee_per_gas_hi", self.blockhash_cols.blk_hdr_reconstruct_value, Q_BASE_FEE_OFFSET + i, || reconstructed_values[18][i],).unwrap();
                region.assign_advice(|| "reconstruct_value for withdrawals_root_hi", self.blockhash_cols.blk_hdr_reconstruct_value, Q_WITHDRAWALS_ROOT_OFFSET + i, || reconstructed_values[20][i],).unwrap();
            }

            if i >= 16 {
                // q_lo for all fields
                for offset in [Q_PARENT_HASH_OFFSET, Q_STATE_ROOT_OFFSET,
                               Q_TX_ROOT_OFFSET, Q_RECEIPTS_ROOT_OFFSET,
                               Q_GAS_LIMIT_OFFSET, Q_GAS_USED_OFFSET,
                               Q_TIMESTAMP_OFFSET, Q_MIX_HASH_OFFSET,
                               Q_BASE_FEE_OFFSET, Q_WITHDRAWALS_ROOT_OFFSET] {
                    region.assign_fixed(|| "q_lo", self.blockhash_cols.q_lo, offset + i, || Value::known(F::one()),).unwrap();
                }

                // reconstructing values for the _lo parts
                region.assign_advice(|| "reconstruct_value for parent_hash_lo", self.blockhash_cols.blk_hdr_reconstruct_value, Q_PARENT_HASH_OFFSET + i, || reconstructed_values[1][i - 16],).unwrap();
                region.assign_advice(|| "reconstruct_value for state_root_lo", self.blockhash_cols.blk_hdr_reconstruct_value, Q_STATE_ROOT_OFFSET + i, || reconstructed_values[4][i - 16],).unwrap();
                region.assign_advice(|| "reconstruct_value for tx_root_lo", self.blockhash_cols.blk_hdr_reconstruct_value, Q_TX_ROOT_OFFSET + i, || reconstructed_values[6][i - 16],).unwrap();
                region.assign_advice(|| "reconstruct_value for receipts_root_lo", self.blockhash_cols.blk_hdr_reconstruct_value, Q_RECEIPTS_ROOT_OFFSET + i, || reconstructed_values[8][i - 16],).unwrap();
                region.assign_advice(|| "reconstruct_value for gas_limit_lo", self.blockhash_cols.blk_hdr_reconstruct_value, Q_GAS_LIMIT_OFFSET + i, || reconstructed_values[11][i - 16],).unwrap();
                region.assign_advice(|| "reconstruct_value for gas_used_lo", self.blockhash_cols.blk_hdr_reconstruct_value, Q_GAS_USED_OFFSET + i, || reconstructed_values[13][i - 16],).unwrap();
                region.assign_advice(|| "reconstruct_value for timestamp_lo", self.blockhash_cols.blk_hdr_reconstruct_value, Q_TIMESTAMP_OFFSET + i, || reconstructed_values[15][i - 16],).unwrap();
                region.assign_advice(|| "reconstruct_value for mix_hash_lo", self.blockhash_cols.blk_hdr_reconstruct_value, Q_MIX_HASH_OFFSET + i, || reconstructed_values[17][i - 16],).unwrap();
                region.assign_advice(|| "reconstruct_value for base_fee_per_gas_lo", self.blockhash_cols.blk_hdr_reconstruct_value, Q_BASE_FEE_OFFSET + i, || reconstructed_values[19][i - 16],).unwrap();
                region.assign_advice(|| "reconstruct_value for withdrawals_root_lo", self.blockhash_cols.blk_hdr_reconstruct_value, Q_WITHDRAWALS_ROOT_OFFSET + i, || reconstructed_values[21][i - 16],).unwrap();
            }
        }

        region.assign_advice(|| "blk_hdr_hash_hi", self.rpi_encoding, BLOCKHASH_TOTAL_ROWS-1, || blk_hdr_hash_hi).unwrap();
        region.assign_advice(|| "blk_hdr_hash_lo", self.rpi_encoding, BLOCKHASH_TOTAL_ROWS-2, || blk_hdr_hash_lo).unwrap();
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        public_data: &PublicData<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        self.assign_fixed_u8(layouter)?;
        self.assign_fixed_u16(layouter)?;

        let (public_inputs, txs_rlc_acc, block_rlc_acc) = layouter.assign_region(
            || "region 0",
            |mut region| {
                // Assign block table
                let (
                    block_hash_hi_cell,
                    block_hash_lo_cell,
                    txs_hash_hi_cell,
                    txs_hash_lo_cell,
                    block_rlc_acc,
                ) = self.assign_block(&mut region, public_data, challenges)?;

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

                self.assign_block_hash_calc(&mut region, public_data, challenges);

                // NOTE: we add this empty row so as to pass mock prover's check
                //      otherwise it will emit CellNotAssigned Error
                let tx_table_len = TX_LEN * self.max_txs + 1;
                self.assign_tx_empty_row(&mut region, tx_table_len + offset)?;

                let (origin_txs_hash_hi_cell, origin_txs_hash_lo_cell, txs_rlc_acc) =
                    self.assign_txs(&mut region, public_data, challenges, rpi_vals)?;
                // assert two txs hash are equal
                region.constrain_equal(txs_hash_hi_cell.cell(), origin_txs_hash_hi_cell.cell())?;
                region.constrain_equal(txs_hash_lo_cell.cell(), origin_txs_hash_lo_cell.cell())?;
                Ok((
                    [block_hash_hi_cell, block_hash_lo_cell],
                    txs_rlc_acc,
                    block_rlc_acc,
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

    _marker: PhantomData<F>,
}

impl<F: Field> PiCircuit<F> {
    /// Creates a new PiCircuit
    pub fn new(max_txs: usize, max_calldata: usize, public_data: PublicData<F>) -> Self {
        Self {
            max_txs,
            max_calldata,
            public_data,
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
        let challenges = Challenges::mock(100.expr(), 100.expr());
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
        let challenges = Challenges::mock(Value::known(F::from(100)), Value::known(F::from(100)));
        let public_data = &self.0.public_data;
        // assign keccak table
        config.keccak_table.dev_load(
            &mut layouter,
            vec![
                &public_data.txs_rlp.to_vec(),
                &public_data.block_rlp.to_vec(),
                &public_data.blockhash_blk_hdr_rlp.to_vec()
            ],
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
        pi: Option<Vec<Vec<F>>>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA>(PiCircuit::new(
            MAX_TXS,
            MAX_CALLDATA,
            public_data,
        ));
        let public_inputs = pi.unwrap_or_else(|| circuit.0.instance());

        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        let res = prover.verify();
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
        res
    }

    #[test]
    fn test_default_pi() {
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 8;
        let public_data = PublicData::default();

        let k = 17;
        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None),
            Ok(())
        );
    }

    #[test]
    fn test_fail_pi_hash() {
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 8;
        let public_data = PublicData::default();

        let k = 17;
        match run::<Fr, MAX_TXS, MAX_CALLDATA>(
            k,
            public_data,
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
        let k = 17;
        match run::<Fr, MAX_TXS, MAX_CALLDATA>(
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

        let k = 17;
        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None),
            Ok(())
        );
    }

    // TODO(George): populate block.context.history_hashes in tests

    #[test]
    fn test_verify() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let prover =
            Address::from_slice(&hex::decode("Df08F82De32B8d460adbE8D72043E3a7e25A3B39").unwrap());

        let logs_bloom:[u8;256] = hex::decode("112d60abc05141f1302248e0f4329627f002380f1413820692911863e7d0871261aa07e90cc01a10c3ce589153570dc2db27b8783aa52bc19a5a4a836722e813190401b4214c3908cb8b468b510c3fe482603b00ca694c806206bf099279919c334541094bd2e085210373c0b064083242d727790d2eecdb2e0b90353b66461050447626366328f0965602e8a9802d25740ad4a33162142b08a1b15292952de423fac45d235622bb0ef3b2d2d4c21690d280a0b948a8a3012136542c1c4d0955a501a022e1a1a4582220d1ae50ba475d88ce0310721a9076702d29a27283e68c2278b93a1c60d8f812069c250042cc3180a8fd54f034a2da9a03098c32b03445").unwrap().try_into().unwrap();

        let mut block = witness::Block::<Fr>::default();
        block.eth_block.parent_hash = *OMMERS_HASH;
        block.eth_block.author = Some(prover);
        block.eth_block.state_root = *OMMERS_HASH;
        block.eth_block.transactions_root = *OMMERS_HASH;
        block.eth_block.receipts_root = *OMMERS_HASH;
        block.eth_block.logs_bloom = Some(logs_bloom.into());
        block.eth_block.difficulty = U256::from(0);
        block.eth_block.number = Some(U64::from(0));
        block.eth_block.gas_limit = U256::from(0);
        block.eth_block.gas_used = U256::from(0);
        block.eth_block.timestamp = U256::from(0);
        block.eth_block.extra_data = eth_types::Bytes::from([0; 0]);
        block.eth_block.mix_hash = Some(*OMMERS_HASH);
        block.eth_block.nonce = Some(H64::from([0, 0, 0, 0, 0, 0, 0, 0]));
        block.eth_block.base_fee_per_gas = Some(U256::from(0));

        let public_data = PublicData::new(&block, prover, Default::default());

        let k = 17;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_short_values () {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let prover =
            Address::from_slice(&hex::decode("df08f82de32b8d460adbe8d72043e3a7e25a3b39").unwrap());

        let mut block = witness::Block::<Fr>::default();
        block.eth_block.parent_hash = *OMMERS_HASH;
        block.eth_block.author = Some(prover);
        block.eth_block.state_root = *OMMERS_HASH;
        block.eth_block.transactions_root = *OMMERS_HASH;
        block.eth_block.receipts_root = *OMMERS_HASH;
        block.eth_block.logs_bloom = Some([0; 256].into());
        block.eth_block.extra_data = eth_types::Bytes::from([0; 0]);
        block.eth_block.mix_hash = Some(*OMMERS_HASH);
        block.eth_block.nonce = Some(H64::from([0, 0, 0, 0, 0, 0, 0, 0]));

        block.context.number = U256::from(0x75);
        block.context.gas_limit = 0x76;
        block.eth_block.gas_used = U256::from(0x77);
        block.context.timestamp = U256::from(0x78);
        block.context.base_fee = U256::from(0x79);
        block.context.difficulty = U256::from(0);

        let public_data = PublicData::new(&block, prover, Default::default());

        let k = 17;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_one_byte_non_short_values () {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let prover =
            Address::from_slice(&hex::decode("df08f82de32b8d460adbe8d72043e3a7e25a3b39").unwrap());

        let mut block = witness::Block::<Fr>::default();
        block.eth_block.parent_hash = *OMMERS_HASH;
        block.eth_block.author = Some(prover);
        block.eth_block.state_root = *OMMERS_HASH;
        block.eth_block.transactions_root = *OMMERS_HASH;
        block.eth_block.receipts_root = *OMMERS_HASH;
        block.eth_block.logs_bloom = Some([0; 256].into());
        block.eth_block.extra_data = eth_types::Bytes::from([0; 0]);
        block.eth_block.mix_hash = Some(*OMMERS_HASH);
        block.eth_block.nonce = Some(H64::from([0, 0, 0, 0, 0, 0, 0, 0]));

        block.context.number = U256::from(0x81);
        block.context.gas_limit = 0x81;
        block.eth_block.gas_used = U256::from(0x81);
        block.context.timestamp = U256::from(0x81);
        block.context.base_fee = U256::from(0x81);

        block.context.difficulty = U256::from(0);

        let public_data = PublicData::new(&block, prover, Default::default());

        let k = 17;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_one_byte_non_short_values_2 () {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let prover =
            Address::from_slice(&hex::decode("df08f82de32b8d460adbe8d72043e3a7e25a3b39").unwrap());

        let mut block = witness::Block::<Fr>::default();
        block.eth_block.parent_hash = *OMMERS_HASH;
        block.eth_block.author = Some(prover);
        block.eth_block.state_root = *OMMERS_HASH;
        block.eth_block.transactions_root = *OMMERS_HASH;
        block.eth_block.receipts_root = *OMMERS_HASH;
        block.eth_block.logs_bloom = Some([0; 256].into());
        block.eth_block.extra_data = eth_types::Bytes::from([0; 0]);
        block.eth_block.mix_hash = Some(*OMMERS_HASH);
        block.eth_block.nonce = Some(H64::from([0, 0, 0, 0, 0, 0, 0, 0]));

        block.context.number = U256::from(0xFF);
        block.context.gas_limit = 0xFF;
        block.eth_block.gas_used = U256::from(0xFF);
        block.context.timestamp = U256::from(0xFF);
        block.context.base_fee = U256::from(0xF);

        block.context.difficulty = U256::from(0);

        let public_data = PublicData::new(&block, prover, Default::default());

        let k = 17;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_leading_zeros() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let prover =
            Address::from_slice(&hex::decode("df08f82de32b8d460adbe8d72043e3a7e25a3b39").unwrap());

        let mut block = witness::Block::<Fr>::default();
        block.eth_block.parent_hash = *OMMERS_HASH;
        block.eth_block.author = Some(prover);
        block.eth_block.state_root = *OMMERS_HASH;
        block.eth_block.transactions_root = *OMMERS_HASH;
        block.eth_block.receipts_root = *OMMERS_HASH;
        block.eth_block.logs_bloom = Some([0; 256].into());
        block.eth_block.extra_data = eth_types::Bytes::from([0; 0]);
        block.eth_block.mix_hash = Some(*OMMERS_HASH);
        block.eth_block.nonce = Some(H64::from([0, 0, 0, 0, 0, 0, 0, 0]));

        block.context.number = U256::from(0x0090909090909090_u128);
        block.context.gas_limit = 0x0000919191919191;
        block.eth_block.gas_used = U256::from(0x92) << (28*8);
        block.context.timestamp = U256::from(0x93) << (27*8);
        block.context.base_fee = U256::from(0x94) << (26*8);

        block.context.difficulty = U256::from(0);

        let public_data = PublicData::new(&block, prover, Default::default());

        let k = 17;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_max_lengths() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let prover =
            Address::from_slice(&hex::decode("df08f82de32b8d460adbe8d72043e3a7e25a3b39").unwrap());

        let mut block = witness::Block::<Fr>::default();
        block.eth_block.parent_hash = *OMMERS_HASH;
        block.eth_block.author = Some(prover);
        block.eth_block.state_root = H256::from_slice(&hex::decode("21223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49349").unwrap());
        block.eth_block.transactions_root = H256::from_slice(&hex::decode("31223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49350").unwrap());
        block.eth_block.receipts_root = H256::from_slice(&hex::decode("41223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49351").unwrap());
        block.eth_block.logs_bloom = Some([0; 256].into());
        block.eth_block.extra_data = eth_types::Bytes::from([0; 0]);
        block.eth_block.mix_hash = Some(H256::from_slice(&hex::decode("51223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49352").unwrap()));
        block.eth_block.nonce = Some(H64::from([0, 0, 0, 0, 0, 0, 0, 0]));
        block.context.number = U256::from(0x9090909090909090_u128);
        block.context.gas_limit = 0x9191919191919191;
        block.eth_block.gas_used = U256::from(0x92) << (31*8);
        block.context.timestamp = U256::from(0x93) << (31*8);
        block.context.base_fee = U256::from(0x94) << (31*8);
        block.context.difficulty = U256::from(0);
        block.context.history_hashes = vec![U256::zero(); 256];
        block.context.history_hashes[255] = U256::from_big_endian(block.eth_block.parent_hash.as_fixed_bytes());

        let public_data = PublicData::new(&block, prover, Default::default());

        let k = 17;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None),
            Ok(())
        );
    }
}
