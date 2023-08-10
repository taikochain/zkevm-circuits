/// Fixed by the spec
// pub(super) const BLOCK_LEN: usize = 7 + 256;
pub(super) const EXTRA_LEN: usize = 2;
pub(super) const ZERO_BYTE_GAS_COST: u64 = 4;
pub(super) const NONZERO_BYTE_GAS_COST: u64 = 16;

pub(super) const BYTE_POW_BASE: u64 = 1 << 8;

// The total number of previous blocks for which to check the hash chain
pub(super) const PREVIOUS_BLOCKS_NUM: usize = 0; //256;
// This is the number of entries each block occupies in the block_table, which
// is equal to the number of header fields per block (coinbase, timestamp,
// number, difficulty, gas_limit, base_fee, blockhash, beneficiary, state_root,
// transactions_root, receipts_root, gas_used, mix_hash, withdrawals_root)
pub(super) const BLOCK_LEN_IN_TABLE: usize = 15;
// previous hashes in rlc, lo and hi
// + zero
pub(super) const BLOCK_TABLE_MISC_LEN: usize = PREVIOUS_BLOCKS_NUM * 3 + 1;
// Total number of entries in the block table:
// + (block fields num) * (total number of blocks)
// + misc entries
pub(super) const TOTAL_BLOCK_TABLE_LEN: usize =
    (BLOCK_LEN_IN_TABLE * (PREVIOUS_BLOCKS_NUM + 1)) + BLOCK_TABLE_MISC_LEN;

pub(super) const OLDEST_BLOCK_NUM: usize = 258; // 0;
pub(super) const CURRENT_BLOCK_NUM: usize = PREVIOUS_BLOCKS_NUM; // 256;

pub(super) const MAX_DEGREE: usize = 9;

pub(super) const WORD_SIZE: usize = 32;
pub(super) const U64_SIZE: usize = 8;
pub(super) const ADDRESS_SIZE: usize = 20;

pub(super) const RLP_HDR_NOT_SHORT: u64 = 0x81;

// Maximum size of block header fields in bytes
pub(super) const PARENT_HASH_SIZE: usize = WORD_SIZE;
pub(super) const OMMERS_HASH_SIZE: usize = WORD_SIZE;
pub(super) const BENEFICIARY_SIZE: usize = ADDRESS_SIZE;
pub(super) const STATE_ROOT_SIZE: usize = WORD_SIZE;
pub(super) const TX_ROOT_SIZE: usize = WORD_SIZE;
pub(super) const RECEIPTS_ROOT_SIZE: usize = WORD_SIZE;
pub(super) const LOGS_BLOOM_SIZE: usize = 256;
pub(super) const DIFFICULTY_SIZE: usize = 1;
pub(super) const NUMBER_SIZE: usize = U64_SIZE;
pub(super) const GAS_LIMIT_SIZE: usize = WORD_SIZE;
pub(super) const GAS_USED_SIZE: usize = WORD_SIZE;
pub(super) const TIMESTAMP_SIZE: usize = WORD_SIZE;
pub(super) const EXTRA_DATA_SIZE: usize = 1;
pub(super) const MIX_HASH_SIZE: usize = WORD_SIZE;
pub(super) const NONCE_SIZE: usize = U64_SIZE;
pub(super) const BASE_FEE_SIZE: usize = WORD_SIZE;
pub(super) const WITHDRAWALS_ROOT_SIZE: usize = WORD_SIZE;

// Helper contants for the offset calculations below
pub(super) const PARENT_HASH_RLP_LEN: usize = PARENT_HASH_SIZE + 1;
pub(super) const OMMERS_HASH_RLP_LEN: usize = OMMERS_HASH_SIZE + 1;
pub(super) const BENEFICIARY_RLP_LEN: usize = BENEFICIARY_SIZE + 1;
pub(super) const STATE_ROOT_RLP_LEN: usize = STATE_ROOT_SIZE + 1;
pub(super) const TX_ROOT_RLP_LEN: usize = TX_ROOT_SIZE + 1;
pub(super) const RECEIPTS_ROOT_RLP_LEN: usize = RECEIPTS_ROOT_SIZE + 1;
pub(super) const LOGS_BLOOM_RLP_LEN: usize = LOGS_BLOOM_SIZE + 3;
pub(super) const DIFFICULTY_RLP_LEN: usize = DIFFICULTY_SIZE;
pub(super) const NUMBER_RLP_LEN: usize = NUMBER_SIZE + 1;
pub(super) const GAS_LIMIT_RLP_LEN: usize = GAS_LIMIT_SIZE + 1;
pub(super) const GAS_USED_RLP_LEN: usize = GAS_USED_SIZE + 1;
pub(super) const TIMESTAMP_RLP_LEN: usize = TIMESTAMP_SIZE + 1;
pub(super) const EXTRA_DATA_RLP_LEN: usize = EXTRA_DATA_SIZE;
pub(super) const MIX_HASH_RLP_LEN: usize = MIX_HASH_SIZE + 1;
pub(super) const NONCE_RLP_LEN: usize = NONCE_SIZE + 1;
pub(super) const BASE_FEE_RLP_LEN: usize = BASE_FEE_SIZE + 1;
pub(super) const WITHDRAWALS_ROOT_RLP_LEN: usize = WITHDRAWALS_ROOT_SIZE;

// Row offsets where the value of block header fields start (after their RLP
// header)
pub(super) const PARENT_HASH_RLP_OFFSET: usize = 4;
pub(super) const BENEFICIARY_RLP_OFFSET: usize =
    PARENT_HASH_RLP_OFFSET + PARENT_HASH_RLP_LEN + OMMERS_HASH_RLP_LEN;
pub(super) const STATE_ROOT_RLP_OFFSET: usize = BENEFICIARY_RLP_OFFSET + BENEFICIARY_RLP_LEN;
pub(super) const TX_ROOT_RLP_OFFSET: usize = STATE_ROOT_RLP_OFFSET + STATE_ROOT_RLP_LEN;
pub(super) const RECEIPTS_ROOT_RLP_OFFSET: usize = TX_ROOT_RLP_OFFSET + TX_ROOT_RLP_LEN;
pub(super) const NUMBER_RLP_OFFSET: usize =
    RECEIPTS_ROOT_RLP_OFFSET + RECEIPTS_ROOT_RLP_LEN + LOGS_BLOOM_RLP_LEN + DIFFICULTY_RLP_LEN;
pub(super) const GAS_LIMIT_RLP_OFFSET: usize = NUMBER_RLP_OFFSET + NUMBER_RLP_LEN;
pub(super) const GAS_USED_RLP_OFFSET: usize = GAS_LIMIT_RLP_OFFSET + GAS_LIMIT_RLP_LEN;
pub(super) const TIMESTAMP_RLP_OFFSET: usize = GAS_USED_RLP_OFFSET + GAS_USED_RLP_LEN;
pub(super) const MIX_HASH_RLP_OFFSET: usize = TIMESTAMP_RLP_OFFSET + TIMESTAMP_RLP_LEN + EXTRA_DATA_RLP_LEN;
pub(super) const BASE_FEE_RLP_OFFSET: usize = MIX_HASH_RLP_OFFSET + MIX_HASH_RLP_LEN + NONCE_RLP_LEN;
pub(super) const WITHDRAWALS_ROOT_RLP_OFFSET: usize = BASE_FEE_RLP_OFFSET + BASE_FEE_RLP_LEN;
pub(super) const BLOCKHASH_TOTAL_ROWS: usize = WITHDRAWALS_ROOT_RLP_OFFSET + WITHDRAWALS_ROOT_RLP_LEN;

// Absolute row number of the row where the LSB of the total RLP length is
// located
pub(super) const TOTAL_LENGTH_OFFSET: i32 = 2;