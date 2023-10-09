extern crate num_bigint;
extern crate num_traits;

use rand::Rng;

use eth_types::Address;
use eth_types::Bytes;
use eth_types::H256;
use eth_types::Word;
use mock::MockAccount;
use mock::MockTransaction;
use num_traits::FromPrimitive;

const CURRENT_NACC: usize = 0;
const CURRENT_NTX: usize = 0;

#[derive(Clone, Copy, Debug)]
pub enum TransactionMember<const NTX: usize> {
    Hash,
    Nonce,
    BlockHash,
    BlockNumber,
    TransactionIdx,
    From,
    To,
    Value,
    GasPrice,
    Gas,
    Input,
    SigData,
    TransactionType,
    EnableSkippingInvalidTx,
    AccessList,
    MaxPriorityFeePerGas,
    MaxFeePerGas,
    ChainId,
}

impl<const NTX: usize> TransactionMember<NTX> {
    pub fn randomize_transactions_vec_one_random_member(
        mut transactions: Vec<MockTransaction>,
        transactions_random_input: Vec<[u8; 128]>,
        transactions_random_from: [u8; 20],
        transactions_random_to: [u8; 20],
        transactions_random_value: [u8; 32],
    ) -> Vec<MockTransaction> {
        if transactions.len() != transactions_random_input.len() {
            panic!("Mismatched lengths of transactions and random input");
        }

        for (transaction, random_input) in transactions.iter_mut().zip(transactions_random_input) {
            Self::randomize_transaction_at_member(TransactionMember::From, &transactions_random_from, transaction);
            Self::randomize_transaction_at_member(TransactionMember::To, &transactions_random_to, transaction);
            Self::randomize_transaction_at_member(TransactionMember::Value, &transactions_random_value, transaction);
            Self::randomize_transaction_at_member(TransactionMember::GasPrice, , transaction);
            let random_member = TransactionMember::random_member();
            Self::randomize_transaction_at_member(random_member, &random_input, transaction);
        }
        transactions
    }

    pub fn randomize_transactions_one_random_member(
        mut transactions: [&mut MockTransaction; NTX],
        transactions_random_input: &[[u8; 128]; NTX],
        skip_on_fail: bool,
    ) {
        for (transaction, random_input) in transactions.iter_mut().zip(transactions_random_input.iter()) {
            let random_member = TransactionMember::random_member();
            transaction.enable_skipping_invalid_tx(skip_on_fail);
            Self::randomize_transaction_at_member(random_member, random_input, transaction);
        }
    }

    pub fn random_member() -> Self {
        let variants = vec![
            TransactionMember::Hash,
            TransactionMember::Nonce,
            TransactionMember::BlockHash,
            TransactionMember::BlockNumber,
            TransactionMember::TransactionIdx,
            // TransactionMember::From,
            // TransactionMember::To,
            TransactionMember::Value,
            TransactionMember::GasPrice,
            TransactionMember::Gas,
            TransactionMember::Input,
            // TransactionMember::SigData,
            TransactionMember::TransactionType,
            // TransactionMember::EnableSkippingInvalidTx,
            // TransactionMember::AccessList,
            TransactionMember::MaxPriorityFeePerGas,
            TransactionMember::MaxFeePerGas,
            // TransactionMember::ChainId,
        ];

        let index = rand::thread_rng().gen_range(0..variants.len());
        variants[index]
    }

    pub fn randomize_transaction_at_member(
        random_entry: TransactionMember<{ NTX }>,
        random_input: &[u8],
        mock_transaction: &mut MockTransaction,
    ) {
        match random_entry {
            TransactionMember::Hash => {
                let hash_bytes: [u8; 32] = random_input[..32].try_into().unwrap();
                let hash = H256::from(hash_bytes);
                dbg!(mock_transaction.hash(hash));
            }
            TransactionMember::Nonce => {
                let nonce_bytes: [u8; 8] = random_input[..8].try_into().unwrap();
                let nonce = u64::from_be_bytes(nonce_bytes);
                dbg!(mock_transaction.nonce(nonce));
            }
            TransactionMember::BlockHash => {
                let block_hash_bytes: [u8; 32] = random_input[..32].try_into().unwrap();
                let block_hash = H256::from(block_hash_bytes);
                dbg!(mock_transaction.block_hash(block_hash));
            }
            TransactionMember::BlockNumber => {
                let block_number_bytes: [u8; 8] = random_input[..8].try_into().unwrap();
                let block_number = u64::from_be_bytes(block_number_bytes);
                dbg!(mock_transaction.block_number(block_number));
            }
            TransactionMember::TransactionIdx => {
                let transaction_idx_bytes: [u8; 8] = random_input[..8].try_into().unwrap();
                let transaction_idx = u64::from_be_bytes(transaction_idx_bytes);
                dbg!(mock_transaction.transaction_idx(transaction_idx));
            }
            TransactionMember::From => {
                let from_bytes: [u8; 20] = random_input[..20].try_into().unwrap();
                let from = Address::from(from_bytes);
                dbg!(mock_transaction.from(from));
            }
            TransactionMember::To => {
                let to_bytes: [u8; 20] = random_input[..20].try_into().unwrap();
                let to = Address::from(to_bytes);
                dbg!(mock_transaction.to(to));
            }
            TransactionMember::Value => {
                let value_bytes: [u8; 32] = random_input[..32].try_into().unwrap();
                let value = Word::from(value_bytes);
                dbg!(mock_transaction.value(value));
            }
            TransactionMember::GasPrice => {
                let gas_price_bytes: [u8; 32] = random_input[..32].try_into().unwrap();
                let gas_price = Word::from(gas_price_bytes);
                dbg!(mock_transaction.gas_price(gas_price));
            }
            TransactionMember::Gas => {
                let gas_bytes: [u8; 32] = random_input[..32].try_into().unwrap();
                let gas = Word::from(gas_bytes);
                dbg!(mock_transaction.gas(gas));
            }
            TransactionMember::Input => {
                let input_bytes: [u8; 32] = random_input[..32].try_into().unwrap();
                let input = Bytes::from(input_bytes);
                dbg!(mock_transaction.input(input));
            }
            TransactionMember::SigData => {
                // let v_bytes: [u8; 8] = random_input[0..8].try_into().unwrap();
                // let r_bytes: [u8; 32] = random_input[8..40].try_into().unwrap();
                // let s_bytes: [u8; 32] = random_input[40..72].try_into().unwrap();
                // let (v, r, s) = (
                //     u64::from_be_bytes(v_bytes),
                //     Word::from(r_bytes),
                //     Word::from(s_bytes),
                // );
                // dbg!(mock_transaction.sig_data((v, r, s)));
                unimplemented!();
            }
            TransactionMember::TransactionType => {
                let transaction_type_bytes: [u8; 8] = random_input[..8].try_into().unwrap();
                let transaction_type = u64::from_be_bytes(transaction_type_bytes);
                dbg!(mock_transaction.transaction_type(transaction_type));
            }
            TransactionMember::EnableSkippingInvalidTx => {
                unimplemented!();
            }
            TransactionMember::AccessList => {
                //TODO
                unimplemented!()
            }
            TransactionMember::MaxPriorityFeePerGas => {
                let max_priority_fee_per_gas_bytes: [u8; 32] = random_input[..32].try_into().unwrap();
                let max_priority_fee_per_gas = Word::from(max_priority_fee_per_gas_bytes);
                dbg!(mock_transaction.max_priority_fee_per_gas(max_priority_fee_per_gas));
            }
            TransactionMember::MaxFeePerGas => {
                let max_fee_per_gas_bytes: [u8; 32] = random_input[..32].try_into().unwrap();
                let max_fee_per_gas = Word::from(max_fee_per_gas_bytes);
                dbg!(mock_transaction.max_fee_per_gas(max_fee_per_gas));
            }
            TransactionMember::ChainId => {
                unimplemented!();
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum AccountMember<const NACC: usize> {
    Address,
    Nonce,
    Balance,
    Code,
    Storage,
}

impl<const NACC: usize> AccountMember<NACC> {
    pub fn randomize_accounts_all_members(random_input: &[[u8; 128]; 5], mock_account: &mut MockAccount) {
        for function in &[
            AccountMember::Address,
            AccountMember::Nonce,
            AccountMember::Balance,
            // AccountMember::Code,
            // AccountMember::Storage,
        ] {
            Self::randomize_account_at_member(random_input, *function, mock_account);
        }
    }

    pub fn randomize_account_at_member(random_input: &[[u8; 128]; 5], function: AccountMember<NACC>, mock_account: &mut MockAccount) {
        match function {
            AccountMember::Address => {
                let address_bytes: [u8; 20] = random_input[0][..20].try_into().unwrap();
                let address = Address::from(address_bytes);
                dbg!(mock_account.address(address));
            }
            AccountMember::Nonce => {
                let nonce_bytes: [u8; 8] = random_input[1][..8].try_into().unwrap();
                let nonce = u64::from_be_bytes(nonce_bytes);
                dbg!(mock_account.nonce(nonce));
            }
            AccountMember::Balance => {
                let balance_bytes: [u8; 32] = random_input[2][..32].try_into().unwrap();
                let balance = Word::from(balance_bytes);
                dbg!(mock_account.balance(balance));
            }
            AccountMember::Code => {
                // let code_bytes: [u8; 32] = random_input[3][..32].try_into().unwrap();
                // let code = Bytes::from(code_bytes);
                // dbg!(mock_account.code(code));
                unimplemented!();
            }
            AccountMember::Storage => {
                unimplemented!();
            }
        }
    }

    pub fn randomize_all_accounts(
        mut accounts: [&mut MockAccount; NACC],
        random_inputs: &[[[u8; 128]; 5]; NACC],
    ) {
        for (index, account) in accounts.iter_mut().enumerate() {
            if let Some(random_input) = random_inputs.get(index) {
                AccountMember::<CURRENT_NACC>::randomize_accounts_all_members(random_input, account);
            }
        }
    }
}