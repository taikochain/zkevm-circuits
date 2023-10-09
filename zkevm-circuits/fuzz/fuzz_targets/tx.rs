#![no_main]

use halo2_proofs::halo2curves::bn256::Fr;
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;

use eth_types::geth_types::Transaction;
use mock::MockTransaction;
use zkevm_circuits::tx_circuit::test::run;

use crate::lib::TransactionMember;

mod lib;


#[derive(Clone, Debug, libfuzzer_sys::arbitrary::Arbitrary)]
pub struct TxRandomInput {
    pub transactions_random_input: Vec<[u8; 128]>,
}

fuzz_target!(|tx_random_input: TxRandomInput| {

    println!("tx random input count: {:?}", tx_random_input.transactions_random_input.len());
    if tx_random_input.transactions_random_input.len() != 1 {
        return;
    }

    const MAX_CALLDATA: usize = 32;
    const NTX: usize = 1;
    let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

    let mut transactions = vec![MockTransaction::default(); NTX];
    transactions = TransactionMember::<NTX>::randomize_transactions_vec_one_random_member(transactions, tx_random_input.transactions_random_input);
    let  transactions: Vec<Transaction>=
            transactions.iter_mut().map(|tx| {
                tx.build();
                tx
    }).map(|tx| tx.clone().into()).collect();

    assert_eq!(run::<Fr>(transactions, chain_id, NTX, MAX_CALLDATA), Ok(()));
});
