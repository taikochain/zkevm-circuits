// Public data circuits verifies the things related to public data, such as rlp decoding txlist and
// public data itself. for examplp: rlp decoding, we need to parse fn calldata from every
// proposalBlock call and give txlist bytes to the circuit.

const TAIKO_CIRCUIT_DEGREE: u32 = 20;

macro_rules! declare_l1_tests {
    ($test_name:ident, $block_num:expr, $expected_tx_cnt: expr, $expected_last_tx_bytes: expr) => {
        /// Get the proposed txlist from L1 and compare the last tx bytes with the expected bytes.
        #[tokio::test]
        async fn $test_name() {
            use crate::{
                get_client, log_init,
                taiko_utils::{filter_proposal_txs, get_txlist_bytes},
                GETH_L1_URL,
            };
            use bus_mapping::rpc::BlockNumber;
            log_init();
            let block = get_client(&GETH_L1_URL)
                .get_block_by_number(BlockNumber::from($block_num))
                .await
                .unwrap();
            let proposal_txs = filter_proposal_txs(&block);
            assert_eq!(proposal_txs.len(), $expected_tx_cnt);
            let txlist_bytes = get_txlist_bytes(&proposal_txs.last().expect("txlist is empty"));
            assert_eq!(txlist_bytes, $expected_last_tx_bytes);
        }
    };
    ($test_name:ident, $block_num:expr) => {
        /// Decode each tx in txlist with rlp
        #[tokio::test]
        async fn $test_name() {
            use crate::{
                get_client, log_init,
                taiko_utils::{filter_proposal_txs, get_txlist_bytes},
                GETH_L1_URL,
            };
            use bus_mapping::rpc::BlockNumber;
            log_init();
            let block = get_client(&GETH_L1_URL)
                .get_block_by_number(BlockNumber::from($block_num))
                .await
                .unwrap();
            let proposal_txs = filter_proposal_txs(&block);
            for tx in proposal_txs {
                let txlist_bytes = get_txlist_bytes(&tx);
                // assert_eq!(run_rlp_circuit_for_valid_bytes(&txlist_bytes), Ok(()));
            }
        }
    };
}

declare_l1_tests!(
    test_l1_get_txlist_call,
    3974689,
    4,
    hex::decode(concat!("blah blah blah")).unwrap()
);

declare_l1_tests!(test_l1_decode_txlist, 4);

macro_rules! declare_l2_tests {
    ($test_name:ident, $block_num:expr, $expected_anchor_info: expr) => {
        /// Get the anchor tx from L2 and compare the anchor info with the expected info.
        /// (l1Hash, l1SignalRoot, l1Height, parentGasUsed)
        #[tokio::test]
        async fn $test_name() {
            use crate::{
                get_client,
                integration_test_circuits::IntegrationTest,
                taiko_utils::{filter_anchor_tx, get_anchor_tx_info, ProtocolInstanceTest},
                GETH_L2_URL,
            };
            use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};
            use lazy_static::lazy_static;
            use zkevm_circuits::{super_circuit::SuperCircuit, util::SubCircuit};
            let block = get_client(&GETH_L2_URL)
                .get_block_by_number(BlockNumber::from($block_num))
                .await
                .unwrap();
            let anchor = filter_anchor_tx(&block);
            let anchor_info = get_anchor_tx_info(&anchor);
            // assert_eq!(anchor_info, $expected_anchor_info);
            println!("anchor_info: {:?}", anchor_info);
        }
    };
    ($test_name:ident, $block_num:expr, $is_actual:expr) => {
        /// Decode each tx in txlist with rlp
        #[tokio::test]
        async fn $test_name() {
            use crate::{
                get_client,
                integration_test_circuits::IntegrationTest,
                taiko_utils::{filter_anchor_tx, get_anchor_tx_info, ProtocolInstanceTest},
            };
            use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};
            use lazy_static::lazy_static;
            use zkevm_circuits::{super_circuit::SuperCircuit, util::SubCircuit};
            let mut taiko_test = IntegrationTest::new("TAIKO_TEST", TAIKO_CIRCUIT_DEGREE);
            let block = taiko_test.block_with_instance(10).await;
            block.randomness = Fr::ONE;
            let circuit = SuperCircuit::new_from_block(&block);
            let instance = circuit.instance();
            if $is_mock {
                taiko_test.test_mock(&circuit, &instance);
            } else {
                taiko_test.test_actual(&circuit, &instance);
            }
        }
    };
}

declare_l2_tests!(
    test_get_anchor_tx,
    10,
    (H256::default(), H256::default(), 0, 0)
);

declare_l2_tests!(test_real_taiko_block_mock_proof, 10, false);

declare_l2_tests!(test_real_taiko_block_real_proof, 10, true);
