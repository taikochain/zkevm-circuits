macro_rules! run_test {
    ($test_instance:expr, $block_num:expr, $real_prover:expr) => {
        log_init();

        let mut test = $test_instance.lock().await;
        test.test_block_by_number($block_num, $real_prover).await;
    };
}

macro_rules! declare_tests {
    (($name:ident, $block_num:expr),$real_prover:expr) => {
        paste! {
            #[tokio::test]
            async fn [<serial_test_evm_ $name>]() {
                run_test! (EVM_CIRCUIT_TEST, $block_num, $real_prover);
            }

            #[tokio::test]
            async fn [<serial_test_super_ $name>]() {
                run_test! (SUPER_CIRCUIT_TEST, $block_num, $real_prover);
            }
        }
    };
}

macro_rules! unroll_tests {
    ($($arg:tt),*) => {
        use paste::paste;
        use integration_tests::integration_test_circuits::{
            EVM_CIRCUIT_TEST,
            SUPER_CIRCUIT_TEST,
        };
        use integration_tests::log_init;
        mod real_prover {
            use super::*;
            $(
                declare_tests! ($arg, true) ;
            )*
        }

        mod mock_prover {
            use super::*;
            $(
                declare_tests! ($arg, false) ;
            )*
        }
    }
}

unroll_tests!(
    (circuit_block_anchor_only, 137947),
    (circuit_block_propose_block, 137932),
    (circuit_block_prove_block, 138019),
    (circuit_block_transfer_succeed, 138018)
);
