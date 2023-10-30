macro_rules! run_test {
    ($test_instance:expr, $block_num:expr, $real_prover:expr) => {
        log_init();

        let mut test = $test_instance.lock().await;
        test.test_block_by_number($block_num, $real_prover, true)
            .await;
    };
}

macro_rules! declare_tests {
    (($name:ident, $block_num:expr),$real_prover:expr) => {
        paste! {
            #[tokio::test]
            async fn [<serial_test_evm_ $name>]() {
                run_test! (PI_CIRCUIT_TEST, $block_num, $real_prover);
            }
        }
    };
}

macro_rules! unroll_tests {
    ($($arg:tt),*) => {
        use paste::paste;
        use integration_tests::circuits_utils::{
            PI_CIRCUIT_TEST,
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
    (circuit_block_anchor_only, 2000),
    (circuit_block_transfer_succeed, 102)
);
