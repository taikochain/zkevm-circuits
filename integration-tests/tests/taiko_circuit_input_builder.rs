#![cfg(feature = "circuit_input_builder")]

use integration_tests::{
    log_init,
};

macro_rules! declare_tests {
    ($test_name:ident, $block_num:expr) => {
        #[tokio::test]
        async fn $test_name() {
            use integration_tests::build_circuit_input_builder_block;
            log_init();
            build_circuit_input_builder_block($block_num).await;
        }
    };
}

// This test builds the complete circuit inputs for the block that has
// only one anchor
declare_tests!(
    test_circuit_input_builder_block_anchor_only,
    66
);
// This test builds the complete circuit inputs for the block that has
// ERC20 transfer
declare_tests!(
    test_circuit_input_builder_block_transfer_succeed,
    88
);
