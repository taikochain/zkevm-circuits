#![cfg(feature = "circuit_input_builder")]

use integration_tests::{build_circuit_input_builder_block, log_init};

macro_rules! declare_tests {
    ($test_name:ident, $block_num:expr) => {
        #[tokio::test]
        async fn $test_name() {
            log_init();
            build_circuit_input_builder_block($block_num).await;
        }
    };
}

// This test builds the complete circuit inputs for the block that has
// only one anchor
declare_tests!(test_circuit_input_builder_block_anchor_only, 137947);
// This test builds the complete circuit inputs for the block that has
// propose block contract call
declare_tests!(test_circuit_input_builder_block_propose_block, 137932);
// This test builds the complete circuit inputs for the block that has
// prove block contract call
declare_tests!(test_circuit_input_builder_block_prove_block, 138019);
// This test builds the complete circuit inputs for the block that has
// ERC20 transfer
declare_tests!(test_circuit_input_builder_block_transfer_succeed, 138018);
