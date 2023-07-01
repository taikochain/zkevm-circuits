#![cfg(feature = "circuit_input_builder")]

use integration_tests::{
    build_circuit_input_builder_block, log_init, TAIKO_BLOCK_ANCHOR_ONLY,
    TAIKO_BLOCK_PROPOSE_BLOCK, TAIKO_BLOCK_PROVE_BLOCK, TAIKO_BLOCK_TRANSFER_SUCCEED,
};

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
declare_tests!(
    test_circuit_input_builder_block_anchor_only,
    TAIKO_BLOCK_ANCHOR_ONLY
);
// This test builds the complete circuit inputs for the block that has
// propose block contract call
declare_tests!(
    test_circuit_input_builder_block_propose_block,
    TAIKO_BLOCK_PROPOSE_BLOCK
);
// This test builds the complete circuit inputs for the block that has
// prove block contract call
declare_tests!(
    test_circuit_input_builder_block_prove_block,
    TAIKO_BLOCK_PROVE_BLOCK
);
// This test builds the complete circuit inputs for the block that has
// ERC20 transfer
declare_tests!(
    test_circuit_input_builder_block_transfer_succeed,
    TAIKO_BLOCK_TRANSFER_SUCCEED
);
