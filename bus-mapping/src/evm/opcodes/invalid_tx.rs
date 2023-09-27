use super::TxExecSteps;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecState, ExecStep},
    operation::{AccountField, AccountOp, CallContextField, TxReceiptField, TxRefundOp, RW},
    state_db::CodeDB,
    Error, exec_trace,
};
use eth_types::{
    evm_types::{GasCost, MAX_REFUND_QUOTIENT_OF_GAS_USED},
    evm_unimplemented, ToWord, Word,
};
use ethers_core::utils::get_contract_address;

#[derive(Clone, Copy, Debug)]
pub(crate) struct InvalidTx;

impl TxExecSteps for InvalidTx {
    fn gen_associated_steps(
        state: &mut CircuitInputStateRef,
        execution_step: ExecState,
    ) -> Result<ExecStep, Error> {
        // Todo(Cecilia)
        let mut exec_step = state.new_invalid_tx_step();
        Ok(exec_step)
    }
}
