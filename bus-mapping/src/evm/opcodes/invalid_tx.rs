use super::TxExecSteps;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecState, ExecStep},
    exec_trace,
    operation::{AccountField, AccountOp, CallContextField, TxReceiptField, TxRefundOp, RW},
    state_db::CodeDB,
    Error,
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
        _execution_step: ExecState,
    ) -> Result<ExecStep, Error> {
        println!("gen_associated_steps InvalidTx {:?}", state.block_ctx.rwc.0);

        // Todo(Cecilia)
        let mut exec_step = state.new_invalid_tx_step();
        let call = state.call()?.clone();
        let caller = call.caller_address;

        // Write the transaction id
        state.call_context_write(
            &mut exec_step,
            call.call_id,
            CallContextField::TxId,
            state.tx_ctx.id().into(),
        );

        // Read the nounce in db to prove mismatch
        state.account_read(
            &mut exec_step,
            caller,
            AccountField::Nonce,
            state.sdb.get_account(&caller).1.nonce.into(),
        );

        // Read the balance in db to compare with intrinsic gas
        state.account_read(
            &mut exec_step,
            caller,
            AccountField::Balance,
            state.sdb.get_account(&caller).1.balance.into(),
        );

        if !state.tx_ctx.is_last_tx() {
            state.call_context_write(
                &mut exec_step,
                state.block_ctx.rwc.0 + 1,
                CallContextField::TxId,
                (state.tx_ctx.id() + 1).into(),
            );
        }

        Ok(exec_step)
    }
}
