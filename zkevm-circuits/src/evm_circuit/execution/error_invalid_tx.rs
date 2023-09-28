use crate::{evm_circuit::{
    execution::ExecutionGadget,
    step::ExecutionState,
    table::{FixedTableTag, Lookup},
    util::{
        common_gadget::CommonErrorGadget, constraint_builder::{EVMConstraintBuilder, ConstrainBuilderCommon}, CachedRegion,
        Cell, math_gadget::{IsEqualGadget, LtGadget},
    },
    witness::{Block, Call, ExecStep, Transaction}, param::N_BYTES_GAS,
}, table::{TxFieldTag, TxContextFieldTag, AccountFieldTag, BlockContextFieldTag}};
use eth_types::{Field, evm_types::GasCost};
use gadgets::util::{Expr, select, not, or};
use halo2_proofs::{circuit::Value, plonk::Error};


/// Gadget for invalid Tx
#[derive(Clone, Debug)]
pub(crate) struct ErrorInvalidTxGadget<F> {
    tx_id: Cell<F>,
    caller_nounce: Cell<F>,
    expected_nounce: Cell<F>,
    nonce_match: IsEqualGadget<F>,
    caller_balance: Cell<F>,
    block_gas_limit: Cell<F>,
    insufficient_balance: LtGadget<F, N_BYTES_GAS>, 
    insufficient_block_gas: LtGadget<F, N_BYTES_GAS>,
}

impl<F: Field> ExecutionGadget<F> for ErrorInvalidTxGadget<F> {
    const NAME: &'static str = "ErrorInvalidTx";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorInvalidTx;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let tx_id = cb.query_cell();
        let [nounce, caller, is_create, call_data_length, call_data_gas_cost, access_list_gas_cost] =
            [
                TxContextFieldTag::Nonce,
                TxContextFieldTag::CallerAddress,
                TxContextFieldTag::IsCreate,
                TxContextFieldTag::CallDataLength,
                TxContextFieldTag::CallDataGasCost,
                TxContextFieldTag::AccessListGasCost,
            ]
            .map(|field_tag| cb.tx_context(tx_id.expr(), field_tag, None));
        
        // Read the current nounce to prove mismatch
        let expected_nounce = cb.query_cell();
        cb.account_read(
            caller.expr(),
             AccountFieldTag::Nonce, 
             expected_nounce.expr()
        );
        let nonce_match = IsEqualGadget::construct(
            cb, 
            nounce.expr(), 
            expected_nounce.expr()
        );

        // Read the current balance to compare with intrinsic gas
        let balance = cb.query_cell_phase2();
        cb.account_read(
            caller.expr(), 
            AccountFieldTag::Balance, 
            balance.expr()
        );
        // Read the block gas limit
        let block_gas_limit = cb.query_cell();
        cb.block_lookup(BlockContextFieldTag::GasLimit.expr(), None, block_gas_limit.expr());

        // Calculate the intrinsic gas cost
        let intrinsic_gas_cost = select::expr(
            is_create.expr(),
            GasCost::CREATION_TX.expr(),
            GasCost::TX.expr(),
        ) + call_data_gas_cost.expr() + access_list_gas_cost.expr();

        let [insufficient_balance, insufficient_block_gas] = [balance.clone(), block_gas_limit.clone()]
            .map(|v| {
                LtGadget::<F, N_BYTES_GAS>::construct(
                    cb,
                    v.expr(), 
                    intrinsic_gas_cost.clone()
                )
            });
        
        let invalid_tx = or::expr(
            [
                not::expr(nonce_match.expr()), 
                insufficient_balance.expr(), 
                insufficient_block_gas.expr()
                ]
        );
        cb.require_zero("Tx is invalid", 1.expr() - invalid_tx);

        Self { 
            tx_id, 
            caller_nounce: nounce, 
            expected_nounce, 
            nonce_match, 
            caller_balance: balance, 
            block_gas_limit, 
            insufficient_balance, 
            insufficient_block_gas 
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
    
        Ok(())
    }
}


#[cfg(test)]
mod test {
}