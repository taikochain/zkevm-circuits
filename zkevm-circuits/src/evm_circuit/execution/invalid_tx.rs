use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::{FixedTableTag, Lookup},
        util::{
            common_gadget::CommonErrorGadget, constraint_builder::{EVMConstraintBuilder, ConstrainBuilderCommon}, CachedRegion,
            Cell, math_gadget::{IsEqualGadget, LtGadget}, StepRws,
        },
        witness::{Block, Call, ExecStep, Transaction}, param::N_BYTES_GAS,
    }, 
    table::{TxFieldTag, TxContextFieldTag, AccountFieldTag, BlockContextFieldTag}
};
use eth_types::{Field, evm_types::GasCost, ToScalar};
use gadgets::util::{Expr, Scalar, select, not, or};
use halo2_proofs::{circuit::Value, plonk::Error};


/// Gadget for invalid Tx
#[derive(Clone, Debug)]
pub(crate) struct InvalidTxGadget<F> {
    tx_id: Cell<F>,
    tx_nonce: Cell<F>,
    bd_nonce: Cell<F>,
    is_nonce_match: IsEqualGadget<F>,
    bd_balance: Cell<F>,
    block_gas_limit: Cell<F>,
    insufficient_balance: LtGadget<F, N_BYTES_GAS>, 
    insufficient_block_gas: LtGadget<F, N_BYTES_GAS>,
}

impl<F: Field> ExecutionGadget<F> for InvalidTxGadget<F> {
    const NAME: &'static str = "ErrorInvalidTx";

    const EXECUTION_STATE: ExecutionState = ExecutionState::InvalidTx;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let tx_id = cb.query_cell();
        let [tx_nonce, caller, is_create, call_data_gas_cost, access_list_gas_cost] =
            [
                TxContextFieldTag::Nonce,
                TxContextFieldTag::CallerAddress,
                TxContextFieldTag::IsCreate,
                TxContextFieldTag::CallDataGasCost,
                TxContextFieldTag::AccessListGasCost,
            ]
            .map(|field_tag| cb.tx_context(tx_id.expr(), field_tag, None));
        
        // Read the current nounce to prove mismatch
        let bd_nonce = cb.query_cell();
        cb.account_read(
            caller.expr(),
             AccountFieldTag::Nonce, 
             bd_nonce.expr()
        );
        let nonce_match = IsEqualGadget::construct(
            cb, 
            tx_nonce.expr(), 
            bd_nonce.expr()
        );

        // Read the current balance to compare with intrinsic gas
        let bd_balance = cb.query_cell_phase2();
        cb.account_read(
            caller.expr(), 
            AccountFieldTag::Balance, 
            bd_balance.expr()
        );
        // Read the block gas limit
        let block_gas_limit = cb.query_cell();
        cb.block_lookup(BlockContextFieldTag::GasLimit.expr(), None, block_gas_limit.expr());

        // Calculate the intrinsic gas cost
        let intrinsic_gas_cost = select::expr(
            is_create.expr(),
            GasCost::CREATION_TX.0.expr(),
            GasCost::TX.0.expr(),
        ) + call_data_gas_cost.expr() + access_list_gas_cost.expr();

        let [insufficient_balance, insufficient_block_gas] = [bd_balance.clone(), block_gas_limit.clone()]
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
            tx_nonce, 
            bd_nonce, 
            is_nonce_match: nonce_match, 
            bd_balance, 
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
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let mut rws = StepRws::new(block, step);
        let bd_nonce = rws.next().account_value_pair().0.to_scalar().unwrap();
        let bd_balance = rws.next().account_value_pair().0.to_scalar().unwrap();
        let block_gas_limit = block.eth_block.gas_limit.to_scalar().unwrap();

        let bd_nonce_val = Value::known(bd_nonce);
        let tx_nonce_val = Value::known(tx.nonce.scalar());
        let bd_balance_val = Value::known(bd_balance);
        let block_gas_limit_val = Value::known(block_gas_limit);

        self.bd_nonce.assign(region, offset, bd_nonce_val)?;
        self.tx_nonce.assign(region, offset, tx_nonce_val)?;
        self.is_nonce_match.assign(region, offset, bd_nonce, tx.nonce.scalar())?;

        self.bd_balance.assign(region, offset, bd_balance_val)?;
        self.block_gas_limit.assign(region, offset, block_gas_limit_val)?;

        let intrinsic_gas_cost = select::value::<F>(
            tx.is_create.scalar(),
            GasCost::CREATION_TX.as_u64().scalar(),
            GasCost::TX.as_u64().scalar(),
        ) + F::from(tx.call_data_gas_cost)
            + F::from(tx.access_list_gas_cost);
            
        self.insufficient_balance.assign(region, offset, bd_balance, intrinsic_gas_cost)?;
        self.insufficient_block_gas.assign(region, offset, block_gas_limit, intrinsic_gas_cost)?;

        Ok(())
    }
}


#[cfg(test)]
mod test {
}