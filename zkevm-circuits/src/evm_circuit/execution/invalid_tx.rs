use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition, Transition::*,
            },
            math_gadget::{
                AddWordsGadget, IsEqualGadget, LtGadget, LtWordGadget, MulWordByU64Gadget,
            },
            CachedRegion, Cell, StepRws, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag, TxContextFieldTag},
};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use gadgets::util::{not, or, select, Expr, Scalar};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

/// Gadget for invalid Tx
#[derive(Clone, Debug)]
pub(crate) struct TxCostGadget<F> {
    id: Cell<F>,
    nonce: Cell<F>,
    caller: Cell<F>,
    is_create: Cell<F>,
    gas_limit: Cell<F>,
    call_data_gas_cost: Cell<F>,
    access_list_gas_cost: Cell<F>,

    gas_price: Word<F>,
    value: Word<F>,

    gas_mul_gas_price: MulWordByU64Gadget<F>,
    gas_mul_gas_price_plus_value: AddWordsGadget<F, 2, false>,
    cost_sum: Word<F>,
}

impl<F: Field> TxCostGadget<F> {
    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        // Use rw_counter of the step which triggers next call as its call_id.
        let call_id: Cell<F> = cb.curr.state.rw_counter.clone();

        let id = cb.query_cell();
        cb.call_context_lookup(
            1.expr(),
            Some(call_id.expr()),
            CallContextFieldTag::TxId,
            id.expr(),
        ); // rwc_delta += 1
        let [nonce, caller, is_create, gas_limit, call_data_gas_cost, access_list_gas_cost] = [
            TxContextFieldTag::Nonce,
            TxContextFieldTag::CallerAddress,
            TxContextFieldTag::IsCreate,
            TxContextFieldTag::Gas,
            TxContextFieldTag::CallDataGasCost,
            TxContextFieldTag::AccessListGasCost,
        ]
        .map(|field_tag| cb.tx_context(id.expr(), field_tag, None));

        let [gas_price, value] = [TxContextFieldTag::GasPrice, TxContextFieldTag::Value]
            .map(|field_tag| cb.tx_context_as_word(id.expr(), field_tag, None));

        let gas_mul_gas_price =
            MulWordByU64Gadget::construct(cb, gas_price.clone(), gas_limit.expr());
        let cost_sum = cb.query_word_rlc();
        let gas_mul_gas_price_plus_value = AddWordsGadget::construct(
            cb,
            [gas_mul_gas_price.product().clone(), value.clone()],
            cost_sum.clone(),
        );
        Self {
            id,
            nonce,
            caller,
            is_create,
            gas_limit,
            call_data_gas_cost,
            access_list_gas_cost,
            gas_price,
            value,
            gas_mul_gas_price,
            gas_mul_gas_price_plus_value,
            cost_sum,
        }
    }

    fn intrinsic_gas(&self) -> Expression<F> {
        select::expr(
            self.is_create.expr(),
            GasCost::CREATION_TX.0.expr(),
            GasCost::TX.0.expr(),
        ) + self.call_data_gas_cost.expr()
            + self.access_list_gas_cost.expr()
    }

    fn total_gas_provided(&self) -> Word<F> {
        self.gas_mul_gas_price.product().clone()
    }

    fn total_cost(&self) -> Word<F> {
        self.gas_mul_gas_price_plus_value.sum().clone()
    }

    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        Transaction {
            id,
            caller_address,
            nonce,
            is_create,
            gas,
            access_list_gas_cost,
            call_data_gas_cost,
            gas_price,
            value,
            ..
        }: &Transaction,
    ) -> Result<(), Error> {
        let caller = caller_address
            .to_scalar()
            .expect("unexpected Address -> Scalar conversion failure");

        self.id.assign(region, offset, Value::known(id.scalar()))?;
        self.nonce
            .assign(region, offset, Value::known(nonce.scalar()))?;
        self.caller.assign(region, offset, Value::known(caller))?;
        self.is_create
            .assign(region, offset, Value::known(is_create.scalar()))?;
        self.gas_limit
            .assign(region, offset, Value::known(gas.scalar()))?;
        self.call_data_gas_cost.assign(
            region,
            offset,
            Value::known(call_data_gas_cost.scalar()),
        )?;
        self.access_list_gas_cost.assign(
            region,
            offset,
            Value::known(access_list_gas_cost.scalar()),
        )?;
        self.gas_price
            .assign(region, offset, Some(gas_price.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        self.gas_mul_gas_price
            .assign(region, offset, *gas_price, *gas, gas_price * gas)?;
        let sum = gas_price * gas + *value;
        self.cost_sum
            .assign(region, offset, Some(sum.to_le_bytes()))?;
        self.gas_mul_gas_price_plus_value
            .assign(region, offset, [gas_price * gas, *value], sum)?;

        Ok(())
    }
}

/// Gadget for invalid Tx
#[derive(Clone, Debug)]
pub(crate) struct InvalidTxGadget<F> {
    tx: TxCostGadget<F>,
    bd_nonce: Cell<F>,
    is_nonce_match: IsEqualGadget<F>,
    bd_balance: Word<F>,
    insufficient_gas_limit: LtGadget<F, N_BYTES_GAS>,
    insufficient_balance: LtWordGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for InvalidTxGadget<F> {
    const NAME: &'static str = "ErrorInvalidTx";

    const EXECUTION_STATE: ExecutionState = ExecutionState::InvalidTx;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let tx = TxCostGadget::configure(cb);
        // Read the current nounce to prove mismatch
        let bd_nonce = cb.query_cell_phase2();
        cb.account_read(tx.caller.expr(), AccountFieldTag::Nonce, bd_nonce.expr());
        let is_nonce_match = IsEqualGadget::construct(cb, bd_nonce.expr(), tx.nonce.expr());
        // Read the current balance to compare with intrinsic gas
        let bd_balance = cb.query_word_rlc();
        cb.account_read(
            tx.caller.expr(),
            AccountFieldTag::Balance,
            bd_balance.expr(),
        );

        let insufficient_gas_limit =
            LtGadget::<F, N_BYTES_GAS>::construct(cb, tx.gas_limit.expr(), tx.intrinsic_gas());
        let insufficient_balance = LtWordGadget::construct(cb, &bd_balance, &tx.total_cost());

        let invalid_tx = or::expr([
            not::expr(is_nonce_match.expr()),
            insufficient_gas_limit.expr(),
            insufficient_balance.expr(),
        ]);
        cb.require_equal("Tx is invalid", invalid_tx.expr(), 1.expr());

        let begin_tx_rw_counter = 4.expr();
        let invalid_tx_rw_counter = 4.expr();
        let end_block_rw_counter = 3.expr();
        [
            ExecutionState::BeginTx,
            ExecutionState::InvalidTx,
            ExecutionState::EndBlock,
        ]
        .iter()
        .zip(
            [
                begin_tx_rw_counter,
                invalid_tx_rw_counter,
                end_block_rw_counter,
            ]
            .iter(),
        )
        .for_each(|(state, rw_counter)| {
            cb.condition(cb.next.execution_state_selector([*state]), |cb| {
                if state == &ExecutionState::EndBlock {
                    println!("transtion ExecutionState::EndBlock");
                    cb.require_step_state_transition(StepStateTransition {
                        rw_counter: Delta(rw_counter.clone()),
                        call_id: Same,
                        ..StepStateTransition::any()
                    });
                } else {
                    cb.call_context_lookup(
                        true.expr(),
                        Some(cb.next.state.rw_counter.expr()),
                        CallContextFieldTag::TxId,
                        tx.id.expr() + 1.expr(),
                    );
                    cb.require_step_state_transition(StepStateTransition {
                        rw_counter: Delta(rw_counter.clone()),
                        ..StepStateTransition::any()
                    });
                }
            });
        });

        Self {
            tx,
            bd_nonce,
            is_nonce_match,
            bd_balance,
            insufficient_balance,
            insufficient_gas_limit,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        println!("-->InvalidTx rwc {:?}", step.rwc.0);
        let mut rws = StepRws::new(block, step);
        rws.offset_add(1);

        let bd_nonce = rws
            .next()
            .account_value_pair()
            .0
            .to_scalar()
            .expect("unexpected U256 -> Scalar conversion failure");
        let bd_balance = rws.next().account_value_pair().0;

        self.tx.assign(region, offset, tx)?;

        self.bd_nonce
            .assign(region, offset, Value::known(bd_nonce))?;
        self.is_nonce_match
            .assign(region, offset, bd_nonce, tx.nonce.scalar())?;
        println!("bd_nonce: {:?}", bd_nonce);
        println!("tx.nonce: {:?}", tx.nonce);

        println!("bd_balance: {:?}", bd_balance);
        self.bd_balance
            .assign(region, offset, Some(bd_balance.to_le_bytes()))?;

        let is_create = tx.is_create as u64;
        let intrinsic_gas = is_create * GasCost::CREATION_TX.as_u64()
            + (1 - is_create) * GasCost::TX.as_u64()
            + tx.call_data_gas_cost
            + tx.access_list_gas_cost;
        println!("intrinsic_gas_cost: {:?}", intrinsic_gas);

        self.insufficient_gas_limit.assign(
            region,
            offset,
            tx.gas.scalar(),
            intrinsic_gas.scalar(),
        )?;
        self.insufficient_balance.assign(
            region,
            offset,
            bd_balance,
            tx.gas_price * tx.gas + tx.value,
        )?;
        println!("tx.id: {:?}", tx.id);

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use crate::test_util::CircuitTestBuilder;
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{self, bytecode, Word};

    use mock::{eth, gwei, TestContext, MOCK_ACCOUNTS};

    #[test]
    fn invalid_tx_invalid_nonce() {
        // The nonce of the account doing the transaction is not correct
        // Use the same nonce value for two transactions.

        let to = MOCK_ACCOUNTS[0];
        let from = MOCK_ACCOUNTS[1];

        let code = bytecode! {
            STOP
        };

        let ctx = TestContext::<2, 3>::new(
            None,
            |accs| {
                accs[0].address(to).balance(eth(1)).code(code);
                accs[1].address(from).balance(eth(1)).nonce(1);
            },
            |mut txs, _| {
                txs[0].to(to).from(from).nonce(5);
                // Tx with wrong nounce is skipped but proved
                txs[1].to(to).from(from).nonce(1);
                // Tx with the right nonce
                txs[2].to(to).from(from).nonce(2);
            },
            |block, _| block,
            true,
        )
        .unwrap()
        .enable_invalid_tx();

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_txs: 3,
                ..Default::default()
            })
            .run();
    }

    #[test]
    fn invalid_tx_not_enough_balance() {
        let to = MOCK_ACCOUNTS[0];
        let from = MOCK_ACCOUNTS[1];

        // Invalid if gas_limit < intrinsic gas
        // intrinsic gas = GasCost::TX = 21000
        // gas limit = 30000
        // total cost = 30000 * 2 gwei = 6 * 10^13

        // Enough balance but not enough gas limit
        let balance = gwei(1) / 100000; // < total cost
        let tx_gas_limit = Word::from(30000); // > intrinsic gas
        let gas_price = gwei(2);

        let ctx = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0].address(to).balance(balance);
                accs[1].address(from).balance(balance).nonce(1);
            },
            |mut txs, _| {
                txs[0]
                    .to(to)
                    .from(from)
                    .nonce(1)
                    .gas_price(gas_price)
                    .gas(tx_gas_limit);
            },
            |block, _| block,
            true,
        )
        .unwrap()
        .enable_invalid_tx();

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_txs: 1,
                ..Default::default()
            })
            .run();
    }

    #[test]
    fn invalid_tx_insufficient_gas() {
        let to = MOCK_ACCOUNTS[0];
        let from = MOCK_ACCOUNTS[1];

        // Invalid if gas_limit < intrinsic gas
        // intrinsic gas = GasCost::TX = 21000
        // gas limit = 100
        // total cost = 100 * 1 gwei = 10^11

        // Enough balance but not enough gas limit
        let balance = eth(1); // > total cost
        let tx_gas_limit = Word::from(100); // < intrinsic gas

        let ctx = TestContext::<2, 3>::new(
            None,
            |accs| {
                accs[0].address(to).balance(balance);
                accs[1].address(from).balance(balance);
            },
            |mut txs, _| {
                // Work around no payment to the coinbase address
                txs[0]
                    .to(to)
                    .from(from)
                    .nonce(1)
                    .gas_price(gwei(1))
                    .gas(tx_gas_limit);
                txs[1]
                    .to(to)
                    .from(from)
                    .nonce(1)
                    .gas_price(gwei(1))
                    .gas(tx_gas_limit);
                txs[2]
                    .to(to)
                    .from(from)
                    .nonce(1)
                    .gas_price(gwei(1))
                    .gas(Word::from(300000));
            },
            |block, _| block,
            true,
        )
        .unwrap()
        .enable_invalid_tx();

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_txs: 3,
                ..Default::default()
            })
            .run();
    }
}
