pub use super::AnchorTxCircuit;
use crate::{
    anchor_tx_circuit::{AnchorTxCircuitConfig, AnchorTxCircuitConfigArgs},
    table::{PiTable, TxTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, Taiko},
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

/// Test circuit for the anchor tx circuit.
#[derive(Clone, Debug, Default)]
pub struct TestAnchorTxCircuit<F: Field> {
    txs: Vec<witness::Transaction>,
    taiko: Taiko,
    max_calldata: usize,
    circuit: AnchorTxCircuit<F>,
}

impl<F: Field> TestAnchorTxCircuit<F> {
    /// Create a new test circuit from a block.
    pub fn new_from_block(block: &witness::Block<F>) -> Self {
        TestAnchorTxCircuit {
            txs: block.txs.clone(),
            taiko: block.taiko.clone(),
            max_calldata: block.circuits_params.max_calldata,
            circuit: AnchorTxCircuit::new_from_block(block),
        }
    }
}

impl<F: Field> Circuit<F> for TestAnchorTxCircuit<F> {
    type Config = (AnchorTxCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = TxTable::construct(meta);
        let pi_table = PiTable::construct(meta);
        let challenges = Challenges::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);
            AnchorTxCircuitConfig::new(
                meta,
                AnchorTxCircuitConfigArgs {
                    tx_table,
                    pi_table,
                    challenges,
                },
            )
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);
        config.tx_table.load(
            &mut layouter,
            &self.txs[..],
            self.circuit.max_txs,
            self.max_calldata,
            &challenges,
        )?;
        config
            .pi_table
            .load(&mut layouter, &self.taiko, &challenges)?;
        self.circuit
            .synthesize_sub(&config, &challenges, &mut layouter)
    }
}
