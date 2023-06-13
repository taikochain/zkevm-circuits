//! The Root circuit implementation.
use eth_types::Field;
use halo2_proofs::{
    arithmetic::Field as Halo2Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::{
        bn256::{Bn256, Fr},
        serde::SerdeObject,
    },
    plonk::{Circuit, ConstraintSystem, Error},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use maingate::{MainGateInstructions, RangeInstructions};
use snark_verifier::{util::arithmetic::MultiMillerLoop, verifier::plonk::PlonkProtocol};
use snark_verifier_sdk::{CircuitExt, GWC, SHPLONK};
use std::{fmt, iter};

mod aggregation;

#[cfg(any(feature = "test", test))]
mod test;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub use self::RootCircuit as TestRootCircuit;

pub use aggregation::{
    aggregate, EccChip, Halo2Loader, KzgAs, KzgDk, KzgSvk, PlonkSuccinctVerifier, PlonkVerifier,
    PoseidonTranscript, BITS, LIMBS,
};

pub use snark_verifier::system::halo2::{compile, Config};
use snark_verifier_sdk::{
    halo2::aggregation::{AggregationCircuit, AggregationConfig},
    Snark,
};

#[cfg(any(feature = "test", test))]
pub use aggregation::TestAggregationCircuit;

/// RootCircuit for aggregating SuperCircuit into a much smaller proof.
#[derive(Clone)]
pub struct RootCircuit<GWC> {
    aggregation_circuit: AggregationCircuit<GWC>,
    input_snarks: Vec<Snark>,
}

impl RootCircuit<GWC> {
    /// Create a `RootCircuit` with accumulator computed given a `SuperCircuit`
    /// proof and its instance. Returns `None` if given proof is invalid.
    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks: impl IntoIterator<Item = Snark>,
    ) -> Result<Self, snark_verifier::Error> {
        let input_snarks = snarks.into_iter().collect_vec();
        Ok(Self {
            aggregation_circuit: AggregationCircuit::<GWC>::new(params, input_snarks.clone()),
            input_snarks,
        })
    }

    /// Returns accumulator indices in instance columns, which will be in
    /// the last `4 * LIMBS` rows of instance column in `MainGate`.
    pub fn accumulator_indices(&self) -> Vec<(usize, usize)> {
        let total_instance_num = self.num_instance().iter().sum::<usize>();
        println!("total_instance_num: {:?}", total_instance_num);
        assert!(total_instance_num >= 4 * LIMBS);
        (total_instance_num - 4 * LIMBS..total_instance_num)
            .map(|idx| (0, idx))
            .collect()
    }

    /// Returns number of instance
    pub fn num_instance(&self) -> Vec<usize> {
        let prev_instance_num = self
            .input_snarks
            .iter()
            .map(|snark| snark.instances.iter().map(|s| s.len()).sum::<usize>())
            .sum::<usize>();
        vec![
            prev_instance_num
                + self
                    .aggregation_circuit
                    .num_instance()
                    .iter()
                    .sum::<usize>(),
        ]
    }

    /// Returns instance
    pub fn instance(&self) -> Vec<Vec<Fr>> {
        let acc_limbs = self.aggregation_circuit.instances();
        println!("acc_limbs: {:?}", acc_limbs);
        assert!(acc_limbs.len() == 1 && acc_limbs[0].len() == 4 * LIMBS);
        let prev_instance = self
            .input_snarks
            .iter()
            .map(|s| s.instances.clone())
            .flatten()
            .collect_vec();

        vec![prev_instance
            .into_iter()
            .chain(acc_limbs.into_iter())
            .flatten()
            .collect_vec()]
    }
}

impl fmt::Display for RootCircuit<GWC> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Root circuit num_instance {:?}, instance: {:?})",
            self.num_instance(),
            self.instance()
        )
    }
}

impl CircuitExt<Fr> for RootCircuit<GWC> {
    fn num_instance(&self) -> Vec<usize> {
        self.num_instance()
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        self.instance()
    }
}

impl Circuit<Fr> for RootCircuit<GWC> {
    type Config = AggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            aggregation_circuit: self.aggregation_circuit.without_witnesses(),
            input_snarks: self.input_snarks.clone(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        AggregationCircuit::<GWC>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let main_gate = config.main_gate();
        let range_chip = config.range_chip();
        range_chip.load_table(&mut layouter)?;

        let (accumulator_limbs, prev_instances) = self
            .aggregation_circuit
            .aggregation_region(config, &mut layouter)?;

        let mut offset = 0;
        // Constrain equality to instance values
        for (row, limb) in prev_instances.into_iter().flatten().enumerate() {
            main_gate.expose_public(layouter.namespace(|| "prev instances"), limb, row)?;
            offset += 1;
        }

        for (idx, limb) in accumulator_limbs.into_iter().enumerate() {
            let row = idx + offset;
            main_gate.expose_public(layouter.namespace(|| "accumulate limbs"), limb, row)?;
        }

        Ok(())
    }
}
