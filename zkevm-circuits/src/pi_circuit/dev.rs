use halo2_proofs::plonk::Circuit;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use super::*;

/// Public Input Circuit configuration parameters
#[derive(Default)]
pub struct PiCircuitParams {
    /// Max Txs
    pub max_txs: usize,
    /// Max Calldata
    pub max_calldata: usize,
}

impl<F: Field> Circuit<F> for PiCircuit<F> {
    type Config = (PiCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = PiCircuitParams;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn params(&self) -> Self::Params {
        PiCircuitParams {
            max_txs: self.max_txs,
            max_calldata: self.max_calldata,
        }
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let tx_table = TxTable::construct(meta);
        let keccak_table = KeccakTable2::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenges_expr = challenges.exprs(meta);
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let randomness = F::random(&mut rng);
        (
            PiCircuitConfig::new(
                meta,
                PiCircuitConfigArgs {
                    max_txs: params.max_txs,
                    max_calldata: params.max_calldata,
                    block_table,
                    tx_table,
                    keccak_table,
                    // challenges: challenges_expr,
                    randomness,
                    // rlp_is_short,
                },
            ),
            challenges,
        )
    }

    fn configure(_meta: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!();
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}
