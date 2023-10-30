pub use super::*;

#[cfg(any(feature = "test", test))]
impl<F: Field> Circuit<F> for TaikoPiCircuit<F> {
    type Config = (TaikoPiCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = PublicData<F>;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn params(&self) -> Self::Params {
        self.evidence.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, PublicData::default())
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let byte_table = ByteTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            TaikoPiCircuitConfig::new(
                meta,
                TaikoPiCircuitConfigArgs {
                    evidence: params,
                    block_table,
                    keccak_table,
                    byte_table,
                    challenges: challenge_exprs,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);
        let evidance = self.params();
        let randomness = challenges.evm_word();
        // assign block table
        config
            .block_table
            .load(&mut layouter, &evidance.block_context, randomness)?;
        // assign keccak table
        config
            .keccak_table
            .dev_load(&mut layouter, vec![&evidance.encode_raw()], &challenges)?;
        config.byte_table.load(&mut layouter)?;

        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}
