//! The super circuit for taiko

#[cfg(any(feature = "test", test))]
pub(crate) mod test;

use crate::{
    pi_circuit2::{PiCircuit, PiCircuitConfig, PiCircuitConfigArgs},
    table::{byte_table::ByteTable, BlockTable, KeccakTable},
    util::{log2_ceil, Challenges, SubCircuit, SubCircuitConfig},
    witness::{block_convert, Block},
};
use bus_mapping::{
    circuit_input_builder::{CircuitInputBuilder, CircuitsParams},
    mock::BlockData,
};
use eth_types::{geth_types::GethData, Field};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};

use itertools::Itertools;
use snark_verifier_sdk::CircuitExt;

/// Configuration of the Super Circuit
#[derive(Clone)]
pub struct SuperCircuitConfig<F: Field> {
    keccak_table: KeccakTable,
    block_table: BlockTable,
    byte_table: ByteTable,
    pi_circuit: PiCircuitConfig<F>,
}

/// Circuit configuration arguments
pub struct SuperCircuitConfigArgs<F: Field> {
    /// Challenges expressions
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for SuperCircuitConfig<F> {
    type ConfigArgs = SuperCircuitConfigArgs<F>;

    /// Configure SuperCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { challenges }: Self::ConfigArgs,
    ) -> Self {
        let block_table = BlockTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let byte_table = ByteTable::construct(meta);

        let pi_circuit = PiCircuitConfig::new(
            meta,
            PiCircuitConfigArgs {
                block_table: block_table.clone(),
                keccak_table: keccak_table.clone(),
                byte_table: byte_table.clone(),
                challenges,
            },
        );

        Self {
            pi_circuit,
            block_table,
            keccak_table,
            byte_table,
        }
    }
}

/// The Super Circuit contains all the zkEVM circuits
#[derive(Clone, Default, Debug)]
pub struct SuperCircuit<F: Field> {
    /// Public Input Circuit
    pub pi_circuit: PiCircuit<F>,
    /// Block witness
    pub block: Block<F>,
}

impl<F: Field> CircuitExt<F> for SuperCircuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        self.instance().iter().map(|v| v.len()).collect_vec()
    }

    fn instances(&self) -> Vec<Vec<F>> {
        self.instance()
    }
}

// Eventhough the SuperCircuit is not a subcircuit we implement the SubCircuit
// trait for it in order to get the `new_from_block` and `instance` methods that
// allow us to generalize integration tests.
impl<F: Field> SubCircuit<F> for SuperCircuit<F> {
    type Config = SuperCircuitConfig<F>;

    fn unusable_rows() -> usize {
        PiCircuit::<F>::unusable_rows()
    }

    fn new_from_block(block: &Block<F>) -> Self {
        let pi_circuit = PiCircuit::new_from_block(block);

        SuperCircuit::<_> {
            pi_circuit,

            block: block.clone(),
        }
    }

    /// Returns suitable inputs for the SuperCircuit.
    fn instance(&self) -> Vec<Vec<F>> {
        let mut instance = Vec::new();
        instance.extend_from_slice(&self.pi_circuit.instance());
        instance
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &Block<F>) -> (usize, usize) {
        PiCircuit::min_num_rows_block(block)
    }

    /// Make the assignments to the SuperCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.pi_circuit
            .synthesize_sub(&config.pi_circuit, challenges, layouter)?;
        Ok(())
    }
}

impl<F: Field> Circuit<F> for SuperCircuit<F> {
    type Config = (SuperCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<F>,
        _params: Self::Params,
    ) -> Self::Config {
        Self::configure(meta)
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            SuperCircuitConfig::new(
                meta,
                SuperCircuitConfigArgs {
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
        let randomness = challenges.evm_word();
        config
            .block_table
            .load(&mut layouter, &self.block.context, randomness)?;
        config.keccak_table.dev_load(
            &mut layouter,
            vec![&self.pi_circuit.public_data.rpi_bytes()],
            &challenges,
        )?;
        config.byte_table.load(&mut layouter)?;
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

impl<F: Field> SuperCircuit<F> {
    /// From the witness data, generate a SuperCircuit instance with all of the
    /// sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the
    /// circuit and the Public Inputs needed.
    #[allow(clippy::type_complexity)]
    pub fn build(
        geth_data: GethData,
        circuits_params: CircuitsParams,
    ) -> Result<(u32, Self, Vec<Vec<F>>, CircuitInputBuilder), bus_mapping::Error> {
        let block_data =
            BlockData::new_from_geth_data_with_params(geth_data.clone(), circuits_params);
        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&geth_data.eth_block, &geth_data.geth_traces)
            .expect("could not handle block tx");

        let ret = Self::build_from_circuit_input_builder(&builder)?;
        Ok((ret.0, ret.1, ret.2, builder))
    }

    /// From CircuitInputBuilder, generate a SuperCircuit instance with all of
    /// the sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the circuit and
    /// the Public Inputs needed.
    pub fn build_from_circuit_input_builder(
        builder: &CircuitInputBuilder,
    ) -> Result<(u32, Self, Vec<Vec<F>>), bus_mapping::Error> {
        let mut block = block_convert(&builder.block, &builder.code_db).unwrap();
        block.protocol_instance.block_hash = block.eth_block.hash.unwrap();
        block.protocol_instance.parent_hash = block.eth_block.parent_hash;
        let (_, rows_needed) = Self::min_num_rows_block(&block);
        let k = log2_ceil(Self::unusable_rows() + rows_needed);
        log::debug!("super circuit uses k = {}", k);

        let circuit = SuperCircuit::new_from_block(&block);

        let instance = circuit.instance();
        Ok((k, circuit, instance))
    }
}

#[cfg(test)]
mod super_circuit_test {
    use std::collections::HashMap;

    use crate::root_circuit::PoseidonTranscript;

    use super::*;
    use eth_types::{address, bytecode, geth_types::GethData, ToWord, Word};
    use ethers_signers::{LocalWallet, Signer};
    use halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::{
            commitment::ParamsProver,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsVerifierKZG},
                multiopen::{ProverGWC, VerifierGWC},
                strategy::SingleStrategy,
            },
        },
    };
    use mock::{TestContext, MOCK_CHAIN_ID};
    use rand::SeedableRng;
    use rand_chacha::{rand_core::OsRng, ChaCha20Rng};
    use snark_verifier_sdk::halo2::gen_srs;

    #[test]
    fn test_super_circuit() {
        let circuits_params = CircuitsParams {
            max_txs: 1,
            max_calldata: 32,
            max_rws: 256,
            max_copy_rows: 256,
            max_exp_steps: 256,
            max_bytecode: 512,
            max_evm_rows: 0,
            max_keccak_rows: 0,
        };

        let k = 18;
        let (_, circuit, instance, _) =
            SuperCircuit::<_>::build(block_1tx(), circuits_params).unwrap();

        let prover = match MockProver::<Fr>::run(k, &circuit, instance.clone()) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));

        let params = gen_srs(k);
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        let proof = {
            let mut transcript = PoseidonTranscript::new(Vec::new());
            create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuit],
                &[&instance.iter().map(Vec::as_slice).collect_vec()],
                OsRng,
                &mut transcript,
            )
            .unwrap();
            transcript.finalize()
        };

        let mut verifier_transcript = PoseidonTranscript::new(&proof[..]);
        let strategy = SingleStrategy::new(&params);
        let verifier_params: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
        let col = instance.iter().map(Vec::as_slice).collect_vec();
        let cols = vec![col.as_slice()];
        let instances = cols.as_slice();

        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierGWC<'_, Bn256>,
            _,
            _,
            SingleStrategy<'_, Bn256>,
        >(
            &verifier_params,
            pk.get_vk(),
            strategy,
            instances,
            &mut verifier_transcript,
        )
        .expect("failed to verify bench circuit");
    }

    pub(crate) fn block_1tx() -> GethData {
        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let chain_id = (*MOCK_CHAIN_ID).as_u64();

        let bytecode = bytecode! {
            GAS
            STOP
        };

        let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

        let addr_a = wallet_a.address();
        let addr_b = address!("0x000000000000000000000000000000000000BBBB");

        let mut wallets = HashMap::new();
        wallets.insert(wallet_a.address(), wallet_a);

        let mut block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(addr_b)
                    .balance(Word::from(1u64 << 20))
                    .code(bytecode);
                accs[1].address(addr_a).balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas(Word::from(1_000_000u64));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();
        block.history_hashes = vec![block.eth_block.parent_hash.to_word()];
        block.sign(&wallets);
        block
    }
}
