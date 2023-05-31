//! SuperCircuit circuit benchmarks
 
use std::fs;
use std::io::Write;
use std::rc::Rc;
use halo2_proofs::plonk::Circuit;
use zkevm_circuits::root_circuit::KzgDk;
use zkevm_circuits::root_circuit::KzgSvk;
use zkevm_circuits::root_circuit::RootCircuit;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::root_circuit::PoseidonTranscript;
use eth_types::{address, Address, bytecode, geth_types::GethData, Word};
use ethers_signers::{LocalWallet, Signer};

use bus_mapping::circuit_input_builder::CircuitsParams;

use rand::SeedableRng;
use std::{collections::HashMap};

use halo2_proofs::{
    circuit::Value,
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC},
        },
    },
    transcript::{
        TranscriptWriterBuffer,
    },
};

use mock::{TestContext, MOCK_CHAIN_ID};

use ark_std::{end_timer, start_timer};
use std::path::Path;

use snark_verifier_sdk::{
    Snark, CircuitExt, SHPLONK,
    evm::{gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk, gen_srs},
    gen_pk,
};

use snark_verifier::{
    pcs::{
        kzg::{self, *},
    },
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::SnarkVerifier,
    loader::evm::{self, encode_calldata, Address as VerifierAddress, EvmLoader, ExecutorBuilder},
};
use rand_chacha::ChaCha20Rng;
use itertools::Itertools;

/// Number of limbs to decompose a elliptic curve base field element into.
pub const LIMBS: usize = 4;
/// Number of bits of each decomposed limb.
pub const BITS: usize = 68;

pub type ProverParams = ParamsKZG<Bn256>;
pub type ProverCommitmentScheme = KZGCommitmentScheme<Bn256>;
pub type ProverKey = ProvingKey<G1Affine>;

/// KZG accumulation scheme with GWC19 multiopen.
pub type KzgAs<M> = kzg::KzgAs<M, Gwc19>;
pub type PlonkVerifier<M> = snark_verifier::verifier::plonk::PlonkVerifier<KzgAs<M>, LimbsEncoding<LIMBS, BITS>>;

use rand::rngs::StdRng;
use rand::rngs::OsRng;

use eth_types::Field;

/// Fixed rng for testing purposes
pub fn fixed_rng() -> StdRng {
    StdRng::seed_from_u64(9)
}

/// Returns [<len>, ...] of `instance`
pub fn gen_num_instance(instance: &[Vec<Fr>]) -> Vec<usize> {
    instance.iter().map(|v| v.len()).collect()
}

#[derive(Clone, Default, Debug, serde::Serialize, serde::Deserialize)]
struct Verifier {
    label: String,
    code: String,
    address: Address,
}

impl Verifier {
    fn build(&mut self) -> &Self {
        let mut tmp = [0; 20];
        let bytes = self.label.as_bytes();
        let x = 20 - bytes.len();
        for (i, v) in bytes.iter().enumerate() {
            tmp[i + x] = *v;
        }
        self.address = Address::from(tmp);

        self
    }

    fn write_yul(&mut self) -> &Self {
        self.build();
        let file_name = format!("verifier-{}-{:?}.yul", self.label, self.address);
        // only keep the runtime section
        let yul_code = format!("object \"{}\" ", self.label)
            + self.code.split("object \"Runtime\"").last().unwrap();
        // strip of the dangling `}`
        let yul_code = &yul_code[0..yul_code.len() - 1];
        write_bytes(&file_name, yul_code.as_bytes());

        self
    }
}

fn write_bytes(name: &str, vec: &[u8]) {
    let dir = "./../contracts/generated/";
    fs::create_dir_all(dir).unwrap_or_else(|_| panic!("create {dir}"));
    let path = format!("{dir}/{name}");
    fs::File::create(&path)
        .unwrap_or_else(|_| panic!("create {}", &path))
        .write_all(vec)
        .unwrap_or_else(|_| panic!("write {}", &path));
}

fn gen_verifier(
    params: &ProverParams,
    vk: &VerifyingKey<G1Affine>,
    config: Config,
    num_instance: Vec<usize>,
) -> String {
    let protocol = compile(params, vk, config);
    let svk = KzgSvk::<Bn256>::new(params.get_g()[0]);
    let dk = KzgDk::<Bn256>::new(svk, params.g2(), params.s_g2());

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&dk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&dk, &protocol, &instances, &proof).unwrap();

    loader.yul_code()
}

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);

    let success = {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build();
        let caller = VerifierAddress::from_low_u64_be(0xfe);
        let deploy = evm.deploy(caller, deployment_code.into(), 0.into());
        let verifier = deploy.address.unwrap();

        let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());

        println!("Deployment cost: {} gas", deploy.gas_used);
        println!("Verification cost: {} gas", result.gas_used);

        !result.reverted
    };
    assert!(success);
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
    block.sign(&wallets);
    block
}

pub fn create_root_super_circuit_prover() {
    let min_k_aggregation = 21;
    let proof_gen_prfx = crate::constants::PROOFGEN_PREFIX;

    /* SuperCircuit */
    // Create super circuit
    const TEST_MOCK_RANDOMNESS: u64 = 0x100;
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
    let (k, super_circuit, super_instance, _) =
        SuperCircuit::<_>::build(block_1tx(), circuits_params, TEST_MOCK_RANDOMNESS.into())
            .unwrap();
    let k = k.max(min_k_aggregation);
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let pk = keygen_pk(&params, keygen_vk(&params, &super_circuit).unwrap(), &super_circuit).unwrap();
    let protocol = compile(
        &params,
        pk.get_vk(),
        Config::kzg()
            .with_num_instance(super_instance.iter().map(|instance| instance.len()).collect()),
    );
    // Create super circuit proof
    let proof_message = format!(
        "{} with degree = {}",
        proof_gen_prfx, k
    );
    let start_proof_super = start_timer!(|| proof_message);
    let super_proof = {
        let mut transcript = PoseidonTranscript::new(Vec::new());
        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
            &params,
            &pk,
            &[super_circuit],
            &[&super_instance.iter().map(Vec::as_slice).collect_vec()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };
    end_timer!(start_proof_super);

    /* RootCircuit */
    // Create root circuit
    println!("root circuit");
    let root_circuit = RootCircuit::new(
        &params,
        &protocol,
        Value::known(&super_instance),
        Value::known(&super_proof),
    )
    .unwrap();
    let root_instance = root_circuit.instance();
    println!("root circuit keygen");
    let root_vk = keygen_vk(&params, &root_circuit).expect("vk");
    println!("root circuit verifier");
    let mut data = Verifier::default();
    data.label = format!("root");
    data.code = gen_verifier(
        &params,
        &root_vk,
        Config::kzg()
            .with_num_instance(root_circuit.num_instance())
            .with_accumulator_indices(Some(root_circuit.accumulator_indices())),
        root_circuit.num_instance(),
    )
    .into();
    data.write_yul();
    // Create root circuit proof
    let pk = keygen_pk(&params, root_vk, &root_circuit).expect("keygen_pk should not fail");
    let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
    let proof_message = format!(
        "{} with degree = {}",
        proof_gen_prfx, k
    );
    let start_proof_root = start_timer!(|| proof_message);
    create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _,>(
        &params,
        &pk,
        &[root_circuit],
        &[&root_instance.iter().map(|v| &v[..]).collect_vec()],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();
    end_timer!(start_proof_root);

    // Verify proof in EVM
    println!("EVM verify");
    let evm_verifier_bytecode = evm::compile_yul(&data.code);
    evm_verify(evm_verifier_bytecode, root_instance, proof.clone());
}


fn gen_application_snark(params: &ParamsKZG<Bn256>) -> Snark {
    println!("gen app snark");
    const TEST_MOCK_RANDOMNESS: u64 = 0x100;
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
    let (k, super_circuit, super_instance, _) =
        SuperCircuit::<_>::build(block_1tx(), circuits_params, TEST_MOCK_RANDOMNESS.into())
            .unwrap();

    //let pk = gen_pk(params, &super_circuit, Some(Path::new("./examples/app.pk")), super_circuit.params());
    let vk = keygen_vk(params, &super_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(params, vk, &super_circuit).expect("keygen_pk should not fail");
    gen_snark_shplonk(params, &pk, super_circuit, None::<&str>)
}

fn create_root_super_circuit_prover_sdk() {
    let params_app = gen_srs(18);
    let snarks = [(); 2].map(|_| gen_application_snark(&params_app));

    println!("gen root snarks");
    let params = gen_srs(22);
    let mut snark_roots = Vec::new();
    for snark in snarks {
        let root_circuit = AggregationCircuit::<SHPLONK>::new(&params, vec![snark]);

        let start0 = start_timer!(|| "gen vk & pk");
        /*let pk = gen_pk(
            &params,
            &agg_circuit.without_witnesses(),
            Some(Path::new("./examples/agg.pk")),
            agg_circuit.params(),
        );*/
        let vk = keygen_vk(&params, &root_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &root_circuit).expect("keygen_pk should not fail");
        end_timer!(start0);

        let _root = gen_snark_shplonk(
            &params,
            &pk,
            root_circuit.clone(),
            /*Some(Path::new("./examples/agg.snark"))*/None::<&str>,
        );

        snark_roots.push(_root);
    }

    println!("gen block agg snark");
    let params = gen_srs(22);
    let agg_circuit = AggregationCircuit::<SHPLONK>::new(&params, snark_roots);

    let start0 = start_timer!(|| "gen vk & pk");
    /*let pk = gen_pk(
        &params,
        &agg_circuit.without_witnesses(),
        Some(Path::new("./examples/agg.pk")),
        agg_circuit.params(),
    );*/
    let vk = keygen_vk(&params, &agg_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &agg_circuit).expect("keygen_pk should not fail");
    end_timer!(start0);

    //std::fs::remove_file("./examples/agg.snark").unwrap_or_default();
    let _snark = gen_snark_shplonk(
        &params,
        &pk,
        agg_circuit.clone(),
        /*Some(Path::new("./examples/agg.snark"))*/None::<&str>,
    );

    println!("gen evm snark");
    // do one more time to verify
    let num_instances = agg_circuit.num_instance();
    let instances = agg_circuit.instances();
    let proof_calldata = gen_evm_proof_shplonk(&params, &pk, agg_circuit, instances.clone());

    let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit<SHPLONK>>(
        &params,
        pk.get_vk(),
        num_instances,
        Some(Path::new("./examples/standard_plonk.yul")),
    );
    evm_verify(deployment_code, instances, proof_calldata);
}



#[cfg(test)]
mod tests {
    use ark_std::{end_timer, start_timer};
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{address, bytecode, geth_types::GethData, Word};
    use ethers_signers::{LocalWallet, Signer};
    use halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::{
            commitment::ParamsProver,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::SingleStrategy,
            },
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };
    use mock::{TestContext, MOCK_CHAIN_ID};
    use rand::SeedableRng;
    use std::{collections::HashMap};
    use zkevm_circuits::super_circuit::SuperCircuit;
    use rand_chacha::ChaChaRng;
    use std::env::var;
    use crate::super_circuit::create_root_super_circuit_prover;
    use crate::super_circuit::create_root_super_circuit_prover_sdk;

    #[test]
    fn bench_root_super_circuit_prover() {
        create_root_super_circuit_prover();
    }

    #[test]
    fn bench_root_super_circuit_prover_sdk() {
        create_root_super_circuit_prover_sdk();
    }

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_super_circuit_prover() {
        let setup_prfx = crate::constants::SETUP_PREFIX;
        let proof_gen_prfx = crate::constants::PROOFGEN_PREFIX;
        let proof_ver_prfx = crate::constants::PROOFVER_PREFIX;
        // Unique string used by bench results module for parsing the result
        const BENCHMARK_ID: &str = "Super Circuit";

        let degree: u32 = var("DEGREE")
            .expect("No DEGREE env var was provided")
            .parse()
            .expect("Cannot parse DEGREE env var as u32");

        let mut rng = ChaChaRng::seed_from_u64(2);

        let chain_id = (*MOCK_CHAIN_ID).as_u64();

        let bytecode = bytecode! {
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

        block.sign(&wallets);

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
        let (_, circuit, instance, _) =
            SuperCircuit::build(block, circuits_params, Fr::from(0x100)).unwrap();
        let instance_refs: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();

        // Bench setup generation
        let setup_message = format!("{} {} with degree = {}", BENCHMARK_ID, setup_prfx, degree);
        let start1 = start_timer!(|| setup_message);
        let general_params = ParamsKZG::<Bn256>::setup(degree, &mut rng);
        let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
        end_timer!(start1);

        // Initialize the proving key
        let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");
        // Create a proof
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!(
            "{} {} with degree = {}",
            BENCHMARK_ID, proof_gen_prfx, degree
        );
        let start2 = start_timer!(|| proof_message);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            ChaChaRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            SuperCircuit<Fr>,
        >(
            &general_params,
            &pk,
            &[circuit],
            &[&instance_refs],
            rng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(start2);

        // Bench verification time
        let start3 = start_timer!(|| format!("{} {}", BENCHMARK_ID, proof_ver_prfx));
        let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleStrategy::new(&general_params);

        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            &verifier_params,
            pk.get_vk(),
            strategy,
            &[&instance_refs],
            &mut verifier_transcript,
        )
        .expect("failed to verify bench circuit");
        end_timer!(start3);
    }
}
