use crate::{get_client, taiko_utils::gen_block_with_instance, GenDataOutput, GETH_L2_URL};
use bus_mapping::{
    circuit_input_builder::{BuilderClient, CircuitsParams},
    mock::BlockData,
};
use cli_table::{format::Separator, print_stdout, Table, WithTitle};
use eth_types::{geth_types::GethData, Field};
use halo2_proofs::{
    dev::{
        cost::{ProofContribution, ProofSize},
        CellValue, CircuitCost, MockProver,
    },
    halo2curves::bn256::{Bn256, Fr, G1Affine, G1},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, ProvingKey,
        VerifyingKey,
    },
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
use lazy_static::lazy_static;
use mock::TestContext;
use rand_chacha::rand_core::SeedableRng;
use rand_core::RngCore;
use rand_xorshift::XorShiftRng;
use std::{collections::HashMap, fmt::Debug, marker::PhantomData, sync::Mutex};
use tokio::sync::Mutex as TokioMutex;
use zkevm_circuits::{
    bytecode_circuit::TestBytecodeCircuit,
    copy_circuit::TestCopyCircuit,
    evm_circuit::TestEvmCircuit,
    exp_circuit::TestExpCircuit,
    keccak_circuit::TestKeccakCircuit,
    state_circuit::TestStateCircuit,
    super_circuit::SuperCircuit,
    tx_circuit::TestTxCircuit,
    taiko_pi_circuit::TestTaikoPiCircuit,
    util::SubCircuit,
    witness::{block_convert, Block},
};
/// TEST_MOCK_RANDOMNESS
const TEST_MOCK_RANDOMNESS: u64 = 0x100;

/// MAX_TXS
const MAX_TXS: usize = 4;
/// MAX_CALLDATA
const MAX_CALLDATA: usize = 5120;
/// MAX_RWS
const MAX_RWS: usize = 588800;
/// MAX_BYTECODE
const MAX_BYTECODE: usize = 5000;
/// MAX_COPY_ROWS
const MAX_COPY_ROWS: usize = 5888;
/// MAX_EVM_ROWS
const MAX_EVM_ROWS: usize = 100000;
/// MAX_EXP_STEPS
const MAX_EXP_STEPS: usize = 1000;

const MAX_KECCAK_ROWS: usize = 15000;

///
pub const CIRCUITS_PARAMS: CircuitsParams = CircuitsParams {
    max_rws: MAX_RWS,
    max_txs: MAX_TXS,
    max_calldata: MAX_CALLDATA,
    max_bytecode: MAX_BYTECODE,
    max_copy_rows: MAX_COPY_ROWS,
    max_evm_rows: MAX_EVM_ROWS,
    max_exp_steps: MAX_EXP_STEPS,
    max_keccak_rows: MAX_KECCAK_ROWS,
};

const EVM_CIRCUIT_DEGREE: u32 = 20;
const STATE_CIRCUIT_DEGREE: u32 = 17;
const TX_CIRCUIT_DEGREE: u32 = 20;
const PI_CIRCUIT_DEGREE: u32 = 20;
const BYTECODE_CIRCUIT_DEGREE: u32 = 16;
const COPY_CIRCUIT_DEGREE: u32 = 16;
const KECCAK_CIRCUIT_DEGREE: u32 = 16;
const SUPER_CIRCUIT_DEGREE: u32 = 20;
const EXP_CIRCUIT_DEGREE: u32 = 16;

lazy_static! {
    /// Data generation.
    static ref GEN_DATA: GenDataOutput = GenDataOutput::load();
    static ref RNG: XorShiftRng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
}

lazy_static! {
    static ref GEN_PARAMS: Mutex<HashMap<u32, ParamsKZG<Bn256>>> = Mutex::new(HashMap::new());
}

lazy_static! {
    /// Integration test for EVM circuit
    pub static ref EVM_CIRCUIT_TEST: TokioMutex<IntegrationTest<TestEvmCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("EVM", EVM_CIRCUIT_DEGREE));

    /// Integration test for State circuit
    pub static ref STATE_CIRCUIT_TEST: TokioMutex<IntegrationTest<TestStateCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("State", STATE_CIRCUIT_DEGREE));

    /// Integration test for State circuit
    pub static ref TX_CIRCUIT_TEST: TokioMutex<IntegrationTest<TestTxCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("Tx", TX_CIRCUIT_DEGREE));

    /// Integration test for State circuit
    pub static ref PI_CIRCUIT_TEST: TokioMutex<IntegrationTest<TestTaikoPiCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("Pi", PI_CIRCUIT_DEGREE));

    /// Integration test for Bytecode circuit
    pub static ref BYTECODE_CIRCUIT_TEST: TokioMutex<IntegrationTest<TestBytecodeCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("Bytecode", BYTECODE_CIRCUIT_DEGREE));

    /// Integration test for Copy circuit
    pub static ref COPY_CIRCUIT_TEST: TokioMutex<IntegrationTest<TestCopyCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("Copy", COPY_CIRCUIT_DEGREE));

    /// Integration test for Keccak circuit
    pub static ref KECCAK_CIRCUIT_TEST: TokioMutex<IntegrationTest<TestKeccakCircuit<Fr>>> =
    TokioMutex::new(IntegrationTest::new("Keccak", KECCAK_CIRCUIT_DEGREE));

    /// Integration test for Copy circuit
    pub static ref SUPER_CIRCUIT_TEST: TokioMutex<IntegrationTest<SuperCircuit::<Fr>>> =
    TokioMutex::new(IntegrationTest::new("Super", SUPER_CIRCUIT_DEGREE));

     /// Integration test for Exp circuit
     pub static ref EXP_CIRCUIT_TEST: TokioMutex<IntegrationTest<TestExpCircuit::<Fr>>> =
     TokioMutex::new(IntegrationTest::new("Exp", EXP_CIRCUIT_DEGREE));
}

/// Generic implementation for integration tests
pub struct IntegrationTest<C: SubCircuit<Fr> + Circuit<Fr>> {
    ///
    pub name: &'static str,
    ///
    pub degree: u32,
    ///
    pub block: HashMap<u64, Block<Fr>>,
    ///
    pub key: HashMap<u64, ProvingKey<G1Affine>>,
    ///
    pub fixed: HashMap<u64, Vec<Vec<CellValue<Fr>>>>,

    _marker: PhantomData<C>,
}

impl<C: SubCircuit<Fr> + Circuit<Fr> + Debug> IntegrationTest<C> {
    ///
    pub fn new(name: &'static str, degree: u32) -> Self {
        Self {
            name,
            degree,
            block: HashMap::new(),
            key: HashMap::new(),
            fixed: HashMap::new(),
            _marker: PhantomData,
        }
    }

    async fn get_block(&mut self, block_num: u64, is_taiko: bool) -> Block<Fr> {
        match self.block.get(&block_num) {
            Some(block) => block.clone(),
            None => {
                let mut block = if is_taiko {
                    gen_block_with_instance(block_num).await
                } else {
                    gen_block(block_num).await
                };
                block.randomness = Fr::from(TEST_MOCK_RANDOMNESS);
                self.block.insert(block_num, block.clone());
                block
            }
        }
    }

    ///
    pub async fn get_key(&mut self, block_num: u64, circuit: &C) -> ProvingKey<G1Affine> {
        match self.key.get(&block_num) {
            Some(key) => key.clone(),
            None => {
                let key = gen_key(circuit, self.degree);
                self.key_veriadic(key.get_vk());
                self.key.insert(block_num, key.clone());
                key
            }
        }
    }
    ///
    pub fn test_actual(
        &self,
        circuit: C,
        instance: Vec<Vec<Fr>>,
        proving_key: ProvingKey<G1Affine>,
    ) {
        print_cs_info(proving_key.get_vk().cs());
        fn test_gen_proof<C: Circuit<Fr>, R: RngCore>(
            rng: R,
            circuit: C,
            general_params: &ParamsKZG<Bn256>,
            proving_key: &ProvingKey<G1Affine>,
            mut transcript: Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            instances: &[&[Fr]],
        ) -> Vec<u8> {
            create_proof::<
                KZGCommitmentScheme<Bn256>,
                ProverSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                R,
                Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
                C,
            >(
                general_params,
                proving_key,
                &[circuit],
                &[instances],
                rng,
                &mut transcript,
            )
            .expect("proof generation should not fail");

            transcript.finalize()
        }

        fn test_verify(
            general_params: &ParamsKZG<Bn256>,
            verifier_params: &ParamsKZG<Bn256>,
            verifying_key: &VerifyingKey<G1Affine>,
            proof: &[u8],
            instances: &[&[Fr]],
        ) {
            let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof);
            let strategy = SingleStrategy::new(general_params);

            verify_proof::<
                KZGCommitmentScheme<Bn256>,
                VerifierSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
                SingleStrategy<'_, Bn256>,
            >(
                verifier_params,
                verifying_key,
                strategy,
                &[instances],
                &mut verifier_transcript,
            )
            .expect("failed to verify circuit");
        }

        let general_params = get_general_params(self.degree);
        let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();

        let transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

        // change instace to slice
        let instance: Vec<&[Fr]> = instance.iter().map(|v| v.as_slice()).collect();

        log::info!("create proof");
        let proof = test_gen_proof(
            RNG.clone(),
            circuit,
            &general_params,
            &proving_key,
            transcript,
            &instance,
        );

        log::info!("verify proof with vk");
        let verifying_key = proving_key.get_vk();
        test_verify(
            &general_params,
            &verifier_params,
            verifying_key,
            &proof,
            &instance,
        );
    }

    ///
    pub fn test_mock(&mut self, circuit: &C, instance: Vec<Vec<Fr>>) {
        let mock_prover = MockProver::<Fr>::run(self.degree, circuit, instance).unwrap();
        print_cs_info(mock_prover.cs());
        self.fixed_variadic(&mock_prover);
        mock_prover
            .verify_par()
            .expect("mock prover verification failed");
    }

    ///
    pub fn fixed_variadic(&mut self, mock_prover: &MockProver<Fr>) {
        let fixed = mock_prover.fixed();
        log::info!("compare fixed columns with recorded vals from prev blocks");
        self.fixed.values().for_each(|prev_fixed| {
            assert!(
                fixed.eq(prev_fixed),
                "circuit fixed columns are not constant for different witnesses"
            );
        });
        // TODO: check mock_prover.permutation(), currently the returning type
        // is private so cannot store.
    }

    ///
    pub fn key_veriadic(&self, cur: &VerifyingKey<G1Affine>) {
        log::info!("compare verfiying key with recorded vals from prev blocks");
        self.key.values().for_each(|key| {
            let prev = key.get_vk();
            assert_eq!(
                prev.get_domain().extended_k(),
                cur.get_domain().extended_k()
            );
            assert_eq!(prev.fixed_commitments(), cur.fixed_commitments());
            assert_eq!(
                prev.permutation().commitments(),
                cur.permutation().commitments()
            );

            let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
            assert_eq!(
                prev.hash_into(&mut transcript.clone()).unwrap(),
                cur.hash_into(&mut transcript).unwrap()
            );
        });
    }

    /// Run integration test at a block identified by a tag.
    pub async fn test_at_block_tag(&mut self, block_tag: &str, actual: bool) {
        let block_num = *GEN_DATA.blocks.get(block_tag).unwrap();
        log::info!("test {} circuit, block tag: {}", self.name, block_tag);
        self.test_block_by_number(block_num, actual, false).await;
    }

    /// Run integration test for a block number
    pub async fn test_block_by_number(&mut self, block_num: u64, actual: bool, is_taiko: bool) {
        log::info!("test {} circuit, block: #{}", self.name, block_num);
        let block = self.get_block(block_num, is_taiko).await;
        let min_rows = C::min_num_rows_block(&block);
        let circuit = C::new_from_block(&block);
        let instance = circuit.instance();
        print_circuit_cost(&circuit, self.degree, min_rows);

        if actual {
            log::info!("generate (pk, vk)");
            let key = self.get_key(block_num, &circuit).await;
            self.test_actual(circuit, instance, key);
        } else {
            log::info!("init mock prover");
            self.test_mock(&circuit, instance);
        }
    }
}

///
pub fn new_empty_block() -> Block<Fr> {
    let block: GethData = TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b)
        .unwrap()
        .into();
    let mut builder = BlockData::new_from_geth_data_with_params(block.clone(), CIRCUITS_PARAMS)
        .new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    block_convert(&builder.block, &builder.code_db).unwrap()
}

///
pub fn get_general_params(degree: u32) -> ParamsKZG<Bn256> {
    let mut map = GEN_PARAMS.lock().unwrap();
    match map.get(&degree) {
        Some(params) => params.clone(),
        None => {
            log::info!("initialize degree #{} params", degree);
            let params = ParamsKZG::<Bn256>::setup(degree, RNG.clone());
            map.insert(degree, params.clone());
            params
        }
    }
}

/// returns gen_inputs for a block number
pub async fn gen_block(block_num: u64) -> Block<Fr> {
    let cli = get_client(&GETH_L2_URL);
    let cli = BuilderClient::new(cli, CIRCUITS_PARAMS, Default::default())
        .await
        .unwrap();

    let (builder, _) = cli.gen_inputs(block_num).await.unwrap();
    block_convert(&builder.block, &builder.code_db).unwrap()
}

///
pub fn gen_key<C: SubCircuit<Fr> + Circuit<Fr>>(circuit: &C, degree: u32) -> ProvingKey<G1Affine> {
    let general_params = get_general_params(degree);
    let verifying_key = keygen_vk(&general_params, circuit).expect("keygen_vk should not fail");

    keygen_pk(&general_params, verifying_key, circuit).expect("keygen_pk should not fail")
}

///
pub fn print_cs_info<Fr: Field>(cs: &ConstraintSystem<Fr>) {
    println!(
        "Constraint System\nminimum_rows: {}\nblinding_factors: {}\ngates count: {}",
        cs.minimum_rows(),
        cs.blinding_factors(),
        cs.gates().len()
    );
}

#[derive(Table)]
struct Row {
    #[table(title = "")]
    name: &'static str,
    #[table(title = "commitments")]
    commitments: usize,
    #[table(title = "evaluations")]
    evaluations: usize,
}

impl Row {
    fn set_name(&mut self, name: &'static str) {
        self.name = name;
    }
}

impl From<ProofContribution> for Row {
    fn from(contribution: ProofContribution) -> Self {
        Self {
            name: "",
            commitments: contribution.commitments,
            evaluations: contribution.evaluations,
        }
    }
}

///
pub fn print_circuit_cost<C: SubCircuit<Fr> + Circuit<Fr> + Debug>(
    circuit: &C,
    degree: u32,
    min_rows: (usize, usize),
) {
    let cost = CircuitCost::<G1, C>::measure(degree as usize, circuit);
    let ProofSize {
        instance,
        advice,
        fixed,
        lookups,
        equality,
        vanishing,
        multiopen,
        polycomm,
        ..
    } = cost.proof_size(1);
    let mut rows: Vec<Row> = vec![
        instance.into(),
        advice.into(),
        fixed.into(),
        lookups.into(),
        equality.into(),
        vanishing.into(),
        multiopen.into(),
        polycomm.into(),
    ];
    rows[0].set_name("instance");
    rows[1].set_name("advice");
    rows[2].set_name("fixed");
    rows[3].set_name("lookups");
    rows[4].set_name("equality");
    rows[5].set_name("vanishing");
    rows[6].set_name("multiopen");
    rows[7].set_name("polycomm");

    print_stdout(rows.with_title().separator(Separator::builder().build()))
        .expect("the table renders");

    println!(
        "min_rows of block: {:?} min_rows with padding: {:?}\n{:?}",
        min_rows.0, min_rows.1, cost
    );
}
