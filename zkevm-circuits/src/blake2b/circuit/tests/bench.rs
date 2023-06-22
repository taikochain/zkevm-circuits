use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use ark_std::{ start_timer, end_timer };
use halo2_proofs:: {
    plonk::{ create_proof, keygen_vk, keygen_pk, verify_proof },
    poly::kzg::{ 
        commitment::{ KZGCommitmentScheme, ParamsKZG },
        multiopen::{ ProverSHPLONK, VerifierSHPLONK },
        strategy::SingleStrategy
    },
    poly::commitment::ParamsProver,
    halo2curves::bn256::{ Bn256, Fr, G1Affine },
    transcript::{ Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer }
};
use blake2b_circuit::{ CompressionCircuit, CompressionInput };

// Binary logarithm of the height of a circuit instance
const K: u32 = 18;
// Number of rows per round 
const R: usize = 8;
// BLAKE2b compression function inputs. Their total round number is the maximum one for  
// the chosen k, number of rows per round and amount of the compression function inputs
const INPUTS:[CompressionInput; 5] = [
   CompressionInput {
        r: 32600,
        h: [534542, 235, 325, 235, 53252, 532452, 235324, 25423],
        m: [5542, 23, 35, 35, 5252, 52452, 2324, 2523, 254, 35, 354, 235, 5532, 5235, 35, 525],
        t: 1234,
        f: true,
    }, 
    CompressionInput {
        r: 13,
        h: [532, 235, 325, 235, 53252, 5324654452, 235324, 25423],
        m: [55142, 23, 35, 31115, 5252, 52452, 2324, 2523, 254, 35, 354, 235, 5532, 5235, 35, 525],
        t: 123784,
        f: false,
    },
    CompressionInput {
        r: 90,
        h: [532, 235, 325, 235, 53252, 0, 235324, 25423],
        m: [55142, 0, 35, 31115, 5252, 52452, 2324, 2523, 254, 35, 354, 235, 5532, 0, 35, 525],
        t: 0,
        f: true,
    },
    CompressionInput {
        r: 0,
        h: [53200, 235, 325, 235, 53252, 0, 235324, 25423],
        m: [55142, 0, 35, 31115, 5252, 52452, 232400, 2523, 254, 35, 354, 235, 5532, 0, 350, 52500],
        t: 5345435,
        f: true
    },
    CompressionInput {
        r: 51,
        h: [53200, 235, 325, 235, 53252, 0, 235324, 25423],
        m: [55142, 0, 35, 31115, 5252, 52452, 232400, 2523, 254, 35, 354, 235, 5532, 0, 350, 52500],
        t: 5345435,
        f: true,
    }
];

// Runs the test bench for the BLAKE2b compression function circuit 
#[test]
#[ignore]
fn bench_circuit() {    
    println!("The test bench for the BLAKE2b compression function circuit:");

    let mut more = INPUTS;
    more[0].r += 1;
    assert!(CompressionCircuit::<Fr,R>::k(&more) > K, 
        "The total round number must be the maximum one for the chosen k, number of rows per round and amount of the compression function inputs!"); 
    
    let circuit = CompressionCircuit::<Fr,R>::new(K, &INPUTS);    

    let timer = start_timer!(|| "KZG setup");
    let mut random = XorShiftRng::from_seed([0xC; 16]);
    let general_kzg_params = ParamsKZG::<Bn256>::setup(K, &mut random);
    let verifier_kzg_params = general_kzg_params.verifier_params().clone();
    end_timer!(timer);

    let verifying_key = keygen_vk(&general_kzg_params, &circuit).expect("The verifying key must be generated successfully!");
    let proving_key = keygen_pk(&general_kzg_params, verifying_key, &circuit).expect("The proving key must be generated successfully!");
    let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<_>>::init(vec![]);

    let timer = start_timer!(|| "Proof generation");
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(&general_kzg_params, 
        &proving_key, &[circuit], &[&[]], random, &mut transcript).expect("The proof must be generated successfully!");
    let transcripted = transcript.finalize();
    end_timer!(timer);
    
    let performance = 1000 * INPUTS.iter().fold(0, |sum, input| sum + input.r) as u128 / timer.time.elapsed().as_millis();
    println!("The prover's performace is {} rounds/second", performance);

    let timer = start_timer!(|| "Proof verification");
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&transcripted[..]);
    let strategy = SingleStrategy::new(&general_kzg_params);
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(&verifier_kzg_params, 
        proving_key.get_vk(), strategy, &[&[]], &mut transcript).expect("The proof must be verified successfully!");
    end_timer!(timer);
}