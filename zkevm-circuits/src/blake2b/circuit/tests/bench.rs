use ark_std::{end_timer, start_timer};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    poly::commitment::ParamsProver,
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::marker::PhantomData;
use blake2b_circuit::{TestGatesCircuit, CompressionInput};


#[test]
fn bench_blake2b_circuit_prover() {
    //Unique string used by bench results module for parsing the result
    const BENCHMARK_ID: &str = "Blake2b Circuit";

    const DEGREE:u32 = 17;
    const R: usize = 8;
    let rounds = (1u32 << DEGREE) / R as u32 - 11;
    println!("Rounds: {}", rounds);

    let inputs = vec![
       CompressionInput {
            r: rounds - 100,
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
            r: 87,
            h: [532, 235, 325, 235, 53252, 0, 235324, 25423],
            m: [55142, 0, 35, 31115, 5252, 52452, 2324, 2523, 254, 35, 354, 235, 5532, 0, 35, 525],
            t: 0,
            f: true,
        }
    ];

    // Create the circuit
    let circuit = TestGatesCircuit::<Fr,R> {
        k: DEGREE,
        inputs,
        _marker: PhantomData
    };

 //   let prover = halo2_proofs::dev::MockProver::run(DEGREE, &circuit, vec![]).unwrap();
 //   prover.assert_satisfied();
 //   return;

    // Initialize the polynomial commitment parameters
    let mut rng = XorShiftRng::from_seed([0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5]);

    // Bench setup generation
    let setup_message = format!("Setup generation with degree = {}", DEGREE);
    let start1 = start_timer!(|| setup_message);
    let general_params = ParamsKZG::<Bn256>::setup(DEGREE, &mut rng);
    let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
    end_timer!(start1);

    // Initialize the proving key
    let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");
    // Create a proof
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    // Bench proof generation time
    let proof_message = format!("{} Proof generation with degree = {}", BENCHMARK_ID, DEGREE);
    let start2 = start_timer!(|| proof_message);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        XorShiftRng,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        TestGatesCircuit::<Fr,R>
    >(
        &general_params,
        &pk,
        &[circuit],
        &[&[]],
        rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();
    end_timer!(start2);

    println!("Proof size: {}", proof.len());
    // Bench verification time
    let start3 = start_timer!(|| format!("{} Proof verification", BENCHMARK_ID));
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
        &[&[]],
        &mut verifier_transcript,
    )
    .expect("failed to verify bench circuit");
    end_timer!(start3);
}