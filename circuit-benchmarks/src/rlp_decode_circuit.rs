//! RLP decode circuit benchmarks

#[cfg(test)]
mod bench {
    use super::*;
    use ark_std::{end_timer, start_timer};
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
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::env::var;

    #[test]
    fn bench_rlp_decode_circuit_prover() {
        let setup_prfx = "crate::constants::SETUP";
        let proof_gen_prfx = "crate::constants::PROOFGEN_PREFIX";
        let proof_ver_prfx = "crate::constants::PROOFVER_PREFIX";
        // Unique string used by bench results module for parsing the result
        const BENCHMARK_ID: &str = "Rlp decode Circuit";

        let degree: u32 = var("DEGREE")
            .unwrap_or_else(|_| "18".to_string())
            .parse()
            .expect("Cannot parse DEGREE env var as u32");

        let mut rng = ChaChaRng::seed_from_u64(2);
        let input_bytes = hex::decode("f850f84e8001830f4240808080820a97a0805d3057e9b74379d814e2c4d264be888a9b560ea2256781af8a6ea83af41208a07168d2b6d3aa47cbc5020c8a9b120926a197e1135b3aaa13ef0b292663345c15").unwrap();
        let circuit = RlpDecoderCircuit::<Fr>::new(input_bytes, degree as usize);

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
            RlpDecoderCircuit<Fr>,
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
            &[&[]],
            &mut verifier_transcript,
        )
        .expect("failed to verify bench circuit");
        end_timer!(start3);
    }
}
