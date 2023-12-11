#![allow(unused_imports)]
use super::{dev::*, param::*, *};
use std::vec;

use alloy_primitives::FixedBytes;
use bus_mapping::circuit_input_builder::{
    protocol_instance::Transition, BlockMetadata, Transaction,
};
use core::result::Result;
use eth_types::{ToWord, H160, H256};
use halo2_proofs::{
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
    plonk::{keygen_pk, keygen_vk},
};
use lazy_static::lazy_static;
use snark_verifier_sdk::halo2::gen_srs;
lazy_static! {
    static ref LAST_HASH: H256 = H256::from_slice(
        &hex::decode("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap(),
    );
    static ref THIS_HASH: H256 = H256::from_slice(
        &hex::decode("1dcc4de8dec751111b85b567b6cc12fea12451b9480000000a142fd40d493111").unwrap(),
    );
    static ref PROVER_ADDR: H160 =
        H160::from_slice(&hex::decode("8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199").unwrap(),);
}

fn run<F: Field>(
    k: u32,
    evidence: PublicData<F>,
    pi: Option<Vec<Vec<F>>>,
) -> Result<(), Vec<VerifyFailure>> {
    let circuit = TaikoPiCircuit::new(evidence);
    let keccak_instance = pi.unwrap_or_else(|| circuit.instance());
    let prover = match MockProver::run(k, &circuit, keccak_instance) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.verify()
}

fn mock_public_data() -> PublicData<Fr> {
    let protocol_instance = ProtocolInstance {
        transition: Transition {
            parentHash: LAST_HASH.as_fixed_bytes().into(),
            blockHash: THIS_HASH.as_fixed_bytes().into(),
            ..Default::default()
        },
        block_metadata: BlockMetadata::default(),
        prover: *PROVER_ADDR,
    };
    let block_context = BlockContext {
        number: 300.into(),
        history_hashes: vec![LAST_HASH.to_word()],
        block_hash: THIS_HASH.to_word(),
        ..Default::default()
    };
    PublicData {
        protocol_instance,
        block_context,
        ..Default::default()
    }
}

fn mock(
    number: Option<U256>,
    this_hash: Option<H256>,
    last_hash: Option<H256>,
) -> witness::Block<Fr> {
    let this_hash = this_hash.unwrap_or_default();
    let last_hash = last_hash.unwrap_or_default();
    let eth_block = eth_types::Block::<eth_types::Transaction> {
        hash: Some(this_hash),
        parent_hash: last_hash,
        ..Default::default()
    };
    let context = BlockContext {
        number: number.unwrap_or_default(),
        history_hashes: vec![last_hash.to_word()],
        block_hash: this_hash.to_word(),
        ..Default::default()
    };
    let protocol_instance = ProtocolInstance {
        transition: Transition {
            parentHash: last_hash.as_fixed_bytes().into(),
            blockHash: this_hash.as_fixed_bytes().into(),
            ..Default::default()
        },
        ..Default::default()
    };

    witness::Block::<Fr> {
        eth_block,
        context,
        protocol_instance: Some(protocol_instance),
        ..Default::default()
    }
}

#[test]
fn test_default_pi() {
    let block = mock(Some(2.into()), None, None);
    let evidence = PublicData::new(&block);
    let k = 17;
    assert_eq!(run::<Fr>(k, evidence, None), Ok(()));
}

#[test]
fn test_simple_pi() {
    let block = mock(Some(300.into()), Some(*THIS_HASH), Some(*LAST_HASH));
    let evidence = PublicData::new(&block);

    let k = 17;
    assert_eq!(run::<Fr>(k, evidence, None), Ok(()));
}

#[test]
fn test_fail_hi_lo() {
    let block = mock(Some(300.into()), Some(*THIS_HASH), Some(*LAST_HASH));
    let evidence = PublicData::new(&block);
    let k = 17;
    match run::<Fr>(k, evidence, Some(vec![vec![Fr::zero(), Fr::one()]])) {
        Ok(_) => unreachable!("this case must fail"),
        Err(errs) => {
            assert_eq!(errs.len(), 4);
            for err in errs {
                match err {
                    VerifyFailure::Permutation { .. } => return,
                    _ => unreachable!("unexpected error"),
                }
            }
        }
    }
}

#[test]
fn test_fail_historical_hash() {
    // ProtocolInstance has default parent hash
    // but context.history_hashes is empty
    let mut block = mock(Some(300.into()), Some(*THIS_HASH), None);
    block.context.history_hashes = vec![];
    let evidence = PublicData::new(&block);

    let k = 17;
    match run::<Fr>(k, evidence, None) {
        Ok(_) => unreachable!("this case must fail"),
        Err(errs) => {
            assert_eq!(errs.len(), 1);
            for err in errs {
                match err {
                    VerifyFailure::Lookup { .. } => return,
                    _ => unreachable!("unexpected error"),
                }
            }
        }
    }
}

#[ignore = "takes too long"]
#[test]
fn test_from_integration() {
    let block = mock(Some(300.into()), Some(*THIS_HASH), Some(*LAST_HASH));
    let evidence1 = PublicData::new(&block);
    let circuit1 = TaikoPiCircuit::new(evidence1);

    let block = mock(Some(454.into()), Some(*THIS_HASH), Some(*LAST_HASH));
    let mut evidence2 = PublicData::new(&block);
    evidence2.protocol_instance.prover = *PROVER_ADDR;
    let circuit2 = TaikoPiCircuit::new(evidence2);

    let k = 22;
    let params = gen_srs(k);
    let vk1 = keygen_vk(&params, &circuit1).expect("keygen_vk should not fail");
    let vk2 = keygen_vk(&params, &circuit2).expect("keygen_vk should not fail");
    let _pk1 = keygen_pk(&params, vk1.clone(), &circuit1).unwrap();
    let _pk2 = keygen_pk(&params, vk2.clone(), &circuit2).unwrap();
    println!("{:?}\n{:?}", vk1, vk2);
}
