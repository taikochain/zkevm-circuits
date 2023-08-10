#![allow(unused_imports)]
use super::{dev::*, *};
use crate::util::unusable_rows;
use eth_types::{H64, U64};
use halo2_proofs::{
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
};
use mock::{CORRECT_MOCK_TXS, MOCK_CHAIN_ID};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn pi_circuit_unusable_rows() {
    assert_eq!(
        PiCircuit::<Fr>::unusable_rows(),
        unusable_rows::<Fr, PiCircuit::<Fr>>(PiCircuitParams {
            max_txs: 2,
            max_calldata: 8,
        }),
    )
}

fn run<F: Field>(
    k: u32,
    max_txs: usize,
    max_calldata: usize,
    public_data: PublicData<F>,
    test_public_data: Option<PublicData<F>>,
) -> Result<(), Vec<VerifyFailure>> {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let randomness = F::random(&mut rng);
    let rand_rpi = F::random(&mut rng);
    let mut public_data = public_data;
    public_data.chain_id = *MOCK_CHAIN_ID;

    let circuit = PiCircuit::<F>::new(max_txs, max_calldata, randomness, rand_rpi, public_data, test_public_data);
    let public_inputs = circuit.instance();

    let prover = match MockProver::run(k, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.verify()
}

// #[test]
// fn test_default_pi() {
//     let max_txs = 2;
//     let max_calldata = 8;
//     let public_data = PublicData::default();

//     let k = 17;
//     assert_eq!(run::<Fr>(k, max_txs, max_calldata, public_data), Ok(()));
// }

// #[test]
// fn test_simple_pi() {
//     let max_txs = 8;
//     let max_calldata = 200;

//     let mut public_data = PublicData::default();

//     let n_tx = 4;
//     for i in 0..n_tx {
//         public_data
//             .transactions
//             .push(CORRECT_MOCK_TXS[i].clone().into());
//     }

//     let k = 17;
//     assert_eq!(run::<Fr>(k, max_txs, max_calldata, public_data), Ok(()));
// }

// fn run_size_check<F: Field>(max_txs: usize, max_calldata: usize, public_data: [PublicData; 2]) {
//     let mut rng = ChaCha20Rng::seed_from_u64(2);
//     let randomness = F::random(&mut rng);
//     let rand_rpi = F::random(&mut rng);

//     let circuit = PiCircuit::<F>::new(
//         max_txs,
//         max_calldata,
//         randomness,
//         rand_rpi,
//         public_data[0].clone(),
//     );
//     let public_inputs = circuit.instance();
//     let prover1 = MockProver::run(20, &circuit, public_inputs).unwrap();

//     let circuit2 = PiCircuit::new(
//         max_txs,
//         max_calldata,
//         randomness,
//         rand_rpi,
//         public_data[1].clone(),
//     );
//     let public_inputs = circuit2.instance();
//     let prover2 = MockProver::run(20, &circuit, public_inputs).unwrap();

//     assert_eq!(prover1.fixed(), prover2.fixed());
//     assert_eq!(prover1.permutation(), prover2.permutation());
// }

// #[test]
// fn variadic_size_check() {
//     let max_txs = 8;
//     let max_calldata = 200;

//     let mut pub_dat_1 = PublicData {
//         chain_id: *MOCK_CHAIN_ID,
//         ..Default::default()
//     };

//     let n_tx = 2;
//     for i in 0..n_tx {
//         pub_dat_1
//             .transactions
//             .push(CORRECT_MOCK_TXS[i].clone().into());
//     }

//     let mut pub_dat_2 = PublicData {
//         chain_id: *MOCK_CHAIN_ID,
//         ..Default::default()
//     };

//     let n_tx = 4;
//     for i in 0..n_tx {
//         pub_dat_2
//             .transactions
//             .push(CORRECT_MOCK_TXS[i].clone().into());
//     }

//     run_size_check::<Fr>(max_txs, max_calldata, [pub_dat_1, pub_dat_2]);
// }


    // #[test]
    // fn test_default_pi() {
    //     const MAX_TXS: usize = 2;
    //     const MAX_CALLDATA: usize = 8;
    //     let public_data = PublicData::default();

    //     let k = 18;
    //     assert_eq!(
    //         run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None),
    //         Ok(())
    //     );
    // }

    // #[test]
    // fn test_fail_pi_hash() {
    //     const MAX_TXS: usize = 2;
    //     const MAX_CALLDATA: usize = 8;
    //     let public_data = PublicData::default();

    //     let k = 18;
    //     match run::<Fr, MAX_TXS, MAX_CALLDATA>(
    //         k,
    //         public_data,
    //         None,
    //         Some(vec![vec![Fr::zero(), Fr::one()]]),
    //     ) {
    //         Ok(_) => unreachable!("this case must fail"),
    //         Err(errs) => {
    //             assert_eq!(errs.len(), 4);
    //             for err in errs {
    //                 match err {
    //                     VerifyFailure::Permutation { .. } => return,
    //                     _ => unreachable!("unexpected error"),
    //                 }
    //             }
    //         }
    //     }
    // }

    // #[test]
    // fn test_fail_pi_prover() {
    //     const MAX_TXS: usize = 2;
    //     const MAX_CALLDATA: usize = 8;
    //     let mut public_data = PublicData::default();
    //     let address_bytes = [
    //         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    //     ];

    //     public_data.prover = Address::from_slice(&address_bytes);

    //     let prover: Fr = public_data.prover.to_scalar().unwrap();
    //     let k = 18;
    //     match run::<Fr, MAX_TXS, MAX_CALLDATA>(
    //         k,
    //         public_data,
    //         None,
    //         Some(vec![vec![prover, Fr::zero(), Fr::one()]]),
    //     ) {
    //         Ok(_) => unreachable!("this case must fail"),
    //         Err(errs) => {
    //             assert_eq!(errs.len(), 4);
    //             for err in errs {
    //                 match err {
    //                     VerifyFailure::Permutation { .. } => return,
    //                     _ => unreachable!("unexpected error"),
    //                 }
    //             }
    //         }
    //     }
    // }

    // #[test]
    // fn test_simple_pi() {
    //     const MAX_TXS: usize = 8;
    //     const MAX_CALLDATA: usize = 200;

    //     let mut rng = ChaCha20Rng::seed_from_u64(2);

    //     let mut public_data = PublicData::default();
    //     let chain_id = 1337u64;
    //     public_data.chain_id = Word::from(chain_id);

    //     let n_tx = 4;
    //     for i in 0..n_tx {
    //         let eth_tx = eth_types::Transaction::from(&rand_tx(&mut rng, chain_id, i & 2 == 0));
    //         public_data.transactions.push(eth_tx);
    //     }

    //     let k = 18;
    //     assert_eq!(
    //         run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None),
    //         Ok(())
    //     );
    // }

    fn get_block_header_rlp_from_block(block: &witness::Block<Fr>) -> (H256, Bytes) {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream
            .append(&block.eth_block.parent_hash)
            .append(&*OMMERS_HASH)
            .append(&block.eth_block.author.unwrap_or_else(H160::zero))
            .append(&block.eth_block.state_root)
            .append(&block.eth_block.transactions_root)
            .append(&block.eth_block.receipts_root)
            .append(&vec![0u8; LOGS_BLOOM_SIZE]) // logs_bloom is all zeros
            .append(&block.context.difficulty)
            .append(&block.context.number.low_u64())
            .append(&block.context.gas_limit)
            .append(&block.eth_block.gas_used)
            .append(&block.context.timestamp);
        rlp_opt(&mut stream, &None::<u8>); // extra_data = ""
        stream
            .append(&block.eth_block.mix_hash.unwrap_or_else(H256::zero))
            .append(&vec![0u8; NONCE_SIZE]) // nonce = 0
            .append(&block.context.base_fee)
            .append(&block.eth_block.withdrawals_root.unwrap_or_else(H256::zero));

        stream.finalize_unbounded_list();
        let out: bytes::Bytes = stream.out().into();
        let rlp_bytes: Bytes = out.into();
        let hash = keccak256(&rlp_bytes);
        (hash.into(), rlp_bytes)
    }

    fn default_test_block() -> (
        witness::Block<Fr>,
        Address,
        Vec<witness::Block<Fr>>,
        Vec<Bytes>,
    ) {
        let prover =
            Address::from_slice(&hex::decode("Df08F82De32B8d460adbE8D72043E3a7e25A3B39").unwrap());

        let mut current_block = witness::Block::<Fr>::default();

        current_block.context.history_hashes = vec![U256::zero(); PREVIOUS_BLOCKS_NUM];
        let mut previous_blocks: Vec<witness::Block<Fr>> =
            vec![witness::Block::<Fr>::default(); PREVIOUS_BLOCKS_NUM];
        let mut previous_blocks_rlp: Vec<Bytes> = vec![Bytes::default(); PREVIOUS_BLOCKS_NUM];
        let mut past_block_hash = H256::zero();
        let mut past_block_rlp: Bytes;
        for i in 0..PREVIOUS_BLOCKS_NUM {
            let mut past_block = witness::Block::<Fr>::default();
            past_block.eth_block.parent_hash = past_block_hash;
            (past_block_hash, past_block_rlp) = get_block_header_rlp_from_block(&past_block);

            current_block.context.history_hashes[i] = U256::from(past_block_hash.as_bytes());
            previous_blocks[i] = past_block.clone();
            previous_blocks_rlp[i] = past_block_rlp.clone();
        }

        // Populate current block
        current_block.eth_block.parent_hash = past_block_hash;
        current_block.eth_block.author = Some(prover);
        current_block.eth_block.state_root = H256::zero();
        current_block.eth_block.transactions_root = H256::zero();
        current_block.eth_block.receipts_root = H256::zero();
        current_block.eth_block.logs_bloom = Some([0; LOGS_BLOOM_SIZE].into());
        current_block.eth_block.difficulty = U256::from(0);
        current_block.eth_block.number = Some(U64::from(0));
        current_block.eth_block.gas_limit = U256::from(0);
        current_block.eth_block.gas_used = U256::from(0);
        current_block.eth_block.timestamp = U256::from(0);
        current_block.eth_block.extra_data = eth_types::Bytes::from([0; 0]);
        current_block.eth_block.mix_hash = Some(H256::zero());
        current_block.eth_block.nonce = Some(H64::from([0, 0, 0, 0, 0, 0, 0, 0]));
        current_block.eth_block.base_fee_per_gas = Some(U256::from(0));
        current_block.eth_block.withdrawals_root = Some(H256::zero());

        (current_block, prover, previous_blocks, previous_blocks_rlp)
    }

    #[test]
    fn test_blockhash_verify() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        let mut public_data = PublicData::new(&block); //, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr>(k, MAX_TXS, MAX_CALLDATA, public_data, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_short_values() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(0x75);
        block.context.gas_limit = 0x76;
        block.eth_block.gas_used = U256::from(0x77);
        block.context.timestamp = U256::from(0x78);
        block.context.base_fee = U256::from(0x79);

        let mut public_data = PublicData::new(&block); //, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr>(k, MAX_TXS, MAX_CALLDATA, public_data, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_one_byte_non_short_values() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(RLP_HDR_NOT_SHORT);
        block.context.gas_limit = RLP_HDR_NOT_SHORT;
        block.eth_block.gas_used = U256::from(RLP_HDR_NOT_SHORT);
        block.context.timestamp = U256::from(RLP_HDR_NOT_SHORT);
        block.context.base_fee = U256::from(RLP_HDR_NOT_SHORT);

        let mut public_data = PublicData::new(&block); //, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr>(k, MAX_TXS, MAX_CALLDATA, public_data, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_one_byte_non_short_values_2() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(0xFF);
        block.context.gas_limit = 0xFF;
        block.eth_block.gas_used = U256::from(0xFF);
        block.context.timestamp = U256::from(0xFF);
        block.context.base_fee = U256::from(0xFF);

        let mut public_data = PublicData::new(&block); //, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr>(k, MAX_TXS, MAX_CALLDATA, public_data, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_leading_zeros() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(0x0090909090909090_u128);
        block.context.gas_limit = 0x0000919191919191;
        block.eth_block.gas_used = U256::from(0x92) << (28 * 8);
        block.context.timestamp = U256::from(0x93) << (27 * 8);
        block.context.base_fee = U256::from(0x94) << (26 * 8);

        let mut public_data = PublicData::new(&block); //, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr>(k, MAX_TXS, MAX_CALLDATA, public_data, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_max_lengths() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();

        block.context.number = U256::from(0x9090909090909090_u128);
        block.context.gas_limit = 0x9191919191919191;
        block.eth_block.gas_used = U256::from(0x92) << (31 * 8);
        block.context.timestamp = U256::from(0x93);// << (31 * 8);
        block.context.base_fee = U256::from(0x94) << (31 * 8);

        let mut public_data = PublicData::new(&block); //, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        println!("Public data: {:?}", public_data);
        assert_eq!(
            run::<Fr>(k, MAX_TXS, MAX_CALLDATA, public_data, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_fail_lookups() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();

        block.eth_block.state_root = H256::from_slice(
            &hex::decode("21223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49349")
                .unwrap(),
        );
        block.eth_block.transactions_root = H256::from_slice(
            &hex::decode("31223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49350")
                .unwrap(),
        );
        block.eth_block.receipts_root = H256::from_slice(
            &hex::decode("41223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49351")
                .unwrap(),
        );
        block.eth_block.logs_bloom = Some([0; LOGS_BLOOM_SIZE].into());
        block.eth_block.extra_data = eth_types::Bytes::from([0; 0]);
        block.eth_block.mix_hash = Some(H256::from_slice(
            &hex::decode("51223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49352")
                .unwrap(),
        ));
        block.context.number = U256::from(0x9090909090909090_u128);
        block.context.gas_limit = 0x9191919191919191;
        block.eth_block.gas_used = U256::from(0x92) << (31 * 8);
        block.context.timestamp = U256::from(0x93) << (31 * 8);
        block.context.base_fee = U256::from(0x94) << (31 * 8);
        block.eth_block.withdrawals_root = Some(H256::from_slice(
            &hex::decode("61223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49353")
                .unwrap(),
        ));

        let mut public_data = PublicData::new(&block);//, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        let (test_block, _, test_previous_blocks, previous_blocks_rlp) = default_test_block();
        let test_public_data = PublicData::new(&test_block);//, H160::default(), Default::default());
        public_data.previous_blocks = test_previous_blocks;

        match run::<Fr>(k, MAX_TXS, MAX_CALLDATA, public_data, Some(test_public_data)) {
            Ok(_) => unreachable!("this case must fail"),
            Err(errs) => {
                //assert_eq!(errs.len(), 14);
                for err in errs {
                    match err {
                        VerifyFailure::Lookup { .. } => return,
                        VerifyFailure::CellNotAssigned { .. } => return,
                        _ => unreachable!("unexpected error"),
                    }
                }
            }
        }
    }
// }



/*
// We define the PiTestCircuit as a wrapper over PiCircuit extended to take the
// generic const parameters MAX_TXS and MAX_CALLDATA.  This is necessary because
// the trait Circuit requires an implementation of `configure` that doesn't take
// any circuit parameters, and the PiCircuit defines gates that use rotations
// that depend on MAX_TXS and MAX_CALLDATA, so these two values are required
// during the configuration.
/// Test Circuit for PiCircuit
#[cfg(any(feature = "test", test))]
#[derive(Default, Clone)]
pub struct PiTestCircuit<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
    pub PiCircuit<F>,
);

#[cfg(any(feature = "test", test))]
impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> Circuit<F>
    for PiTestCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    type Config = PiCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let tx_table = TxTable::construct(meta);
        // let rlp_table = array_init::array_init(|_| meta.advice_column());
        let keccak_table = KeccakTable2::construct(meta);
        let challenges = Challenges::mock(100.expr(), 110.expr(), 120.expr());
        PiCircuitConfig::new(
            meta,
            PiCircuitConfigArgs {
                max_txs: MAX_TXS,
                max_calldata: MAX_CALLDATA,
                block_table,
                tx_table,
                // rlp_table,
                keccak_table,
                challenges,
            },
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // let challenges = challenges.values(&mut layouter);
        let challenges = Challenges::mock(Value::known(F::from(100)), Value::known(F::from(110)), Value::known(F::from(120)));
        let public_data = &self.0.public_data;

        // Include all previous block RLP hashes
        let previous_blocks_rlp: Vec<Vec<u8>> = public_data
            .previous_blocks_rlp
            .clone()
            .into_iter()
            .map(|r| r.to_vec())
            .collect();

        // assign keccak table
        config.keccak_table.dev_load(
            &mut layouter,
            previous_blocks_rlp.iter().chain(
                vec![
                    &public_data.txs_rlp.to_vec(),
                    &public_data.block_rlp.to_vec(),
                    &public_data.blockhash_blk_hdr_rlp.to_vec(),
                ]
                .into_iter(),
            ),
            &challenges,
        )?;

        self.0.synthesize_sub(&config, &challenges, &mut layouter)
    }
}


#[cfg(test)]
mod pi_circuit_test {

    use super::*;

    use crate::test_util::rand_tx;
    use eth_types::{H64, U256, U64};
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };
    use pretty_assertions::assert_eq;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn run<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
        k: u32,
        public_data: PublicData<F>,
        test_public_data: Option<PublicData<F>>,
        pi: Option<Vec<Vec<F>>>,
        block: &witness::Block<Fr>,
        test_block: Option<witness::Block<Fr>>,
    ) -> Result<(), Vec<VerifyFailure>> {

        let block = test_block.as_ref().unwrap_or(block);
        let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA>(PiCircuit::new_from_block(block));

        // let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA>(PiCircuit::new(
        //     MAX_TXS,
        //     MAX_CALLDATA,
        //     randomness,
        //     rand_rpi,
        //     public_data,
        //     test_public_data,
        // ));
        let public_inputs = pi.unwrap_or_else(|| circuit.0.instance());

        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        let res: Result<(), Vec<VerifyFailure>> = prover.verify();
        let mut curated_res = Vec::new();
        if res.is_err() {
            let errors = res.as_ref().err().unwrap();
            for error in errors.iter() {
                match error {
                    VerifyFailure::CellNotAssigned { .. } => (),
                    _ => curated_res.push(<&halo2_proofs::dev::VerifyFailure>::clone(&error)),
                };
            }
            if !curated_res.is_empty() {
                return res;
            }
        }
        let hash_byte_hi: Vec<u8> = circuit
            .0
            .public_data
            .block_hash
            .as_bytes()
            .iter()
            .take(16)
            .copied()
            .collect();
        let hash_byte_lo: Vec<u8> = circuit
            .0
            .public_data
            .block_hash
            .as_bytes()
            .iter()
            .skip(16)
            .copied()
            .collect();
        let _s1 = hex::encode(hash_byte_hi);
        let _s2 = hex::encode(hash_byte_lo);
        Ok(())
    }

    // #[test]
    // fn test_default_pi() {
    //     const MAX_TXS: usize = 2;
    //     const MAX_CALLDATA: usize = 8;
    //     let public_data = PublicData::default();

    //     let k = 18;
    //     assert_eq!(
    //         run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None),
    //         Ok(())
    //     );
    // }

    // #[test]
    // fn test_fail_pi_hash() {
    //     const MAX_TXS: usize = 2;
    //     const MAX_CALLDATA: usize = 8;
    //     let public_data = PublicData::default();

    //     let k = 18;
    //     match run::<Fr, MAX_TXS, MAX_CALLDATA>(
    //         k,
    //         public_data,
    //         None,
    //         Some(vec![vec![Fr::zero(), Fr::one()]]),
    //     ) {
    //         Ok(_) => unreachable!("this case must fail"),
    //         Err(errs) => {
    //             assert_eq!(errs.len(), 4);
    //             for err in errs {
    //                 match err {
    //                     VerifyFailure::Permutation { .. } => return,
    //                     _ => unreachable!("unexpected error"),
    //                 }
    //             }
    //         }
    //     }
    // }

    // #[test]
    // fn test_fail_pi_prover() {
    //     const MAX_TXS: usize = 2;
    //     const MAX_CALLDATA: usize = 8;
    //     let mut public_data = PublicData::default();
    //     let address_bytes = [
    //         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    //     ];

    //     public_data.prover = Address::from_slice(&address_bytes);

    //     let prover: Fr = public_data.prover.to_scalar().unwrap();
    //     let k = 18;
    //     match run::<Fr, MAX_TXS, MAX_CALLDATA>(
    //         k,
    //         public_data,
    //         None,
    //         Some(vec![vec![prover, Fr::zero(), Fr::one()]]),
    //     ) {
    //         Ok(_) => unreachable!("this case must fail"),
    //         Err(errs) => {
    //             assert_eq!(errs.len(), 4);
    //             for err in errs {
    //                 match err {
    //                     VerifyFailure::Permutation { .. } => return,
    //                     _ => unreachable!("unexpected error"),
    //                 }
    //             }
    //         }
    //     }
    // }

    // #[test]
    // fn test_simple_pi() {
    //     const MAX_TXS: usize = 8;
    //     const MAX_CALLDATA: usize = 200;

    //     let mut rng = ChaCha20Rng::seed_from_u64(2);

    //     let mut public_data = PublicData::default();
    //     let chain_id = 1337u64;
    //     public_data.chain_id = Word::from(chain_id);

    //     let n_tx = 4;
    //     for i in 0..n_tx {
    //         let eth_tx = eth_types::Transaction::from(&rand_tx(&mut rng, chain_id, i & 2 == 0));
    //         public_data.transactions.push(eth_tx);
    //     }

    //     let k = 18;
    //     assert_eq!(
    //         run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None),
    //         Ok(())
    //     );
    // }

    fn get_block_header_rlp_from_block(block: &witness::Block<Fr>) -> (H256, Bytes) {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream
            .append(&block.eth_block.parent_hash)
            .append(&*OMMERS_HASH)
            .append(&block.eth_block.author.unwrap_or_else(H160::zero))
            .append(&block.eth_block.state_root)
            .append(&block.eth_block.transactions_root)
            .append(&block.eth_block.receipts_root)
            .append(&vec![0u8; LOGS_BLOOM_SIZE]) // logs_bloom is all zeros
            .append(&block.context.difficulty)
            .append(&block.context.number.low_u64())
            .append(&block.context.gas_limit)
            .append(&block.eth_block.gas_used)
            .append(&block.context.timestamp);
        rlp_opt(&mut stream, &None::<u8>); // extra_data = ""
        stream
            .append(&block.eth_block.mix_hash.unwrap_or_else(H256::zero))
            .append(&vec![0u8; NONCE_SIZE]) // nonce = 0
            .append(&block.context.base_fee)
            .append(&block.eth_block.withdrawals_root.unwrap_or_else(H256::zero));

        stream.finalize_unbounded_list();
        let out: bytes::Bytes = stream.out().into();
        let rlp_bytes: Bytes = out.into();
        let hash = keccak256(&rlp_bytes);
        (hash.into(), rlp_bytes)
    }

    fn default_test_block() -> (
        witness::Block<Fr>,
        Address,
        Vec<witness::Block<Fr>>,
        Vec<Bytes>,
    ) {
        let prover =
            Address::from_slice(&hex::decode("Df08F82De32B8d460adbE8D72043E3a7e25A3B39").unwrap());

        let mut current_block = witness::Block::<Fr>::default();

        current_block.context.history_hashes = vec![U256::zero(); PREVIOUS_BLOCKS_NUM];
        let mut previous_blocks: Vec<witness::Block<Fr>> =
            vec![witness::Block::<Fr>::default(); PREVIOUS_BLOCKS_NUM];
        let mut previous_blocks_rlp: Vec<Bytes> = vec![Bytes::default(); PREVIOUS_BLOCKS_NUM];
        let mut past_block_hash = H256::zero();
        let mut past_block_rlp: Bytes;
        for i in 0..PREVIOUS_BLOCKS_NUM {
            let mut past_block = witness::Block::<Fr>::default();
            past_block.eth_block.parent_hash = past_block_hash;
            (past_block_hash, past_block_rlp) = get_block_header_rlp_from_block(&past_block);

            current_block.context.history_hashes[i] = U256::from(past_block_hash.as_bytes());
            previous_blocks[i] = past_block.clone();
            previous_blocks_rlp[i] = past_block_rlp.clone();
        }

        // Populate current block
        current_block.eth_block.parent_hash = past_block_hash;
        current_block.eth_block.author = Some(prover);
        current_block.eth_block.state_root = H256::zero();
        current_block.eth_block.transactions_root = H256::zero();
        current_block.eth_block.receipts_root = H256::zero();
        current_block.eth_block.logs_bloom = Some([0; LOGS_BLOOM_SIZE].into());
        current_block.eth_block.difficulty = U256::from(0);
        current_block.eth_block.number = Some(U64::from(0));
        current_block.eth_block.gas_limit = U256::from(0);
        current_block.eth_block.gas_used = U256::from(0);
        current_block.eth_block.timestamp = U256::from(0);
        current_block.eth_block.extra_data = eth_types::Bytes::from([0; 0]);
        current_block.eth_block.mix_hash = Some(H256::zero());
        current_block.eth_block.nonce = Some(H64::from([0, 0, 0, 0, 0, 0, 0, 0]));
        current_block.eth_block.base_fee_per_gas = Some(U256::from(0));
        current_block.eth_block.withdrawals_root = Some(H256::zero());

        (current_block, prover, previous_blocks, previous_blocks_rlp)
    }

    #[test]
    fn test_blockhash_verify() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None, &block, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_short_values() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(0x75);
        block.context.gas_limit = 0x76;
        block.eth_block.gas_used = U256::from(0x77);
        block.context.timestamp = U256::from(0x78);
        block.context.base_fee = U256::from(0x79);

        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None, &block, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_one_byte_non_short_values() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(RLP_HDR_NOT_SHORT);
        block.context.gas_limit = RLP_HDR_NOT_SHORT;
        block.eth_block.gas_used = U256::from(RLP_HDR_NOT_SHORT);
        block.context.timestamp = U256::from(RLP_HDR_NOT_SHORT);
        block.context.base_fee = U256::from(RLP_HDR_NOT_SHORT);

        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None, &block, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_one_byte_non_short_values_2() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(0xFF);
        block.context.gas_limit = 0xFF;
        block.eth_block.gas_used = U256::from(0xFF);
        block.context.timestamp = U256::from(0xFF);
        block.context.base_fee = U256::from(0xFF);

        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None, &block, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_leading_zeros() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();
        block.context.number = U256::from(0x0090909090909090_u128);
        block.context.gas_limit = 0x0000919191919191;
        block.eth_block.gas_used = U256::from(0x92) << (28 * 8);
        block.context.timestamp = U256::from(0x93) << (27 * 8);
        block.context.base_fee = U256::from(0x94) << (26 * 8);

        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None, &block, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_max_lengths() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();

        block.context.number = U256::from(0x9090909090909090_u128);
        block.context.gas_limit = 0x9191919191919191;
        block.eth_block.gas_used = U256::from(0x92) << (31 * 8);
        block.context.timestamp = U256::from(0x93) << (31 * 8);
        block.context.base_fee = U256::from(0x94) << (31 * 8);

        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, None, None, &block, None),
            Ok(())
        );
    }

    #[test]
    fn test_blockhash_calc_fail_lookups() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;
        let k = 18;

        let (mut block, prover, previous_blocks, previous_blocks_rlp) = default_test_block();

        block.eth_block.state_root = H256::from_slice(
            &hex::decode("21223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49349")
                .unwrap(),
        );
        block.eth_block.transactions_root = H256::from_slice(
            &hex::decode("31223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49350")
                .unwrap(),
        );
        block.eth_block.receipts_root = H256::from_slice(
            &hex::decode("41223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49351")
                .unwrap(),
        );
        block.eth_block.logs_bloom = Some([0; LOGS_BLOOM_SIZE].into());
        block.eth_block.extra_data = eth_types::Bytes::from([0; 0]);
        block.eth_block.mix_hash = Some(H256::from_slice(
            &hex::decode("51223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49352")
                .unwrap(),
        ));
        block.context.number = U256::from(0x9090909090909090_u128);
        block.context.gas_limit = 0x9191919191919191;
        block.eth_block.gas_used = U256::from(0x92) << (31 * 8);
        block.context.timestamp = U256::from(0x93) << (31 * 8);
        block.context.base_fee = U256::from(0x94) << (31 * 8);
        block.eth_block.withdrawals_root = Some(H256::from_slice(
            &hex::decode("61223344dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49353")
                .unwrap(),
        ));

        let mut public_data = PublicData::new(&block, prover, Default::default());
        public_data.previous_blocks = previous_blocks;
        public_data.previous_blocks_rlp = previous_blocks_rlp;

        let (test_block, _, test_previous_blocks, previous_blocks_rlp) = default_test_block();
        let test_public_data = PublicData::new(&test_block, H160::default(), Default::default());
        public_data.previous_blocks = test_previous_blocks;

        match run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data, Some(test_public_data), None, &block, &test_block) {
            Ok(_) => unreachable!("this case must fail"),
            Err(errs) => {
                //assert_eq!(errs.len(), 14);
                for err in errs {
                    match err {
                        VerifyFailure::Lookup { .. } => return,
                        VerifyFailure::CellNotAssigned { .. } => return,
                        _ => unreachable!("unexpected error"),
                    }
                }
            }
        }
    }
}
*/