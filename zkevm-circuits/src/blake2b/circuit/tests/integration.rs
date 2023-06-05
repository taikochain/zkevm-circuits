use hex::{ decode_to_slice };
use std::{ array, convert::TryInto };
use halo2_proofs::{ halo2curves::bn256::Fr, dev::MockProver };
use blake2b_circuit::{ CompressionCircuit, CompressionInput, compress };

// EIP-152 test vectors 4-7
const EIP152_VECTORS: [[&str; 2]; 4] = [
    ["0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001", 
     "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b"],
    ["0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001", 
     "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"],
    ["0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000", 
     "75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d2875298743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735"],
    ["0000000148c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001", 
     "b63a380cb2897d521994a85234ee2c181b5f844d2c624c002677e9703449d2fba551b3a8333bcdf5f2f7e08993d53923de3d64fcc68c034e717b9293fed7a421"]
]; 

pub fn hex_to_input(x: &str) -> CompressionInput { 
    let mut buffer = [0u8; 213];
    decode_to_slice(x, &mut buffer).expect("Hex input must be correct!");
    assert!(buffer[212] <= 1, "Incorrect final block indicator flag!");

    CompressionInput {
        r: u32::from_be_bytes(buffer[0..4].try_into().unwrap()),
        h: array::from_fn(|i| u64::from_le_bytes(buffer[4 + 8 * i..][..8].try_into().unwrap())),
        m: array::from_fn(|i| u64::from_le_bytes(buffer[68 + 8 * i..][..8].try_into().unwrap())),
        t: u128::from_le_bytes(buffer[196..212].try_into().unwrap()),
        f: buffer[212] == 1
    }
}

#[test]
fn circuit_check() {
    let k = 17;
    let vectors: Vec<CompressionInput> = EIP152_VECTORS.iter().map(|v| hex_to_input(v[0])).collect();
    let circuit = CompressionCircuit::<Fr,128>::new(k, &vectors);
    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

#[test]
fn compression_check() {
    let mut expected = [0u8; 64];  
    for vector in &EIP152_VECTORS {
        let input = hex_to_input(vector[0]);
        let result = compress(input.r, &input.h, &input.m, input.t, input.f);
        decode_to_slice(vector[1], &mut expected).expect("Hex expected value must be correct!");
        let expected: [u64; 8] =  array::from_fn(|i| u64::from_le_bytes(expected[8 * i..][..8].try_into().unwrap()));            
        assert_eq!(result, expected); 
    }
}

#[test]
fn optimums_check() {
    let inputs = [
        CompressionInput { r: 200, h: [0; 8], m: [1; 16], t: 2, f: true },
        CompressionInput { r: 9000, h: [1; 8], m: [3; 16], t: 1, f: true }, 
        CompressionInput { r: 10000, h: [2; 8], m: [6; 16], t: 0, f: true }];
    let optimums = CompressionCircuit::<Fr, 8>::optimums(&inputs);
    assert_eq!(optimums[0..18], [None; 18]);
    assert_eq!(optimums[18..22], [Some(8), Some(24), Some(48), Some(88)]);
    assert_eq!(optimums[22..32],  [Some(128); 10]);   
}