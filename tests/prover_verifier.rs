#[macro_use]
extern crate bulletproofs_gadgets;
extern crate stringreader;
use stringreader::StringReader;
use bulletproofs_gadgets::c_prover::c_prove;
use bulletproofs_gadgets::verifier::verify;
use std::io::{BufReader, Lines};

fn check_prover_verifier(filename: &'static str) {
        assert_eq!(prove(filename), true);
        assert_eq!(verify(filename), true);
    }

#[test]
fn test_prover_verifier_bounds_check() {
    check_prover_verifier("tests/resources/bounds_check");
}

#[test]
fn test_prover_verifier_equality() {
    check_prover_verifier("tests/resources/equality");
}

#[test]
fn test_prover_verifier_inequality() {
    check_prover_verifier("tests/resources/inequality");
}

#[test]
fn test_prover_verifier_less_than() {
    check_prover_verifier("tests/resources/less_than");
}

#[test]
fn test_prover_verifier_merkle_tree() {
    check_prover_verifier("tests/resources/merkle_tree");
}

#[test]
fn test_prover_verifier_mimc_hash() {
    check_prover_verifier("tests/resources/mimc_hash");
}

#[test]
fn test_prover_verifier_membership() {
    check_prover_verifier("tests/resources/set_membership");
}

#[test]
fn test_prover_verifier_or() {
    check_prover_verifier("tests/resources/or");
}

#[test]
fn test_prover_verifier_or2() {
    check_prover_verifier("tests/resources/or2");
}

#[test]
fn test_prover_verifier_or3() {
    check_prover_verifier("tests/resources/or3");
}

#[test]
fn test_prover_verifier_or4() {
    check_prover_verifier("tests/resources/or4");
}

#[test]
fn test_prover_verifier_or5() {
    check_prover_verifier("tests/resources/or5");
}

#[test]
fn test_fake_file() {


    use std::io::{Read, BufRead, BufReader};
    // use stringreader::StringReader;

    let instance = "I0 = 0x11
        I1 = 0x64
        I2 = 0x0de8eeb8afc63189ec850308717dcae82c9af5d0251165898a2a22569878f844
        I3 = 0x54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e
        I4 = 0x29d057ef2f9761fcf0f4cd9138f83d9b1442475195ac3b9c571cae05a7f6f6377e6f7d635dd466ddc47ba1456a7e56f6a0696d1fd5ec4f248888792953bb5cba
        I5 = 0x041b1219449041dadcddbe404febe98435d472951dcecf891ba6fe5650cb646c
        I6 = 0x4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f726520657420646f6c6f7265206d61676e6120616c697175612e20557420656e696d206164206d696e696d2076656e69616d2c2071756973206e6f737472756420657865726369746174696f6e20756c6c616d636f206c61626f726973206e69736920757420616c697175697020657820656120636f6d6d6f646f20636f6e7365717561742e2044756973206175746520697275726520646f6c6f7220696e20726570726568656e646572697420696e20766f6c7570746174652076656c697420657373652063696c6c756d20646f6c6f726520657520667567696174206e756c6c612070617269617475722e204578636570746575722073696e74206f6363616563617420637570696461746174206e6f6e2070726f6964656e742c2073756e7420696e2063756c706120717569206f666669636961206465736572756e74206d6f6c6c697420616e696d20696420657374206c61626f72756d2e
        I7 = 0x0e449bd43822b20b5b163aded0e0fbece4a51ebbdaa4136ff6a2ec1a26ab8719
        ".replace(" ", "");

    let witness = "W0 = 0x43
        W1 = 0x43
        W2 = 0x0cfb0c17618211c607febf703ac3f3078f7d96798fae9d4a1682bc592f7cb126
        W3 = 0x90dce2591ecb497c93bb4b2e276174ed39552c8d88de59669f0bde51e5f2a44e75767aaa27a1f73c7c4d89d7f9d9ba08f993e2047df9b190155f2bc73e5ca24b
        W4 = 0x00
        ".replace(" ", "");

    let gadgets = "EQUALS W0 W1
        BOUND W1 I0 I1
        HASH W2 W1
        MERKLE I2 (W1 I3)
        MERKLE I7 (I6 W4)
        MERKLE I5 ((W1 I3) (I6 W4))
        UNEQUAL W3 I4
        SET_MEMBER W0 I0 I1 W1 I7
        LESS_THAN W4 W0
        ".replace(" ", "");


    let mut streader_instance = StringReader::new(&instance);
    let mut streader_witness = StringReader::new(&witness);
    let mut streader_gadgets = StringReader::new(&gadgets);

    let mut bufreader_instance = BufReader::new(streader_instance);
    let mut bufreader_witness = BufReader::new(streader_witness);
    let mut bufreader_gadgets = BufReader::new(streader_gadgets);

    // for line in bufreader.lines() {
    //     assert_eq!("I0=0x11", &line.unwrap());
    // }
    let proof = c_prove(&mut bufreader_instance, &mut bufreader_witness, &mut bufreader_gadgets);
    assert_eq("h", proof);


}