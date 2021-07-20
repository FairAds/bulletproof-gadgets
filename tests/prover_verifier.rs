#[macro_use]
extern crate bulletproofs_gadgets;
use bulletproofs_gadgets::prover::prove;
use bulletproofs_gadgets::verifier::verify;

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
