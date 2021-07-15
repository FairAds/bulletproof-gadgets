use bulletproofs::r1cs::{ConstraintSystem, Variable, LinearCombination};
use curve25519_dalek::scalar::Scalar;
use gadget::Gadget;
use merkle_tree::merkle_tree_gadget::{Pattern};
use merkle_root_hash::merkle_root::MerkleRoot;


pub struct MerkleRootHash {
    root: LinearCombination,
    instance_vars: Vec<Scalar>,
    pattern: Pattern
}

impl Gadget for MerkleRootHash {
    fn preprocess(&self, witnesses: &Vec<Scalar>) -> Vec<Scalar> {
        let mut derived_witnesses: Vec<Scalar> = Vec::new();
        println!("MerkleTree.pattern = {}", self.pattern.clone());
        let mut root_calculator = MerkleRoot::new();
        root_calculator.calculate_merkle_root(witnesses, &self.instance_vars, self.pattern.clone());
        println!("Calculated Merkle Root hash = {}", root_calculator.get_merkle_root_hash());
        derived_witnesses.push(root_calculator.get_merkle_root_scalar());
        derived_witnesses
    }

    fn assemble(
        &self, 
        cs: &mut dyn ConstraintSystem, 
        _: &Vec<Variable>,
        derived_witnesses: &Vec<(Option<Scalar>, Variable)>
    ) {

        let (derived_scalar, derived_witness): (Option<Scalar>, Variable) = *derived_witnesses.get(0).unwrap();
        println!("derived_scalar = {:?}", derived_scalar);
        println!("derived_witness = {:?}", derived_witness);
        let derived_witness_lc : LinearCombination = derived_witness.into();
        cs.constrain(self.root.clone() - derived_witness_lc);
    }
}

impl MerkleRootHash {
    pub fn new(
        root: LinearCombination,
        instance_vars: Vec<Scalar>,
        pattern: Pattern
    ) -> MerkleRootHash {
        MerkleRootHash {
            root: root,
            instance_vars: instance_vars,
            pattern: pattern,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(warnings)]
    use super::*;
    use merkle_tree::merkle_tree_gadget::Pattern::*;
    use merlin::Transcript;
    use commitments::{commit_all_single, verifier_commit};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use bulletproofs::r1cs::{Prover, Verifier};
    use conversions::{vars_to_lc, be_to_scalar, hex_to_bytes};
    use mimc_hash::mimc::mimc_hash;

    const W1: [u8; 32] = [  // 0x06b131554e4e50b52e096971533411c7623504f6a56edf1bccdc810672efdd22
        0x06, 0xb1, 0x31, 0x55, 0x4e, 0x4e, 0x50, 0xb5,
        0x2e, 0x09, 0x69, 0x71, 0x53, 0x34, 0x11, 0xc7,
        0x62, 0x35, 0x04, 0xf6, 0xa5, 0x6e, 0xdf, 0x1b,
        0xcc, 0xdc, 0x81, 0x06, 0x72, 0xef, 0xdd, 0x22
    ];
    const HEX_8:  &str = "5065676779";  // "Peggy"
    const HEX_9:  &str = "50726f766572736f6e";  // "Proverson"
    const HEX_10: &str = "012fcfd4";    // 019910612
    const HEX_11: &str = "54696d62756b7475";    // "Timbuktu"
    const HEX_12: &str = "01337894";    // 020150420
    const HEX_13: &str = "0134ff33";    // 020250419
    const HEX_14: &str = "50617373706f7274204f6666696365205a7572696368"; // "Passport Office Zurich"
    const HEX_15: &str = "82440e";  // 8537102

    #[test]
    fn test_merkle_root_hash_gadget_0() {
        //                   1
        //                  / \
        //         2                  3
        //        / \                / \
        //     4        5        6        7
        //    / \      / \      / \      / \
        //   8   9   10   11  12   13  14   15

        let root: Scalar = be_to_scalar(&W1.to_vec());
        let W8:  Vec<u8> = hex_to_bytes(String::from(HEX_8)).unwrap();
        let W9:  Vec<u8> = hex_to_bytes(String::from(HEX_9)).unwrap();
        let W10: Vec<u8> = hex_to_bytes(String::from(HEX_10)).unwrap();
        let W11: Vec<u8> = hex_to_bytes(String::from(HEX_11)).unwrap();
        let W12: Vec<u8> = hex_to_bytes(String::from(HEX_12)).unwrap();
        let W13: Vec<u8> = hex_to_bytes(String::from(HEX_13)).unwrap();
        let W14: Vec<u8> = hex_to_bytes(String::from(HEX_14)).unwrap();
        let W15: Vec<u8> = hex_to_bytes(String::from(HEX_15)).unwrap();

        let witnesses: Vec<Vec<u8>> = vec![
            W8.clone(),
            W9.clone(),
            W10.clone(),
            W11.clone(),
            W12.clone(),
            W13.clone(),
            W14.clone(),
            W15.clone(),
        ];

        let pattern: Pattern = hash!(hash!(hash!(W, W), hash!(W, W)), hash!(hash!(W, W), hash!(W, W)));


        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(16384, 1);

        // Prover

        let mut prover_transcript = Transcript::new(b"MerkleRootHash");

        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        let (witness_scalars, witness_commitments, variables) = commit_all_single(&mut prover, &witnesses);
        let witnesses_hashed = witnesses.iter().map(|x| mimc_hash(x)).collect();
        let gadget = MerkleRootHash::new(root.into(), Vec::new(), pattern.clone());
        let (derived_commitments, derived_witnesses) = gadget.setup(&mut prover, &witnesses_hashed);

        gadget.prove(&mut prover, &Vec::new(), &derived_witnesses);

        let proof = prover.prove(&bp_gens).unwrap();

        // Verifier
        let mut verifier_transcript = Transcript::new(b"MerkleRootHash");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let witness_vars: Vec<Variable> = verifier_commit(&mut verifier, witness_commitments);
        let derived_vars: Vec<Variable> = verifier_commit(&mut verifier, derived_commitments);

        gadget.verify(&mut verifier, &Vec::new(), &derived_vars);
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
    }
}