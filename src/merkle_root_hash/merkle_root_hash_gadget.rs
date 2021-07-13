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

    const W1: [u8; 32] = [  // 0x01ae250876c59b361be2dfe5c68e36530d1e3a7215b6c8c112014dbef90fb348
        0x01, 0xae, 0x25, 0x08, 0x76, 0xc5, 0x9b, 0x36,
        0x1b, 0xe2, 0xdf, 0xe5, 0xc6, 0x8e, 0x36, 0x53,
        0x0d, 0x1e, 0x3a, 0x72, 0x15, 0xb6, 0xc8, 0xc1,
        0x12, 0x01, 0x4d, 0xbe, 0xf9, 0x0f, 0xb3, 0x48
    ];
    /*
    const W2: [u8; 32] = [  // 0x0214b6e121107be7e63e71f134d7311a9b47d447afbc1adb1e41f0dbf309e5b4
        0x02, 0x14, 0xb6, 0xe1, 0x21, 0x10, 0x7b, 0xe7,
        0xe6, 0x3e, 0x71, 0xf1, 0x34, 0xd7, 0x31, 0x1a,
        0x9b, 0x47, 0xd4, 0x47, 0xaf, 0xbc, 0x1a, 0xdb,
        0x1e, 0x41, 0xf0, 0xdb, 0xf3, 0x09, 0xe5, 0xb4
    ];
    const W3: [u8; 32] = [  // 0x093c97ac736b6b27c0f3dad15e1a2e122d570a92f52d2bb126d5f6095e2e1add
        0x09, 0x3c, 0x97, 0xac, 0x73, 0x6b, 0x6b, 0x27,
        0xc0, 0xf3, 0xda, 0xd1, 0x5e, 0x1a, 0x2e, 0x12,
        0x2d, 0x57, 0x0a, 0x92, 0xf5, 0x2d, 0x2b, 0xb1,
        0x26, 0xd5, 0xf6, 0x09, 0x5e, 0x2e, 0x1a, 0xdd
    ];
    const W4: [u8; 32] = [  // 0x0cea09a7fb3e03f36c459236232a2cfaf13543a2831157d5cf8a4bfbf9367766
        0x0c, 0xea, 0x09, 0xa7, 0xfb, 0x3e, 0x03, 0xf3,
        0x6c, 0x45, 0x92, 0x36, 0x23, 0x2a, 0x2c, 0xfa,
        0xf1, 0x35, 0x43, 0xa2, 0x83, 0x11, 0x57, 0xd5,
        0xcf, 0x8a, 0x4b, 0xfb, 0xf9, 0x36, 0x77, 0x66
    ];
    const W5: [u8; 32] = [  // 0x070b46c6ed59536ccc0617d60133336fab6c324f795a220850e240695cf42f26
        0x07, 0x0b, 0x46, 0xc6, 0xed, 0x59, 0x53, 0x6c,
        0xcc, 0x06, 0x17, 0xd6, 0x01, 0x33, 0x33, 0x6f,
        0xab, 0x6c, 0x32, 0x4f, 0x79, 0x5a, 0x22, 0x08,
        0x50, 0xe2, 0x40, 0x69, 0x5c, 0xf4, 0x2f, 0x26
    ];
    const W6: [u8; 32] = [  // 0x0ec53eb4e2d523c8752f1060305ebf37f69a8bcef96122e56fc651b5da8c5cf8
        0x0e, 0xc5, 0x3e, 0xb4, 0xe2, 0xd5, 0x23, 0xc8,
        0x75, 0x2f, 0x10, 0x60, 0x30, 0x5e, 0xbf, 0x37,
        0xf6, 0x9a, 0x8b, 0xce, 0xf9, 0x61, 0x22, 0xe5,
        0x6f, 0xc6, 0x51, 0xb5, 0xda, 0x8c, 0x5c, 0xf8
    ];
    const W7: [u8; 32] = [  // 0x02ef2c328405a0720a45bab328fd02bfe429109485a7af7c593175d671cbea03
        0x02, 0xef, 0x2c, 0x32, 0x84, 0x05, 0xa0, 0x72,
        0x0a, 0x45, 0xba, 0xb3, 0x28, 0xfd, 0x02, 0xbf,
        0xe4, 0x29, 0x10, 0x94, 0x85, 0xa7, 0xaf, 0x7c,
        0x59, 0x31, 0x75, 0xd6, 0x71, 0xcb, 0xea, 0x03
    ];
    */
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