use mimc_hash::mimc::mimc_hash_sponge;
use curve25519_dalek::scalar::Scalar;
use merkle_tree::merkle_tree_gadget::{Pattern};
use conversions::{scalar_to_hex};

pub struct MerkleRoot {
    root: Scalar
}

impl MerkleRoot {

    pub fn new() -> MerkleRoot {
        MerkleRoot {
            root: Scalar::zero(),
        }
    }

    fn parse_merkle_tree(
        &self,
        w_vars: &mut Vec<Scalar>,
        i_vars: &mut Vec<Scalar>,
        pattern: Pattern,
        index: &mut usize,
    ) -> Scalar {
        let tab = ".    ".repeat(*index);
        println!("{}Parse call index = {}", tab, &index);
        *index = *index +1;
        println!("{}---------------", tab);
        let preimage: Vec<Scalar>;
        let patt = pattern.clone();
        println!("{}MerkleTreePattern = {}",tab, patt);
        match pattern {
            Pattern::Hash(left @ box Pattern::Hash(_,_), box Pattern::W) =>
                preimage = vec![self.parse_merkle_tree( w_vars, i_vars, *left, index), self.next_val(w_vars)],
            Pattern::Hash(left @ box Pattern::Hash(_,_), box Pattern::I) =>
                preimage = vec![self.parse_merkle_tree(w_vars, i_vars, *left, index), self.next_val(i_vars)],
            Pattern::Hash(box Pattern::W, right @ box Pattern::Hash(_,_)) =>
                preimage = vec![self.next_val(w_vars), self.parse_merkle_tree(w_vars, i_vars, *right, index)],
            Pattern::Hash(box Pattern::I, right @ box Pattern::Hash(_,_)) =>
                preimage = vec![self.next_val(i_vars), self.parse_merkle_tree(w_vars, i_vars, *right, index)],
            Pattern::Hash(left @ box Pattern::Hash(_,_), right @ box Pattern::Hash(_,_)) =>
                preimage = vec![self.parse_merkle_tree(w_vars, i_vars, *left, index), self.parse_merkle_tree(w_vars, i_vars, *right, index)],
            Pattern::Hash(box Pattern::W, box Pattern::W) =>
                preimage = vec![self.next_val(w_vars), self.next_val(w_vars)],
            Pattern::Hash(box Pattern::I, box Pattern::I) =>
                preimage = vec![self.next_val(i_vars), self.next_val(i_vars)],
            Pattern::Hash(box Pattern::W, box Pattern::I) =>
                preimage = vec![self.next_val(w_vars), self.next_val(i_vars)],
            Pattern::Hash(box Pattern::I, box Pattern::W) =>
                preimage = vec![self.next_val(i_vars), self.next_val(w_vars)],
            Pattern::W => preimage = vec![self.next_val(w_vars)],
            Pattern::I => preimage = vec![self.next_val(i_vars)]
        }

        println!("{}Preimage({}): [", tab, index);
        for p in preimage.iter(){
            println!("{}      0x{},",tab, scalar_to_hex(p));
        }
        println!("{}]",tab);
        let hash = mimc_hash_sponge(&preimage);
        println!("{}Image({}): 0x{}", tab, index, scalar_to_hex(&hash));
        hash
    }
    fn next_val(&self, values: &mut Vec<Scalar>) -> Scalar {
        assert!(values.len() > 0, "too few variables provided to satisfy the given pattern");

        values.remove(0)
    }

    pub fn calculate_merkle_root(
        &mut self,
        w_vars: &Vec<Scalar>,
        i_vars: &Vec<Scalar>,
        pattern: Pattern
    ){
        let mut w_values: Vec<Scalar> = w_vars.clone();
        let mut i_values: Vec<Scalar> = i_vars.clone();
        let mut index: usize = 0;
        self.root = self.parse_merkle_tree(&mut w_values, &mut i_values, pattern, &mut index);
    }


    pub fn get_merkle_root_scalar(&self) -> Scalar {
        self.root
    }

    pub fn get_merkle_root_hash(&self) -> String {
        let root_hash: String = format!("0x{}", scalar_to_hex(&self.root));
        root_hash
    }

}


#[cfg(test)]
mod tests {
    #![allow(warnings)]
    use super::*;
    use merkle_tree::merkle_tree_gadget::Pattern::*;
    use conversions::hex_to_bytes;
    use mimc_hash::mimc::{mimc_hash_sponge, mimc_hash};

    const HEX_8:  &str = "5065676779";  // "Peggy"
    const HEX_9:  &str = "50726f766572736f6e";  // "Proverson"
    const HEX_10: &str = "012fcfd4";    // 019910612
    const HEX_11: &str = "54696d62756b7475";    // "Timbuktu"
    const HEX_12: &str = "01337894";    // 020150420
    const HEX_13: &str = "0134ff33";    // 020250419
    const HEX_14: &str = "50617373706f7274204f6666696365205a7572696368"; // "Passport Office Zurich"
    const HEX_15: &str = "82440e";  // 8537102

    // The "original" merkle root hash of the Passport Example
    const MERKLE_ROOT_HASH_HEX: &str = "0x06b131554e4e50b52e096971533411c7623504f6a56edf1bccdc810672efdd22";

    #[test]
    fn merkle_root_passport_example_test() {

        //                   1
        //                  / \
        //         2                  3
        //        / \                / \
        //     4        5        6        7
        //    / \      / \      / \      / \
        //   8   9   10   11  12   13  14   15

        let W8: Vec<u8> = hex_to_bytes(String::from(HEX_8)).unwrap();
        let W9: Vec<u8> = hex_to_bytes(String::from(HEX_9)).unwrap();
        let W10: Vec<u8> = hex_to_bytes(String::from(HEX_10)).unwrap();
        let W11: Vec<u8> = hex_to_bytes(String::from(HEX_11)).unwrap();
        let W12: Vec<u8> = hex_to_bytes(String::from(HEX_12)).unwrap();
        let W13: Vec<u8> = hex_to_bytes(String::from(HEX_13)).unwrap();
        let W14: Vec<u8> = hex_to_bytes(String::from(HEX_14)).unwrap();
        let W15: Vec<u8> = hex_to_bytes(String::from(HEX_15)).unwrap();

        let pattern: Pattern = hash!(hash!(hash!(W, W), hash!(W, W)), hash!(hash!(W, W), hash!(W, W)));

        let w_hashed_vars: Vec<Scalar> = vec![
            mimc_hash(&W8),
            mimc_hash(&W9),
            mimc_hash(&W10),
            mimc_hash(&W11),
            mimc_hash(&W12),
            mimc_hash(&W13),
            mimc_hash(&W14),
            mimc_hash(&W15),
        ];

        let mut root_calculator = MerkleRoot::new();
        root_calculator.calculate_merkle_root(&w_hashed_vars, &Vec::new(), pattern);
        let rootHash_hex: String = root_calculator.get_merkle_root_hash();
        println!("Merkle Root hash: {}", rootHash_hex);
        assert_eq!(MERKLE_ROOT_HASH_HEX, rootHash_hex);
    }
}