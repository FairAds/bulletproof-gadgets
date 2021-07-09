use mimc_hash::mimc::mimc_hash_sponge;
use curve25519_dalek::scalar::Scalar;
use merkle_tree::merkle_tree_gadget::{Pattern};
use conversions::{scalar_to_hex, scalar_to_bytes, str_hex_decode, num_hex_decode};

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
        index: &mut u8,
    ) -> Scalar {
        println!("---------------");
        let preimage: Vec<Scalar>;
        let patt = pattern.clone();
        println!("MerkleTreePattern = {}", patt);
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
        println!("Parse call index = {}", &index);
        *index = *index +1;
        println!("Preimage(decoded): [");
        for p in preimage.iter(){
            let bytes_array = scalar_to_bytes(&p);
            let decoded_str = str_hex_decode(&bytes_array);
            if decoded_str.eq("") && bytes_array.len() <= 8 {
                let decoded_int = num_hex_decode(&bytes_array);
                println!("      {},", decoded_int);
            }
            else{
                println!("      {},", decoded_str);
            }
        }
        println!("]");
        let hash = mimc_hash_sponge(&preimage);
        //println!("Recursive hash node ?? = 0x{}", scalar_to_hex(&hash));
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
        let mut index: u8 = 0;
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
