#![allow(non_snake_case)]
#![allow(dead_code)]
extern crate curve25519_dalek;
extern crate bulletproofs;
extern crate hex;

#[macro_use] extern crate bulletproofs_gadgets;
use curve25519_dalek::scalar::Scalar;
use bulletproofs_gadgets::merkle_root_hash::merkle_root::MerkleRoot;
use bulletproofs_gadgets::mimc_hash::mimc::{mimc_hash};
use bulletproofs_gadgets::conversions::{hex_to_bytes, scalar_to_hex, str_hex_encode, num_hex_encode};
use bulletproofs_gadgets::merkle_tree::merkle_tree_gadget::{Pattern, Pattern::*};
use std::fs::File;
use std::env;

const PROFILE_EXT: &str = ".json";


fn calc_merkle_root(witness_vars: Vec<String>, pattern: Pattern) {
    let w_bytes: Vec<Vec<u8>> = witness_vars.iter().map(|x| hex_to_bytes(x.clone()).unwrap()).collect();
    println!("Witnesses as byte vectors:");
    for x in w_bytes.iter() {
        println!("    {:?}", x);
    }
    let w_hashed: Vec<Scalar> = w_bytes.iter().map(|x| mimc_hash(x)).collect();
    println!("Hashed witnesses:");
    for x in w_hashed.iter() {
        println!("    0x{}", scalar_to_hex(x));
        println!("        as scalar: {:?}", x);
    }
    let mut root_calculator = MerkleRoot::new();
    root_calculator.calculate_merkle_root(&w_hashed, &Vec::new(), pattern);
    println!("Merkle Root hash: {}", root_calculator.get_merkle_root_hash());
}


fn parse_witness_values(json: &serde_json::Value, witnesses_values: &mut Vec<serde_json::Value>) {
    for (key, value) in json.as_object().unwrap() {
        println!("{:?} ===> {:?}", key, value);
        if !value.is_object() {
            witnesses_values.push(value.clone());
        }
        else{
            parse_witness_values(value, witnesses_values);
        }
    }
}
fn get_merkle_tree_pattern(n_vars: u64) -> Pattern{
    let mut pattern: Pattern = Pattern::W;
    match n_vars {
        1 => pattern = Pattern::W,
        2 => pattern = hash!(W,W),
        3 => pattern = hash!(
            hash!(W,W),
            W
        ),
        4 => pattern = hash!(
            hash!(W,W),
            hash!(W,W)
        ),
        5 => pattern = hash!(
            hash!(
                hash!(W,W),
                hash!(W,W)
            ),
            W
        ),
        6 => pattern = hash!(
            hash!(
                hash!(W,W),
                hash!(W,W)
            ),
            hash!(W,W)
        ),
        7 => pattern = hash!(
            hash!(
                hash!(
                    hash!(W,W),
                    hash!(W,W)
                ),
                hash!(W,W)
            ),
            W
        ),
        8 => pattern = hash!(
            hash!(
                hash!(W,W),
                hash!(W,W)
            ),
            hash!(
                hash!(W,W),
                hash!(W,W)
            )
        ),
        9 => pattern = hash!(hash!(hash!(W,W), hash!(hash!(W,W), hash!(W,W))),hash!(hash!(W,W),W)),
        10 => pattern = hash!(hash!(hash!(W,W), hash!(hash!(W,W), hash!(W,W))),hash!(hash!(W,W),hash!(W,W))),
        _ => panic!("Invalid witness variables length (>10)")
    }
    pattern
}



fn parse_json(filename: &str) -> std::io::Result<Vec<String>> {
    let file = File::open(format!("{}{}", filename, PROFILE_EXT))?;
    let json: serde_json::Value = serde_json::from_reader(file)?;
    let mut witnesses_values: Vec<serde_json::Value> = Vec::new();
    parse_witness_values(&json, &mut witnesses_values);
    Ok(get_witness_hex_literals(&witnesses_values))
}

fn get_witness_hex_literals(witnesses_data: &Vec<serde_json::Value>) -> Vec<String> {
    let mut witnesses_hex_literals: Vec<String> = Vec::new();
    for value in witnesses_data.iter(){
        if value.is_string(){
            witnesses_hex_literals.push(str_hex_encode(value.as_str().unwrap().into()));
        }
        if value.is_number(){
            witnesses_hex_literals.push(num_hex_encode(value.as_u64().unwrap().into()));
        }
    }
    witnesses_hex_literals
}

fn main() -> std::io::Result<()> {
    let filename = Box::leak(env::args().nth(1).expect("missing argument").into_boxed_str());
    let witness_vars = parse_json(filename).expect("unable to read .json file");
    let pattern: Pattern = get_merkle_tree_pattern(witness_vars.len() as u64);
    calc_merkle_root(witness_vars, pattern);

    //println!("\n\n\n\n Passport Example:\n\n");
    //merkle_root_calculation_passport_example();
    Ok(())
}

