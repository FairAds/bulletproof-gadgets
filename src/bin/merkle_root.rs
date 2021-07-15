#![allow(non_snake_case)]
#![allow(dead_code)]
extern crate curve25519_dalek;
extern crate bulletproofs;
extern crate hex;
extern crate regex;
extern crate log;
extern crate env_logger;
#[macro_use] extern crate bulletproofs_gadgets;
#[macro_use] extern crate lalrpop_util;

use curve25519_dalek::scalar::Scalar;
use bulletproofs_gadgets::merkle_root_hash::merkle_root::MerkleRoot;
use bulletproofs_gadgets::mimc_hash::mimc::{mimc_hash};
use bulletproofs_gadgets::conversions::{hex_to_bytes, scalar_to_hex, str_hex_encode, num_hex_encode};
use bulletproofs_gadgets::merkle_tree::merkle_tree_gadget::{Pattern, Pattern::*};
use std::fs::File;
use std::env;
use regex::Regex;

lalrpop_mod!(gadget_grammar, "/lalrpop/gadget_grammar.rs");

const PROFILE_EXT: &str = ".json";
const SCHEMA_EXT: &str = ".schema.json";
const MERKLE_TREE_PATT: &str = "IS MERKLE ROOT OF ";


fn calc_merkle_root(witness_vars: Vec<String>, pattern: Pattern) {
    let w_bytes: Vec<Vec<u8>> = witness_vars.iter().map(|x| hex_to_bytes(x.clone()).unwrap()).collect();
    log::debug!("Witnesses as byte vectors:");
    for x in w_bytes.iter() {
        log::debug!("    {:?}", x);
    }
    let w_hashed: Vec<Scalar> = w_bytes.iter().map(|x| mimc_hash(x)).collect();
    log::debug!("Hashed witnesses:");
    for x in w_hashed.iter() {
        log::debug!("    0x{}", scalar_to_hex(x));
        log::debug!("        as scalar: {:?}", x);
    }
    let mut root_calculator = MerkleRoot::new();
    root_calculator.calculate_merkle_root(&w_hashed, &Vec::new(), pattern);
    log::info!("Merkle Root hash: {}", root_calculator.get_merkle_root_hash());
}


fn parse_witness_values(json: &serde_json::Value, witnesses_values: &mut Vec<serde_json::Value>) {
    for (key, value) in json.as_object().unwrap() {
        log::debug!("{:?} ===> {:?}", key, value);
        if !value.is_object() {
            witnesses_values.push(value.clone());
        }
        else{
            parse_witness_values(value, witnesses_values);
        }
    }
}

fn parse_json(filename: &str) -> std::io::Result<Vec<String>> {
    let file = File::open(format!("{}{}", filename, PROFILE_EXT))?;
    let json: serde_json::Value = serde_json::from_reader(file)?;
    let mut witnesses_values: Vec<serde_json::Value> = Vec::new();
    parse_witness_values(&json, &mut witnesses_values);
    Ok(get_witness_hex_literals(&witnesses_values))
}

fn get_hash_pattern_from_str(pattern_str: String) -> Pattern{
    let re = Regex::new(r"[A-Za-z.\s]+").unwrap();
    let mut result = re.replace_all(pattern_str.as_str(), "").replace("(,)", "(W W)");
    while result.contains(','){
        result = result.replace(",", " ");
    }
    /* This takes an unnumbered pattern of witnesses and numerates form left to right.
    *  The assumption is that the fields in the validation rule come in the same order as they
    *  are in the .json file.
    */
    let mut witness_index = 0;
    let mut witness_pattern: String = String::new();
    for c in result.chars() {
        if c == 'W'{
            witness_pattern.push_str(format!("W{}", witness_index).as_str());
            witness_index += 1;
        }
        else{
            witness_pattern.push(c);
        }
    }
    let tree_parser = gadget_grammar::TreeParser::new();
    let (_, _, pattern) = tree_parser.parse(witness_pattern.as_str()).unwrap();
    pattern
}
fn parse_schema_pattern(filename: &str) -> std::io::Result<Pattern> {
    let file = File::open(format!("{}{}", filename, SCHEMA_EXT))?;
    let json: serde_json::Value = serde_json::from_reader(file)?;
    let validation_rule_split = json.get("validationRule").unwrap().as_str().unwrap().split(MERKLE_TREE_PATT);
    let rule_parts: Vec<&str> = validation_rule_split.collect();
    let fields_pattern = rule_parts.last().unwrap().clone().replace("private.", "");
    log::debug!("fields_pattern: {}", fields_pattern);
    Ok(get_hash_pattern_from_str(fields_pattern))
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
/// Assumptions for the .json  and .schema.json files:
/// 1. The MerkleRoot statement is defined at the 'validationRule' in the .schema.json file.
/// 2. The 'validationRule' field does not have any statement after the 'IS MERKLE ROOT OF'.
/// 3. Only private fields are used for the MerkleRoot validation.
/// 4. The number and order of fields in the .json file is the same as the ones in the validationRule.
fn main() -> std::io::Result<()> {
    env_logger::init_from_env(
    env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"));
    let filename = Box::leak(env::args().nth(1).expect("missing argument").into_boxed_str());
    let pattern = parse_schema_pattern(filename).expect("unable to read .schema.json file");
    let witness_vars = parse_json(filename).expect("unable to read .json file");
    calc_merkle_root(witness_vars, pattern);

    //println!("\n\n\n\n Passport Example:\n\n");
    //merkle_root_calculation_passport_example();
    Ok(())
}

