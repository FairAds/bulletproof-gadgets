extern crate bulletproofs_gadgets;

use std::io::prelude::*;
use std::env;
use std::fs::read_to_string;
use std::fs::File;

use bulletproofs_gadgets::prove::prove;

const INSTANCE_VARS_EXT: &str = ".inst";
const WITNESS_VARS_EXT: &str = ".wtns";
const COMMITMENTS_EXT: &str = ".coms";
const GADGETS_EXT: &str = ".gadgets";
const PROOF_EXT: &str = ".proof";

fn main() -> std::io::Result<()> {
    let filename = Box::leak(env::args().nth(1).expect("missing argument").into_boxed_str());
    let instance = read_to_string(format!("{}{}", filename, INSTANCE_VARS_EXT)).expect("unable to read instance file");
    let witness = read_to_string(format!("{}{}", filename, WITNESS_VARS_EXT)).expect("unable to read instance file");
    let gadgets = read_to_string(format!("{}{}", filename, GADGETS_EXT)).expect("unable to read instance file");
    let mut commitments = String::new();
    let mut commitments_file = File::create(format!("{}{}", filename, COMMITMENTS_EXT))?;
    let mut proof_file = File::create(format!("{}{}", filename, PROOF_EXT))?;

    let proof = prove(filename, instance, witness, gadgets, &mut commitments).expect("unable to generate proof from provided files");
    commitments_file.write_all(&commitments.as_bytes())?;
    proof_file.write_all(&proof)?;

    Ok(())
}
