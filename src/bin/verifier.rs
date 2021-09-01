extern crate bulletproofs_gadgets;

use bulletproofs_gadgets::verify::verify;

use std::env;
use std::fs::read;
use std::fs::read_to_string;

const INSTANCE_VARS_EXT: &str = ".inst";
const COMMITMENTS_EXT: &str = ".coms";
const GADGETS_EXT: &str = ".gadgets";
const PROOF_EXT: &str = ".proof";

fn main() -> std::io::Result<()> {
    let filename = Box::leak(env::args().nth(1).expect("missing argument").into_boxed_str());
    let instance = read_to_string(format!("{}{}", filename, INSTANCE_VARS_EXT)).expect("unable to read instance file");
    let commitments = read_to_string(format!("{}{}", filename, COMMITMENTS_EXT)).expect("unable to read commitments file");
    let proof = read(format!("{}{}", filename, PROOF_EXT)).expect("unable to read proof file");
    let gadgets = read_to_string(format!("{}{}", filename, GADGETS_EXT)).expect("unable to read gadgets file");

    let verified = verify(filename, instance, proof, commitments, gadgets).expect("unable to verify provided files");

    println!("{}", verified);
    Ok(())
}
