use lalrpop::ast::*;
use commitments::commit;
use cs_buffer::ProverBuffer;

use bulletproofs::r1cs::{Verifier, Prover, Variable};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use std::collections::HashMap;
use merlin::Transcript;

// lalrpop parsers
lalrpop_mod!(var_grammar, "/lalrpop/var_grammar.rs");

pub struct Assignments {
    commitments: HashMap<String, Variable>,
    witness_vars: HashMap<String, (Vec<Scalar>, Vec<CompressedRistretto>, Vec<Variable>, Vec<u8>)>,
    derived_witnesses: Vec<Scalar>,
    instance_vars: HashMap<String, Vec<u8>>
}

impl Assignments {
    pub fn new() -> Assignments {
        Assignments {
            commitments: HashMap::new(),
            witness_vars: HashMap::new(),
            derived_witnesses: Vec::new(),
            instance_vars: HashMap::new()
        }
    }

    fn set_instance(&mut self, key: String, val: Vec<u8>) {
        self.instance_vars.insert(key, val);
    }

    fn set_commitment(&mut self, key: String, val: Variable) {
        self.commitments.insert(key, val);
    }

    pub fn get_commitment(&self, var: Var, index: usize) -> Variable {
        match self.inquire_commitment(var, index) {
            Ok(commitment) => commitment,
            Err(message) => panic!("{}", message)
        }
    }

    pub fn get_all_commitments(&self, var: Var) -> Vec<Variable> {
        let mut variables = Vec::new();

        let mut index = 0;
        while {
            let result = self.inquire_commitment(var.clone(), index);
            match result.clone() {
                Ok(witness) => variables.push(witness),
                Err(_) => ()
            }
            index += 1;

            result.is_ok()
        } {}

        variables
    }

    fn inquire_commitment(&self, var: Var, index: usize) -> Result<Variable, String> {
        match var {
            Var::Witness(name) => {
                let key = format!("C{}-{}", &name[1..name.len()], index);
                match self.commitments.get(&key) {
                    Some(commitment) => Ok(*commitment),
                    None => Err(format!("missing commitment {}", &key))
                }
            }
            _ => Err(String::from("provided variable is not of type witness"))
        }
    }

    pub fn inquire_derived(&self, gadget: usize, index: usize, subroutine: usize) -> Option<&Variable> {
        let key = format!("D{}-{}-{}", gadget, subroutine, index);
        self.commitments.get(&key)
    }

    pub fn get_derived(&self, gadget: usize, index: usize, subroutine: usize) -> Variable {
        let key = format!("D{}-{}-{}", gadget, subroutine, index);
        *self.commitments.get(&key).expect(&format!("missing commitment {}", &key))
    }

    pub fn get_instance(&self, var: Var, assertion: Option<&dyn Fn(String, &Vec<u8>)>) -> Vec<u8> {
        match var {
            Var::Instance(name) => {
                let error = &format!("missing instance var {}", &name);
                let assignment = self.instance_vars.get(&name).expect(error).to_vec();
                match assertion {
                    Some(fnc) => fnc(name, &assignment),
                    None => ()
                }
                assignment
            }
            _ => panic!("provided variable is not of type instance")
        }
    }

    pub fn get_witness(
        &self,
        var: Var,
        assertion: Option<&dyn Fn(String, &(Vec<Scalar>, Vec<CompressedRistretto>, Vec<Variable>, Vec<u8>))>
    ) -> (Vec<Scalar>, Vec<CompressedRistretto>, Vec<Variable>, Vec<u8>) {
        match var {
            Var::Witness(name) => {
                let error = &format!("missing witness var {}", &name);
                let assignment = self.witness_vars.get(&name).expect(error);
                match assertion {
                    Some(fnc) => fnc(name, &assignment),
                    None => ()
                }
                assignment.clone()
            }
            _ => panic!("provided variable is not of type witness")
        }
    }

    /// read instance variables from string
    pub fn parse_instance(&mut self, instance: String) -> std::io::Result<()> {
        let instance_parser = var_grammar::InstanceVarParser::new();
        for line in instance.lines() {
            let (name, bytes) = instance_parser.parse(&line).unwrap();
            self.set_instance(name, bytes);
        }
        Ok(())
    }

    /// parse prover commitments from string
    pub fn parse_commitments(&mut self, commitments: String, verifier: &mut Verifier<&mut Transcript>) -> std::io::Result<()> {
        let commitment_parser = var_grammar::CommitmentVarParser::new();
        for line in commitments.lines() {
            let (name, bytes) = commitment_parser.parse(&line).unwrap();
            let com = CompressedRistretto::from_slice(&bytes);
            self.set_commitment(name, verifier.commit(com));
        }
        Ok(())
    }

    /// commit to vars from witness instance to coms instance
    pub fn parse_witness(&mut self, witness: String, prover: &mut Prover<&mut Transcript>, commitments: &mut String) -> std::io::Result<()> {
        let witness_parser = var_grammar::WitnessVarParser::new();
        for line in witness.lines() {
            let (name, bytes) = witness_parser.parse(&line).unwrap();
            let commitment = commit(prover, &bytes);
            self.witness_vars.insert(name.clone(), (commitment.0.clone(), commitment.1.clone(), commitment.2.clone(), bytes));
            for (index, com) in commitment.1.iter().enumerate() {
                commitments.push_str(&format_com("C", &name[1..name.len()], &index, com));
            }
        }
        Ok(())
    }

    /// commit all witnesses previously read into the given constraint system (used to create cs buffers)
    pub fn buffer_commit_wtns(
        &self,
        prover_buffer: &mut ProverBuffer
    ) {
        for (_, (scalars, _, _, _)) in self.witness_vars.clone() {
            prover_buffer.commit(&scalars);
        }
    }

    /// commit the buffer to all previsouly derived witnesses for the variable index to match the real cs
    pub fn buffer_commit_drvd(
        &self,
        prover_buffer: &mut ProverBuffer
    ) {
        for scalar in self.derived_witnesses.clone() {
            prover_buffer.commit(&vec![scalar]);
        }
    }

    pub fn cache_derived_wtns(&mut self, derived_witnesses: Vec<(Option<Scalar>, Variable)>) {
        for (scalar, _) in derived_witnesses {
            self.derived_witnesses.push(scalar.unwrap());
        }
    }

    /// write derived witness commitment to string
    pub fn parse_derived_witness(
        &self,
        coms: Vec<CompressedRistretto>,
        gadget: usize,
        subroutine: usize,
        commitments: &mut String
    ) -> std::io::Result<()> {
        for (index, com) in coms.iter().enumerate() {
            let identifier = format!("{}-{}", gadget.to_string(), subroutine);
            commitments.push_str(&format_com("D", &identifier, &index, com));
        }
        Ok(())
    }
}

fn format_com(
    identifier: &str,
    gadget_no: &str,
    com_idx: &usize,
    com: &CompressedRistretto
) -> String {
    format!("{}{}-{} = 0x{}\n", identifier, gadget_no, com_idx, hex::encode(com.as_bytes()))
}

pub fn assert_32(name: String, assignment: &Vec<u8>) {
    assert!(assignment.len() <= 32, "instance var {} is longer than 32 bytes", &name);
}

pub fn assert_witness_32(
    name: String,
    assignment: &(Vec<Scalar>, Vec<CompressedRistretto>, Vec<Variable>, Vec<u8>)
) {
    assert!(assignment.0.len() == 1, "witness var {} is longer than 32 bytes", &name);
}
