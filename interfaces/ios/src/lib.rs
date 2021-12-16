use std::boxed::Box;
use std::ffi::{CString, CStr};
use std::mem::forget;
use std::slice;
use std::os::raw::{c_char};

use bulletproofs_gadgets::prove::prove;
use bulletproofs_gadgets::verify::verify;

#[repr(C)]
pub struct ProofArtifacts {
    commitments: *const c_char,
    proof: *const u8,
    // CString magically converts strings to deallocate them, but byte vectors don't have access to that magic
    // We need to pass forth and back the constituent elements of a byte vector in order to free it after it's used
    proof_len: usize,
    proof_cap: usize,
}

#[no_mangle]
pub extern fn c_prove(name: *const c_char, instance: *const c_char, witness: *const c_char, gadgets: *const c_char) -> *mut ProofArtifacts {
    let name_str: &str = (unsafe {CStr::from_ptr(name)}).to_str().expect("Error during UTF-8 parse of iOS instance name");
    let instance_str: String = (unsafe {CStr::from_ptr(instance)}).to_string_lossy().into_owned();
    let witness_str: String = (unsafe {CStr::from_ptr(witness)}).to_string_lossy().into_owned();
    let gadgets_str: String = (unsafe {CStr::from_ptr(gadgets)}).to_string_lossy().into_owned();
    let mut commitments = String::new();
    let proof: Vec<u8> = prove(name_str, instance_str, witness_str, gadgets_str, &mut commitments).expect("unable to generate proof from provided iOS data");

    let commitments_c = CString::new(commitments).expect("could not convert coms to a C string");
    let commitments_pointer = commitments_c.as_ptr();
    let proof_pointer = proof.as_ptr();
    let proof_len = proof.len();
    let proof_cap = proof.capacity();
    forget(commitments_c); forget(proof);

    Box::into_raw(Box::new(ProofArtifacts {
        commitments: commitments_pointer,
        proof: proof_pointer,
        proof_len: proof_len,
        proof_cap: proof_cap,
    }))
}

#[no_mangle]
pub extern fn c_verify(name: *const c_char, instance: *const c_char, gadgets: *const c_char, commitments: *const c_char, proof: *const u8, proof_len: usize) -> bool {
    let name_str: &str = (unsafe {CStr::from_ptr(name)}).to_str().expect("Error during UTF-8 parse of iOS instance name");
    let instance_str: String = (unsafe {CStr::from_ptr(instance)}).to_string_lossy().into_owned();
    let gadgets_str: String = (unsafe {CStr::from_ptr(gadgets)}).to_string_lossy().into_owned();
    let commitments_str: String = (unsafe {CStr::from_ptr(commitments)}).to_string_lossy().into_owned();
    let proof_vec: Vec<u8> = (unsafe {slice::from_raw_parts(proof as *mut u8, proof_len)}).to_vec();
    verify(name_str, instance_str, proof_vec, commitments_str, gadgets_str).unwrap()
}

#[no_mangle]
pub extern fn free_proof(artifacts_pointer: *mut ProofArtifacts) {
    if artifacts_pointer.is_null() {
        return;
    }
    unsafe {
        let artifacts_boxed = Box::from_raw(artifacts_pointer);
        let artifacts = *artifacts_boxed;
        let ProofArtifacts {commitments: commitments_pointer, proof: proof_pointer, proof_len, proof_cap} = artifacts;
        CString::from_raw(commitments_pointer as *mut c_char);
        Vec::from_raw_parts(proof_pointer as *mut u8, proof_len, proof_cap);
    }
}
