extern crate jni;

use super::*;
use self::jni::JNIEnv;
use self::jni::objects::{JClass, JString};
use self::jni::sys::{jstring};
use std::os::raw::{c_char};
use std::ffi::{CString, CStr};
use c_prover::c_prove;
use verifier::verify;

// fn convert_string(to: *const c_char) -> &str {
//     let c_str = unsafe { CStr::from_ptr(to) }; // convertirlo a Rust string
//     let recipient = match c_str.to_str() {
//         Err(_) => "there",
//         Ok(string) => string,
//     };

//     return recipient;
// }

#[no_mangle]
pub unsafe extern fn Java_com_example_testapplication_RustGreetings_prover(env: JNIEnv, _: JClass, instance: JString, witness: JString, gadget: JString) -> jstring {
    let instance_ptr = env.get_string(instance).expect("invalid pattern string").as_ptr();
    let witness_ptr = env.get_string(witness).expect("invalid pattern string").as_ptr();
    let gadget_ptr = env.get_string(gadget).expect("invalid pattern string").as_ptr();

    let c_instance_str = unsafe { CStr::from_ptr(instance_ptr) }; // convertirlo a Rust string
    let filename_instance = match c_instance_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let c_witness_str = unsafe { CStr::from_ptr(witness_ptr) }; // convertirlo a Rust string
    let filename_witness = match c_witness_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let c_gadget_str = unsafe { CStr::from_ptr(gadget_ptr) }; // convertirlo a Rust string
    let filename_gadget = match c_gadget_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    // Our Java companion code might pass-in "world" as a string, hence the name.
    let proof = c_prove(&filename_instance, &filename_witness, &filename_gadget);
    // Retake pointer so that we can use it below and allow memory to be freed when it goes out of scope.
    let proof_ptr = CString::from_raw(proof);
    let output = env.new_string(proof_ptr.to_str().unwrap()).expect("Couldn't create java string!");

    output.into_inner()
}

#[no_mangle]
pub unsafe extern fn Java_com_example_testapplication_RustGreetings_verifier(env: JNIEnv, _: JClass, java_pattern: JString) -> bool {
    let filename_ptr = env.get_string(java_pattern).expect("invalid pattern string").as_ptr();
    let filename = unsafe { CStr::from_ptr(filename_ptr) }; // convertirlo a Rust string

    match filename.to_str() {
        Err(_) => return false,
        Ok(string) => return verify(string),
    };
}
