extern crate jni;

use super::*;
use self::jni::JNIEnv;
use self::jni::objects::{JClass, JString};
use self::jni::sys::{jstring};
use std::os::raw::{c_char};
use std::ffi::{CString, CStr};
use prover::prove;
use verifier::verify;

#[no_mangle]
pub unsafe extern fn Java_com_example_testapplication_RustGreetings_prover(env: JNIEnv, _: JClass, java_pattern: JString) -> bool {
    let filename_ptr = env.get_string(java_pattern).expect("invalid pattern string").as_ptr();
    let filename = unsafe { CStr::from_ptr(filename_ptr) }; // convertirlo a Rust string

    match filename.to_str() {
        Err(_) => return false,
        Ok(string) => return prove(string),
    };
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
