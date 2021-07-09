#![feature(box_syntax, box_patterns)]
#![allow(unused_parens)]
#![allow(non_snake_case)]
#![allow(non_fmt_panics)]

//------------------------------------------------------------------------
// External dependencies
//------------------------------------------------------------------------
extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate pkcs7;
extern crate rand;
extern crate hex;
extern crate regex;
#[macro_use]
extern crate lalrpop_util;

//------------------------------------------------------------------------
// Modules containing macros
//------------------------------------------------------------------------
#[macro_use]
mod macros;
#[macro_use]
pub mod merkle_tree;
pub mod merkle_root_hash;
//------------------------------------------------------------------------
// Public modules
//------------------------------------------------------------------------
pub mod commitments;
pub mod bounds_check;
pub mod mimc_hash;
pub mod equality;
pub mod inequality;
pub mod less_than;
pub mod set_membership;
pub mod or;
pub mod gadget;
pub mod conversions;
pub mod cs_buffer;
pub mod utils;
pub mod lalrpop;

//------------------------------------------------------------------------
// Private modules
//------------------------------------------------------------------------
