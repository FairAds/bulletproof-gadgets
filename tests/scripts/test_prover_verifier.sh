#!/bin/bash
cargo run --release --bin prover tests/resources/$1
cargo run --release --bin verifier tests/resources/$1