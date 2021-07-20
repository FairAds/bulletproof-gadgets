FROM rust:1.47-slim

RUN rustup install nightly-2020-09-20 && rustup set profile minimal && rustup default nightly-2020-09-20

RUN mkdir -p /bulletproof-gadgets

WORKDIR /bulletproof-gadgets

COPY build.rs ./build.rs
COPY Cargo.toml ./Cargo.toml
COPY src ./src
COPY tests ./tests

RUN cargo build --bins --release && chmod +x ./tests/scripts/test_prover_verifier.sh