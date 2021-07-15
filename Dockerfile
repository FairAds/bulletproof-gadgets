FROM rust:1.53.0

RUN rustup install nightly-2020-08-20 && rustup default nightly-2020-08-20

RUN mkdir -p /bulletproof-gadgets

WORKDIR /bulletproof-gadgets

COPY build.rs ./build.rs
COPY Cargo.toml ./Cargo.toml
COPY src ./src
COPY tests ./tests

RUN cargo build --release && chmod +x ./tests/scripts/test_prover_verifier.sh