# New MerkleRootHash Bulletproof Gadget:
Syntax is the same used for the MerkleTree256 gadget (`MERKLE I0 (W0 W1)`), but the gadget token is renamed as ROOT.
Then, a valid `.gadgets` file instruction for this new gadget should have lines in the form:
```
ROOT I0 (W0 W1)
```
This will prove/verify that the instance variable `I0` is the Merkle Root of the tree with `W0` and `W1` as its leaves.

### Run MerkleRootHash tests:
```
cargo test merkle_root_hash -- --color always --nocapture
```

### Run prover & verifier example:

```
cargo run --bin prover custom_examples/test_root
```
```
cargo run --bin verifier custom_examples/test_root
```

# "Non-bulletproof" MiMC Hash Merkle Root implementation:

In the `merkle_root_hash/merkle_root.rs` module, a new `MerkleRoot` struct is defined
for calculating the Merkle Root of a given tree outside the scope of a constrain system,
making the resulting Merkle Root available for a posterior proof/validation process. 

## MiMC Hash for Merkle Root:

The **MiMC Hash** function used by the Merkle Root implementation is defined in the `mimc_hash/mimc.rs` module.

Using the passport example introduced in [Marc Kloter's ZkStrata repository](https://github.com/MarcKloter/zkStrata/tree/master/examples/passport), we can reuse the hex literals from the passport's values 
to verify the hash output.

## Run MiMC Hash conversion for passport example:

The bin script `mimc_hash.rs` performs the following steps: 
1. Conversions from the string and integer values to the respective Hex Literals.
2. Conversion of Hex Literals to byte arrays.
3. Conversion of Byte arrays to Scalars from `curve25519_dalek`'s implementation.
4. MiMC Hashing of the values resulting also in Curve25519 Scalars.
5. Conversion from Scalar MiMC Hash to a Hex Literal.

To run this example, use the following command:
```
cargo run --bin mimc_hash
```

### Run prover & verifier MiMC HASH gadget for passport example:
Using the output of the `mimc_hash` script a MiMC Hash Gadget validation can be done
for each value using the `custom example/test_hash.*`, where the following can be found:

1. The Hex Literal values of each of the passport fields in the `.wtns` file.
2. The Hex Literal values of the expected resulting MiMC Hash of each passport fields in the `.inst` file.
3. The `HASH` predicates for each value with the MiMC Hash Gadget in the `.gadgets` file. 

The prove/verify steps can be run with the following commands:
```
cargo run --bin prover custom_examples/test_hash
```
```
cargo run --bin verifier custom_examples/test_hash
```

### (WIP) Merkle Root Hash calculations for passport example:
A script `merkle_root` using the "Non-bulletproof" MiMC Hash Merkle Root implementation for the 
passport example values can be run with the following command:

```
cargo run --bin merkle_root
```
