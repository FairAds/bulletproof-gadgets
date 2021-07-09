#![allow(non_snake_case)]
#![allow(dead_code)]
extern crate curve25519_dalek;
extern crate bulletproofs;
extern crate hex;

#[macro_use] extern crate bulletproofs_gadgets;
use curve25519_dalek::scalar::Scalar;
use bulletproofs_gadgets::merkle_root_hash::merkle_root::MerkleRoot;
use bulletproofs_gadgets::mimc_hash::mimc::{mimc_hash_sponge};
use bulletproofs_gadgets::conversions::{be_to_scalar, be_to_scalars, hex_to_bytes, scalar_to_hex, scalar_to_bytes, bytes_to_hex_strs};
use bulletproofs_gadgets::merkle_tree::merkle_tree_gadget::{Pattern, Pattern::*};

const HEX_8:  &str = "5065676779";  // "Peggy"
const HEX_9:  &str = "50726f766572736f6e";  // "Proverson"
const HEX_10: &str = "012fcfd4";    // 019910612
const HEX_11: &str = "54696d62756b7475";    // "Timbuktu"
const HEX_12: &str = "01337894";    // 020150420
const HEX_13: &str = "0134ff33";    // 020250419
const HEX_14: &str = "50617373706f7274204f6666696365205a7572696368"; // "Passport Office Zurich"
const HEX_15: &str = "82440e";  // 8537102

// The "original" merkle root hash of the Passport Example
// const MERKLE_ROOT_HASH: &str = "06b131554e4e50b52e096971533411c7623504f6a56edf1bccdc810672efdd22";


fn direct_merkle_tree_pattern_hashing_calcs() {
    //                   1
    //                  / \
    //         2                  3
    //        / \                / \
    //     4        5        6        7
    //    / \      / \      / \      / \
    //   8   9   10   11  12   13  14   15

    let W8: Vec<u8> = hex_to_bytes(HEX_8.into()).unwrap();
    let W9: Vec<u8> = hex_to_bytes(HEX_9.into()).unwrap();
    let W10: Vec<u8> = hex_to_bytes(HEX_10.into()).unwrap();
    let W11: Vec<u8> = hex_to_bytes(HEX_11.into()).unwrap();
    let W12: Vec<u8> = hex_to_bytes(HEX_12.into()).unwrap();
    let W13: Vec<u8> = hex_to_bytes(HEX_13.into()).unwrap();
    let W14: Vec<u8> = hex_to_bytes(HEX_14.into()).unwrap();
    let W15: Vec<u8> = hex_to_bytes(HEX_15.into()).unwrap();
    println!("W8: {:?}", W8);
    println!("W9: {:?}", W9);
    println!("W10: {:?}", W10);
    println!("W11: {:?}", W11);
    println!("W12: {:?}", W12);
    println!("W13: {:?}", W13);
    println!("W14: {:?}", W14);
    println!("W15: {:?}", W15);

    //HARD CODED HASH PATTERN FOR MERKLE ROOT...
    let preimage_W8: Vec<Scalar> = be_to_scalars(&W8.to_vec());
    let preimage_W9: Vec<Scalar> = be_to_scalars(&W9.to_vec());
    let preimage_W10: Vec<Scalar> = be_to_scalars(&W10.to_vec());
    let preimage_W11: Vec<Scalar> = be_to_scalars(&W11.to_vec());
    let preimage_W12: Vec<Scalar> = be_to_scalars(&W12.to_vec());
    let preimage_W13: Vec<Scalar> = be_to_scalars(&W13.to_vec());
    let preimage_W14: Vec<Scalar> = be_to_scalars(&W14.to_vec());
    let preimage_W15: Vec<Scalar> = be_to_scalars(&W15.to_vec());

    let hash_W8: Scalar = mimc_hash_sponge(&preimage_W8);
    let hash_W9: Scalar = mimc_hash_sponge(&preimage_W9);
    let hash_W10: Scalar = mimc_hash_sponge(&preimage_W10);
    let hash_W11: Scalar = mimc_hash_sponge(&preimage_W11);
    let hash_W12: Scalar = mimc_hash_sponge(&preimage_W12);
    let hash_W13: Scalar = mimc_hash_sponge(&preimage_W13);
    let hash_W14: Scalar = mimc_hash_sponge(&preimage_W14);
    let hash_W15: Scalar = mimc_hash_sponge(&preimage_W15);

    println!("W8_hex: 0x{}", scalar_to_hex(&hash_W8));
    println!("W9_hex: 0x{}", scalar_to_hex(&hash_W9));
    println!("W10_hex: 0x{}", scalar_to_hex(&hash_W10));
    println!("W11_hex: 0x{}", scalar_to_hex(&hash_W11));
    println!("W12_hex: 0x{}", scalar_to_hex(&hash_W12));
    println!("W13_hex: 0x{}", scalar_to_hex(&hash_W13));
    println!("W14_hex: 0x{}", scalar_to_hex(&hash_W14));
    println!("W15_hex: 0x{}", scalar_to_hex(&hash_W15));

    let W4: Vec<Scalar> = vec![ be_to_scalar(&W8.to_vec()),  be_to_scalar(&W9.to_vec())];
    let W5: Vec<Scalar> = vec![ be_to_scalar(&W10.to_vec()),  be_to_scalar(&W11.to_vec())];
    let W6: Vec<Scalar> = vec![ be_to_scalar(&W12.to_vec()),  be_to_scalar(&W13.to_vec())];
    let W7: Vec<Scalar> = vec![ be_to_scalar(&W14.to_vec()),  be_to_scalar(&W15.to_vec())];

    let hash_W4 = mimc_hash_sponge(&W4);
    let hash_W5 = mimc_hash_sponge(&W5);
    let hash_W6 = mimc_hash_sponge(&W6);
    let hash_W7 = mimc_hash_sponge(&W7);

    let W2: Vec<Scalar> = vec![hash_W4, hash_W5];
    let W3: Vec<Scalar> = vec![hash_W6, hash_W7];

    let hash_W2 = mimc_hash_sponge(&W2);
    let hash_W3 = mimc_hash_sponge(&W3);

    let W1: Vec<Scalar> = vec![hash_W2, hash_W3];

    let hash_W1 = mimc_hash_sponge(&W1);


    let W4_bytes_array: Vec<u8> = scalar_to_bytes(&hash_W4);
    println!("W4_bytes = {:?}", W4_bytes_array);
    println!("W4_hex = 0x{}", scalar_to_hex(&hash_W4));
    let W4_formatted_hex_array: Vec<String> = bytes_to_hex_strs(&W4_bytes_array).iter().map(|b| format!("0x{}", b)).collect();
    println!("W4 = {:?}", W4_formatted_hex_array);

    let W5_bytes_array: Vec<u8> = scalar_to_bytes(&hash_W5);
    println!("W5_bytes = {:?}", W5_bytes_array);
    println!("W5_hex = 0x{}", scalar_to_hex(&hash_W5));
    let W5_formatted_hex_array: Vec<String> = bytes_to_hex_strs(&W5_bytes_array).iter().map(|b| format!("0x{}", b)).collect();
    println!("W5 = {:?}", W5_formatted_hex_array);

    let W6_bytes_array: Vec<u8> = scalar_to_bytes(&hash_W6);
    println!("W6_bytes = {:?}", W6_bytes_array);
    println!("W6_hex = 0x{}", scalar_to_hex(&hash_W6));
    let W6_formatted_hex_array: Vec<String> = bytes_to_hex_strs(&W6_bytes_array).iter().map(|b| format!("0x{}", b)).collect();
    println!("W6 = {:?}", W6_formatted_hex_array);

    let W7_bytes_array: Vec<u8> = scalar_to_bytes(&hash_W7);
    println!("W7_bytes = {:?}", W7_bytes_array);
    println!("W7_hex = 0x{}", scalar_to_hex(&hash_W7));
    let W7_formatted_hex_array: Vec<String> = bytes_to_hex_strs(&W7_bytes_array).iter().map(|b| format!("0x{}", b)).collect();
    println!("W7 = {:?}", W7_formatted_hex_array);

    let W2_bytes_array: Vec<u8> = scalar_to_bytes(&hash_W2);
    println!("W2_bytes = {:?}", W2_bytes_array);
    println!("W2_hex = 0x{}", scalar_to_hex(&hash_W2));
    let W2_formatted_hex_array: Vec<String> = bytes_to_hex_strs(&W2_bytes_array).iter().map(|b| format!("0x{}", b)).collect();
    println!("W2 = {:?}", W2_formatted_hex_array);

    let W3_bytes_array: Vec<u8> = scalar_to_bytes(&hash_W3);
    println!("W3_bytes = {:?}", W3_bytes_array);
    println!("W3_hex = 0x{}", scalar_to_hex(&hash_W3));
    let W3_formatted_hex_array: Vec<String> = bytes_to_hex_strs(&W3_bytes_array).iter().map(|b| format!("0x{}", b)).collect();
    println!("W3 = {:?}", W3_formatted_hex_array);

    let W1_bytes_array: Vec<u8> = scalar_to_bytes(&hash_W1);
    println!("W1_bytes = {:?}", W1_bytes_array);
    println!("W1_hex = 0x{}", scalar_to_hex(&hash_W1));
    let W1_formatted_hex_array: Vec<String> = bytes_to_hex_strs(&W1_bytes_array).iter().map(|b| format!("0x{}", b)).collect();
    println!("W1 = {:?}", W1_formatted_hex_array);

}

fn merkle_root_calculation_for_combine_gadgets_test(){
     let image: Vec<u8> = vec![
        0x0c, 0xfb, 0x0c, 0x17, 0x61, 0x82, 0x11, 0xc6,
        0x07, 0xfe, 0xbf, 0x70, 0x3a, 0xc3, 0xf3, 0x07,
        0x8f, 0x7d, 0x96, 0x79, 0x8f, 0xae, 0x9d, 0x4a,
        0x16, 0x82, 0xbc, 0x59, 0x2f, 0x7c, 0xb1, 0x26
    ]; // W2
     let root: Scalar = be_to_scalar(&vec![
        0x0c, 0x8c, 0x87, 0xb6, 0x48, 0xe8, 0xfa, 0x0d,
        0x97, 0x26, 0xee, 0x82, 0x25, 0xbe, 0x06, 0x28,
        0x79, 0x4f, 0x2e, 0x1d, 0x1a, 0xb9, 0x32, 0x42,
        0x1d, 0x45, 0x85, 0x1a, 0x35, 0xd8, 0x1a, 0xc1
    ]); // I1
    let merkle_leaf: Vec<u8> = vec![
        0x09, 0x24, 0x33, 0x33, 0xe3, 0x74, 0xe7, 0x6e,
        0x49, 0x75, 0xab, 0x48, 0xae, 0x38, 0x24, 0x1b,
        0xa6, 0x78, 0x05, 0xcd, 0x60, 0xf1, 0x52, 0x3e,
        0x9b, 0x79, 0xa4, 0x8d, 0xaa, 0xc9, 0xa8, 0x4d
    ]; // I2
    let w_vars: Vec<Scalar> = vec![
        mimc_hash_sponge(&vec![be_to_scalar(&image)]),
    ];
    let i_vars: Vec<Scalar> = vec![
        mimc_hash_sponge(&vec![be_to_scalar(&merkle_leaf)]),
    ];
    println!("W2: 0x{}", bytes_to_hex_strs(&image).join(""));
    println!("I2: 0x{}", bytes_to_hex_strs(&merkle_leaf).join(""));
    let pattern: Pattern = hash!(W, I);

    let mut root_calculator = MerkleRoot::new();
    root_calculator.calculate_merkle_root(&w_vars, &i_vars, pattern.clone());
    let root2 = root_calculator.get_merkle_root_scalar();
    println!("ROOT: 0x{}", scalar_to_hex(&root));
    println!("ROOT2: 0x{}", scalar_to_hex(&root2));
    let bytes = bytes_to_hex_strs(&scalar_to_bytes(&root2));
    let hex_bytes: Vec<String> = bytes.iter().map(|x| format!("0x{}",x)).collect();
    println!("ROOT2 bytes: {:?}", hex_bytes);

}
fn merkle_root_calculation_passport_example() {

    //                   1
    //                  / \
    //         2                  3
    //        / \                / \
    //     4        5        6        7
    //    / \      / \      / \      / \
    //   8   9   10   11  12   13  14   15

    let W8: Vec<u8> = hex_to_bytes(String::from(HEX_8)).unwrap();
    let W9: Vec<u8> = hex_to_bytes(String::from(HEX_9)).unwrap();
    let W10: Vec<u8> = hex_to_bytes(String::from(HEX_10)).unwrap();
    let W11: Vec<u8> = hex_to_bytes(String::from(HEX_11)).unwrap();
    let W12: Vec<u8> = hex_to_bytes(String::from(HEX_12)).unwrap();
    let W13: Vec<u8> = hex_to_bytes(String::from(HEX_13)).unwrap();
    let W14: Vec<u8> = hex_to_bytes(String::from(HEX_14)).unwrap();
    let W15: Vec<u8> = hex_to_bytes(String::from(HEX_15)).unwrap();

    let pattern: Pattern = hash!(hash!(hash!(W, W), hash!(W, W)), hash!(hash!(W, W), hash!(W, W)));

    let w_vars: Vec<Scalar> = vec![
        be_to_scalar(&W8),
        be_to_scalar(&W9),
        be_to_scalar(&W10),
        be_to_scalar(&W11),
        be_to_scalar(&W12),
        be_to_scalar(&W13),
        be_to_scalar(&W14),
        be_to_scalar(&W15),
    ];


    let mut root_calculator = MerkleRoot::new();
    root_calculator.calculate_merkle_root(&w_vars, &Vec::new(), pattern);
    println!("Merkle Root hash: {}", root_calculator.get_merkle_root_hash());
}
fn main() -> std::io::Result<()> {
    //direct_merkle_tree_pattern_hashing_calcs();
    //merkle_root_calculation_for_combine_gadgets_test();
    merkle_root_calculation_passport_example();
    Ok(())
}

