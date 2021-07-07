extern crate curve25519_dalek;
extern crate bulletproofs;
extern crate hex;

#[macro_use] extern crate bulletproofs_gadgets;
use curve25519_dalek::scalar::Scalar;
use bulletproofs_gadgets::merkle_root_hash::merkle_root::MerkleRoot;
use bulletproofs_gadgets::mimc_hash::mimc::mimc_hash_sponge;
use bulletproofs_gadgets::conversions::{be_to_scalar, be_to_scalars, scalar_to_be, be_to_u64, str_hex_encode, num_hex_encode, hex_to_bytes, scalar_to_hex, scalar_to_bytes, bytes_to_hex_strs};
use bulletproofs_gadgets::merkle_tree::merkle_tree_gadget::{Pattern, Pattern::*};

// MERKLE I1 (((W0 W1) (W2 W3)) ((W4 W5) (W6 W7)))

/* These values come from zkStrata java conversion form .json values to Hex Literals.
W0 = 0x5065676779;  // (firstName: "Peggy") -> String.toHex()
W1 = 0x50726f766572736f6e;  // (lastName: "Proverson") -> String.toHex()
W2 = 0x012fcfd4;    // (dateOfBirth: 19910612)  -> pad 0 left + String.format("%x", int)
W3 = 0x54696d62756b7475;    // (placeOfOrigin: "Timbuktu") -> String.toHex()
W4 = 0x01337894;    // (dateOfIssue: 20150420) -> pad 0 left + String.format("%x", int)
W5 = 0x0134ff33;    // (dateOfExpiry: 20250419) -> pad 0 left + String.format("%x", int)
W6 = 0x50617373706f7274204f6666696365205a7572696368;    // (authority: "Passport Office Zurich") -> String.toHex()
W7 = 0x82440e;  // (identifier: 8537102) -> String.format("%x", int)
*/

const HEX_8: &str = "5065676779";  // "Peggy"
const HEX_9: &str = "50726f766572736f6e";  // "Proverson"
const HEX_10: &str = "012fcfd4";    // 019910612
const HEX_11: &str = "54696d62756b7475";    // "Timbuktu"
const HEX_12: &str = "01337894";    // 020150420
const HEX_13: &str = "0134ff33";    // 020250419
const HEX_14: &str = "50617373706f7274204f6666696365205a7572696368"; // "Passport Office Zurich"
const HEX_15: &str = "82440e";  // 8537102


fn hard_coded_passport_hash_calcs() {
    let first_name: String = String::from("Peggy");
    let last_name: String = String::from("Proverson");
    let date_of_birth = 19910612;
    let place_of_origin: String = String::from("Timbuktu");
    let date_of_issue = 20150420;
    let date_of_expiry = 20250419;
    let authority = String::from("Passport Office Zurich");
    let identifier = 8537102;
    // The "GOAL" root hash...
    let root_hash_hex: String = String::from("06b131554e4e50b52e096971533411c7623504f6a56edf1bccdc810672efdd22");

    /*
    *    Conversion from values (int/string) to hex -> bytes -> Scalars
    */

    let hex_first_name = str_hex_encode(first_name);
    let hex_last_name = str_hex_encode(last_name);
    let hex_date_of_birth = num_hex_encode(date_of_birth);
    let hex_place_of_origin = str_hex_encode(place_of_origin);
    let hex_date_of_issue = num_hex_encode(date_of_issue);
    let hex_date_of_expiry = num_hex_encode(date_of_expiry);
    let hex_authority = str_hex_encode(authority);
    let hex_identifier = num_hex_encode(identifier);

    assert_eq!(hex_date_of_birth, "012fcfd4");
        //                   1
        //                  / \
        //         2                  3
        //        / \                / \
        //     4        5        6        7
        //    / \      / \      / \      / \
        //   8   9   10   11  12   13  14   15

    let mut W8: Vec<u8> = hex_to_bytes(hex_first_name).unwrap();
    let mut W9: Vec<u8> = hex_to_bytes(hex_last_name).unwrap();
    let mut W10: Vec<u8> = hex_to_bytes(hex_date_of_birth).unwrap();
    let mut W11: Vec<u8> = hex_to_bytes(hex_place_of_origin).unwrap();
    let mut W12: Vec<u8> = hex_to_bytes(hex_date_of_issue).unwrap();
    let mut W13: Vec<u8> = hex_to_bytes(hex_date_of_expiry).unwrap();
    let mut W14: Vec<u8> = hex_to_bytes(hex_authority).unwrap();
    let mut W15: Vec<u8> = hex_to_bytes(hex_identifier).unwrap();
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

    let mut W4: Vec<Scalar> = vec![ be_to_scalar(&W8.to_vec()),  be_to_scalar(&W9.to_vec())];
    let mut W5: Vec<Scalar> = vec![ be_to_scalar(&W10.to_vec()),  be_to_scalar(&W11.to_vec())];
    let mut W6: Vec<Scalar> = vec![ be_to_scalar(&W12.to_vec()),  be_to_scalar(&W13.to_vec())];
    let mut W7: Vec<Scalar> = vec![ be_to_scalar(&W14.to_vec()),  be_to_scalar(&W15.to_vec())];

    let hash_W4 = mimc_hash_sponge(&W4);
    let hash_W5 = mimc_hash_sponge(&W5);
    let hash_W6 = mimc_hash_sponge(&W6);
    let hash_W7 = mimc_hash_sponge(&W7);

    let mut W2: Vec<Scalar> = vec![hash_W4, hash_W5];
    let mut W3: Vec<Scalar> = vec![hash_W6, hash_W7];

    let hash_W2 = mimc_hash_sponge(&W2);
    let hash_W3 = mimc_hash_sponge(&W3);

    let mut W1: Vec<Scalar> = vec![hash_W2, hash_W3];

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


fn merkle_root_calculation() {

    //                   1
    //                  / \
    //         2                  3
    //        / \                / \
    //     4        5        6        7
    //    / \      / \      / \      / \
    //   8   9   10   11  12   13  14   15

    let mut W8: Vec<u8> = hex_to_bytes(String::from(HEX_8)).unwrap();
    let mut W9: Vec<u8> = hex_to_bytes(String::from(HEX_9)).unwrap();
    let mut W10: Vec<u8> = hex_to_bytes(String::from(HEX_10)).unwrap();
    let mut W11: Vec<u8> = hex_to_bytes(String::from(HEX_11)).unwrap();
    let mut W12: Vec<u8> = hex_to_bytes(String::from(HEX_12)).unwrap();
    let mut W13: Vec<u8> = hex_to_bytes(String::from(HEX_13)).unwrap();
    let mut W14: Vec<u8> = hex_to_bytes(String::from(HEX_14)).unwrap();
    let mut W15: Vec<u8> = hex_to_bytes(String::from(HEX_15)).unwrap();

    let pattern: Pattern = hash!(hash!(hash!(W, W), hash!(W, W)), hash!(hash!(W, W), hash!(W, W)));

    let w_vars: Vec<Scalar> = vec![
        be_to_scalar(&W8.to_vec()),
        be_to_scalar(&W9.to_vec()),
        be_to_scalar(&W10.to_vec()),
        be_to_scalar(&W11.to_vec()),
        be_to_scalar(&W12.to_vec()),
        be_to_scalar(&W13.to_vec()),
        be_to_scalar(&W14.to_vec()),
        be_to_scalar(&W15.to_vec()),
    ];


    let mut root_calculator = MerkleRoot::new();
    root_calculator.calculate_merkle_root(w_vars, Vec::new(), pattern);
    println!("{}", root_calculator.get_merkle_root_hash());
}
fn main() -> std::io::Result<()> {
    //hard_coded_passport_hash_calcs();
    merkle_root_calculation();
    Ok(())
}

