extern crate curve25519_dalek;
extern crate bulletproofs;
extern crate hex;

#[macro_use] extern crate bulletproofs_gadgets;
use curve25519_dalek::scalar::Scalar;
use bulletproofs_gadgets::mimc_hash::mimc::{mimc_hash, mimc_hash_sponge};
use bulletproofs_gadgets::conversions::{be_to_scalar, be_to_scalars, scalar_to_be, be_to_u64, str_hex_encode, num_hex_encode, hex_to_bytes, scalar_to_hex, scalar_to_bytes, bytes_to_hex_strs};

const HEX_8: &str = "5065676779";  // "Peggy"
const HEX_9: &str = "50726f766572736f6e";  // "Proverson"
const HEX_10: &str = "012fcfd4";    // 019910612
const HEX_11: &str = "54696d62756b7475";    // "Timbuktu"
const HEX_12: &str = "01337894";    // 020150420
const HEX_13: &str = "0134ff33";    // 020250419
const HEX_14: &str = "50617373706f7274204f6666696365205a7572696368"; // "Passport Office Zurich"
const HEX_15: &str = "82440e";  // 8537102

const first_name: &str = "Peggy";
const last_name: &str = "Proverson";
const date_of_birth: u64 = 19910612;
const place_of_origin: &str = "Timbuktu";
const date_of_issue: u64 = 20150420;
const date_of_expiry: u64 = 20250419;
const authority: &str = "Passport Office Zurich";
const identifier: u64 = 8537102;

fn mimc_hash_calculations() {

    let first_name_hex = str_hex_encode(first_name.into());
    let last_name_hex = str_hex_encode(last_name.into());
    let date_of_birth_hex = num_hex_encode(date_of_birth);
    let place_of_origin_hex = str_hex_encode(place_of_origin.into());
    let date_of_issue_hex = num_hex_encode(date_of_issue);
    let date_of_expiry_hex = num_hex_encode(date_of_expiry);
    let authority_hex = str_hex_encode(authority.into());
    let identifier_hex = num_hex_encode(identifier);

    println!("\nHexLiterals:\n");
    println!("  first_name: {:?}", first_name_hex);
    println!("  last_name: {:?}", last_name_hex);
    println!("  date_of_birth: {:?}", date_of_birth_hex);
    println!("  place_of_origin: {:?}", place_of_origin_hex);
    println!("  date_of_issue: {:?}", date_of_issue_hex);
    println!("  date_of_expiry: {:?}", date_of_expiry_hex);
    println!("  authority: {:?}", authority_hex);
    println!("  identifier: {:?}", identifier_hex);
    println!("\n----------------------------\n");

    // 1. Convert Hex Literal to Bytes array
    let mut first_name_bytes: Vec<u8> = hex_to_bytes(first_name_hex).unwrap();
    let mut last_name_bytes: Vec<u8> = hex_to_bytes(last_name_hex).unwrap();
    let mut date_of_birth_bytes: Vec<u8> = hex_to_bytes(date_of_birth_hex).unwrap();
    let mut place_of_origin_bytes: Vec<u8> = hex_to_bytes(place_of_origin_hex).unwrap();
    let mut date_of_issue_bytes: Vec<u8> = hex_to_bytes(date_of_issue_hex).unwrap();
    let mut date_of_expiry_bytes: Vec<u8> = hex_to_bytes(date_of_expiry_hex).unwrap();
    let mut authority_bytes: Vec<u8> = hex_to_bytes(authority_hex).unwrap();
    let mut identifier_bytes: Vec<u8> = hex_to_bytes(identifier_hex).unwrap();

    println!("Bytes:\n");
    println!("  first_name: {:?}", first_name_bytes);
    println!("  last_name: {:?}", last_name_bytes);
    println!("  date_of_birth: {:?}", date_of_birth_bytes);
    println!("  place_of_origin: {:?}", place_of_origin_bytes);
    println!("  date_of_issue: {:?}", date_of_issue_bytes);
    println!("  date_of_expiry: {:?}", date_of_expiry_bytes);
    println!("  authority: {:?}", authority_bytes);
    println!("  identifier: {:?}", identifier_bytes);
    println!("\n----------------------------\n");
    // Convert to Scalars

    let first_name_preimage: Vec<Scalar> = be_to_scalars(&first_name_bytes);
    let last_name_preimage: Vec<Scalar> = be_to_scalars(&last_name_bytes);
    let date_of_birth_preimage: Vec<Scalar> = be_to_scalars(&date_of_birth_bytes);
    let place_of_origin_preimage: Vec<Scalar> = be_to_scalars(&place_of_origin_bytes);
    let date_of_issue_preimage: Vec<Scalar> = be_to_scalars(&date_of_issue_bytes);
    let date_of_expiry_preimage: Vec<Scalar> = be_to_scalars(&date_of_expiry_bytes);
    let authority_preimage: Vec<Scalar> = be_to_scalars(&authority_bytes);
    let identifier_preimage: Vec<Scalar> = be_to_scalars(&identifier_bytes);

    println!("Scalars (Preimages):\n");
    println!("  first_name: {:?}", first_name_preimage);
    println!("  last_name: {:?}", last_name_preimage);
    println!("  date_of_birth: {:?}", date_of_birth_preimage);
    println!("  place_of_origin: {:?}", place_of_origin_preimage);
    println!("  date_of_issue: {:?}", date_of_issue_preimage);
    println!("  date_of_expiry: {:?}", date_of_expiry_preimage);
    println!("  authority: {:?}", authority_preimage);
    println!("  identifier: {:?}", identifier_preimage);
    println!("\n----------------------------\n");

    let first_name_image: Scalar = mimc_hash_sponge(&first_name_preimage);
    let last_name_image: Scalar = mimc_hash_sponge(&last_name_preimage);
    let date_of_birth_image: Scalar = mimc_hash_sponge(&date_of_birth_preimage);
    let place_of_origin_image: Scalar = mimc_hash_sponge(&place_of_origin_preimage);
    let date_of_issue_image: Scalar = mimc_hash_sponge(&date_of_issue_preimage);
    let date_of_expiry_image: Scalar = mimc_hash_sponge(&date_of_expiry_preimage);
    let authority_image: Scalar = mimc_hash_sponge(&authority_preimage);
    let identifier_image: Scalar = mimc_hash_sponge(&identifier_preimage);

    println!("MiMC Hashed Scalars (Images)\n");
    println!("  first_name: {:?}", first_name_image);
    println!("  last_name: {:?}", last_name_image);
    println!("  date_of_birth: {:?}", date_of_birth_image);
    println!("  place_of_origin: {:?}", place_of_origin_image);
    println!("  date_of_issue: {:?}", date_of_issue_image);
    println!("  date_of_expiry: {:?}", date_of_expiry_image);
    println!("  authority: {:?}", authority_image);
    println!("  identifier: {:?}", identifier_image);
    println!("\n----------------------------\n");

    println!("MiMC Hash (HexLiterals):\n");
    println!("  first_name ('{}'): 0x{}",first_name, scalar_to_hex(&first_name_image));
    println!("  last_name ('{}'): 0x{}",last_name, scalar_to_hex(&last_name_image));
    println!("  date_of_birth ({}): 0x{}",date_of_birth, scalar_to_hex(&date_of_birth_image));
    println!("  place_of_origin ('{}'): 0x{}",place_of_origin, scalar_to_hex(&place_of_origin_image));
    println!("  date_of_issue ({}): 0x{}",date_of_issue, scalar_to_hex(&date_of_issue_image));
    println!("  date_of_expiry ({}): 0x{}",date_of_expiry, scalar_to_hex(&date_of_expiry_image));
    println!("  authority ('{}'): 0x{}",authority, scalar_to_hex(&authority_image));
    println!("  identifier ({}): 0x{}",identifier, scalar_to_hex(&identifier_image));
    println!("\n----------------------------\n");
}

fn main() -> std::io::Result<()> {
    mimc_hash_calculations();
    Ok(())
}

