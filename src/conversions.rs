use crate::curve25519_dalek::scalar::Scalar;
use bulletproofs::r1cs::{Variable, LinearCombination};
use std::convert::TryInto;
use std::str;

/// Constructs 32 byte Scalars from the given byte vector in little endian order
pub fn le_to_scalars(bytes: &Vec<u8>) -> Vec<Scalar> {
    let mut bytes = bytes.clone();
    if bytes.len() % 32 != 0 {
        zero_padding!(bytes, 32 - (bytes.len() % 32));
    }
    
    let mut scalars: Vec<Scalar> = Vec::new();

    for i in (0..bytes.len()).step_by(32) {
        // extract current u8 32 bytes block
        let _block: [u8; 32] = bytes[i..(i+32)].try_into().unwrap();

        let scalar: Scalar = Scalar::from_bits(_block);
        scalars.push(scalar);
    }

    scalars
}

/// Constructs 32 byte Scalars from the given byte vector in big endian order
pub fn be_to_scalars(bytes: &Vec<u8>) -> Vec<Scalar> {
    let mut bytes = bytes.clone();
    bytes.reverse();
    le_to_scalars(&bytes)
}

/// Constructs a 32 byte Scalar from the given byte vector in little endian order
pub fn le_to_scalar(bytes: &Vec<u8>) -> Scalar {
    assert!(bytes.len() <= 32, "the given vector is longer than 32 bytes");

    let mut bytes: Vec<u8> = bytes.clone();
    if bytes.len() % 32 != 0 {
        zero_padding!(bytes, 32 - (bytes.len() % 32));
    }

    let _block: [u8; 32] = bytes[0..32].try_into().unwrap();

    let scalar: Scalar = Scalar::from_bits(_block);

    scalar
}

/// Constructs a 32 byte Scalar from the given byte vector in big endian order
pub fn be_to_scalar(bytes: &Vec<u8>) -> Scalar {
    let mut bytes = bytes.clone();
    bytes.reverse();
    le_to_scalar(&bytes)
}

/// Convert given byte vector in little endian order to u64
pub fn le_to_u64(bytes: &Vec<u8>) -> u64 {
    let mut bytes: Vec<u8> = bytes.clone();
    remove_zero_padding!(bytes);
    assert!(bytes.len() <= 8, "the given vec contains more than 8 non-zero le bytes");
    zero_padding!(bytes, 8 - (bytes.len() % 8));
    u64::from_le_bytes(slice_to_array!(&bytes[0..8],8))
}

/// Convert given byte vector in big endian order to u64
pub fn be_to_u64(bytes: &Vec<u8>) -> u64 {
    let mut bytes: Vec<u8> = bytes.clone();
    bytes.reverse();
    le_to_u64(&bytes)
}

/// Constructs a 32 byte Scalar from the given byte vector in big endian order
pub fn scalar_to_be(scalar: &Scalar) -> Vec<u8> {
    let mut bytes: Vec<u8> = scalar.as_bytes().to_vec();
    bytes.reverse();
    bytes
}

pub fn vars_to_lc(variables: &Vec<Variable>) -> Vec<LinearCombination> {
    let lcs: Vec<LinearCombination> = variables
        .iter()
        .map(|var| var.clone().into())
        .collect();
    
    lcs
}

pub fn scalars_to_lc(scalars: &Vec<Scalar>) -> Vec<LinearCombination> {
    let lcs: Vec<LinearCombination> = scalars
        .iter()
        .map(|scalar| scalar.clone().into())
        .collect();
    
    lcs
}

/// Transforms the given byte vector to a vector of hexadecimal String bytes.
pub fn bytes_to_hex_strs(bytes: &Vec<u8>) -> Vec<String> {
    let mut tmp: Vec<u8> = Vec::new();
    tmp.extend(bytes);
    remove_zero_padding!(tmp);
    let strs: Vec<String> = tmp.iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    strs
}
/// Transforms a hex literal with even length to a byte vector.
pub fn hex_to_bytes(hex_str: String) -> Option<Vec<u8>> {
    {
        (0..hex_str.len())
        .step_by(2)
        .map(|i| hex_str.get(i..i + 2)
        .and_then(|sub| u8::from_str_radix(sub, 16).ok()))
        .collect()
    }
}

fn pad(string: String)-> String {
    let mut tmp = string.clone();
    if string.len() % 2 == 1 {
        tmp = format!("0{}", string);
    }
    tmp
}
/// Encodes an integer to a lowercase hex literal String (does not include 0x prefix).
/// If the resulting length is uneven, pads one zero to the left.
pub fn num_hex_encode(number: u64) -> String {
    let hex_number: String = format!("{:x}", number);
    pad(hex_number)
}
/// Encodes a String to a lowercase hex literal String (does not include 0x prefix).
pub fn str_hex_encode(str: String) -> String {
    let hex_str: String = hex::encode(str);
    hex_str
}

/// Returns the byte vector in big endian order from the given Scalar, removing the zero padding.
pub fn scalar_to_bytes(scalar: &Scalar) -> Vec<u8> {
    let mut bytes: Vec<u8> = scalar.as_bytes().to_vec();
    remove_zero_padding!(bytes);
    bytes.reverse();
    bytes
}

/// Returns the hex literal form of the Scalar.
pub fn scalar_to_hex(scalar: &Scalar) -> String {
    let bytes: Vec<u8> = scalar_to_bytes(scalar);
    let hex_str: String = bytes_to_hex_strs(&bytes).join("");
    hex_str
}

/// Decodes a String from the given byte vector assuming UTF-8 encoding. Returns "" when decoding fails.
pub fn str_hex_decode(bytes_array: &Vec<u8>) -> String {
    let decoded = match str::from_utf8(&bytes_array) {
        Ok(v) => v,
        Err(_e) => "",
    };
    String::from(decoded)
}

/// Decodes an integer value from the given byte vector in big endian order
pub fn num_hex_decode(bytes_array: &Vec<u8>) -> u64 {
    let decoded = be_to_u64(&bytes_array);
    decoded
}


#[cfg(test)]
mod tests {
    use super::*;

    const BYTES_1: [u8; 32] = [
        0x7b, 0x24, 0x60, 0xbe, 0x18, 0x05, 0x44, 0xcd, 
        0x18, 0xe3, 0xe7, 0xe2, 0x73, 0x30, 0xce, 0xc9, 
        0x51, 0x7a, 0x31, 0x4a, 0xcb, 0xd4, 0xa0, 0x11, 
        0xd2, 0x73, 0xa5, 0x9b, 0x48, 0x0c, 0x1e, 0x00
    ];

    const BYTES_2: [u8; 32] = [
        0x7b, 0x98, 0x7c, 0xf9, 0x7a, 0x9f, 0x1b, 0xd5, 
        0x49, 0x23, 0x47, 0xd6, 0xf4, 0xe5, 0x50, 0xae, 
        0x29, 0x49, 0xa5, 0x13, 0xde, 0x92, 0xfe, 0x50, 
        0x65, 0x35, 0x0e, 0xbc, 0xd5, 0x1d, 0xb6, 0x04
    ];

    const BYTES_3: [u8; 32] = [
        0x06, 0x2a, 0xca, 0x04, 0x51, 0xab, 0x15, 0x8b,
        0x33, 0x78, 0x18, 0xe2, 0x5c, 0x5d, 0x69, 0x06,
        0x6d, 0xc1, 0x42, 0x1a, 0x56, 0xf1, 0x65, 0x9a,
        0x55, 0xee, 0x67, 0x32, 0xb8, 0x0c, 0xf9, 0xd7
    ];
    const HEX_STR: &str = "062aca0451ab158b337818e25c5d69066dc1421a56f1659a55ee6732b80cf9d7";

    const HEX_8: &str = "5065676779";  // "Peggy"
    const HEX_9: &str = "50726f766572736f6e";  // "Proverson"
    const HEX_10: &str = "012fcfd4";    // 019910612
    const HEX_11: &str = "54696d62756b7475";    // "Timbuktu"
    const HEX_12: &str = "01337894";    // 020150420
    const HEX_13: &str = "0134ff33";    // 020250419
    const HEX_14: &str = "50617373706f7274204f6666696365205a7572696368"; // "Passport Office Zurich"
    const HEX_15: &str = "82440e";  // 8537102

    #[test]
    fn test_le_to_scalars() {
        let scalars: Vec<Scalar> = le_to_scalars(&[BYTES_1, BYTES_2].concat());

        assert_eq!(&BYTES_1, scalars[0].as_bytes());
        assert_eq!(&BYTES_2, scalars[1].as_bytes());
    }

    #[test]
    fn test_le_to_scalar() {
        let scalar: Scalar = le_to_scalar(&BYTES_1.to_vec());

        assert_eq!(&BYTES_1, scalar.as_bytes());
    }

    #[test]
    fn test_be_to_scalar() {
        let scalar: Scalar = be_to_scalar(&BYTES_1.to_vec());

        let mut bytes = BYTES_1.to_vec();
        bytes.reverse();
        
        assert_eq!(&bytes, scalar.as_bytes());
    }

    #[test]
    fn test_be_to_scalars() {
        let scalars: Vec<Scalar> = be_to_scalars(&[BYTES_1, BYTES_2].concat());

        let mut bytes1 = BYTES_1.to_vec();
        bytes1.reverse();
        let mut bytes2 = BYTES_2.to_vec();
        bytes2.reverse();

        assert_eq!(&bytes2, scalars[0].as_bytes());
        assert_eq!(&bytes1, scalars[1].as_bytes());
    }

    #[test]
    fn test_hex_to_bytes() {
        let bytes_array: Vec<u8> = hex_to_bytes(String::from(HEX_STR)).unwrap();

        assert_eq!(BYTES_3.to_vec(), bytes_array);
    }
    #[test]
    fn test_scalar_to_bytes() {
        let scalar: Scalar = be_to_scalar(&BYTES_3.to_vec());
        let bytes_array: Vec<u8> = scalar_to_bytes(&scalar);

        assert_eq!(BYTES_3.to_vec(), bytes_array);
    }
    #[test]
    fn test_scalar_to_hex() {
        let scalar: Scalar = be_to_scalar(&BYTES_3.to_vec());
        let hex_str: String = scalar_to_hex(&scalar);

        assert_eq!(HEX_STR, hex_str);
    }
    #[test]
    fn test_bytes_to_hex() {
        let bytes_array: Vec<u8> = BYTES_3.to_vec();
        let hex_str: String = bytes_to_hex_strs(&bytes_array).join("");

        assert_eq!(HEX_STR, hex_str);
    }
    #[test]
    fn test_num_hex_encode() {
        let hex_hash_10: String = num_hex_encode(19910612);
        let hex_hash_12: String = num_hex_encode(20150420);
        let hex_hash_13: String = num_hex_encode(20250419);
        let hex_hash_15: String = num_hex_encode(8537102);

        assert_eq!(HEX_10, hex_hash_10);
        assert_eq!(HEX_12, hex_hash_12);
        assert_eq!(HEX_13, hex_hash_13);
        assert_eq!(HEX_15, hex_hash_15);
    }
    #[test]
    fn test_str_hex_encode() {
        let hex_hash_8: String = str_hex_encode(String::from("Peggy"));
        let hex_hash_9: String = str_hex_encode(String::from("Proverson"));
        let hex_hash_11: String = str_hex_encode(String::from("Timbuktu"));
        let hex_hash_14: String = str_hex_encode(String::from("Passport Office Zurich"));

        assert_eq!(HEX_8, hex_hash_8);
        assert_eq!(HEX_9, hex_hash_9);
        assert_eq!(HEX_11, hex_hash_11);
        assert_eq!(HEX_14, hex_hash_14);
    }
    #[test]
    fn test_str_hex_decode() {
        let bytes_array_8 = hex_to_bytes(String::from(HEX_8)).unwrap();
        let bytes_array_9 = hex_to_bytes(String::from(HEX_9)).unwrap();
        let bytes_array_11 = hex_to_bytes(String::from(HEX_11)).unwrap();
        let bytes_array_14 = hex_to_bytes(String::from(HEX_14)).unwrap();

        let str_value_8 = str_hex_decode(&bytes_array_8);
        let str_value_9 = str_hex_decode(&bytes_array_9);
        let str_value_11 = str_hex_decode(&bytes_array_11);
        let str_value_14 = str_hex_decode(&bytes_array_14);

        assert_eq!("Peggy", str_value_8);
        assert_eq!("Proverson", str_value_9);
        assert_eq!("Timbuktu", str_value_11);
        assert_eq!("Passport Office Zurich", str_value_14);
    }
    #[test]
    fn test_num_hex_decode() {
        let bytes_array_10 = hex_to_bytes(String::from(HEX_10)).unwrap();
        let bytes_array_12 = hex_to_bytes(String::from(HEX_12)).unwrap();
        let bytes_array_13 = hex_to_bytes(String::from(HEX_13)).unwrap();
        let bytes_array_15 = hex_to_bytes(String::from(HEX_15)).unwrap();

        let int_value_10: u64 = num_hex_decode(&bytes_array_10);
        let int_value_12: u64 = num_hex_decode(&bytes_array_12);
        let int_value_13: u64 = num_hex_decode(&bytes_array_13);
        let int_value_15: u64 = num_hex_decode(&bytes_array_15);

        assert_eq!(19910612, int_value_10);
        assert_eq!(20150420, int_value_12);
        assert_eq!(20250419, int_value_13);
        assert_eq!(8537102, int_value_15);
    }

    #[test]
    fn test_wrong_decode_1() {
        let bytes_array_12 = hex_to_bytes(String::from(HEX_12)).unwrap();
        let decoded_str = str_hex_decode(&bytes_array_12);
        assert_eq!("", decoded_str);
        let decoded_int = num_hex_decode(&bytes_array_12);
        assert_eq!(20150420, decoded_int);

    }
    #[test]
    fn test_wrong_decode_2() {
        let bytes_array_8 = hex_to_bytes(String::from(HEX_8)).unwrap();
        let decoded_str = str_hex_decode(&bytes_array_8);
        assert_ne!("", decoded_str);
        assert_eq!("Peggy", decoded_str);
    }
}