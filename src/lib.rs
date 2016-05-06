extern crate rustc_serialize;
use self::rustc_serialize::hex::FromHex;
use self::rustc_serialize::hex::ToHex;
use self::rustc_serialize::base64::ToBase64;
use self::rustc_serialize::base64::Config as Base64Config;

pub fn hex_to_base64(input: &str) -> String {
    let config = Base64Config {
        char_set: rustc_serialize::base64::CharacterSet::Standard,
        newline: rustc_serialize::base64::Newline::LF,
        pad: false,
        line_length: None,
    };
    let hex = input.from_hex();
    hex.map(|byte| byte.to_base64(config)).unwrap()
}

pub fn fixed_xor(lhs: &str, rhs: &str) -> String {
    let lhs_bytes = lhs.from_hex().unwrap();
    let rhs_bytes = rhs.from_hex().unwrap();
    let result_vec = lhs_bytes.
        into_iter().
        zip(rhs_bytes).
        map(|a| a.0 ^ a.1).
        collect::<Vec<_>>();
    result_vec.to_hex()
}

#[test]
fn test_conversion() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64 = hex_to_base64(hex);
    assert!(base64 == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

#[test]
fn test_xor() {
    let lhs = "1c0111001f010100061a024b53535009181c";
    let rhs = "686974207468652062756c6c277320657965";
    let result = fixed_xor(lhs, rhs);
    assert!(result == "746865206b696420646f6e277420706c6179");
}
