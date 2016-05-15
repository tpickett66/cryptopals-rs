extern crate rustc_serialize;
use self::rustc_serialize::hex::FromHex;
use self::rustc_serialize::hex::ToHex;
use self::rustc_serialize::base64::ToBase64;
use self::rustc_serialize::base64::Config as Base64Config;

use std::string::FromUtf8Error;

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

pub fn xor_cipher_decrypt(key: u8, ciphertext: &str) -> Result<String, FromUtf8Error> {
    let ciphertext_bytes = ciphertext.from_hex().unwrap();
    let result_bytes = ciphertext_bytes.
        into_iter().
        map(|b| b ^ key).
        collect::<Vec<u8>>();
    String::from_utf8(result_bytes)
}

const ETAOIN_SHRDLU: [char; 13] = ['E', 'T', 'A', 'O', 'I', 'N', ' ', 'S', 'H', 'R', 'D', 'L', 'U'];

pub fn is_likely_message(maybe_message: &String) -> bool {
    let magic_letters = maybe_message.chars().into_iter().
        filter(|c| ETAOIN_SHRDLU.contains(&c.to_uppercase().next().unwrap())).
        collect::<Vec<_>>();
    magic_letters.len() >= 20
}

pub fn repeating_xor_cipher_encrypt(key: &str, plaintext: &str) -> String {
    let key_bytes = key.as_bytes().into_iter();
    let ciphertext_bytes = plaintext.as_bytes().into_iter().
        zip(key_bytes.cycle().take(plaintext.len())).
        map(|bytes| bytes.0 ^ bytes.1).
        collect::<Vec<u8>>();
    ciphertext_bytes.to_hex()
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

#[test]
fn test_repeating_xor_cipher_encrypt() {
    let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";
    let expected_ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    let ciphertext = repeating_xor_cipher_encrypt(key, plaintext);
    println!("Expected Ciphertext: {}", expected_ciphertext);
    println!("         Ciphertext: {}", ciphertext);
    assert!(ciphertext == expected_ciphertext);
}
