extern crate crypto;
extern crate rustc_serialize;

use crypto::aes::{KeySize, ecb_decryptor};
use crypto::blockmodes::NoPadding;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::symmetriccipher::SymmetricCipherError;

use self::rustc_serialize::hex::FromHex;
use self::rustc_serialize::hex::ToHex;
use self::rustc_serialize::base64::Config as Base64Config;
use self::rustc_serialize::base64::FromBase64;
use self::rustc_serialize::base64::ToBase64;

pub fn aes_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut decryptor = ecb_decryptor(KeySize::KeySize128, key, NoPadding);

    let mut read_buffer = RefReadBuffer::new(ciphertext);
    let mut plaintext_bytes = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        plaintext_bytes.extend(write_buffer.take_read_buffer()
                               .take_remaining()
                               .iter()
                               .cloned());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    Ok(plaintext_bytes)
}

pub fn pkcs7_pad(message: &[u8], block_length: u8) -> Vec<u8> {
    let initial_length = message.len() as u8;
    let padding = block_length - initial_length.wrapping_rem(block_length);
    let mut padded_message = Vec::with_capacity(block_length as usize);
    padded_message.extend_from_slice(message);
    for _ in 0..padding {
        padded_message.push(padding);
    }
    padded_message
}

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

pub fn base64_to_hex(input: &str) -> String {
    input.from_base64().unwrap().to_hex()
}

pub fn fixed_xor(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    lhs.iter().
        zip(rhs).
        map(|a| a.0 ^ a.1).
        collect::<Vec<_>>()
}

pub fn xor_cipher_crypt(key: u8, ciphertext: &[u8]) -> Vec<u8> {
    ciphertext.into_iter().
        map(|b| b ^ key).
        collect::<Vec<u8>>()
}

pub fn repeating_xor_cipher_crypt(key: &[u8], text: &[u8]) -> Vec<u8> {
    text.iter().
        zip(key.iter().cycle().take(text.len())).
        map(|bytes| bytes.0 ^ bytes.1).
        collect::<Vec<u8>>()
}

const ETAOIN_SHRDLU: [char; 13] = ['E', 'T', 'A', 'O', 'I', 'N', ' ', 'S', 'H', 'R', 'D', 'L', 'U'];
pub fn etaoin_shrdlu_score(scorable: &String) -> usize {
     scorable.chars().into_iter().
        filter(|c| ETAOIN_SHRDLU.contains(&c.to_uppercase().next().unwrap())).
        collect::<Vec<_>>().
        len()
}

pub fn byte_array_hamming_distance(a: &[u8], b: &[u8]) -> u64 {
    assert_eq!(a.len(), b.len());
    a.into_iter().
        zip(b).
        fold(0, |ones, (a, b)| ones + (a ^ b).count_ones() as u64)
}

pub fn hamming_distance(a: &str, b: &str) -> u64 {
    byte_array_hamming_distance(a.as_bytes(), b.as_bytes())
}

pub fn hex_hamming_distance(a: &str, b: &str) -> u64 {
    assert_eq!(a.len(), b.len());
    byte_array_hamming_distance(
        a.from_hex().unwrap().as_slice(),
        b.from_hex().unwrap().as_slice()
    )
}

mod test {
    extern crate rustc_serialize;

    use super::*;
    use self::rustc_serialize::hex::FromHex;

#[test]
    fn test_pkcs7_pad() {
        let message = "YELLOW SUBMARINE".as_bytes();
        let padded_message = pkcs7_pad(message, 20);
        assert_eq!(padded_message, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes());
    }

#[test]
    fn test_hex_to_base64_conversion() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64 = hex_to_base64(hex);
        assert!(base64 == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    }

#[test]
    fn test_base64_to_hex_conversion() {
        let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let hex = base64_to_hex(base64);
        assert!(hex == "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    }

#[test]
    fn test_xor() {
        let lhs = "1c0111001f010100061a024b53535009181c".from_hex().unwrap();
        let rhs = "686974207468652062756c6c277320657965".from_hex().unwrap();
        let result = fixed_xor(lhs.as_slice(), rhs.as_slice());

        assert!(result == "746865206b696420646f6e277420706c6179".from_hex().unwrap());
    }

#[test]
    fn test_repeating_xor_cipher_crypt() {
        let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";
        let expected_ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".from_hex().unwrap();
        let ciphertext = repeating_xor_cipher_crypt(key.as_bytes(), plaintext.as_bytes());
        assert!(ciphertext == expected_ciphertext);
    }

#[test]
    fn test_hamming() {
        let a = "this is a test";
        let b = "wokka wokka!!!";
        let distance = hamming_distance(a, b);
        assert_eq!(37, distance);
    }

#[test]
    fn test_hex_hamming() {
        let a = "3749521a010715114f104f211a632d1f0c4e084e5848264f030a491c0b";
        let b = "78453102040b411b01522a0856413b521d060654540e104e0516491e10";
        let distance = hex_hamming_distance(a, b);
        assert_eq!(77, distance);
    }
}
