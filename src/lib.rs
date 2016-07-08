extern crate crypto;
extern crate rustc_serialize;

use std::collections::HashMap;

use crypto::aes::{KeySize, ecb_encryptor, ecb_decryptor};
use crypto::blockmodes::NoPadding;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::symmetriccipher::SymmetricCipherError;

use self::rustc_serialize::hex::FromHex;
use self::rustc_serialize::hex::ToHex;
use self::rustc_serialize::base64::Config as Base64Config;
use self::rustc_serialize::base64::FromBase64;
use self::rustc_serialize::base64::ToBase64;

pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut previous = iv.to_vec();
    let mut ciphertext: Vec<u8> = vec![];

    for chunk in plaintext.chunks(16) {
        let block = try!(aes_ecb_encrypt(key, fixed_xor(chunk, previous.as_slice()).as_slice()));
        previous = block.to_vec();
        ciphertext.extend(block.iter());
    }
    Ok(ciphertext)
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut ciphertext_with_iv = iv.to_vec();
    ciphertext_with_iv.extend_from_slice(ciphertext);

    let chunks = ciphertext_with_iv.chunks(16).
        rev().
        collect::<Vec<&[u8]>>();

    let mut plaintext_chunks: Vec<Vec<u8>> = vec![];

    for pair in chunks.windows(2) {
        let current = pair[0];
        let previous = pair[1];
        let block = try!(aes_ecb_decrypt(key, current));
        let plaintext = fixed_xor(block.as_slice(), previous);
        plaintext_chunks.push(plaintext);
    }

    plaintext_chunks.reverse();
    let mut plaintext_bytes: Vec<u8> = vec![];
    for chunk in plaintext_chunks.iter() {
        plaintext_bytes.extend(chunk.iter());
    }
    Ok(plaintext_bytes)
}

pub fn aes_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut encryptor = ecb_encryptor(KeySize::KeySize128, key, NoPadding);

    let mut read_buffer = RefReadBuffer::new(plaintext);
    let mut ciphertext_bytes = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        ciphertext_bytes.extend(write_buffer.take_read_buffer()
                               .take_remaining()
                               .iter()
                               .cloned());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    Ok(ciphertext_bytes)
}

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

pub fn detect_aes_ecb(ciphertext: &Vec<u8>) -> bool {
    let mut map = HashMap::new();
    for chunk in ciphertext.chunks(16) {
        let count = map.entry(chunk).or_insert(0);
        *count += 1;
    }
    map.values().any(|&val| val > 1)
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

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use super::*;
    use self::rustc_serialize::hex::FromHex;

    #[test]
    fn test_aes_ecb_encrypt() {
        let key = "YELLOW SUBMARINE";

        let plaintext = "This is my sekret value, there are many like it, but this one is mine!\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A";
        let expected_ciphertext = vec![48, 191, 30, 99, 228, 57, 238, 48, 51,
        50, 86, 34, 163, 156, 60, 210, 109, 170, 64, 252, 122, 45, 6, 130,
        58, 207, 167, 143, 52, 72, 72, 83, 159, 105, 53, 69, 114, 221, 88,
        41, 193, 164, 242, 145, 150, 146, 125, 173, 177, 113, 174, 211, 124,
        238, 9, 73, 184, 186, 13, 237, 229, 68, 68, 99, 237, 42, 198, 70,
        161, 252, 239, 189, 176, 77, 69, 184, 33, 143,1, 20];
        let ciphertext = aes_ecb_encrypt(key.as_bytes(), plaintext.as_bytes()).unwrap();
        assert_eq!(expected_ciphertext, ciphertext);
    }

    #[test]
    fn test_aes_ecb_decrypt() {
        let key = "YELLOW SUBMARINE";

        let ciphertext = vec![48, 191, 30, 99, 228, 57, 238, 48, 51,
            50, 86, 34, 163, 156, 60, 210, 109, 170, 64, 252, 122, 45, 6, 130,
            58, 207, 167, 143, 52, 72, 72, 83, 159, 105, 53, 69, 114, 221, 88,
            41, 193, 164, 242, 145, 150, 146, 125, 173, 177, 113, 174, 211, 124,
            238, 9, 73, 184, 186, 13, 237, 229, 68, 68, 99, 237, 42, 198, 70,
            161, 252, 239, 189, 176, 77, 69, 184, 33, 143,1, 20];
        let expected_plaintext = "This is my sekret value, there are many like it, but this one is mine!\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A";
        let plaintext = aes_ecb_decrypt(key.as_bytes(), ciphertext.as_slice()).unwrap();
        assert_eq!(expected_plaintext.as_bytes(), plaintext.as_slice());
    }


    #[test]
    fn test_detect_aes_ecb() {
        let ciphertext = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
        let bytes = ciphertext.from_hex().unwrap();
        assert!(detect_aes_ecb(&bytes));
    }

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
