extern crate crypto_challenges;
extern crate rustc_serialize;

use std::fs::File;
use std::io::prelude::*;
use self::rustc_serialize::base64::FromBase64;
use crypto_challenges::{aes_cbc_encrypt, aes_cbc_decrypt};

fn main() {
    let key = "YELLOW SUBMARINE";
    let iv = std::iter::repeat(0).take(key.len()).collect::<Vec<_>>();

    let mut f = File::open("data/10.txt").unwrap();
    let mut file_buffer = String::new();
    f.read_to_string(&mut file_buffer).unwrap();
    let ciphertext = file_buffer.as_str().from_base64().unwrap();

    let plaintext_bytes = aes_cbc_decrypt(key.as_bytes(), iv.as_slice(), ciphertext.as_slice()).unwrap();

    println!("Result:\n{}", String::from_utf8(plaintext_bytes.to_vec()).unwrap());

    let second_ciphertext = aes_cbc_encrypt(key.as_bytes(), iv.as_slice(), plaintext_bytes.as_slice()).unwrap();
    assert_eq!(ciphertext, second_ciphertext);
    println!("Successfully round tripped using custom implementation of AES-CBC");
}
