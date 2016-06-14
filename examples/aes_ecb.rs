extern crate crypto_challenges;
extern crate rustc_serialize;

use std::fs::File;
use std::io::prelude::*;

use self::rustc_serialize::base64::FromBase64;
use crypto_challenges::aes_ecb_decrypt;

fn main() {
    let mut f = File::open("data/7.txt").unwrap();
    let mut file_buffer = String::new();
    f.read_to_string(&mut file_buffer).unwrap();
    let ciphertext = file_buffer.as_str().from_base64().unwrap();

    let key = "YELLOW SUBMARINE";
    let plaintext_bytes = aes_ecb_decrypt(key.as_bytes(), ciphertext.as_slice()).unwrap();

    let plaintext = String::from_utf8(plaintext_bytes).unwrap();
    println!("Decrypt successful!\nResult:\n{}", plaintext);
}
