extern crate rustc_serialize;
extern crate crypto_challenges;

use crypto_challenges::{detect_aes_ecb, random_encrypt};

fn main() {
    let ciphertext = random_encrypt("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar").unwrap();
    println!("Detected ECB: {}", detect_aes_ecb(&ciphertext));
}
