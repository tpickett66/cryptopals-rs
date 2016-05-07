extern crate crypto_challenges;

use std::collections::HashMap;
use crypto_challenges::xor_cipher_decrypt as decrypt;
use crypto_challenges::is_likely_message;

static CIPHERTEXT: &'static str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

fn main() {
    let mut candidates = HashMap::new();
    let keys = 0..255;

    for key in keys {
        let result = decrypt(key, CIPHERTEXT);
        match result {
            Ok(val) => {
                if is_likely_message(&val) {
                    candidates.insert(key, val.to_string());
                }
            },
            Err(_) => {}
        }

    }

    println!("Possible Candidates:");
    for (key, plaintext) in candidates {
        println!("{:?}: {}", key as char, plaintext);
    }
}
