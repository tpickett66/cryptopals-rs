extern crate rustc_serialize;
extern crate crypto_challenges;

use std::collections::HashMap;
use self::rustc_serialize::hex::FromHex;
use crypto_challenges::xor_cipher_crypt as decrypt;
use crypto_challenges::etaoin_shrdlu_score;

fn main() {
    let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".from_hex().unwrap();

    let mut candidates = HashMap::new();
    let keys = 0..255;

    for key in keys {
        let result = decrypt(key, ciphertext.as_slice());
        match String::from_utf8(result) {
            Ok(val) => {
                if etaoin_shrdlu_score(&val) >= 20 {
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
