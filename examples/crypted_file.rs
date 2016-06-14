extern crate rustc_serialize;
extern crate crypto_challenges;

use crypto_challenges::xor_cipher_crypt as decrypt;
use crypto_challenges::etaoin_shrdlu_score;

use self::rustc_serialize::hex::FromHex;
use std::collections::HashMap;
use std::io::prelude::*;
use std::fs::File;

pub fn main() {
    let mut candidates = HashMap::new();
    let keys = 0..255;

    let mut f = File::open("data/4.txt").unwrap();
    let mut buffer = String::new();

    f.read_to_string(&mut buffer).unwrap();

    for key in keys {
        let lines = buffer.lines().into_iter();
        let plaintext_lines = lines.
            map(|line| line.from_hex().unwrap()).
            map(|line| decrypt(key, line.as_slice())).
            map(|line| String::from_utf8(line)).
            filter(|result| result.is_ok()).
            map(|result| result.unwrap()).
            filter(|line| etaoin_shrdlu_score(&line) >= 20).
            collect::<Vec<String>>();
        if !plaintext_lines.is_empty() {
            candidates.insert(key, plaintext_lines);
        }
    }

    println!("Possible Candidates:");
    for (key, lines) in candidates {
        println!("{:?}: {}", key as char, lines.join("\n"));
    }
}
