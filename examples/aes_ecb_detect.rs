extern crate rustc_serialize;
extern crate crypto_challenges;

use std::fs::File;
use std::io::prelude::*;
use std::collections::HashMap;
use self::rustc_serialize::hex::FromHex;
use crypto_challenges::detect_aes_ecb;

fn main() {
    let mut f = File::open("data/8.txt").unwrap();
    let mut file_buffer = String::new();
    f.read_to_string(&mut file_buffer).unwrap();

    let mut candidates = HashMap::new();
    for (line_number, line) in file_buffer.lines().enumerate() {
        let bytes = line.from_hex().unwrap();
        if detect_aes_ecb(&bytes) {
            candidates.insert(line_number, line);
        }
    }

    println!("Candidates: {:?}", candidates);
}
