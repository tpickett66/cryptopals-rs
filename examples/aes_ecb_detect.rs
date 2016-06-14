extern crate rustc_serialize;

use std::fs::File;
use std::io::prelude::*;
use std::collections::HashMap;
use self::rustc_serialize::hex::FromHex;


fn main() {
    let mut f = File::open("data/8.txt").unwrap();
    let mut file_buffer = String::new();
    f.read_to_string(&mut file_buffer).unwrap();

    let mut candidates = HashMap::new();
    for (line_number, line) in file_buffer.lines().enumerate() {
        let bytes = line.from_hex().unwrap();
        let mut map = HashMap::new();
        for chunk in bytes.chunks(16) {
            let count = map.entry(chunk).or_insert(0);
            *count += 1;
        }
        if map.values().any(|&val| val > 1) {
            candidates.insert(line_number, line);
        }
    }

    println!("Candidates: {:?}", candidates);
}
