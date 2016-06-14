extern crate rustc_serialize;
extern crate crypto_challenges;

use std::fs::File;
use std::io::prelude::*;

use self::rustc_serialize::base64::FromBase64;

use crypto_challenges::etaoin_shrdlu_score;
use crypto_challenges::byte_array_hamming_distance;
use crypto_challenges::xor_cipher_crypt;
use crypto_challenges::repeating_xor_cipher_crypt;

fn main() {
    let mut f = File::open("data/6.txt").unwrap();
    let mut buffer = String::new();

    f.read_to_string(&mut buffer).unwrap();
    let ciphertext = buffer.as_str().from_base64().unwrap();

    let possible_key_sizes = 2..41;
    let mut distances: Vec<(usize, u64)> = vec![];
    for possible_key_size in possible_key_sizes {
         let total_score = ciphertext.
            chunks(possible_key_size).
            collect::<Vec<&[u8]>>().
            windows(2).
            filter(|pair| pair[0].len() == pair[1].len()).
            map(|pair| byte_array_hamming_distance(pair[0], pair[1])).
            fold(0, |a, b| a + b);
        distances.push((possible_key_size, total_score));
    }

    distances.sort_by(|a, b| a.1.cmp(&b.1));

    let keysize = distances[0].0;
    println!("Chosen Key Size: {}", keysize);

    let mut transposed_ciphertext: Vec<Vec<u8>> = (0..keysize).map(|_| vec![]).collect();
    for chunk in ciphertext.chunks(keysize) {
        for (idx, byte) in chunk.iter().enumerate() {
            transposed_ciphertext[idx].push(byte.clone());
        }
    }

    let mut key_bytes: Vec<u8> = vec![];

    for block in transposed_ciphertext.iter() {
        let mut key_scores: Vec<(u8, usize)> = vec![];
        let keys = 0..255;

        for key in keys {
            let result = xor_cipher_crypt(key, block.as_slice());
            match String::from_utf8(result) {
                Ok(val) => {
                    key_scores.push((key, etaoin_shrdlu_score(&val)));
                },
                Err(_) => {}
            }
        }
        key_scores.sort_by(|a, b| b.1.cmp(&a.1));
        key_bytes.push(key_scores[0].0);
    }

    let key = String::from_utf8(key_bytes.clone()).unwrap();
    println!("Probable Key: \"{}\"", key);
    let plaintext = repeating_xor_cipher_crypt(key_bytes.as_slice(), ciphertext.as_slice());
    println!("Plaintext:\n{}", String::from_utf8(plaintext).unwrap());
}
