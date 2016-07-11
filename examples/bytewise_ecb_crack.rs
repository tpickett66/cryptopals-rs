extern crate crypto;
extern crate rustc_serialize;
extern crate crypto_challenges;

use crypto_challenges::{aes_ecb_encrypt, detect_aes_ecb, pkcs7_pad};

use crypto::symmetriccipher::SymmetricCipherError;
use self::rustc_serialize::base64::FromBase64;

const KEY: &'static [u8] = b"Ice Ice baby!!1!";
const RAW_DATA: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\naGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\ndXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\nYnkK";

fn decoded_data() -> Vec<u8> {
    RAW_DATA.from_base64().unwrap()
}

fn ecb_oracle(padding: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut data: Vec<u8> = Vec::new();
    data.extend(padding);
    data.extend(decoded_data());
    let padded_data = pkcs7_pad(data.as_slice(), 16);
    aes_ecb_encrypt(KEY, padded_data.as_slice())
}

// Begin actual cracking implementation!
fn determine_block_length() -> usize {
    let mut padding_size = 0;
    let mut current_size = ecb_oracle(b"").unwrap().len();
    let mut previous_size = ecb_oracle(b"").unwrap().len();
    while current_size == previous_size {
        padding_size += 1;
        previous_size = current_size;
        let padding: Vec<u8> = vec![42].into_iter().cycle().take(padding_size).collect();
        current_size = ecb_oracle(padding.as_slice()).unwrap().len();
    }
    current_size - previous_size
}


fn main() {
    let block_length = determine_block_length();
    println!("Found block length of {}.", block_length);

    // We're going to pad with at least 3 identical blocks to ensure the
    // ECB check is accurate.
    let check_padding: Vec<u8> = vec![42].into_iter().cycle().take(3*block_length).collect();
    let check_ciphertext = ecb_oracle(&check_padding).unwrap();
    if detect_aes_ecb(&check_ciphertext) {
        println!("ECB cipher detected, proceeding with crack...");
    } else {
        panic!("ECB Cipher not detected, aborting!!");
    }

    let message_length = decoded_data().len();
    let mut plaintext_bytes: Vec<u8> = Vec::new();

    for plaintext_position in 1..message_length {
        let padding_length = block_length - (plaintext_position % block_length);
        let work_block = (plaintext_position).wrapping_div(block_length);
        let check_position = work_block * block_length + block_length;

        let padding: Vec<u8> = vec![42].into_iter().cycle().take(padding_length).collect();
        let reference_ciphertext = ecb_oracle(&padding.as_slice()).unwrap();
        let reference_block = reference_ciphertext[..check_position].to_vec();

        for potential_plaintext_byte in 0..255 {
            let mut chosen_text: Vec<u8> = Vec::new();
            chosen_text.extend(padding.iter());
            chosen_text.extend(plaintext_bytes.iter());
            chosen_text.extend(vec![potential_plaintext_byte]);

            let current_ciphertext = ecb_oracle(&chosen_text.as_slice()).unwrap();
            let current_block = current_ciphertext[..check_position].to_vec();

            if reference_block ==  current_block {
                plaintext_bytes.push(potential_plaintext_byte);
                break;
            }
            if potential_plaintext_byte == 254 {
                let plaintext = String::from_utf8(plaintext_bytes).unwrap();
                println!("Current plaintext: {}", plaintext);
                panic!("Couldn't find match for plaintext position {}", plaintext_position);
            }
        }
    }
    let plaintext = String::from_utf8(plaintext_bytes).unwrap();
    println!("Plaintext found:\n{}", plaintext);
}
