extern crate crypto;
extern crate rustc_serialize;

use std::fs::File;
use std::io::prelude::*;

use self::rustc_serialize::base64::FromBase64;
use crypto::aes::{KeySize as AESKeySize, ecb_decryptor as build_aes_decryptor};
use crypto::blockmodes::NoPadding;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};

fn main() {
    let mut f = File::open("data/7.txt").unwrap();
    let mut file_buffer = String::new();
    f.read_to_string(&mut file_buffer).unwrap();
    let ciphertext = file_buffer.as_str().from_base64().unwrap();

    let key = "YELLOW SUBMARINE";
    let mut decryptor = build_aes_decryptor(AESKeySize::KeySize128, key.as_bytes(), NoPadding);

    let mut read_buffer = RefReadBuffer::new(ciphertext.as_slice());
    let mut plaintext_bytes = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        // If main() returned a Result here we could use try! but since main
        // returns and empty tuple we can't. To get around some of the
        // verbosity here we could extract this to a function returning
        // Result<Vec<u8>, SymmetricCipherError> but that would be overkill
        // for this toy, perhaps as this gets used more we will do that.
        match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(result) => {
                println!("Successful decrypt");
                plaintext_bytes.extend(write_buffer.take_read_buffer()
                                    .take_remaining()
                                    .iter()
                                    .cloned());
                match result {
                    BufferResult::BufferUnderflow => break,
                    BufferResult::BufferOverflow => { println!("Buffer Overflowed, going for another round") }
                }
            },
            Err(_) => {
                println!("Cipher error encountered!");
                break;
            }
        }
    }

    let plaintext = String::from_utf8(plaintext_bytes).unwrap();
    println!("Decrypt successful!\nResult:\n{}", plaintext);
}
