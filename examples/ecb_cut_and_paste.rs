//extern crate crypto;
extern crate crypto_challenges;

//use crypto::symmetriccipher::SymmetricCipherError;
//use crypto_challenges::{aes_ecb_encrypt, detect_aes_ecb, pkcs7_pad};
use crypto_challenges::query_string;

//const KEY: &'static [u8] = b"Ice Ice baby!!1!";

fn main() {
    for email in vec!["foo@bar.com", "baz@qux.com", "really-super-long-email@to-mess-with-hasher.com"] {
        let result = query_string::profile_for(email);
        println!("encoded_profile: {}", result);
    }
}
