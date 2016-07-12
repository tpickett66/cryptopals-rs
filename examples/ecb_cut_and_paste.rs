//extern crate crypto;
extern crate crypto_challenges;

use crypto_challenges::{padded_ecb_encrypt, aes_ecb_decrypt};
use crypto_challenges::query_string;

const KEY: &'static [u8] = b"Ice Ice baby!!1!";

fn main() {
    let first_profile = query_string::profile_for("1337pwner@pwners.com");
    let second_profile = query_string::profile_for("pwn@pwn.coadmin           ");
    let third_profile = query_string::profile_for("pwner@pwners.com");

    // Blocks 0 and 1 to positions 0 and 1 respectively
    let first_ciphertext = padded_ecb_encrypt(KEY, first_profile.bytes().collect::<Vec<u8>>().as_slice()).unwrap();
    // Block 1 to position 2
    let second_ciphertext = padded_ecb_encrypt(KEY, second_profile.bytes().collect::<Vec<u8>>().as_slice()).unwrap();
    // Block 2 to position 3
    let third_ciphertext = padded_ecb_encrypt(KEY, third_profile.bytes().collect::<Vec<u8>>().as_slice()).unwrap();

    let mut admin_ciphertext = Vec::new();
    admin_ciphertext.extend(first_ciphertext[..32].to_vec());
    admin_ciphertext.extend(second_ciphertext[16..32].to_vec());
    admin_ciphertext.extend(third_ciphertext[32..48].to_vec());

    let decrypted_admin_query = aes_ecb_decrypt(KEY, &admin_ciphertext.as_slice()).unwrap().to_vec();
    let admin_profile_string = String::from_utf8(decrypted_admin_query).unwrap();
    println!("Profile: {}", admin_profile_string);
    let hacked_profile = query_string::decode(admin_profile_string.as_str());
    let final_role = hacked_profile.get("role").unwrap();
    println!("Got Role: '{}'", final_role);
    assert_eq!(final_role, &"admin");
}
