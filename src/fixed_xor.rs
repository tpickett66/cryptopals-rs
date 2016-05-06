extern crate rustc_serialize;
use self::rustc_serialize::hex::FromHex;
use self::rustc_serialize::hex::ToHex;

#[test]
fn test_xor() {
    let lhs = "1c0111001f010100061a024b53535009181c";
    let rhs = "686974207468652062756c6c277320657965";
    let result = fixed_xor(lhs, rhs);
    assert!(result == "746865206b696420646f6e277420706c6179");
}

pub fn fixed_xor(lhs: &str, rhs: &str) -> String {
    let lhs_bytes = lhs.from_hex().unwrap();
    let rhs_bytes = rhs.from_hex().unwrap();
    let result_vec = lhs_bytes.
        into_iter().
        zip(rhs_bytes).
        map(|a| a.0 ^ a.1).
        collect::<Vec<_>>();
    result_vec.to_hex()
}
