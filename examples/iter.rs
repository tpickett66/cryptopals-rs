extern crate rustc_serialize;
use self::rustc_serialize::hex::FromHex;
use self::rustc_serialize::hex::ToHex;

fn main() {
    let lhs = "1c0111001f010100061a024b53535009181c";
    let rhs = "686974207468652062756c6c277320657965";
    let lhs_bytes = lhs.from_hex().unwrap();
    let rhs_bytes = rhs.from_hex().unwrap();
    println!("lhs: {:?}", lhs);
    println!("lhs_bytes: {:?}", lhs_bytes);
    println!("rhs: {:?}", rhs);
    println!("rhs_bytes: {:?}", rhs_bytes);

    let iter = lhs_bytes.into_iter().zip(rhs_bytes);
    let result = iter.
        inspect(|&t| println!("Yielded: {:?}", t)).
        map(|a| a.0 ^ a.1).
        inspect(|&t| println!("Yielded: {:?}", t)).
        collect::<Vec<_>>();
    println!("result: {:?}", result);
    println!("hex result: {}", result.to_hex());
}
