
extern crate cryptofriends;

fn main() {
    let test_1 = cryptofriends::set_1::hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    println!("set 1 challenge 1: {}", test_1);
}
