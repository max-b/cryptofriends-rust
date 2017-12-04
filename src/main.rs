
extern crate cryptofriends;

fn main() {
    let decoded = cryptofriends::set_1::word_scorer("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    println!("decoded = {}", decoded);
}
