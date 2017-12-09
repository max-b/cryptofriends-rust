
extern crate cryptofriends;

fn main() {
    // let (decoded, score, _) = cryptofriends::set_1::word_scorer("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    // println!("decoded = {} and score = {}", decoded, score);

    // let decoded_single_xor = cryptofriends::set_1::detect_single_char_xor();
    // println!("decoded_single_xor = {}", decoded_single_xor);

    // cryptofriends::set_1::break_repeating_xor();

    if let Some(answer) = cryptofriends::set_1::detect_aes_ecb() {
        println!("answer = {}", answer);
    }
}
