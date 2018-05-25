extern crate cryptofriends;

fn main() {
    // let (decoded, score, _) = cryptofriends::set_1::word_scorer("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    // println!("decoded = {} and score = {}", decoded, score);

    // let decoded_single_xor = cryptofriends::set_1::detect_single_char_xor();
    // println!("decoded_single_xor = {}", decoded_single_xor);

    // cryptofriends::set_1::break_repeating_xor();

    // if let Some(answer) = cryptofriends::set_1::detect_aes_ecb() {
    //     println!("answer = {}", answer);
    // }
    //
    // let padded_string = cryptofriends::set_2::pkcs_7_pad_string("YELLOW SUBMARINE", 20);
    // println!("Padded string = {}", padded_string);
    // println!("Padded string length = {}", padded_string.len());

    // let padded_string = cryptofriends::set_2::pkcs_7_pad_string("YELLOW SUBMARINE", 20);

    // let result = encrypted_profile_for("foo@bar.co");
    // println!("encrypted profile = {:?}", result);
    let output1 =
        cryptofriends::set_2::consistent_key_encryption_oracle("YELLOW SUBMARINE".as_bytes());
    println!("output1 = {:?}", output1);
    println!("output1 len = {:?}", output1.len());

    let output2 =
        cryptofriends::set_2::challenge_14_encryption_oracle("YELLOW SUBMARINE".as_bytes());
    println!("output2 = {:?}", output2);
    println!("output2 len = {:?}", output2.len());
}
