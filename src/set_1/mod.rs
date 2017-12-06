extern crate itertools;
extern crate base64;

use std::u8;
use std::str;
use std::collections::HashMap;
use std::ascii::AsciiExt;
use std::io::BufReader;
use std::io::prelude::*;
use std::path::PathBuf;
use std::fs::File;
use self::itertools::Itertools;
use self::base64::{encode, decode};

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for i in 0..(hex.len()/2) {
        let hex_string = &hex[(i*2)..(i*2)+2];
        let res = u8::from_str_radix(hex_string, 16).expect(&format!("Problem with hex {}", hex_string));
        bytes.push(res);
    }

    bytes
}

fn base64_to_bytes(string: &str) -> Vec<u8> {
    decode(&string).expect("error decoding base64 string")
}

pub fn hex_to_base64(hex: &str) -> String {
    let bytes: Vec<u8> = hex_to_bytes(hex);
    encode(&bytes)
}

fn xor(buf1: &Vec<u8>, buf2: &Vec<u8>) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for i in 0..buf1.len() {
        bytes.push(buf1[i] ^ buf2[i]);
    }

    bytes
}

fn single_xor(buf: &[u8], key: u8) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for i in buf.into_iter() {
        bytes.push(i ^ key);
    }

    bytes
}

fn bytes_to_hex(buf: &Vec<u8>) -> String {
    let result = buf.iter().format("");

    format!("{:02x}", result)
}

pub fn xor_hex_strings(hex1: &str, hex2: &str) -> String {
    let buf1 = hex_to_bytes(hex1);
    let buf2 = hex_to_bytes(hex2);

    let bytes = xor(&buf1, &buf2);

    bytes_to_hex(&bytes)
}

fn get_chi_squared(buf: &[u8]) -> f64 {

    let english_freq = vec![
        0.0651738, 0.0124248, 0.0217339, 0.0349835,  //'A', 'B', 'C', 'D',...
        0.1041442, 0.0197881, 0.0158610, 0.0492888,
        0.0558094, 0.0009033, 0.0050529, 0.0331490,
        0.0202124, 0.0564513, 0.0596302, 0.0137645,
        0.0008606, 0.0497563, 0.0515760, 0.0729357,
        0.0225134, 0.0082903, 0.0171272, 0.0013692,
        0.0145984, 0.0007836, 0.1918182,  //'Y', 'Z', ' '
    ];

    let ordered_letters = String::from("abcdefghijklmnopqrstuvwxyz ");
    let frequency_score_map: HashMap<_, _> = ordered_letters.chars().zip(english_freq.iter()).collect();

    let mut count: HashMap<char, usize> = HashMap::new();

    for &byte in buf.into_iter() {

        let byte_as_char = (byte as char).to_ascii_lowercase();

        let i = count.entry(byte_as_char).or_insert(0);
        *i += 1;
    }

    let mut chi2 = 0.0;
    let len = buf.len();

    for (letter, occurences) in &count {
        let expected = match frequency_score_map.get(&letter) {
            None => 0.0008,
            Some(frequency) => len as f64 * *frequency,
        };

        let difference = *occurences as f64 - expected;

        if expected > 0.0 {
            chi2 += (difference * difference) / expected as f64;
        }
    }

    chi2
}

fn word_scorer_bytes(buf: &[u8]) -> (String, f64, u8) {

    let mut best_key = 0;
    let mut best_score = 99999.0;

    for i in 0..255 {
        let result = &single_xor(&buf, i)[..];

        match str::from_utf8(&result) {
            Ok(string) => {

                if string.is_ascii() {

                    let score = get_chi_squared(result);

                    if score < best_score {
                        best_score = score;
                        best_key = i;
                    }
                }
            },
            Err(_) => {},
        }
    }

    let plaintext_bytes = single_xor(&buf, best_key);
    let plaintext_char_buffer: Vec<char> = plaintext_bytes.iter().map(|&x| x as char).collect();

    (format!("{}", plaintext_char_buffer.iter().format("")), best_score, best_key)
}

pub fn word_scorer(hex: &str) -> (String, f64, u8) {
    let buf = hex_to_bytes(hex);
    word_scorer_bytes(&buf[..])
}

pub fn repeating_key_xor(buf: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();

    let mut key_iter = key.into_iter().cycle();

    for i in buf.into_iter() {
        result.push(key_iter.next().unwrap() ^ i);
    }

    result
}

pub fn detect_single_char_xor() -> String {
    let mut strings_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    strings_path.push("src");
    strings_path.push("set_1");
    strings_path.push("4.txt");

    let strings_file = File::open(&strings_path).expect("Error reading strings file.");

    let strings_file_as_reader = BufReader::new(strings_file);

    let mut best_score = 99999.0;
    let mut best_decoded = String::from("");

    for line in strings_file_as_reader.lines() {
        let (decoded, score, _) = word_scorer(&line.expect("error reading line"));

        if score < best_score {
            best_score = score;
            best_decoded = decoded;
        }
    }

    best_decoded
}

pub fn hamming_distance_strings(str1: &str, str2: &str) -> usize {
    let buf1 = str1.as_bytes();
    let buf2 = str2.as_bytes();

    hamming_distance_bytes(&buf1, &buf2)
}

fn hamming_distance_bytes(buf1: &[u8], buf2: &[u8]) -> usize {
    assert_eq!(buf1.len(), buf2.len());

    let buf1 = Vec::from(buf1);
    let buf2 = Vec::from(buf2);

    let xor_result = xor(&buf1, &buf2);

    let mut dist = 0;

    for &i in xor_result.iter() {
        let mut val = i;
        while val > 0 {
            dist += 1;
            val = val & (val - 1);
        }
    }

    dist
}

pub fn break_repeating_xor() -> String {

    let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ciphertext_path.push("src");
    ciphertext_path.push("set_1");
    ciphertext_path.push("6.txt");

    let mut goal_keysize = 99999;
    let mut goal_dist = 99999.0;

    let mut ciphertext_file = File::open(&ciphertext_path).expect("Error opening ciphertext file.");
    let mut ciphertext_buffer = Vec::new();
    ciphertext_file.read_to_end(&mut ciphertext_buffer).expect("Error reading ciphertext file.");

    let base64_decoded_ciphertext = base64_to_bytes(&str::from_utf8(&ciphertext_buffer).expect("Error reading string from_utf8 bytes").replace('\n', ""));

    for keysize in 2..40 {

        let chunk1 = &base64_decoded_ciphertext[0..keysize];
        let chunk2 = &base64_decoded_ciphertext[keysize..keysize*2];
        let chunk3 = &base64_decoded_ciphertext[keysize*2..keysize*3];
        let chunk4 = &base64_decoded_ciphertext[keysize*3..keysize*4];

        let dist_1_2 = hamming_distance_bytes(&chunk1, &chunk2);
        let dist_1_3 = hamming_distance_bytes(&chunk1, &chunk3);
        let dist_1_4 = hamming_distance_bytes(&chunk1, &chunk4);
        let dist_2_3 = hamming_distance_bytes(&chunk2, &chunk3);
        let dist_2_4 = hamming_distance_bytes(&chunk2, &chunk4);
        let dist_3_4 = hamming_distance_bytes(&chunk3, &chunk4);

        // TODO: all of this could probably be made nicer with a collection/combination
        let average_dist: f64 = (dist_1_2 + dist_1_3 + dist_1_4 + dist_2_3 + dist_2_4 + dist_3_4) as f64 / (6.0 * keysize as f64);

        if average_dist < goal_dist {
            goal_dist = average_dist;
            goal_keysize = keysize;
        }
    }

    let mut transposed: Vec<Vec<u8>> = vec![vec![]; goal_keysize];
    for slice in base64_decoded_ciphertext.chunks(goal_keysize) {
        if slice.len() == goal_keysize {
            for i in 0..slice.len() {
                let item = slice[i];
                transposed[i].push(item);
            }
        }
    }

    let mut key_vector: Vec<u8> = Vec::new();

    for block in transposed {
        let (_, _, key) = word_scorer_bytes(&block[..]);
        key_vector.push(key);
    }

    let decrypted_buf = repeating_key_xor(&base64_decoded_ciphertext , &key_vector[..]);

    let decrypted_string = &str::from_utf8(&decrypted_buf).expect("Error converting decrypted buffer to string");

    println!("decrypted string = {}", decrypted_string);

    decrypted_string.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_1() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64_encoded = hex_to_base64(hex);
        let answer_bytes = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(base64_encoded, answer_bytes);
    }

    #[test]
    fn challenge_2() {
        let hex1 = "1c0111001f010100061a024b53535009181c";
        let hex2 = "686974207468652062756c6c277320657965";
        let xor_result = xor_hex_strings(hex1, hex2);
        let answer_bytes = "746865206b696420646f6e277420706c6179";
        assert_eq!(xor_result, answer_bytes);
    }

    #[test]
    fn challenge_3() {
        let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let (decode_result, _, _) = word_scorer(hex);
        let decoded_answer = "Cooking MC's like a pound of bacon";
        assert_eq!(decode_result, decoded_answer);
    }

    #[test] //#[ignore]
    fn challenge_4() {
        let xored_decrypt = detect_single_char_xor();
        let decoded_answer = "Now that the party is jumping\n";
        assert_eq!(xored_decrypt, decoded_answer);
    }

    #[test] //#[ignore]
    fn challenge_5() {
        let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let repeated_xor_bytes = repeating_key_xor(&(plaintext.as_bytes()), &(String::from("ICE").as_bytes()));
        let repeated_xor_string = bytes_to_hex(&repeated_xor_bytes);
        let encrypted_answer = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(repeated_xor_string, encrypted_answer);
    }

    #[test]
    fn hamming_distance_test() {
        let distance = hamming_distance_strings("this is a test", "wokka wokka!!!");
        assert_eq!(distance, 37);
    }

    #[test]
    fn challenge_6() {
        let decoded = break_repeating_xor().replace("\n", "").replace(" ", "");
        let answer = String::from("I'm back and I'm ringin' the bell
A rockin' on the mike while the fly girls yell
In ecstasy in the back of me
Well that's my DJ Deshay cuttin' all them Z's
Hittin' hard and the girlies goin' crazy
Vanilla's on the mike, man I'm not lazy.

I'm lettin' my drug kick in
It controls my mouth and I begin
To just let it flow, let my concepts go
My posse's to the side yellin', Go Vanilla Go!

Smooth 'cause that's the way I will be
And if you don't give a damn, then
Why you starin' at me
So get off 'cause I control the stage
There's no dissin' allowed
I'm in my own phase
The girlies sa y they love me and that is ok
And I can dance better than any kid n' play

Stage 2 -- Yea the one ya' wanna listen to
It's off my head so let the beat play through
So I can funk it up and make it sound good
1-2-3 Yo -- Knock on some wood
For good luck, I like my rhymes atrocious
Supercalafragilisticexpialidocious
I'm an effect and that you can bet
I can take a fly girl and make her wet.

I'm like Samson -- Samson to Delilah
There's no denyin', You can try to hang
But you'll keep tryin' to get my style
Over and over, practice makes perfect
But not if you're a loafer.

You'll get nowhere, no place, no time, no girls
Soon -- Oh my God, homebody, you probably eat
Spaghetti with a spoon! Come on and say it!

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino
Intoxicating so you stagger like a wino
So punks stop trying and girl stop cryin'
Vanilla Ice is sellin' and you people are buyin'
'Cause why the freaks are jockin' like Crazy Glue
Movin' and groovin' trying to sing along
All through the ghetto groovin' this here song
Now you're amazed by the VIP posse.

Steppin' so hard like a German Nazi
Startled by the bases hittin' ground
There's no trippin' on mine, I'm just gettin' down
Sparkamatic, I'm hangin' tight like a fanatic
You trapped me once and I thought that
You might have it
So step down and lend me your ear
'89 in my time! You, '90 is my year.

You're weakenin' fast, YO! and I can tell it
Your body's gettin' hot, so, so I can smell it
So don't be mad and don't be sad
'Cause the lyrics belong to ICE, You can call me Dad
You're pitchin' a fit, so step back and endure
Let the witch doctor, Ice, do the dance to cure
So come up close and don't be square
You wanna battle me -- Anytime, anywhere

You thought that I was weak, Boy, you're dead wrong
So come on, everybody and sing this song

Say -- Play that funky music Say, go white boy, go white boy go
play that funky music Go white boy, go white boy, go
Lay down and boogie and play that funky music till you die.

Play that funky music Come on, Come on, let me hear
Play that funky music white boy you say it, say it
Play that funky music A little louder now
Play that funky music, white boy Come on, Come on, Come on
Play that funky music").replace("\n", "").replace(" ", "");

        assert_eq!(decoded, answer);
    }
}
