use super::bytes::{generate_random_aes_key, hex_to_bytes, single_xor, xor};
use itertools::Itertools;
use std::collections::HashMap;
use std::f64;
use std::io::{Error, ErrorKind};
use std::str;

fn get_chi_squared(buf: &[u8]) -> f64 {
    let english_freq = vec![
        0.0651738, 0.0124248, 0.0217339, 0.0349835, //'A', 'B', 'C', 'D',...
        0.1041442, 0.0197881, 0.0158610, 0.0492888, 0.0558094, 0.0009033, 0.0050529, 0.0331490,
        0.0202124, 0.0564513, 0.0596302, 0.0137645, 0.0008606, 0.0497563, 0.0515760, 0.0729357,
        0.0225134, 0.0082903, 0.0171272, 0.0013692, 0.0145984, 0.0007836,
        0.1918182, //'Y', 'Z', ' '
    ];

    let ordered_letters = String::from("abcdefghijklmnopqrstuvwxyz ");
    let frequency_score_map: HashMap<_, _> =
        ordered_letters.chars().zip(english_freq.iter()).collect();

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

pub fn hamming_distance_strings(str1: &str, str2: &str) -> usize {
    let buf1 = str1.as_bytes();
    let buf2 = str2.as_bytes();

    hamming_distance_bytes(&buf1, &buf2)
}

pub fn hamming_distance_bytes(buf1: &[u8], buf2: &[u8]) -> usize {
    assert_eq!(buf1.len(), buf2.len());

    let buf1 = Vec::from(buf1);
    let buf2 = Vec::from(buf2);

    let xor_result = xor(&buf1[..], &buf2[..]);

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

pub fn word_scorer_bytes(buf: &[u8]) -> Result<(String, f64, u8), Error> {
    let mut best_key = 0;
    let mut best_score = None;

    for i in 0..255 {
        let result = &single_xor(&buf, i)[..];

        match str::from_utf8(&result) {
            Ok(string) => {
                if string.is_ascii() {
                    let score = get_chi_squared(result);

                    if let Some(best) = best_score {
                        if score < best {
                            best_score = Some(score);
                            best_key = i;
                        }
                    } else {
                        best_score = Some(score);
                        best_key = i;
                    }
                }
            }
            Err(_) => {}
        }
    }

    match best_score {
        None => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Unable to find any valid xored byte buffer",
            ))
        }
        Some(score) => {
            let plaintext_bytes = single_xor(&buf, best_key);
            let plaintext_char_buffer: Vec<char> =
                plaintext_bytes.iter().map(|&x| x as char).collect();

            return Ok((
                format!("{}", plaintext_char_buffer.iter().format("")),
                score,
                best_key,
            ));
        }
    }
}

pub fn word_scorer_string(hex: &str) -> Result<(String, f64, u8), Error> {
    let buf = hex_to_bytes(hex);
    word_scorer_bytes(&buf[..])
}

pub fn find_keysize(ciphertext: &Vec<u8>) -> Result<usize, Error> {
    let mut goal_keysize = None;
    let mut goal_dist = f64::INFINITY;

    for keysize in 2..40 {
        let chunk1 = &ciphertext[0..keysize];
        let chunk2 = &ciphertext[keysize..keysize * 2];
        let chunk3 = &ciphertext[keysize * 2..keysize * 3];
        let chunk4 = &ciphertext[keysize * 3..keysize * 4];

        let dist_1_2 = hamming_distance_bytes(&chunk1, &chunk2);
        let dist_1_3 = hamming_distance_bytes(&chunk1, &chunk3);
        let dist_1_4 = hamming_distance_bytes(&chunk1, &chunk4);
        let dist_2_3 = hamming_distance_bytes(&chunk2, &chunk3);
        let dist_2_4 = hamming_distance_bytes(&chunk2, &chunk4);
        let dist_3_4 = hamming_distance_bytes(&chunk3, &chunk4);

        // TODO: all of this could probably be made nicer with a collection/combination
        let average_dist: f64 = (dist_1_2 + dist_1_3 + dist_1_4 + dist_2_3 + dist_2_4 + dist_3_4)
            as f64
            / (6.0 * keysize as f64);

        if let Some(_) = goal_keysize {
            if average_dist < goal_dist {
                goal_dist = average_dist;
                goal_keysize = Some(keysize);
            }
        } else {
            goal_dist = average_dist;
            goal_keysize = Some(keysize);
        }
    }

    goal_keysize.ok_or_else(|| Error::new(ErrorKind::InvalidData, "Unable to find a keysize"))
}

thread_local!(static CONSISTENT_RANDOM_KEY: Vec<u8> = generate_random_aes_key());

pub fn admin_string_encrypt_challenge(
    input: &str,
    iv: &[u8],
    encrypt: &Fn(&[u8], &[u8], &[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let mut quoted_input = str::replace(input, ";", "\";\"");
    quoted_input = str::replace(&quoted_input[..], "=", "\"=\"");

    let input_bytes = quoted_input.as_bytes();
    let prepend_bytes = "comment1=cooking%20MCs;userdata=".as_bytes();
    let append_bytes = ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes();

    let mut plaintext = Vec::new();

    plaintext.extend_from_slice(&prepend_bytes[..]);
    plaintext.extend_from_slice(&input_bytes[..]);
    plaintext.extend_from_slice(&append_bytes[..]);

    CONSISTENT_RANDOM_KEY.with(|k| encrypt(&k[..], &plaintext[..], &iv[..]))
}

pub fn admin_string_decrypt_and_check(
    ciphertext: &[u8],
    iv: &[u8],
    decrypt: &Fn(&[u8], &[u8], &[u8]) -> Result<Vec<u8>, &'static str>,
) -> bool {
    let mut plaintext = Vec::new();

    CONSISTENT_RANDOM_KEY.with(|k| {
        plaintext = decrypt(&k[..], &ciphertext[..], &iv[..]).expect("Error decrypting");
    });

    let plaintext_string = String::from_utf8_lossy(&plaintext);

    if let Some(_) = plaintext_string.find(";admin=true;") {
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance_test() {
        let distance = hamming_distance_strings("this is a test", "wokka wokka!!!");
        assert_eq!(distance, 37);
    }
}
