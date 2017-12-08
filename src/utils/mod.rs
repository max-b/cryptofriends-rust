extern crate itertools;
extern crate base64;

use std::u8;
use std::str;
use std::collections::HashMap;
use std::ascii::AsciiExt;
use self::itertools::Itertools;
use self::base64::{encode, decode};
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::fs::File;

pub fn xor(buf1: &Vec<u8>, buf2: &Vec<u8>) -> Vec<u8> {
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

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for i in 0..(hex.len()/2) {
        let hex_string = &hex[(i*2)..(i*2)+2];
        let res = u8::from_str_radix(hex_string, 16).expect(&format!("Problem with hex {}", hex_string));
        bytes.push(res);
    }

    bytes
}

pub fn base64_to_bytes(string: &str) -> Vec<u8> {
    decode(&string).expect("error decoding base64 string")
}

pub fn hex_to_base64(hex: &str) -> String {
    let bytes: Vec<u8> = hex_to_bytes(hex);
    encode(&bytes)
}

pub fn bytes_to_hex(buf: &Vec<u8>) -> String {
    let result = buf.iter().format("");

    format!("{:02x}", result)
}

pub fn xor_hex_strings(hex1: &str, hex2: &str) -> String {
    let buf1 = hex_to_bytes(hex1);
    let buf2 = hex_to_bytes(hex2);

    let bytes = xor(&buf1, &buf2);

    bytes_to_hex(&bytes)
}

pub fn repeating_key_xor(buf: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();

    let mut key_iter = key.into_iter().cycle();

    for i in buf.into_iter() {
        result.push(key_iter.next().unwrap() ^ i);
    }

    result
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

pub fn hamming_distance_strings(str1: &str, str2: &str) -> usize {
    let buf1 = str1.as_bytes();
    let buf2 = str2.as_bytes();

    hamming_distance_bytes(&buf1, &buf2)
}

pub fn hamming_distance_bytes(buf1: &[u8], buf2: &[u8]) -> usize {
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
                        if score < best{
                            best_score = Some(score);
                            best_key = i;
                        }
                    } else {
                        best_score = Some(score);
                        best_key = i;
                    }
                }
            },
            Err(_) => {},
        }
    }

    match best_score {
        None => return Err(Error::new(ErrorKind::InvalidData, "Unable to find any valid xored byte buffer")),
        Some(score) => {
            let plaintext_bytes = single_xor(&buf, best_key);
            let plaintext_char_buffer: Vec<char> = plaintext_bytes.iter().map(|&x| x as char).collect();

            return Ok((format!("{}", plaintext_char_buffer.iter().format("")), score, best_key));
        },
    }
}

pub fn word_scorer_string(hex: &str) ->  Result<(String, f64, u8), Error> {
    let buf = hex_to_bytes(hex);
    word_scorer_bytes(&buf[..])
}

fn read_file_as_bytes(path: &PathBuf) -> Vec<u8> {
    let mut file = File::open(&path).expect("Error opening ciphertext file.");

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Error reading ciphertext file.");

    buffer
}

pub fn read_base64_file_as_bytes(path: &PathBuf) -> Vec<u8>  {
    let buffer = read_file_as_bytes(&path);

    base64_to_bytes(&str::from_utf8(&buffer).expect("Error reading string from_utf8 bytes").replace('\n', ""))
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

