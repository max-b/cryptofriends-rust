pub mod challenge_25;
pub mod challenge_26;
pub mod challenge_27;
pub mod challenge_28;
pub mod challenge_29;
pub mod challenge_30;
pub mod challenge_31_32;

extern crate reqwest;

use rand::{OsRng, Rng};
use std::fs;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;

pub fn generate_mac_secret() -> Vec<u8> {
    let words_path = PathBuf::from("/usr/share/dict/words");

    let mut rng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e),
    };

    let file = fs::File::open(&words_path).expect("Error opening words file.");
    let buf_reader = BufReader::new(file);
    let num_lines = buf_reader.lines().count();

    let choice = rng.gen_range(0, num_lines);

    // It seems like BufReader consumes the file object,
    // so I *think* re-opening is necessary
    let file = fs::File::open(&words_path).expect("Error opening words file.");
    let buf_reader = BufReader::new(file);
    let word = buf_reader.lines().nth(choice).unwrap().unwrap();

    let mut output = Vec::new();
    output.extend_from_slice(word.as_bytes());
    output
}

thread_local!(static CONSISTENT_MAC_SECRET: Vec<u8> = generate_mac_secret());

pub fn secret_prefix_mac(message: &[u8], hash: &Fn(&[u8], &[u8]) -> Vec<u8>) -> Vec<u8> {
    CONSISTENT_MAC_SECRET.with(|s| hash(&s, &message))
}

pub fn validate_mac(message: &[u8], mac: &[u8], hash: &Fn(&[u8], &[u8]) -> Vec<u8>) -> bool {
    let actual_mac = secret_prefix_mac(&message, hash);
    (actual_mac == mac)
}
