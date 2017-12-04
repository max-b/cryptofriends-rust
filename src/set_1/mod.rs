extern crate itertools;
extern crate base64;

use std::u8;
use self::itertools::Itertools;
use self::base64::encode;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for i in 0..(hex.len()/2) {
        let hex_string = &hex[(i*2)..(i*2)+2];
        let res = u8::from_str_radix(hex_string, 16).expect(&format!("Problem with hex {}", hex_string));
        bytes.push(res);
    }

    bytes
}

pub fn hex_to_base64(hex: &str) -> String {
    let bytes: Vec<u8> = hex_to_bytes(hex);
    encode(&bytes)
}

fn xor(buf1: &Vec<u8>, buf2: &Vec<u8>) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    println!("buf.len() = {}", buf1.len());
    for i in 0..buf1.len() {
        bytes.push(buf1[i] ^ buf2[i]);
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
}
