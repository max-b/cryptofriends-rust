use base64::{decode, encode};
use itertools::Itertools;
use rand::distributions::{IndependentSample, Range};
use rand::{OsRng, RngCore};

pub fn xor(buf1: &[u8], buf2: &[u8]) -> Vec<u8> {
    assert_eq!(buf1.len(), buf2.len());
    let mut bytes: Vec<u8> = Vec::with_capacity(buf1.len());
    for i in 0..buf1.len() {
        bytes.push(buf1[i] ^ buf2[i]);
    }

    bytes
}

pub fn single_xor(buf: &[u8], key: u8) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(buf.len());
    for i in buf.into_iter() {
        bytes.push(i ^ key);
    }

    bytes
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(hex.len() / 2);
    for i in 0..(hex.len() / 2) {
        let hex_string = &hex[(i * 2)..(i * 2) + 2];
        let res =
            u8::from_str_radix(hex_string, 16).expect(&format!("Problem with hex {}", hex_string));
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

pub fn bytes_to_hex(buf: &[u8]) -> String {
    let result = buf.iter().format("");

    format!("{:02x}", result)
}

pub fn xor_hex_strings(hex1: &str, hex2: &str) -> String {
    let buf1 = hex_to_bytes(hex1);
    let buf2 = hex_to_bytes(hex2);

    let bytes = xor(&buf1[..], &buf2[..]);

    bytes_to_hex(&bytes)
}

pub fn repeating_key_xor(buf: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(buf.len());

    let mut key_iter = key.into_iter().cycle();

    for i in buf.into_iter() {
        result.push(key_iter.next().unwrap() ^ i);
    }

    result
}

pub fn random_size_bytes() -> Vec<u8> {
    let mut rng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e),
    };

    let size = Range::new(0, 256);

    random_bytes(size.ind_sample(&mut rng))
}

pub fn random_bytes(size: u32) -> Vec<u8> {
    let mut rng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e),
    };

    let mut bytes = vec![0u8; size as usize];
    rng.fill_bytes(&mut bytes[..]);

    bytes
}

pub fn generate_random_aes_key() -> Vec<u8> {
    // There's a conflict between using AesSafe1238Decryptor.block_size()
    // above and hardcoding 16 here, but not that big of deal
    random_bytes(16)
}

pub fn pad_bytes(input: &[u8], byte: u8, num: usize) -> Vec<u8> {
    let mut padded = input.to_vec();

    for _ in 0..num {
        padded.push(byte);
    }

    padded
}
