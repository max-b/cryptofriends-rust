use std::u8;
use std::f64;
use std::str;
use std::collections::HashMap;
use std::ascii::AsciiExt;
use itertools::Itertools;
use base64::{encode, decode};
use crypto::aessafe;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::fs::File;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};
use rand::distributions::{IndependentSample, Range};
use rand::{OsRng, Rng};

pub fn xor(buf1: &[u8], buf2: &[u8]) -> Vec<u8> {
    assert_eq!(buf1.len(), buf2.len());
    let mut bytes: Vec<u8> = Vec::with_capacity(buf1.len());
    for i in 0..buf1.len() {
        bytes.push(buf1[i] ^ buf2[i]);
    }

    bytes
}

fn single_xor(buf: &[u8], key: u8) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(buf.len());
    for i in buf.into_iter() {
        bytes.push(i ^ key);
    }

    bytes
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(hex.len()/2);
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

pub fn read_file_as_bytes(path: &PathBuf) -> Vec<u8> {
    println!("{:?}", path);
    let mut file = File::open(&path).expect("Error opening ciphertext file.");

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Error reading ciphertext file.");

    buffer
}

pub fn read_base64_file_as_bytes(path: &PathBuf) -> Vec<u8>  {
    let buffer = read_file_as_bytes(&path);

    base64_to_bytes(&str::from_utf8(&buffer).expect("Error reading string from_utf8 bytes").replace('\n', ""))
}

pub fn find_keysize(ciphertext: &Vec<u8>) -> Result<usize, Error> {

    let mut goal_keysize = None;
    let mut goal_dist = f64::INFINITY;

    for keysize in 2..40 {

        let chunk1 = &ciphertext[0..keysize];
        let chunk2 = &ciphertext[keysize..keysize*2];
        let chunk3 = &ciphertext[keysize*2..keysize*3];
        let chunk4 = &ciphertext[keysize*3..keysize*4];

        let dist_1_2 = hamming_distance_bytes(&chunk1, &chunk2);
        let dist_1_3 = hamming_distance_bytes(&chunk1, &chunk3);
        let dist_1_4 = hamming_distance_bytes(&chunk1, &chunk4);
        let dist_2_3 = hamming_distance_bytes(&chunk2, &chunk3);
        let dist_2_4 = hamming_distance_bytes(&chunk2, &chunk4);
        let dist_3_4 = hamming_distance_bytes(&chunk3, &chunk4);

        // TODO: all of this could probably be made nicer with a collection/combination
        let average_dist: f64 = (dist_1_2 + dist_1_3 + dist_1_4 + dist_2_3 + dist_2_4 + dist_3_4) as f64 / (6.0 * keysize as f64);

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

pub fn pkcs_7_pad(input: &[u8], size: usize) -> Vec<u8> {
    let mut padded = input.to_vec();

    let mut difference = if input.len() < size {
        size - input.len()
    } else {
        size - (input.len() % size)
    };

    if difference == 0 {
        difference = size;
    }

    for _ in 0..difference {
        padded.push(difference as u8);
    }

    padded
}

pub fn pkcs_7_unpad(input: &[u8]) -> Vec<u8> {
    let amount_padded = input[input.len() - 1];
    input[..input.len() - amount_padded as usize].to_vec()
}

pub fn strip_pkcs_padding(input: &[u8]) -> Result<Vec<u8>, &'static str> {

    let last = match input.last() {
       None => return Err("input must be nonzero length"),
       Some(&l) => l,
    };

    if last as usize > input.len() {
        return Err("Invalid pkcs")
    }

    let mut padding = Vec::new();
    padding.extend_from_slice(&input[input.len() - last as usize..]);

    for i in padding {
        if i != last {
            return Err("Invalid pkcs")
        }
    }

    Ok(pkcs_7_unpad(input))
}

pub fn ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {

    let decryptor = aessafe::AesSafe128Decryptor::new(&key);

    let mut decrypted: Vec<u8> = vec![0; ciphertext.len()];

    let block_size = decryptor.block_size();

    let mut chunk_index = 0;

    while chunk_index < ciphertext.len() {
        decryptor.decrypt_block(&ciphertext[chunk_index..chunk_index+block_size], &mut decrypted[chunk_index..chunk_index+block_size]);
        chunk_index += block_size;
    }

    pkcs_7_unpad(&decrypted[..])
}

pub fn ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {

    let encryptor = aessafe::AesSafe128Encryptor::new(&key);

    let block_size = encryptor.block_size();

    let plaintext = pkcs_7_pad(plaintext, block_size);
    let mut encrypted: Vec<u8> = vec![0; plaintext.len()];

    let mut chunk_index = 0;

    for block in plaintext.chunks(block_size) {
        encryptor.encrypt_block(&block, &mut encrypted[chunk_index..chunk_index+block_size]);
        chunk_index += block_size;
    }

    encrypted
}

pub fn cbc_decrypt(key: &[u8], ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {

    let decryptor = aessafe::AesSafe128Decryptor::new(&key);

    let block_size = decryptor.block_size();

    assert!(ciphertext.len() % block_size == 0);

    let mut decrypted: Vec<u8> = vec![0; ciphertext.len()];

    let mut chunk_index = 0;

    let mut decrypt_output: Vec<u8> = vec![0; block_size];

    while chunk_index < ciphertext.len() {

        let decryption_slice: &mut[u8] = &mut decrypted[chunk_index..chunk_index+block_size];

        decryptor.decrypt_block(&ciphertext[chunk_index..chunk_index+block_size], &mut decrypt_output[..]);

        let plaintext = if chunk_index == 0 {
            xor(&decrypt_output[..], iv)
        } else {
            let previous_ciphertext = &ciphertext[chunk_index-block_size..chunk_index];
            xor(&decrypt_output[..], previous_ciphertext)
        };

        decryption_slice.copy_from_slice(&plaintext[..]);

        chunk_index += block_size;
    }

    pkcs_7_unpad(&decrypted[..])
}

pub fn cbc_encrypt(key: &[u8], plaintext: &[u8], iv: &[u8]) -> Vec<u8> {

    let encryptor = aessafe::AesSafe128Encryptor::new(&key);

    let block_size = encryptor.block_size();

    let plaintext = pkcs_7_pad(plaintext, block_size);

    let mut encrypted: Vec<u8> = vec![0; plaintext.len()];

    let mut chunk_index = 0;

    let mut plaintext_slice: Vec<u8> = vec![0; block_size];
    let mut previous_ciphertext_block: Vec<u8> = iv.to_vec();

    while chunk_index < plaintext.len() {

        plaintext_slice.copy_from_slice(&plaintext[chunk_index..chunk_index+block_size]);

        let iv_xor_plaintext = xor(&plaintext_slice[..], &previous_ciphertext_block[..]);

        encryptor.encrypt_block(&iv_xor_plaintext[..], &mut encrypted[chunk_index..chunk_index+block_size]);

        previous_ciphertext_block.copy_from_slice(&encrypted[chunk_index..chunk_index+block_size]);

        chunk_index += block_size;
    }

    encrypted
}

pub fn random_size_bytes() -> Vec<u8> {

    let mut rng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e)
    };

    let size = Range::new(0, 256);

    random_bytes(size.ind_sample(&mut rng))
}

pub fn random_bytes(size: u32) -> Vec<u8> {

    let mut rng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e)
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



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance_test() {
        let distance = hamming_distance_strings("this is a test", "wokka wokka!!!");
        assert_eq!(distance, 37);
    }
}

