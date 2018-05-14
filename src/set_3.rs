use std::io::BufReader;
use std::io::prelude::*;
use std::path::PathBuf;
use std::fs::File;
use rand::distributions::{IndependentSample, Range};
use rand::{OsRng};
use std::cmp::Ordering;
use utils;

thread_local!(static CONSISTENT_RANDOM_KEY: Vec<u8> = utils::generate_random_aes_key());

pub fn challenge_17_encrypt(string_num: Option<usize>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut strings_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    strings_path.push("data");
    strings_path.push("set_3");
    strings_path.push("17.txt");

    let strings_file = File::open(&strings_path).expect("Error reading strings file.");

    let strings_file_as_reader = BufReader::new(strings_file);

    let strings: Vec<_> = strings_file_as_reader.lines().map(|l| l.unwrap()).collect();

    let mut rng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e)
    };

    let num = match string_num {
        Some(n) => n,
        None => {
            let sample = Range::new(0, strings.len());
            sample.ind_sample(&mut rng) as usize
        },
    };

    let chosen_string: &String = strings.get(num).unwrap();
    let plaintext = utils::base64_to_bytes(chosen_string);

    let iv: Vec<u8> = vec![0; 16];

    CONSISTENT_RANDOM_KEY.with(|k| {
        (utils::cbc_encrypt(&k[..], &plaintext[..], &iv[..]), iv, plaintext) 
    })
}

pub fn challenge_17_padding_oracle(ciphertext: &[u8], iv: &[u8]) -> bool {
    let mut decrypted = None;
    CONSISTENT_RANDOM_KEY.with(|k| {
        decrypted = Some(utils::cbc_decrypt(&k[..], &ciphertext[..], &iv[..]));
    });

    let decrypted_result = decrypted.unwrap();

    if let Ok(_) = decrypted_result {
        true
    } else {
        false
    }
}

pub fn exploit_padding_oracle(oracle: &Fn(&[u8], &[u8]) -> bool, ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
    let block_size = iv.len();

    let mut plaintext: Vec<u8> = Vec::new();
    let mut ciphertext_blocks = Vec::new();
    ciphertext_blocks.extend_from_slice(&ciphertext);

    let mut ciphertext_blocks = ciphertext_blocks.chunks_mut(block_size);

    let mut ivs = Vec::new();
    ivs.extend_from_slice(&iv);
    ivs.extend_from_slice(&ciphertext);

    let mut ivs = ivs.chunks_mut(block_size);

    for block in &mut ciphertext_blocks {
        assert_eq!(block.len(), block_size);
        let mut plaintext_block = vec![0; block.len()];
        let mut decrypt_output = vec![0; block.len()];
        let mut original_iv = ivs.next().expect("somehow overran ivs?");
        let mut iv = Vec::new();
        iv.extend_from_slice(&original_iv);
        for block_index in (0..(*block).len()).rev() {
            let padding_index = block_size - block_index;

            for i in block_index..block_size {
                iv[i] = decrypt_output[i] ^ padding_index as u8;
            }

            let mut valid_options: Vec<(u8, u8)> = Vec::new();
            for test_byte in 0..=255 {
                iv[block_index] = test_byte;

                let valid = oracle(&block[..], &iv[..]);
                if valid {
                    let decrypted_byte = test_byte ^ (padding_index as u8);
                    let plaintext_byte = decrypted_byte ^ original_iv[block_index];
                    valid_options.push((decrypted_byte, plaintext_byte));
                }
            }

            valid_options.sort_by(|(_, p1), (_, p2)| {
                if p1.is_ascii_alphanumeric() {
                    return Ordering::Greater;
                }
                if p2.is_ascii_punctuation() {
                    return Ordering::Less;
                }
                if p1.is_ascii_punctuation() {
                    return Ordering::Greater;
                }
                if p2.is_ascii_punctuation() {
                    return Ordering::Less;
                }
                if *p1 > 122 {
                    return Ordering::Less;
                }
                if *p2 > 122 {
                    return Ordering::Greater;
                }
                p2.cmp(&p1)
            });

            match valid_options.first() {
                Some((decrypted_byte, plaintext_byte)) => {
                    plaintext_block[block_index] = *plaintext_byte;
                    decrypt_output[block_index] = *decrypted_byte;
                },
                None => {
                    println!("No valid option found...");
                }
            }
        } 
        plaintext.extend_from_slice(&plaintext_block[..]);
    }

    plaintext
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_17() {
        for i in 0..10 {
            let (ciphertext, iv, plaintext) = challenge_17_encrypt(Some(i));
            let padded_plaintext = utils::pkcs_7_pad(&plaintext[..], iv.len());
            let plaintext_string = String::from_utf8_lossy(&plaintext[..]).into_owned();
            let oracle_result = challenge_17_padding_oracle(&ciphertext[..], &iv[..]);
            assert!(oracle_result);

            let result = exploit_padding_oracle(&challenge_17_padding_oracle, &ciphertext[..], &iv[..]);
            let plaintext_string_result = String::from_utf8_lossy(&result[..]);
            println!("\n\nplaintext    = {:?}", &plaintext[..]);
            println!("padded plaintext = {:?}", &padded_plaintext[..]);
            println!("result           = {:?}", result);
            println!("plaintext_string        = {:?}", plaintext_string);
            println!("plaintext_string_result = {:?}", plaintext_string_result);
            assert_eq!(&padded_plaintext[..], &result[..]);
        }
    }

    #[test]
    fn challenge_18() {
        let base64_challenge_ciphertext_string = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
        let challenge_ciphertext = utils::base64_to_bytes(&base64_challenge_ciphertext_string);
        let key = "YELLOW SUBMARINE".as_bytes();
        let nonce: Vec<u8> = vec![0; 8];

        let result = utils::aes_ctr(&key[..], &challenge_ciphertext[..], &nonce[..]);

        println!("result = {:?}", result);
        let plaintext_string_result = String::from_utf8_lossy(&result[..]);
        println!("plaintext_string_result = {:?}", plaintext_string_result);
        let actual_plaintext_string_result = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";

        assert_eq!(&actual_plaintext_string_result[..], &plaintext_string_result[..]);
    }
}
