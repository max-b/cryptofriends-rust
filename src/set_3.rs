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

pub fn reused_nonce_encrypt_strings(filename: &str) -> (Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
    let mut strings_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    strings_path.push("data");
    strings_path.push("set_3");
    strings_path.push(filename);

    let strings_file = File::open(&strings_path).expect("Error reading strings file.");

    let strings_file_as_reader = BufReader::new(strings_file);

    let nonce: Vec<u8> = vec![0; 8];

    CONSISTENT_RANDOM_KEY.with(|k| {
        let strings: Vec<_> = strings_file_as_reader.lines().map(|l| {
            let string = utils::base64_to_bytes(&l.unwrap()[..]);
            let result = utils::aes_ctr(&k[..], &string[..], &nonce[..]);
            result
        }).collect();
        (strings, nonce, k.clone())
    })
}

pub fn break_repeated_nonce_statistically(ciphertext_list: &[Vec<u8>]) -> Vec<u8> {
    let mut result = Vec::from(ciphertext_list);

    let min_ciphertext_len = result.iter().min_by(|x, y| x.len().cmp(&y.len())).unwrap().len();

    for ciphertext in &mut result {
        ciphertext.truncate(min_ciphertext_len);
    }

    let mut transposed: Vec<Vec<u8>> = vec![vec![]; min_ciphertext_len];
    for string in &result {
        for i in 0..string.len() {
            let item = string[i];
            transposed[i].push(item);
        }
    }

    let mut key_vector: Vec<u8> = Vec::new();

    for block in transposed {
        if let Ok((_, _, key)) = utils::word_scorer_bytes(&block[..]) {
            key_vector.push(key);
        } else {
            print!("Can't run word scorer on this block..");
        }
    }

    let flattened_strings: Vec<u8> = result.into_iter().flat_map(|s| s).collect();



    let decrypted_buf = utils::repeating_key_xor(&flattened_strings[..], &key_vector[..]);
    decrypted_buf
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

    #[test]
    fn challenge_19() {
        let (result, _nonce, _actual_key) = reused_nonce_encrypt_strings("19.txt");

        println!("result = {:?}", result);
        println!("result len = {}", result.len());
    }

    #[test]
    fn challenge_20() {
        let (result, _nonce, _actual_key) = reused_nonce_encrypt_strings("20.txt");

        let actual_plaintext_string_snippet = "i\'m rated \"R\"...this is a warning, ya better void / Pcuz I came back to attack others in spite- / Strike lbut don\'t be afraid in the dark, in a park / Not a scya tremble like a alcoholic, muscles tighten up / Whasuddenly you feel like your in a horror flick / You gmusic\'s the clue, when I come your warned / Apocalypshaven\'t you ever heard of a MC-murderer? / This is thdeath wish, so come on, step to this / Hysterical idefriday the thirteenth, walking down Elm Street / You this is off limits, so your visions are blurry / All terror in the styles, never error-files / Indeed I\'m for those that oppose to be level or next to this / Iworse than a nightmare, you don\'t have to sleep a winflashbacks interfere, ya start to hear: / The R-A-K-Ithen the beat is hysterical / That makes Eric go get soon the lyrical format is superior / Faces of death mC\'s decaying, cuz they never stayed / The scene of athe fiend of a rhyme on the mic that you know / It\'s melodies-unmakable, pattern-unescapable / A horn if wi bless the child, the earth, the gods and bomb the rhazardous to your health so be friendly";

        let plaintext_result = break_repeated_nonce_statistically(&result[..]);
        let plaintext_string_result = String::from_utf8_lossy(&plaintext_result[..]);
        println!("plaintext_string_result = {:?}", plaintext_string_result);
        assert!(plaintext_string_result.contains(actual_plaintext_string_snippet));

    }
}
