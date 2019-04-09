use rand::{OsRng, Rng};
use std::fs;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;
use utils::crypto::{sha1};

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

pub fn secret_prefix_mac(message: &[u8]) -> Vec<u8> {
    CONSISTENT_MAC_SECRET.with(|s| sha1(&s, &message))
}

pub fn validate_mac(message: &[u8], mac: &[u8]) -> bool {
    let actual_mac = secret_prefix_mac(&message);
    (actual_mac == mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::crypto::{md_padding, md_padding_with_length, sha1_registers};

    #[test]
    fn challenge_29() {
        let hashed_message = secret_prefix_mac(b"testing");

        let hashed_message2 = secret_prefix_mac(b"testing");

        assert_eq!(hashed_message, hashed_message2);

        let original_string =
            b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

        let original_hash = secret_prefix_mac(&original_string[..]);

        let (mut a, mut b, mut c, mut d, mut e) = (0u32, 0u32, 0u32, 0u32, 0u32);

        for i in 0..4 {
            a |= u32::from(original_hash[i]) << (8 * i);
            b |= u32::from(original_hash[i + 4]) << (8 * i);
            c |= u32::from(original_hash[i + 8]) << (8 * i);
            d |= u32::from(original_hash[i + 12]) << (8 * i);
            e |= u32::from(original_hash[i + 16]) << (8 * i);
        }

        let mut found_signature = None;
        let mut test_password = String::new();
        for _i in 1..20 {
            // check up to 20 character long secrets
            test_password.push('A');
            let mut check_padding_bytes = Vec::new();
            check_padding_bytes.extend_from_slice(test_password.as_bytes());
            check_padding_bytes.extend_from_slice(&original_string[..]);

            let padding = md_padding(&check_padding_bytes);

            let mut forged_bytes = Vec::new();
            forged_bytes.extend_from_slice(&original_string[..]);
            forged_bytes.extend_from_slice(&padding);
            forged_bytes.extend_from_slice(b";admin=true");

            let forged_bytes_len = forged_bytes.len();
            let mut new_message = Vec::new();
            new_message.extend_from_slice(b";admin=true");
            let new_message_padding =
                md_padding_with_length(&forged_bytes, forged_bytes_len + test_password.len());
            new_message.extend_from_slice(&new_message_padding);

            let forged_mac = sha1_registers(
                a.to_be(),
                b.to_be(),
                c.to_be(),
                d.to_be(),
                e.to_be(),
                &new_message,
            );

            if validate_mac(&forged_bytes, &forged_mac) {
                found_signature = Some(forged_mac);
            }
        }
        assert!(found_signature.is_some());
        println!("found_signature = {:?}", found_signature.unwrap());
    }
}
