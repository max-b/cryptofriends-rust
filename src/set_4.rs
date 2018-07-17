use std::fs;
use rand::distributions::{IndependentSample, Range};
use std::path::PathBuf;
use std::io::BufReader;
use std::io::prelude::*;
use utils::bytes::*;
use utils::files::*;
use utils::crypto::{aes_ctr, ecb_decrypt, sha1};
use rand::{OsRng};


thread_local!(static CONSISTENT_RANDOM_KEY: Vec<u8> = generate_random_aes_key());

pub fn challenge_25_encrypt() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {

    let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ciphertext_path.push("data");
    ciphertext_path.push("set_4");
    ciphertext_path.push("25.txt");

    let base64_decoded_ciphertext = read_base64_file_as_bytes(&ciphertext_path);

    let key = "YELLOW SUBMARINE".as_bytes();

    let plaintext = ecb_decrypt(key, &base64_decoded_ciphertext[..]);

    let nonce: Vec<u8> = vec![0; 8];

    CONSISTENT_RANDOM_KEY.with(|k| {
        let ciphertext = aes_ctr(&k[..], &plaintext[..], &nonce[..]);

        (ciphertext, plaintext,  k.clone(), nonce)
    })
}

pub fn generate_mac_secret() -> Vec<u8> {
    let words_path = PathBuf::from("/usr/share/dict/words");

    let mut rng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e),
    };

    let file = fs::File::open(&words_path).expect("Error opening words file.");
    let buf_reader = BufReader::new(file);
    let num_lines = buf_reader.lines().count();

    let random_range = Range::new(0, num_lines);
    let choice = random_range.ind_sample(&mut rng);

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

    CONSISTENT_MAC_SECRET.with(|s| {
        let digest = sha1(&s, &message);
        digest
    })
}

pub fn validate_mac(message: &[u8], mac: &[u8]) -> bool {
    let actual_mac = secret_prefix_mac(&message);
    (actual_mac == mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::crypto::{md_padding, md_padding_with_length, sha1_registers, sha1, edit_aes_ctr};
    use utils::misc::*;

    #[test]
    fn challenge_25() {
        let (ciphertext, actual_plaintext, actual_key, nonce) = challenge_25_encrypt();

        let mut discovered_plaintext = Vec::new();
        for i in 0..ciphertext.len() {
            let mut found_byte = None;
            for byte in 0..255 {
                let new_ciphertext = edit_aes_ctr(&ciphertext[..], &actual_key[..], &nonce[..], i, &[byte]);
                if &new_ciphertext[..] == &ciphertext[..] {
                    found_byte = Some(byte);
                    break;
                }
            }
            let byte = found_byte.expect(&format!("Error finding byte at position {:?}", i));
            discovered_plaintext.push(byte);
        }

        let discovered_plaintext_string = String::from_utf8_lossy(&discovered_plaintext[..]);
        println!("Discovered plaintext string: {:?}", discovered_plaintext_string);

        assert_eq!(&actual_plaintext[..], &discovered_plaintext[..]);
    }

    #[test]
    fn challenge_26() {
        let iv: Vec<u8> = vec![0; 8];
        let encrypted = admin_string_encrypt_challenge("testing 123;admin=true;blah", &iv[..], &aes_ctr);
        let decrypted_contains_admin = admin_string_decrypt_and_check(&encrypted[..], &iv[..], &|key, ciphertext, nonce | { Ok(aes_ctr(&key[..], &ciphertext[..], &nonce[..])) });
        assert!(!decrypted_contains_admin);

        // prepend string is 32 bytes
        let mut encrypted = admin_string_encrypt_challenge("\x00admin\x00true", &iv[..], &aes_ctr);
        encrypted[32] ^= 59; // ascii ";"
        encrypted[38] ^= 61; // ascii "="

        let decrypted_contains_admin = admin_string_decrypt_and_check(&encrypted[..], &iv[..], &|key, ciphertext, nonce | { Ok(aes_ctr(&key[..], &ciphertext[..], &nonce[..])) });
        assert!(decrypted_contains_admin);
    }

    #[test]
    fn challenge_28() {
        let hashed = sha1("".as_bytes(), "hello world".as_bytes());
        let hashed_str = bytes_to_hex(&hashed);
        assert_eq!(hashed_str, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");

        let hashed = sha1("key".as_bytes(), "message".as_bytes());
        let hashed_str = bytes_to_hex(&hashed);
        assert_eq!(hashed_str, "7d89ca5f9535d3bd925ca99f484ae4413a14fe2d");

        let hashed = sha1("notthekey".as_bytes(), "message".as_bytes());
        let hashed_str = bytes_to_hex(&hashed);
        assert_ne!(hashed_str, "7d89ca5f9535d3bd925ca99f484ae4413a14fe2d");
    }

    #[test]
    fn challenge_29() {

        let hashed_message = secret_prefix_mac("testing".as_bytes());

        let hashed_message2 = secret_prefix_mac("testing".as_bytes());

        assert_eq!(hashed_message, hashed_message2);

        let original_string = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".as_bytes();

        let original_hash = secret_prefix_mac(&original_string);

        let (mut a, mut b, mut c, mut d, mut e) = (0u32, 0u32, 0u32, 0u32, 0u32);

        for i in 0..4 {
            a = a | ((original_hash[i] as u32) << (8 * i));
            b = b | ((original_hash[i + 4] as u32) << (8 * i));
            c = c | ((original_hash[i + 8] as u32) << (8 * i));
            d = d | ((original_hash[i + 12] as u32) << (8 * i));
            e = e | ((original_hash[i + 16] as u32) << (8 * i));
        }

        let mut found_signature = None;
        let mut test_password = String::new();
        for _i in 1..20 { // check up to 20 character long secrets
            test_password.push('A');
            let mut check_padding_bytes = Vec::new();
            check_padding_bytes.extend_from_slice(test_password.as_bytes());
            check_padding_bytes.extend_from_slice(&original_string);

            let padding = md_padding(&check_padding_bytes);

            let mut forged_bytes = Vec::new();
            forged_bytes.extend_from_slice(&original_string);
            forged_bytes.extend_from_slice(&padding);
            forged_bytes.extend_from_slice(";admin=true".as_bytes());

            let forged_bytes_len = forged_bytes.len();
            let mut new_message = Vec::new();
            new_message.extend_from_slice(";admin=true".as_bytes());
            let new_message_padding = md_padding_with_length(&forged_bytes, forged_bytes_len + test_password.len());
            new_message.extend_from_slice(&new_message_padding);

            let forged_mac = sha1_registers(a.to_be(), b.to_be(), c.to_be(), d.to_be(), e.to_be(), &new_message);

            if validate_mac(&forged_bytes, &forged_mac) {
                found_signature = Some(forged_mac);
            }
        }
        assert!(found_signature.is_some());
        println!("found_signature = {:?}", found_signature.unwrap());
    }
}
