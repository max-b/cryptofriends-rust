pub mod challenge_11;
pub mod challenge_12;
pub mod challenge_13;
pub mod challenge_14;
pub mod challenge_15;
pub mod challenge_16;

use std::path::PathBuf;
use std::str;
use utils::bytes::*;
use utils::crypto::{cbc_decrypt, ecb_decrypt, ecb_encrypt, pkcs_7_pad};
use utils::files::*;

pub fn pkcs_7_pad_string(input: &str, size: usize) -> String {
    assert!(input.len() <= size);

    let input = String::from(input);
    let input_as_bytes = input.as_bytes();

    let padded_bytes = pkcs_7_pad(input_as_bytes, size);

    match str::from_utf8(&padded_bytes) {
        Ok(string) => string.to_string(),
        Err(_) => "nope".to_string(),
    }
}

pub fn aes_cbc() -> String {
    let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ciphertext_path.push("data");
    ciphertext_path.push("set_2");
    ciphertext_path.push("10.txt");

    let base64_decoded_ciphertext = read_base64_file_as_bytes(&ciphertext_path);

    let key = b"YELLOW SUBMARINE";
    let iv = [0u8; 16];

    let decrypted =
        cbc_decrypt(key, &base64_decoded_ciphertext[..], &iv[..]).expect("Error cbc decrypting");

    let decrypted = str::from_utf8(&decrypted).expect("Error converting decrypted bytes to string");

    decrypted.to_string()
}

thread_local!(static CONSISTENT_RANDOM_KEY: Vec<u8> = generate_random_aes_key());

thread_local!(static CONSISTENT_RANDOM_PREFIX: Vec<u8> = random_size_bytes());

pub fn key_value_parser(s: &str) -> Vec<(String, String)> {
    let input = s.to_string();
    let mut result: Vec<(String, String)> = Vec::new();
    let pairs = input.split('&');

    for pair in pairs {
        let mut key_value = pair.split('=');
        let key = key_value.next().expect("no key found");
        let value = key_value.next().expect("no value found");

        result.push((key.to_string(), value.to_string()));
    }

    result
}

pub fn profile_for(s: &str) -> String {
    let stripped = s.to_string().replace("&", "");
    let stripped = stripped.replace("=", "");

    "email=".to_string() + &stripped + "&uid=10&role=user"
}

pub fn encrypted_profile_for(s: &str) -> Vec<u8> {
    let plaintext = profile_for(s);
    let plaintext_bytes = plaintext.as_bytes();

    CONSISTENT_RANDOM_KEY.with(|k| ecb_encrypt(&k[..], &plaintext_bytes[..]))
}

pub fn decrypt_and_parse_profile(ciphertext: &[u8]) -> Vec<(String, String)> {
    CONSISTENT_RANDOM_KEY.with(|k| {
        let plaintext_bytes = ecb_decrypt(&k[..], &ciphertext[..]);
        let plaintext = str::from_utf8(&plaintext_bytes)
            .expect("Cannot create string from decrypted plaintext bytes.")
            .trim();
        key_value_parser(&plaintext[..])
    })
}

pub fn find_block_size(oracle: &Fn(&[u8]) -> Vec<u8>) -> usize {
    let mut test_plaintext = vec![b'A'; 256];
    let mut block_size = 0;

    'outer: for i in 1..256 {
        // assume 1 < block size < 256
        let block_for_testing = vec![b'A'; i * 4];
        test_plaintext.extend_from_slice(&block_for_testing[..]);

        let oracle_output = oracle(&test_plaintext[..]);

        for j in 0..oracle_output.len() - ((i + 1) * 2) {
            if oracle_output[j..=j + i] == oracle_output[j + i + 1..j + ((i + 1) * 2)] {
                block_size = i + 1;
                break 'outer;
            }
        }
    }

    // TODO: change this to Result
    assert!(block_size > 0);
    block_size
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::crypto::{cbc_encrypt};

    #[test]
    fn challenge_9() {
        let padded_string = pkcs_7_pad_string("YELLOW SUBMARINE", 20);
        println!("padded string = {}", padded_string);
        assert_eq!(padded_string.len(), 20);

        let padded_string_2 = pkcs_7_pad_string("YELLOW SUBMARINE", 16);
        println!("padded string2 = {}", padded_string_2);
        assert_eq!(padded_string_2.len(), 32);
    }

    #[test]
    fn challenge_10() {
        let cbc_decrypted = aes_cbc();

        // TODO: Do I want to copy the full text from the set_1 tests?
        // or maybe refactor all the challenge tests entirely?
        assert!(
            cbc_decrypted
                .as_str()
                .contains("Play that funky music white boy you say it,")
        );
    }

    #[test]
    fn test_aes_cbc_encrypt() {
        let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ciphertext_path.push("data");
        ciphertext_path.push("set_2");
        ciphertext_path.push("10.txt");

        println!("{:?}", ciphertext_path);

        let base64_decoded_ciphertext = read_base64_file_as_bytes(&ciphertext_path);

        let key = b"YELLOW SUBMARINE";
        let iv: Vec<u8> = vec![0; 16];

        let decrypted = cbc_decrypt(key, &base64_decoded_ciphertext[..], &iv[..])
            .expect("Error cbc decrypting");

        let encrypted = cbc_encrypt(key, &decrypted[..], &iv[..]);

        assert_eq!(
            &encrypted[..base64_decoded_ciphertext.len()],
            &base64_decoded_ciphertext[..]
        );

        let mut plaintext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        plaintext_path.push("src");
        plaintext_path.push("set_1.rs");

        let plaintext_bytes = read_file_as_bytes(&plaintext_path);

        let key = b"YELLOW SUBMARINE";
        let iv: Vec<u8> = vec![0; 16];

        let encrypted = cbc_encrypt(key, &plaintext_bytes[..], &iv[..]);

        let decrypted = cbc_decrypt(key, &encrypted[..], &iv[..]).expect("Error cbc decrypting");

        assert_eq!(decrypted[..plaintext_bytes.len()], plaintext_bytes[..]);
    }

    #[test]
    fn key_value_parser_test() {
        let result = key_value_parser("foo=bar&baz=qux&zap=zazzle");
        println!("result = {:?}", result);
    }

    #[test]
    fn profile_for_test() {
        let result = profile_for("foo@bar.com");
        assert_eq!(result, "email=foo@bar.com&uid=10&role=user");
        let result = profile_for("foo@bar.com&test=value");
        assert_eq!(result, "email=foo@bar.comtestvalue&uid=10&role=user");
    }

    #[test]
    fn encrypt_and_decrypt_profile() {
        let result = encrypted_profile_for("foo@bar.co");
        println!("encrypted profile = {:?}", result);
        let parsed = decrypt_and_parse_profile(&result[..]);
        println!("parsed = {:?}", parsed);
    }
}
