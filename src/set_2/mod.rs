extern crate crypto;

use std::str;
use ::utils;
use std::path::PathBuf;


pub fn pkcs_7_pad_string(input: &str, size: usize) -> String {
    assert!(input.len() <= size);

    let input = String::from(input);
    let input_as_bytes = input.as_bytes();

    let padded_bytes = utils::pkcs_7_pad(input_as_bytes, size);

    match str::from_utf8(&padded_bytes) {
        Ok(string) => {
            string.to_string()
        },
        Err(_) => { "nope".to_string() },
    }
}

pub fn aes_cbc() -> String {
    let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ciphertext_path.push("data");
    ciphertext_path.push("set_2");
    ciphertext_path.push("10.txt");

    let base64_decoded_ciphertext = utils::read_base64_file_as_bytes(&ciphertext_path);

    let key = "YELLOW SUBMARINE".as_bytes();
    let iv: Vec<u8> = vec![0; 16];

    let decrypted = utils::cbc_decrypt(key, &base64_decoded_ciphertext[..], &iv[..]);

    let decrypted = str::from_utf8(&decrypted).expect("Error converting decrypted bytes to string");

    decrypted.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_9() {
        let padded_string = pkcs_7_pad_string("YELLOW SUBMARINE", 20);
        assert_eq!(padded_string.len(), 20);

        let padded_string_2 = pkcs_7_pad_string("YELLOW SUBMARINE", 16);
        assert_eq!(padded_string_2.len(), 16);
    }


    #[test]
    fn challenge_10() {
        let cbc_decrypted = aes_cbc();

        // TODO: Do I want to copy the full text from the set_1 tests?
        // or maybe refactor all the challenge tests entirely?
        assert!(cbc_decrypted.as_str().contains("Play that funky music white boy you say it,"));
    }

    #[test]
    fn aes_cbc_encrypt() {
        let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ciphertext_path.push("data");
        ciphertext_path.push("set_2");
        ciphertext_path.push("10.txt");

        let base64_decoded_ciphertext = utils::read_base64_file_as_bytes(&ciphertext_path);

        let key = "YELLOW SUBMARINE".as_bytes();
        let iv: Vec<u8> = vec![0; 16];

        let decrypted = utils::cbc_decrypt(key, &base64_decoded_ciphertext[..], &iv[..]);

        let encrypted = utils::cbc_encrypt(key, &decrypted[..], &iv[..]);

        assert_eq!(encrypted, base64_decoded_ciphertext);

        let mut plaintext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        plaintext_path.push("src");
        plaintext_path.push("set_1");
        plaintext_path.push("mod.rs");

        let plaintext_bytes = utils::read_file_as_bytes(&plaintext_path);

        let key = "YELLOW SUBMARINE".as_bytes();
        let iv: Vec<u8> = vec![0; 16];

        let encrypted = utils::cbc_encrypt(key, &plaintext_bytes[..], &iv[..]);

        let decrypted = utils::cbc_decrypt(key, &encrypted[..], &iv[..]);

        assert_eq!(decrypted[..plaintext_bytes.len()], plaintext_bytes[..]);
    }


}

