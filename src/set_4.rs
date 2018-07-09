use std::path::PathBuf;
use utils::bytes::*;
use utils::files::*;
use utils::crypto::{aes_ctr, ecb_decrypt};


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

#[cfg(test)]
mod tests {
    use super::*;
    use utils::crypto::{edit_aes_ctr};
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
}
