use std::path::PathBuf;
use utils::bytes::*;
use utils::crypto::{aes_ctr, ecb_decrypt};
use utils::files::read_base64_file_as_bytes;

thread_local!(static CONSISTENT_RANDOM_KEY: Vec<u8> = generate_random_aes_key());

pub fn challenge_25_encrypt() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ciphertext_path.push("data");
    ciphertext_path.push("set_4");
    ciphertext_path.push("25.txt");

    let base64_decoded_ciphertext = read_base64_file_as_bytes(&ciphertext_path);

    let key = b"YELLOW SUBMARINE";

    let plaintext = ecb_decrypt(key, &base64_decoded_ciphertext[..]);

    let nonce: Vec<u8> = vec![0; 8];

    CONSISTENT_RANDOM_KEY.with(|k| {
        let ciphertext = aes_ctr(&k[..], &plaintext[..], &nonce[..]);

        (ciphertext, plaintext, k.clone(), nonce)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::crypto::edit_aes_ctr;

    #[test]
    fn challenge_25() {
        let (ciphertext, actual_plaintext, actual_key, nonce) = challenge_25_encrypt();

        let mut discovered_plaintext = Vec::new();
        for i in 0..ciphertext.len() {
            let mut found_byte = None;
            for byte in 0..255 {
                let new_ciphertext =
                    edit_aes_ctr(&ciphertext[..], &actual_key[..], &nonce[..], i, &[byte]);
                if new_ciphertext == ciphertext {
                    found_byte = Some(byte);
                    break;
                }
            }
            let byte =
                found_byte.unwrap_or_else(|| panic!("Error finding byte at position {:?}", i));

            discovered_plaintext.push(byte);
        }

        let discovered_plaintext_string = String::from_utf8_lossy(&discovered_plaintext[..]);
        println!(
            "Discovered plaintext string: {:?}",
            discovered_plaintext_string
        );

        assert_eq!(&actual_plaintext[..], &discovered_plaintext[..]);
    }
}
