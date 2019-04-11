use utils::crypto::{cbc_decrypt};
use utils::bytes::*;

thread_local!(static CONSISTENT_RANDOM_KEY: Vec<u8> = generate_random_aes_key());

pub fn ascii_compliance(
    ciphertext: &[u8], 
) -> Vec<u8> {
    let mut plaintext = Vec::new();

    CONSISTENT_RANDOM_KEY.with(|k| {
        plaintext = cbc_decrypt(&k, &ciphertext[..], &k).expect("Error decrypting");
    });

    plaintext
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::crypto::{cbc_encrypt};
    use utils::bytes::xor;

    #[test]
    fn challenge_27() {
        let actual_plaintext = "I would love to use a cute emoji here but alas!!!".as_bytes();
        let mut ciphertext = Vec::new();
        let mut padding_ciphertext = Vec::new();

        CONSISTENT_RANDOM_KEY.with(|k| {
            ciphertext = cbc_encrypt(&k, &actual_plaintext, &k);
            padding_ciphertext = cbc_encrypt(&k, &actual_plaintext[0..16], &k);
        });

        let mut modified_ciphertext = Vec::new();
        modified_ciphertext.extend_from_slice(&ciphertext[0..16]);
        modified_ciphertext.extend_from_slice(&vec![0; 16]);
        modified_ciphertext.extend_from_slice(&ciphertext[0..16]);
        modified_ciphertext.extend_from_slice(&padding_ciphertext[16..32]);

        let compliance_results = ascii_compliance(&modified_ciphertext);

        let found_key = xor(&compliance_results[0..16], &compliance_results[32..48]);

        CONSISTENT_RANDOM_KEY.with(|k| {
            assert_eq!(k, &found_key);
        });
    }
}

