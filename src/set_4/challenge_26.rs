#[cfg(test)]
mod tests {
    use utils::crypto::aes_ctr;
    use utils::misc::*;

    #[test]
    fn challenge_26() {
        let iv: Vec<u8> = vec![0; 8];
        let encrypted =
            admin_string_encrypt_challenge("testing 123;admin=true;blah", &iv[..], &aes_ctr);
        let decrypted_contains_admin =
            admin_string_decrypt_and_check(&encrypted[..], &iv[..], &|key, ciphertext, nonce| {
                Ok(aes_ctr(&key[..], &ciphertext[..], &nonce[..]))
            });
        assert!(!decrypted_contains_admin);

        // prepend string is 32 bytes
        let mut encrypted = admin_string_encrypt_challenge("\x00admin\x00true", &iv[..], &aes_ctr);
        encrypted[32] ^= 59; // ascii ";"
        encrypted[38] ^= 61; // ascii "="

        let decrypted_contains_admin =
            admin_string_decrypt_and_check(&encrypted[..], &iv[..], &|key, ciphertext, nonce| {
                Ok(aes_ctr(&key[..], &ciphertext[..], &nonce[..]))
            });
        assert!(decrypted_contains_admin);
    }
}
