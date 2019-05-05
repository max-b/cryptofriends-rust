#[cfg(test)]
mod tests {

    use utils::crypto::{cbc_decrypt, cbc_encrypt};
    use utils::misc::{admin_string_decrypt_and_check, admin_string_encrypt_challenge};

    #[test]
    fn challenge_16() {
        let iv: Vec<u8> = vec![0; 16];
        let encrypted =
            admin_string_encrypt_challenge("testing 123;admin=true;blah", &iv[..], &cbc_encrypt);
        let decrypted_contains_admin =
            admin_string_decrypt_and_check(&encrypted[..], &iv[..], &cbc_decrypt);
        assert!(!decrypted_contains_admin);

        // prepend string is 32 bytes
        let mut encrypted =
            admin_string_encrypt_challenge("\x00admin\x00true", &iv[..], &cbc_encrypt);
        encrypted[16] ^= 59; // ascii ";"
        encrypted[22] ^= 61; // ascii "="

        let decrypted_contains_admin =
            admin_string_decrypt_and_check(&encrypted[..], &iv[..], &cbc_decrypt);
        assert!(decrypted_contains_admin);
    }
}
