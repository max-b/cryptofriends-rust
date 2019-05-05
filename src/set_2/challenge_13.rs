#[cfg(test)]
mod tests {
    use set_2::{decrypt_and_parse_profile, encrypted_profile_for, key_value_parser};
    use std::str;

    #[test]
    fn challenge_13() {
        let junk1: Vec<u8> = vec![b'A'; 10];
        let junk2: Vec<u8> = vec![b'A'; 4];

        let mut admin_with_padding = b"admin".to_vec();
        let padding = vec![11; 11];

        admin_with_padding.extend_from_slice(&padding[..]);

        let total_length = junk1.len() + junk2.len() + admin_with_padding.len();
        let mut test_bytes = Vec::with_capacity(total_length);

        test_bytes.extend_from_slice(&junk1[..]);
        test_bytes.extend_from_slice(&admin_with_padding[..]);
        test_bytes.extend_from_slice(&junk2[..]);

        let test_plaintext =
            str::from_utf8(&test_bytes[..]).expect("cannot convert bytes to string");

        let ciphertext = encrypted_profile_for(test_plaintext);

        let test_plaintext = "foooo@bar.com";
        let mut ciphertext2 = encrypted_profile_for(test_plaintext);

        // truncate last 16 bytes of ciphertext2
        ciphertext2.truncate(32);

        ciphertext2.extend_from_slice(&ciphertext[16..32]);

        let decrypted = decrypt_and_parse_profile(&ciphertext2[..]);

        let admin_parsed = key_value_parser("email=foooo@bar.com&uid=10&role=admin");
        assert_eq!(decrypted, admin_parsed);
    }
}
