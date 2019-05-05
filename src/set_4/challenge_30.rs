#[cfg(test)]
mod tests {
    use byteorder::{ByteOrder, LittleEndian};
    use set_4::{secret_prefix_mac, validate_mac};
    use utils::crypto::{compute_md4_from_registers, keyed_md4, md_padding, Endianness};

    #[test]
    fn challenge_30() {
        let hashed_message = secret_prefix_mac(b"testing", &keyed_md4);

        let hashed_message2 = secret_prefix_mac(b"testing", &keyed_md4);

        assert_eq!(hashed_message, hashed_message2);

        let original_string =
            b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

        let original_hash = secret_prefix_mac(&original_string[..], &keyed_md4);

        println!("hash length = {}", original_hash.len());

        let a = LittleEndian::read_u32(&original_hash[0..4]);
        let b = LittleEndian::read_u32(&original_hash[4..8]);
        let c = LittleEndian::read_u32(&original_hash[8..12]);
        let d = LittleEndian::read_u32(&original_hash[12..16]);

        let mut found_signature = None;
        let mut test_password = String::new();
        for _i in 1..20 {
            // check up to 20 character long secrets
            test_password.push('A');
            let mut check_padding_bytes = Vec::new();
            check_padding_bytes.extend_from_slice(test_password.as_bytes());
            check_padding_bytes.extend_from_slice(&original_string[..]);

            let padding = md_padding(check_padding_bytes.len(), Endianness::Little);

            let mut forged_bytes = Vec::new();
            forged_bytes.extend_from_slice(&original_string[..]);
            forged_bytes.extend_from_slice(&padding);
            forged_bytes.extend_from_slice(b";admin=true");

            let forged_bytes_len = forged_bytes.len();
            let mut new_message = Vec::new();
            new_message.extend_from_slice(b";admin=true");
            let new_message_padding =
                md_padding(forged_bytes_len + test_password.len(), Endianness::Little);
            new_message.extend_from_slice(&new_message_padding);

            let forged_mac = compute_md4_from_registers(
                a.to_le(),
                b.to_le(),
                c.to_le(),
                d.to_le(),
                &new_message,
            );

            if validate_mac(&forged_bytes, &forged_mac, &keyed_md4) {
                found_signature = Some(forged_mac);
            }
        }
        assert!(found_signature.is_some());
        println!("found_signature = {:?}", found_signature.unwrap());
    }
}
