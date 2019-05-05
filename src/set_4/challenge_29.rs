#[cfg(test)]
mod tests {
    use set_4::{secret_prefix_mac, validate_mac};
    use utils::crypto::{compute_sha1_from_registers, keyed_sha1, md_padding, Endianness};

    #[test]
    fn challenge_29() {
        let hashed_message = secret_prefix_mac(b"testing", &keyed_sha1);

        let hashed_message2 = secret_prefix_mac(b"testing", &keyed_sha1);

        assert_eq!(hashed_message, hashed_message2);

        let original_string =
            b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

        let original_hash = secret_prefix_mac(&original_string[..], &keyed_sha1);

        println!("hash length = {}", original_hash.len());
        let (mut a, mut b, mut c, mut d, mut e) = (0u32, 0u32, 0u32, 0u32, 0u32);

        for i in 0..4 {
            a |= u32::from(original_hash[i]) << (8 * i);
            b |= u32::from(original_hash[i + 4]) << (8 * i);
            c |= u32::from(original_hash[i + 8]) << (8 * i);
            d |= u32::from(original_hash[i + 12]) << (8 * i);
            e |= u32::from(original_hash[i + 16]) << (8 * i);
        }

        let mut found_signature = None;
        let mut test_password = String::new();
        for _i in 1..20 {
            // check up to 20 character long secrets
            test_password.push('A');
            let mut check_padding_bytes = Vec::new();
            check_padding_bytes.extend_from_slice(test_password.as_bytes());
            check_padding_bytes.extend_from_slice(&original_string[..]);

            let padding = md_padding(check_padding_bytes.len(), Endianness::Big);

            let mut forged_bytes = Vec::new();
            forged_bytes.extend_from_slice(&original_string[..]);
            forged_bytes.extend_from_slice(&padding);
            forged_bytes.extend_from_slice(b";admin=true");

            let forged_bytes_len = forged_bytes.len();
            let mut new_message = Vec::new();
            new_message.extend_from_slice(b";admin=true");
            let new_message_padding =
                md_padding(forged_bytes_len + test_password.len(), Endianness::Big);
            new_message.extend_from_slice(&new_message_padding);

            let forged_mac = compute_sha1_from_registers(
                a.to_be(),
                b.to_be(),
                c.to_be(),
                d.to_be(),
                e.to_be(),
                &new_message,
            );

            if validate_mac(&forged_bytes, &forged_mac, &keyed_sha1) {
                found_signature = Some(forged_mac);
            }
        }
        assert!(found_signature.is_some());
        println!("found_signature = {:?}", found_signature.unwrap());
    }
}
