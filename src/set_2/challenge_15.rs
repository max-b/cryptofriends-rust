#[cfg(test)]
mod tests {
    use utils::crypto::strip_pkcs_padding;

    #[test]
    fn challenge_15() {
        let valid = b"ICE ICE BABY\x04\x04\x04\x04";
        assert_eq!(strip_pkcs_padding(valid), Ok(Vec::from("ICE ICE BABY")));

        let valid2 = b"ICE \x04\x04\x04\x04";
        assert_eq!(strip_pkcs_padding(valid2), Ok(Vec::from("ICE ")));

        let invalid1 = b"ICE ICE BABY\x05\x05\x05\x05";
        assert_eq!(strip_pkcs_padding(invalid1), Err("Invalid pkcs"));

        let invalid2 = b"ICE ICE BABY\x01\x02\x03\x04";
        assert_eq!(strip_pkcs_padding(invalid2), Err("Invalid pkcs"));

        let invalid3 = b"RANDOM NON ICE STRING WITHOUT PADDING";
        assert_eq!(strip_pkcs_padding(invalid3), Err("Invalid pkcs"));
    }
}
