#[cfg(test)]
mod tests {
    use utils::bytes::*;
    use utils::crypto::{keyed_sha1};

    #[test]
    fn challenge_28() {
        let hashed = keyed_sha1(b"", b"hello world");
        let hashed_str = bytes_to_hex(&hashed);
        assert_eq!(hashed_str, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");

        let hashed = keyed_sha1(b"key", b"message");
        let hashed_str = bytes_to_hex(&hashed);
        assert_eq!(hashed_str, "7d89ca5f9535d3bd925ca99f484ae4413a14fe2d");

        let hashed = keyed_sha1(b"notthekey", b"message");
        let hashed_str = bytes_to_hex(&hashed);
        assert_ne!(hashed_str, "7d89ca5f9535d3bd925ca99f484ae4413a14fe2d");
    }
}
