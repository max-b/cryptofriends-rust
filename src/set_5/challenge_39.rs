#[cfg(test)]
mod tests {
    use utils::crypto::rsa::RSA;

    #[test]
    fn challenge_39() {
        let rsa = RSA::new();
        let plaintext = "this is a test of the emergency encryption system 💖";
        println!("plaintext = {:?}", &plaintext);
        let ciphertext = rsa.encrypt_string(&plaintext);
        println!("ciphertext = {:?}", &ciphertext);
        let decrypted = rsa.decrypt_string(&ciphertext);
        println!("decrypted = {:?}", &decrypted);
        assert_eq!(&plaintext, &decrypted);
    }
}
