#[cfg(test)]
mod tests {
    use openssl::bn::{BigNum, BigNumContext};
    use utils::crypto::rsa::{RSA};
    use utils::bigint::{bignum_to_string, euclidean_algorithm};

    #[test]
    fn challenge_41() {
        let rsa = RSA::new().expect("RSA::new()");
        let plaintext = "I'll meet you at the place at the time, near the thing.  Don't be late, or early. Bring snacks.";
        println!("plaintext = {:?}", &plaintext);

        let ciphertext = rsa.encrypt_string(&plaintext).expect("rsa.encrypt");
        println!("ciphertext = {:?}", &ciphertext);

        let s = BigNum::from(0xb33fc4f3);
        let mut c_prime = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();

        c_prime
            .mod_exp(&s, &rsa.e, &rsa.n, &mut ctx)
            .expect("mod_exp");
        c_prime = &(&c_prime * &ciphertext) % &rsa.n;

        let p_prime = rsa.decrypt(&c_prime).expect("rsa.decrypt");
        let (_, s_inv) = euclidean_algorithm(&rsa.n, &s);
        let p = &(&p_prime * &s_inv) % &rsa.n;

        let recovered_plaintext = bignum_to_string(&p);

        println!("recovered plaintext = {:?}", &recovered_plaintext);
        assert_eq!(&plaintext, &recovered_plaintext);
    }
}
