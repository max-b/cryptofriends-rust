#[cfg(test)]
mod tests {
    use bigint::BigUint;
    use utils::bigint::{biguint_to_string, euclidean_algorithm};
    use utils::crypto::rsa::RSA;

    #[test]
    fn challenge_41() {
        let rsa = RSA::new();
        let plaintext = "I'll meet you at the place at the time, near the thing.  Don't be late, or early. Bring snacks.";
        println!("plaintext = {:?}", &plaintext);

        let ciphertext = rsa.encrypt_string(&plaintext);
        println!("ciphertext = {:?}", &ciphertext);

        let s = BigUint::from(0xb33fc4f3 as usize);

        let mut c_prime = s.modpow(&rsa.e, &rsa.n);
        c_prime = (&c_prime * &ciphertext) % &rsa.n;

        let p_prime = rsa.decrypt(&c_prime);
        let (_, s_inv) = euclidean_algorithm(&rsa.n, &s);
        let p = (&p_prime * &s_inv) % &rsa.n;

        let recovered_plaintext = biguint_to_string(&p);

        println!("recovered plaintext = {:?}", &recovered_plaintext);
        assert_eq!(&plaintext, &recovered_plaintext);
    }
}
