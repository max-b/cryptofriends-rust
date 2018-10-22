
#[cfg(test)]
mod tests {
    use openssl::bn::{BigNum, BigNumContext};
    use utils::crypto::rsa::{CubeRoot, RSA};

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
        let (_, s_inv) = RSA::euclidean_algorithm(&rsa.n, &s);
        let p = &(&p_prime * &s_inv) % &rsa.n;

        let recovered_plaintext = RSA::bignum_to_string(&p);

        println!("recovered plaintext = {:?}", &recovered_plaintext);
        assert_eq!(&plaintext, &recovered_plaintext);
    }

    #[test]
    fn challenge_42() {
        let mut forged_plaintext = vec![0x00, 0x01, 0xff, 0x00];
        forged_plaintext.extend_from_slice(&"hello".as_bytes());
        println!("forged plaintext = {:?}", &forged_plaintext);
        let mut num_pad = 20;

        loop {
            let mut test_plaintext = Vec::new();
            test_plaintext.extend_from_slice(&forged_plaintext);
            let mut right_pad = vec![0x00; num_pad];
            test_plaintext.extend_from_slice(&right_pad);
            let cuberoot = RSA::cube_root(&BigNum::from_slice(&test_plaintext).unwrap());

            let test_ciphertext = match cuberoot {
                CubeRoot::Exact(n) => n,
                CubeRoot::Nearest(n) => n,
            };

            println!("test ciphertext = {:?}", test_ciphertext);

            let mut cube = BigNum::new().unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            cube.exp(&test_ciphertext, &BigNum::from(3), &mut ctx);

            let cube_bytes = cube.to_vec();

            println!("forged plaintext = {:?}", &forged_plaintext);
            println!("resulting plaintext = {:?}", &cube_bytes);

            if &cube_bytes[0..8] == &forged_plaintext[1..9] {
                println!("found match");
                break;
            }
            num_pad += 1;
        }
    }
}
