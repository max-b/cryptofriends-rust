#[cfg(test)]
mod tests {
    use bigint::{BigUint, RandBigInt};
    use crypto::digest::Digest;
    use crypto::sha1::Sha1;
    use num_traits::{One, Zero};
    use rand::OsRng;
    use utils::crypto::dsa::{Dsa, DsaParams, DsaSignature};

    #[test]
    fn challenge_45() {
        let mut rng = match OsRng::new() {
            Ok(g) => g,
            Err(e) => panic!("Failed to obtain OS RNG: {}", e),
        };

        let mut params = DsaParams::default();
        params.g = BigUint::zero();

        let private_key = RandBigInt::gen_biguint_below(&mut rng, &params.q);

        let public_key = Dsa::gen_public_key(&params, &private_key);

        let dsa = Dsa {
            params,
            private_key,
            public_key,
        };

        let message = "Very secure algorithm with insecure parameters 🤷".as_bytes();

        let signature = dsa.sign(&message, None);

        assert!(dsa.verify(&signature));

        let mut hasher = Sha1::new();
        hasher.input(&message);
        let mut hash: Vec<u8> = vec![0; hasher.output_bytes()];
        hasher.result(&mut hash);
        let hash_value = BigUint::from_bytes_be(&hash); // sha1 outputs big endian

        let forged_signature = DsaSignature {
            r: BigUint::zero(),
            s: BigUint::one(),
            message_hash: hash_value,
        };

        assert!(dsa.verify(&forged_signature));

        let message = "A new message to sign with insecure params 🐈".as_bytes();

        let mut hasher = Sha1::new();
        hasher.input(&message);
        let mut hash: Vec<u8> = vec![0; hasher.output_bytes()];
        hasher.result(&mut hash);
        let hash_value = BigUint::from_bytes_be(&hash); // sha1 outputs big endian

        let forged_signature = DsaSignature {
            r: BigUint::zero(),
            s: BigUint::one(),
            message_hash: hash_value.clone(),
        };

        assert!(dsa.verify(&forged_signature));

        let default_params = DsaParams::default();
        let params = DsaParams {
            g: &default_params.p + BigUint::one(),
            p: default_params.p,
            q: default_params.q,
        };

        let private_key = RandBigInt::gen_biguint_below(&mut rng, &params.q);

        let public_key = Dsa::gen_public_key(&params, &private_key);

        let magic_r = (&public_key % &params.p) % &params.q;
        let magic_s = &magic_r % &params.q;

        let dsa = Dsa {
            params,
            private_key,
            public_key,
        };

        let forged_signature = DsaSignature {
            r: magic_r.clone(),
            s: magic_s.clone(),
            message_hash: hash_value.clone(),
        };

        assert!(dsa.verify(&forged_signature));

        let message = "Hello World 🗺️".as_bytes();

        let mut hasher = Sha1::new();
        hasher.input(&message);
        let mut hash: Vec<u8> = vec![0; hasher.output_bytes()];
        hasher.result(&mut hash);
        let hash_value = BigUint::from_bytes_be(&hash); // sha1 outputs big endian

        let forged_signature = DsaSignature {
            r: magic_r.clone(),
            s: magic_s.clone(),
            message_hash: hash_value.clone(),
        };

        assert!(dsa.verify(&forged_signature));
    }
}
