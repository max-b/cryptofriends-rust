#[cfg(test)]
mod tests {
    use rand::OsRng;
    use crypto::digest::Digest;
    use crypto::sha1::Sha1;
    use bigint::{BigUint, RandBigInt};
    use num_traits::{FromPrimitive, One, Zero};
    use set_6::recover_dsa_private_key_from_signing_key;
    use utils::crypto::dsa::{Dsa, DsaParams, DsaSignature};

    #[test]
    fn challenge_43() {
        let mut rng = match OsRng::new() {
            Ok(g) => g,
            Err(e) => panic!("Failed to obtain OS RNG: {}", e),
        };

        let dsa = Dsa::new();
        let dsa_params = DsaParams::default();

        println!("dsa = {:#x?}", &dsa);
        let message = "Hello from Oakland 👋".as_bytes();

        let k = RandBigInt::gen_biguint_below(&mut rng, &dsa_params.q);
        let signature = dsa.sign(&message, Some(&k));

        println!("k = {:#x?}", &k);

        println!("signature = {:#x?}", &signature);

        let recovered_key =
            recover_dsa_private_key_from_signing_key(&dsa_params, &signature, &k).unwrap();

        println!("derived_key = {:#x?}", &recovered_key);
        println!("actual_key = {:#x?}", &dsa.private_key);

        assert_eq!(recovered_key, dsa.private_key);

        let y = BigUint::parse_bytes(
            b"84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4\
        abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004\
        e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed\
        1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b\
        bb283e6633451e535c45513b2d33c99ea17",
            16,
        ).unwrap();

        let message = b"For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch\n";

        let mut hasher = Sha1::new();
        hasher.input(message);
        let mut hash: Vec<u8> = vec![0; hasher.output_bytes()];
        hasher.result(&mut hash);

        println!("hash = {:#x?}", &hasher.result_str());
        assert_eq!(
            "d2d0714f014a9784047eaeccf956520045c45265",
            &hasher.result_str()
        );

        let hash_value = BigUint::from_bytes_be(&hash); // sha1 outputs big endian

        println!("hash_value = {}", hash_value.to_str_radix(16));

        assert_eq!(
            hash_value.to_str_radix(16),
            "d2d0714f014a9784047eaeccf956520045c45265"
        );

        let signature = DsaSignature {
            message_hash: hash_value,
            r: BigUint::parse_bytes(b"548099063082341131477253921760299949438196259240", 10)
                .unwrap(),
            s: BigUint::parse_bytes(b"857042759984254168557880549501802188789837994940", 10)
                .unwrap(),
        };

        println!("signature = {:#x?}", &signature);
        println!("signature r = {}", signature.r.to_str_radix(10));
        println!("signature s = {}", signature.s.to_str_radix(10));
        assert_eq!(
            signature.r.to_str_radix(10),
            "548099063082341131477253921760299949438196259240"
        );
        assert_eq!(
            signature.s.to_str_radix(10),
            "857042759984254168557880549501802188789837994940"
        );

        let mut test_signing_key = BigUint::zero();
        let mut recovered_private_key = None;
        while recovered_private_key.is_none()
            && test_signing_key < BigUint::from_u32(1 << 16).unwrap()
        {
            let test_private_key = recover_dsa_private_key_from_signing_key(
                &dsa_params,
                &signature,
                &test_signing_key,
            );

            if let Some(private_key) = test_private_key {
                let test_dsa = Dsa {
                    params: dsa_params.clone(),
                    public_key: y.clone(),
                    private_key: private_key.clone(),
                };

                let test_signature = test_dsa.sign(message, Some(&test_signing_key));

                if test_signature == signature {
                    let gen_public_key = Dsa::gen_public_key(&dsa_params, &private_key);

                    if gen_public_key == y {
                        recovered_private_key = Some(private_key.clone());
                    }
                }
            }

            test_signing_key += BigUint::one();
            // Output progress
            if (&test_signing_key % &BigUint::from(500 as u32)).is_zero() {
                println!("{}", &test_signing_key);
            }
        }

        let recovered_private_key = recovered_private_key.unwrap();
        println!("Found private key: {:#x?}", &recovered_private_key);

        let gen_public_key = Dsa::gen_public_key(&dsa_params, &recovered_private_key);

        println!("gen_public_key = {:#x?}", &gen_public_key);
        println!("y = {:#x?}", &y);
        assert_eq!(gen_public_key, y);
    }
}
