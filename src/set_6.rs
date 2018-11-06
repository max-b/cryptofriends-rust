use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;
use bigint::{BigUint};
use utils::crypto::dsa::{DsaSignature, DsaParams};
use utils::crypto::rsa::RSA;
use num_traits::ops::checked::CheckedSub;
use itertools::Itertools;
use crypto::sha1::Sha1;
use crypto::digest::Digest;

pub fn recover_dsa_private_key_from_signing_key(params: &DsaParams, signature: &DsaSignature, k: &BigUint) -> Option<BigUint> {
    let (_, inv_r) = RSA::euclidean_algorithm(&params.q, &signature.r);
    let sk = &signature.s * k;
    match sk.checked_sub(&signature.message_hash) {
        Some(t) => Some(((t % &params.q) * &inv_r) % &params.q),
        None => None
    }
}

pub fn parse_messages_and_signatures(path: PathBuf) -> Vec<DsaSignature> {

    let messages_file = File::open(&path).expect("Error reading messages file.");

    let messages_file_as_reader = BufReader::new(messages_file);

    let lines = messages_file_as_reader.lines();

    let mut signatures: Vec<DsaSignature> = Vec::new();

    for mut signature in &lines.chunks(4) {
        let mut msg = signature.next().unwrap().unwrap();
        assert_eq!(&msg[0..5], "msg: ");
        let msg = String::from(&msg[5..msg.len()]);

        let s = signature.next().unwrap().unwrap();
        assert_eq!(&s[0..3], "s: ");
        let s = String::from(&s[3..]);

        let r = signature.next().unwrap().unwrap();
        assert_eq!(&r[0..3], "r: ");
        let r = String::from(&r[3..]);

        let m = signature.next().unwrap().unwrap();
        assert_eq!(&m[0..3], "m: ");
        let m = String::from(&m[3..]);

        let mut hasher = Sha1::new();
        hasher.input(&msg.as_bytes());
        let mut hash: Vec<u8> = vec![0; hasher.output_bytes()];
        hasher.result(&mut hash);

        let hash_value = BigUint::from_bytes_be(&hash); // sha1 outputs big endian

        assert_eq!(m, hash_value.to_str_radix(16));

        let signature = DsaSignature {
            message_hash: hash_value,
            r: BigUint::parse_bytes(r.as_bytes(), 10).unwrap(),
            s: BigUint::parse_bytes(s.as_bytes(), 10).unwrap(),
        };

        assert_eq!(r, signature.r.to_str_radix(10));
        assert_eq!(s, signature.s.to_str_radix(10));

        signatures.push(signature);
    }

    signatures
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::bn::{BigNum, BigNumContext};
    use bigint::{BigUint, RandBigInt};
    use num_traits::{FromPrimitive, Zero, One};
    use num_integer::Integer;
    use utils::crypto::rsa::{CubeRoot, RSA};
    use utils::crypto::dsa::{Dsa};
    use crypto::sha1::Sha1;
    use crypto::digest::Digest;
    use rand::{OsRng};

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

        let recovered_key = recover_dsa_private_key_from_signing_key(&dsa_params, &signature, &k).unwrap();

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

        let message = "For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch\n".as_bytes();

        let mut hasher = Sha1::new();
        hasher.input(&message);
        let mut hash: Vec<u8> = vec![0; hasher.output_bytes()];
        hasher.result(&mut hash);

        println!("hash = {:#x?}", &hasher.result_str());
        assert_eq!("d2d0714f014a9784047eaeccf956520045c45265", &hasher.result_str());

        let hash_value = BigUint::from_bytes_be(&hash); // sha1 outputs big endian

        println!("hash_value = {}", hash_value.to_str_radix(16));

        assert_eq!(hash_value.to_str_radix(16), "d2d0714f014a9784047eaeccf956520045c45265");

        let signature = DsaSignature {
            message_hash: hash_value,
            r: BigUint::parse_bytes(b"548099063082341131477253921760299949438196259240", 10).unwrap(),
            s: BigUint::parse_bytes(b"857042759984254168557880549501802188789837994940", 10).unwrap(),
        };

        println!("signature = {:#x?}", &signature);
        println!("signature r = {}", signature.r.to_str_radix(10));
        println!("signature s = {}", signature.s.to_str_radix(10));
        assert_eq!(signature.r.to_str_radix(10), "548099063082341131477253921760299949438196259240");
        assert_eq!(signature.s.to_str_radix(10), "857042759984254168557880549501802188789837994940");

        let mut test_signing_key = BigUint::zero();
        let mut recovered_private_key = None;
        while recovered_private_key.is_none() && test_signing_key < BigUint::from_u32(1 << 16).unwrap() {

            let test_private_key = recover_dsa_private_key_from_signing_key(&dsa_params, &signature, &test_signing_key);

            if let Some(private_key) = test_private_key {
                let test_dsa = Dsa {
                    params: dsa_params.clone(),
                    public_key: y.clone(),
                    private_key: private_key.clone()
                };

                let test_signature = test_dsa.sign(&message, Some(&test_signing_key));

                if test_signature == signature {
                    let gen_public_key = Dsa::gen_public_key(&dsa_params, &private_key);

                    if gen_public_key == y {
                        recovered_private_key = Some(private_key.clone());
                    }
                }
            }

            test_signing_key = test_signing_key + BigUint::one();
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

    #[test]
    fn challenge_44() {

        let y = BigUint::parse_bytes(
            b"2d026f4bf30195ede3a088da85e398ef869611d0f68f07\
                13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8\
                5519b1c23cc3ecdc6062650462e3063bd179c2a6581519\
                f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430\
                f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3\
                2971c3de5084cce04a2e147821",
            16,
        ).unwrap();

        let mut messages_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        messages_path.push("data");
        messages_path.push("set_6");
        messages_path.push("44.txt");

        let signatures = parse_messages_and_signatures(messages_path);

        let mut found_private_key = None;

        let params = DsaParams::default();

        signatures.iter().combinations(2)
            .filter(|v|
                v[0].r == v[1].r
            )
            .filter(|v|
                    ((&v[0].message_hash % &params.q) >= (&v[1].message_hash % &params.q) &&
                     (&v[0].s % &params.q) >= (&v[1].s % &params.q)) ||
                    ((&v[1].message_hash % &params.q) >= (&v[0].message_hash % &params.q) &&
                     (&v[1].s % &params.q) >= (&v[0].s % &params.q))
            )
            .for_each(|v| {
                let (a, b) =
                    match (&v[0].message_hash % &params.q)
                        .checked_sub(&(&v[1].message_hash % &params.q)) {

                        Some(_) => (v[0], v[1]),
                        None => (v[1], v[0])
                    };

                let top = (&a.message_hash % &params.q) - (&b.message_hash % &params.q);
                let (_, inv_bottom) = RSA::euclidean_algorithm(&params.q, &((&a.s % &params.q) - (&b.s % &params.q)));

                let k = (top * inv_bottom) % &params.q;

                let recovered_key = recover_dsa_private_key_from_signing_key(&params, &a, &k).unwrap();
                found_private_key = match found_private_key {
                    None => Some(recovered_key),
                    Some(ref private_key) => {
                        assert_eq!(&recovered_key, private_key);
                        Some(recovered_key)
                    }
                }

            });

        let found_private_key = found_private_key.unwrap();
        println!("private key: {}", found_private_key.to_str_radix(16));

        let mut hasher = Sha1::new();
        hasher.input(&found_private_key.to_str_radix(16).as_bytes());
        let mut hash: Vec<u8> = vec![0; hasher.output_bytes()];
        hasher.result(&mut hash);

        assert_eq!(hasher.result_str(), "ca8f6f7c66fa362d40760d135b763eb8527d3d52");

        let gen_public_key = Dsa::gen_public_key(&params, &found_private_key);

        assert_eq!(gen_public_key, y);
    }
}
