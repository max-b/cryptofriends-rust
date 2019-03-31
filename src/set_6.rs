use bigint::BigUint;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use itertools::Itertools;
use num_traits::ops::checked::CheckedSub;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;
use openssl::bn::{BigNum, BigNumContext};
use utils::crypto::dsa::{DsaParams, DsaSignature};
use utils::crypto::rsa::RSA;


#[derive(Debug)]
pub struct Range {
    pub min: BigNum,
    pub max: BigNum,
}

impl Range {
    fn contains(&self, other: &Range) -> bool {
        self.min <= other.min && self.max >= other.max
    }
}

pub fn recover_dsa_private_key_from_signing_key(
    params: &DsaParams,
    signature: &DsaSignature,
    k: &BigUint,
) -> Option<BigUint> {
    let (_, inv_r) = RSA::euclidean_algorithm(&params.q, &signature.r);
    let sk = &signature.s * k;
    match sk.checked_sub(&signature.message_hash) {
        Some(t) => Some(((t % &params.q) * &inv_r) % &params.q),
        None => None,
    }
}

pub fn parse_messages_and_signatures(path: &PathBuf) -> Vec<DsaSignature> {
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

#[derive(PartialEq)]
pub enum Parity {
    Even,
    Odd,
}

pub fn plaintext_parity(ciphertext: &BigNum, rsa: &RSA) -> Parity {
    let decrypt = rsa.decrypt(ciphertext).expect("error decrypting");

    if decrypt.is_bit_set(0) {
        Parity::Even
    } else {
        Parity::Odd
    }
}

pub fn bleichenbacher_oracle(ciphertext: &BigNum, rsa: &RSA) -> bool {
    let k = rsa.n.to_vec().len();
    let mut decrypt_bytes = rsa.decrypt(ciphertext).expect("error decrypting").to_vec();
    while decrypt_bytes.len() < k {
        decrypt_bytes.insert(0, 0);
    }
    
    decrypt_bytes[0] == 2 && decrypt_bytes[1] == 2
}

pub fn bleichenbacher_step_2(i: usize, c0: &BigNum, s: &mut Vec<BigNum>, M: &Vec<Vec<Range>>, B: &BigNum, rsa: &RSA, m: &BigNum) {

    let zero = BigNum::from(0);
    let one = BigNum::from(1);
    let two = BigNum::from(2);
    let three = BigNum::from(3);
    let mut ctx = BigNumContext::new().expect("BigNumContext::new()");

    println!("s = {:?}", &s);
    println!("B = {:?}", &B);
    println!("n = {:?}", &rsa.n);
    println!("c0 = {:?}", c0);

    if i == 1  || M[i - 1].len() > 1 {
        // search for smallest s >= n/3B such that c0(s[i]^e) % n is pkcs conforming
        let mut s_new = ceil_div(&rsa.n, &(&three * B));

        if i > 1 {
            s_new = &s[i - 1] + &one;
        }
        // search for smallest integer s[i] > s[i-1] such that c0(s[i]^e) % n is pkcs conforming
        
        let mut s_e_mod_n = BigNum::new().expect("BigNum::new()");
        s_e_mod_n.mod_exp(&s_new, &rsa.e, &rsa.n, &mut ctx).unwrap();
        while !bleichenbacher_oracle(&(&(c0 * &s_e_mod_n) % &rsa.n), &rsa) {
            // println!("s_new = {:?}", &s_new);
            // println!("s_e_mod_n = {:?}", &s_e_mod_n);
            s_new = &s_new + &one;
            s_e_mod_n.mod_exp(&s_new, &rsa.e, &rsa.n, &mut ctx).unwrap();
        }

        s.push(s_new)
    } else {
        // search for s[i] r[i] such that 
        // r[i] >= (2 * (b*s[i - 1] - 2B)) / n
        // s[i] >= (2B + r[i]*n) / b && s[i] < (2B + r[i]*n)  a
        let a = &M[i - 1][0].min + &zero;
        let b = &M[i - 1][0].max + &zero;

        let mut r = ceil_div(&(&two * &(&(&b * &s[i - 1]) - &(&two * B))), &rsa.n);
        let mut s_new = ceil_div(&(&(&two * B) + &(&r * &rsa.n)), &b);

        let mut s_e_mod_n = BigNum::new().expect("BigNum::new()");
        s_e_mod_n.mod_exp(&s_new, &rsa.e, &rsa.n, &mut ctx).unwrap();

        while !bleichenbacher_oracle(&(&(c0 * &s_e_mod_n) % &rsa.n), &rsa) {
            // println!("STEP 2c");
            // println!("i = {}", i);
            // println!("a = {:?}", a);
            // println!("b = {:?}", b);
            // println!("m = {:?}", &m);
            // println!("r = {:?}", &s_new);
            // println!("s_new = {:?}", &s_new);
            // println!("s_e_mod_n = {:?}", &s_e_mod_n);
            s_new = &s_new + &one;
            if s_new > &(&(&three * B) + &(&r * &rsa.n)) / &a {
                r = &r + &one;
                s_new = ceil_div(&(&(&two * B) + &(&r * &rsa.n)), &b);
            }
            s_e_mod_n.mod_exp(&s_new, &rsa.e, &rsa.n, &mut ctx).unwrap();
        }

        s.push(s_new)
    }
}

pub fn ceil_div(num: &BigNum, den: &BigNum) -> BigNum {
    &(&(num + den) - &BigNum::from(1)) / den
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp;
    use bigint::{BigUint, RandBigInt};
    use crypto::digest::Digest;
    use crypto::sha1::Sha1;
    use num_traits::{FromPrimitive, One, Zero};
    use openssl::bn::{BigNum, BigNumContext};
    use rand::OsRng;
    use utils::bytes::{base64_to_bytes, random_bytes};
    use utils::crypto::dsa::Dsa;
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
        forged_plaintext.extend_from_slice(b"hello");
        println!("forged plaintext = {:?}", &forged_plaintext);
        let mut num_pad = 20;
        let three = BigNum::from(3);

        loop {
            let mut test_plaintext = Vec::new();
            test_plaintext.extend_from_slice(&forged_plaintext);
            let right_pad = vec![0x00; num_pad];
            test_plaintext.extend_from_slice(&right_pad);
            let cuberoot = RSA::cube_root(&BigNum::from_slice(&test_plaintext).unwrap());

            let test_ciphertext = match cuberoot {
                CubeRoot::Exact(n) => n,
                CubeRoot::Nearest(n) => n,
            };

            println!("test ciphertext = {:?}", test_ciphertext);

            let mut cube = BigNum::new().unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            cube.exp(&test_ciphertext, &three, &mut ctx)
                .expect("cube exponentiation failed");

            let cube_bytes = cube.to_vec();

            println!("forged plaintext = {:?}", &forged_plaintext);
            println!("resulting plaintext = {:?}", &cube_bytes);

            if cube_bytes[0..8] == forged_plaintext[1..9] {
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

        let signatures = parse_messages_and_signatures(&messages_path);

        let mut found_private_key = None;

        let params = DsaParams::default();

        signatures
            .iter()
            .combinations(2)
            .filter(|v| v[0].r == v[1].r)
            .filter(|v| {
                ((&v[0].message_hash % &params.q) >= (&v[1].message_hash % &params.q)
                    && (&v[0].s % &params.q) >= (&v[1].s % &params.q))
                    || ((&v[1].message_hash % &params.q) >= (&v[0].message_hash % &params.q)
                        && (&v[1].s % &params.q) >= (&v[0].s % &params.q))
            }).for_each(|v| {
                let (a, b) = match (&v[0].message_hash % &params.q)
                    .checked_sub(&(&v[1].message_hash % &params.q))
                {
                    Some(_) => (v[0], v[1]),
                    None => (v[1], v[0]),
                };

                let top = (&a.message_hash % &params.q) - (&b.message_hash % &params.q);
                let (_, inv_bottom) =
                    RSA::euclidean_algorithm(&params.q, &((&a.s % &params.q) - (&b.s % &params.q)));

                let k = (top * inv_bottom) % &params.q;

                let recovered_key =
                    recover_dsa_private_key_from_signing_key(&params, &a, &k).unwrap();
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

        assert_eq!(
            hasher.result_str(),
            "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
        );

        let gen_public_key = Dsa::gen_public_key(&params, &found_private_key);

        assert_eq!(gen_public_key, y);
    }

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

    #[test]
    fn challenge_46() {
        let actual_plaintext = "That\'s why I found you don\'t play around with the Funky Cold Medin";
        let rsa = RSA::new().expect("RSA::new()");
        let plaintext = BigNum::from_slice(&base64_to_bytes("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")).unwrap();

        let ciphertext = rsa.encrypt(&plaintext).unwrap();

        let zero = BigNum::from(0);
        let two = BigNum::from(2);

        // So much hacky cloning
        let mut ctx = BigNumContext::new().expect("BugNum new()");
        let mut c = &zero + &ciphertext;
        let mut tmp = BigNum::new().expect("BugNum new()");
        let mut higher_bound = &zero + &rsa.n;
        let mut lower_bound = &zero + &zero;

        while &higher_bound > &zero {
            tmp.mod_exp(&two, &rsa.e, &rsa.n, &mut ctx)
                .expect("mod_exp");
            let c2 = &(&c * &tmp) % &rsa.n;
            c = &zero + &c2;

            let parity = plaintext_parity(&c2, &rsa);

            let diff = &higher_bound - &lower_bound;
            let delta = &diff / &two;
            if parity == Parity::Odd {
                higher_bound = &higher_bound - &delta;
            } else {
                lower_bound = &lower_bound + &delta;
            }

            let high_guess_string = RSA::bignum_to_string(&higher_bound);
            let low_guess_string = RSA::bignum_to_string(&lower_bound);
            println!("guess = {:?}", &high_guess_string);
            println!("guess = {:?}", &low_guess_string);
            if high_guess_string.contains(actual_plaintext) {
                println!("FOUND = {:?}", &high_guess_string);
                break;
            }
            if low_guess_string.contains(actual_plaintext) {
                println!("FOUND = {:?}", &low_guess_string);
                break;
            }
        }
    }

    #[test]
    fn challenge_47() {
        // We're going to re-use these a bunch, so might as well
        let zero = BigNum::from(0);
        let one = BigNum::from(1);
        let two = BigNum::from(2);
        let three = BigNum::from(3);

        let rsa = RSA::new_with_size(128).expect("RSA::new_with_size(128)");
        let k = rsa.n.to_vec().len();
        #[allow(non_snake_case)]
        let mut B = BigNum::new().expect("BigNum::new()");
        let mut ctx = BigNumContext::new().expect("BigNumContext::new()");
        B.exp(&two, &BigNum::from((8 * (k - 2)) as u32), &mut ctx).expect("B.exp()");
        let plaintext_bytes = "kick it, CC".as_bytes();

        let mut n_min = BigNum::new().expect("BigNum::new()");
        n_min.exp(&two, &BigNum::from((8 * (k - 1)) as u32), &mut ctx).expect("n_min.exp()");
        assert!(n_min <= rsa.n);
        let mut n_max = BigNum::new().expect("BigNum::new()");
        n_max.exp(&two, &BigNum::from((8 * k) as u32), &mut ctx).expect("n_max.exp()");
        assert!(n_max > rsa.n);
        // TODO: refactor pkcs padding into library
        let padding_bytes = random_bytes((k - 3 - plaintext_bytes.len()) as u32);
        println!("padding_bytes.len() = {:?}", padding_bytes.len());
        let mut padded_plaintext = vec![0x00, 0x02];
        padded_plaintext.extend_from_slice(&padding_bytes);
        padded_plaintext.extend_from_slice(&[0x00]);
        padded_plaintext.extend_from_slice("kick it, CC".as_bytes());
        let plaintext_num = BigNum::from_slice(&padded_plaintext).expect("BigNum::from_slice()");
        let ciphertext = rsa.encrypt(&plaintext_num).expect("rsa.encrypt()");

        let decryption = rsa.decrypt(&ciphertext).unwrap();

        println!("k = {:?}", k);
        println!("n = {:?}", rsa.n.to_vec());
        println!("plaintext = {:?}", &padded_plaintext);
        println!("decryption = {:?}", &decryption.to_vec());

        // Step 1
        let mut s = vec![&one + &zero];
        let c0 = &ciphertext * &one;

        #[allow(non_snake_case)]
        let mut M = vec![
            vec![
                Range { 
                    min: &two * &B,
                    max: &(&three * &B) - &one,
                }
            ]
        ];

        let mut found = false;
        let mut i: usize = 1;

        while !found {
            
            bleichenbacher_step_2(i, &c0, &mut s, &M, &B, &rsa, &plaintext_num);

            println!("s = {:?}", &s);
            assert!(s.len() > 1);

            // Step 3
            // Not yet handling the case of M containing multiple ranges
            assert!(M[i - 1].len() == 1);

            let a = &M[i - 1][0].min + &zero;
            let b = &M[i - 1][0].max + &zero;

            // We're taking a ceiling here because r >= the computed (float) r_min value
            let r_min = ceil_div(&(&(&(&a * &s[i]) - &(&three * &B)) + &one), &rsa.n);
            let r_max = &(&(&b * &s[i]) - &(&two * &B)) / &rsa.n;

            // For now only handle r_max == r_min
            assert!(r_max == r_min);
            println!("i = {:?}", i);
            println!("M[i - 1] = {:?}", &M[i - 1]);
            println!("a = {:?}", &a);
            println!("b = {:?}", &b);
            println!("r_min = {:?}", &r_min);
            println!("r_max = {:?}", &r_max);
            let mut m_new: Vec<Range> = Vec::new();

            let mut r = &r_min + &zero;
            // while r <= r_max {

            println!("r = {:?}", &r);
            let new_min = cmp::max(
                &a + &zero, 
                ceil_div(&(&(&two * &B) + &(&r * &rsa.n)), &s[i])
            );
            println!("a =          {:?}", &a);
            println!("2B + n / s = {:?}", &ceil_div(&(&(&two * &B) + &(&r * &rsa.n)), &s[i]));
            println!("new_min =    {:?}", &new_min);

            let new_max = cmp::min(
                &b + &zero,
                &(&(&(&three * &B) - &one) + &(&r * &rsa.n)) / &s[i]
            );
            println!("b =               {:?}", &b);
            println!("3B - 1 + rn / s = {:?}", &(&(&(&three * &B) - &one) + &(&r * &rsa.n)) / &s[i]);
            println!("new_max =         {:?}", &new_max);

            let mut contains = false;
            let new_range = Range {
                min: new_min,
                max: new_max,
            };

            // TODO: fix overlapping issue???
            for range in &m_new {
                contains = contains || range.contains(&new_range);
            }

            println!("new_range = {:?}", &new_range);
            if !contains && new_range.min <= new_range.max {
                m_new.push(new_range);
            }

            r = &r + &one;
            // }

            M.push(m_new);
            println!("i = {:?}", i);
            println!("B        = {:?}", &B);
            println!("n        = {:?}", &rsa.n);
            println!("M[i].min = {:?}", &M[i][0].min);
            println!("M[i].max = {:?}", &M[i][0].max);
            println!("m =        {:?}", &plaintext_num);
            assert!(M[i].len() == 1);
            assert!(&M[i][0].min < &plaintext_num);
            assert!(&M[i][0].max > &plaintext_num);

            // Step 4
            // i <- i + 1
            if M[i].len() == 1 && M[i][0].min == M[i][0].max {
                found = true;
            }
            i = i + 1;
            assert!(i < 4);
        }

        println!("FOUND :)");
    }
}
