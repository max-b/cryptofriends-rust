use std::io::BufReader;
use std::io::prelude::*;
use itertools::Itertools;
use std::fs::File;
use std::path::PathBuf;
use crypto::sha1::Sha1;
use crypto::digest::Digest;
use bigint::BigUint;
use utils::crypto::dsa::DsaSignature;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use num_traits::ops::checked::CheckedSub;
    use bigint::BigUint;
    use crypto::sha1::Sha1;
    use crypto::digest::Digest;
    use utils::bigint;
    use utils::crypto::dsa::{Dsa, DsaParams};
    use set_6::recover_dsa_private_key_from_signing_key;

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
                    bigint::euclidean_algorithm(&params.q, &((&a.s % &params.q) - (&b.s % &params.q)));

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
}
