use bigint::{BigUint, RandBigInt};
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use num_traits::identities::Zero;
use rand::OsRng;
use utils::bigint;

#[derive(Debug, Default, Clone)]
pub struct Dsa {
    pub params: DsaParams,
    pub private_key: BigUint,
    pub public_key: BigUint,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DsaSignature {
    pub r: BigUint,
    pub s: BigUint,
    pub message_hash: BigUint,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DsaParams {
    pub p: BigUint,
    pub q: BigUint,
    pub g: BigUint,
}

impl Default for DsaParams {
    fn default() -> Self {
        DsaParams::new()
    }
}

impl DsaParams {
    pub fn new() -> DsaParams {
        let p = BigUint::parse_bytes(
            b"800000000000000089e1855218a0e7dac38136ffafa72eda7\
        859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
        2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
        ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
        b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
        1a584471bb1",
            16,
        )
        .unwrap();

        let q = BigUint::parse_bytes(b"f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap();

        let g = BigUint::parse_bytes(
            b"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
        458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
        322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
        0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
        878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
        9fc95302291",
            16,
        )
        .unwrap();

        DsaParams { p, q, g }
    }
}

impl Dsa {
    pub fn new() -> Self {
        let mut rng = match OsRng::new() {
            Ok(g) => g,
            Err(e) => panic!("Failed to obtain OS RNG: {}", e),
        };

        let params = DsaParams::default();

        let private_key = RandBigInt::gen_biguint_below(&mut rng, &params.q);

        let public_key = Dsa::gen_public_key(&params, &private_key);

        Self {
            params,
            private_key,
            public_key,
        }
    }

    pub fn gen_public_key(params: &DsaParams, private_key: &BigUint) -> BigUint {
        params.g.modpow(&private_key, &params.p)
    }

    pub fn sign(&self, message: &[u8], k: Option<&BigUint>) -> DsaSignature {
        let mut rng = match OsRng::new() {
            Ok(g) => g,
            Err(e) => panic!("Failed to obtain OS RNG: {}", e),
        };

        let k = match k {
            Some(k) => k.clone(),
            None => RandBigInt::gen_biguint_below(&mut rng, &self.params.q),
        };

        let r = self.params.g.modpow(&k, &self.params.p) % &self.params.q;
        // Allow r to be zero for challenge 45 param tampering
        // assert!(!r.is_zero());

        let mut hasher = Sha1::new();
        hasher.input(&message);
        let mut hash: Vec<u8> = vec![0; hasher.output_bytes()];
        hasher.result(&mut hash);
        let hash_value = BigUint::from_bytes_be(&hash); // sha1 outputs big endian

        let xr = &self.private_key * &r;

        let (_, invmod) = bigint::euclidean_algorithm(&self.params.q, &k);

        let s = (invmod * (&hash_value + xr)) % &self.params.q;

        assert!(!s.is_zero());
        DsaSignature {
            r,
            s,
            message_hash: hash_value,
        }
    }

    pub fn verify(&self, signature: &DsaSignature) -> bool {
        let (r, s) = (&signature.r, &signature.s);
        if *r >= self.params.q || *s >= self.params.q {
            return false;
        }

        let (_, w) = bigint::euclidean_algorithm(&self.params.q, &s);

        let u1 = (&signature.message_hash * &w) % &self.params.q;
        let u2 = (r * &w) % &self.params.q;

        let v = ((&self.params.g.modpow(&u1, &self.params.p)
            * &self.public_key.modpow(&u2, &self.params.p))
            % &self.params.p)
            % &self.params.q;

        &v == r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dsa_signature_verification() {
        let dsa = Dsa::new();

        println!("dsa = {:#x?}", &dsa);
        let plaintext = "Hello from Oakland 👋".as_bytes();
        let signature = dsa.sign(&plaintext, None);

        println!("message = {:#x?}", &plaintext);
        println!("signature = {:#x?}", &signature);

        let valid = dsa.verify(&signature);

        assert!(valid);
    }

    #[test]
    fn dsa_pub_key_gen() {
        let dsa_params = DsaParams::default();
        let dsa = Dsa::new();

        println!("dsa = {:#x?}", &dsa);

        let generated_public_key = Dsa::gen_public_key(&dsa_params, &dsa.private_key);

        assert_eq!(generated_public_key, dsa.public_key);
    }
}
