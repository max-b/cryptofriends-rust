use bigint::{BigUint, RandBigInt};
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use rand::OsRng;

pub struct DHKeyPair {
    pub private_key: BigUint,
    pub public_key: BigUint,
    pub p: BigUint,
}

impl DHKeyPair {
    pub fn new(p: &BigUint, g: &BigUint) -> DHKeyPair {
        let mut rng = OsRng::new().expect("Can't get rng");
        let private_key = rng.gen_biguint_below(&p);

        let public_key = g.modpow(&private_key, &p);

        DHKeyPair {
            private_key,
            public_key,
            p: p.clone(),
        }
    }

    pub fn get_public_key(&self) -> BigUint {
        self.public_key.clone()
    }

    pub fn gen_session_key(&self, b: &BigUint) -> BigUint {
        let b = b.clone();
        let s1 = b.modpow(&self.private_key, &self.p);
        println!("session key (before aes) = {:?}", &s1);
        s1
    }

    pub fn gen_aes_session_key(&self, b: &BigUint) -> Vec<u8> {
        let s = self.gen_session_key(b);
        let mut hasher = Sha1::new();

        hasher.input(&s.to_bytes_le()[..]);

        let output_size = hasher.output_bits();
        let mut output_bytes = vec![0; output_size / 8];

        hasher.result(&mut output_bytes);
        // TODO: keep some more global notion of aes keysize!
        output_bytes.truncate(16);
        output_bytes
    }
}
