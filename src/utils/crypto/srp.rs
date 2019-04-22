use bigint::{BigUint, RandBigInt};
use rand::OsRng;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use crypto::mac::{Mac, MacResult};
use crypto::hmac::Hmac;
use utils::misc::nist_prime;

pub static g: u32 = 2;
pub static k: u32 = 3;

pub struct ServerSRP {
    pub salt: BigUint,
    pub v: BigUint,
}

pub fn generate_server_vals(email: &[u8], password: &[u8]) -> ServerSRP {

    let N = nist_prime();
    let mut rng = OsRng::new().expect("Can't get rng");
    let salt = rng.gen_biguint_below(&N);

    let x = hash_salt_password(&salt, &password);

    let v = BigUint::from(g).modpow(&x, &N);

    ServerSRP {
        salt,
        v
    }
}

pub fn hash_salt_password(salt: &BigUint, password: &[u8]) -> BigUint {

    let mut digest_input = Vec::new();
    digest_input.extend_from_slice(&salt.to_bytes_be());
    digest_input.extend_from_slice(&password);

    let mut hasher = Sha256::new();
    hasher.input(&digest_input);

    let output_size = hasher.output_bits();
    let mut output_bytes = vec![0; output_size / 8];

    hasher.result(&mut output_bytes);
    BigUint::from_bytes_be(&output_bytes)
}

pub fn hash_biguint(a: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.input(&a.to_bytes_be());

    let output_size = hasher.output_bits();
    let mut output_bytes = vec![0; output_size / 8];

    hasher.result(&mut output_bytes);
    BigUint::from_bytes_be(&output_bytes)
}

pub fn hash_concat(a: &BigUint, b: &BigUint) -> BigUint {
    let mut digest_input = Vec::new();
    digest_input.extend_from_slice(&a.to_bytes_be());
    digest_input.extend_from_slice(&b.to_bytes_be());

    let mut hasher = Sha256::new();
    hasher.input(&digest_input);

    let output_size = hasher.output_bits();
    let mut output_bytes = vec![0; output_size / 8];

    hasher.result(&mut output_bytes);
    BigUint::from_bytes_be(&output_bytes)
}

pub fn compute_hmac(key: &BigUint, val: &BigUint) -> MacResult {
    let hasher = Sha256::new();
    let mut hmac = Hmac::new(hasher, &key.to_bytes_be());
    hmac.input(&val.to_bytes_be());

    hmac.result()
}
