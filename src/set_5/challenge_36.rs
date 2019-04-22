use std::thread;
use std::sync::mpsc;

#[cfg(test)]
mod tests {
    use super::*;
    use bigint::{BigUint, RandBigInt};
    use crypto::sha2::Sha256;
    use crypto::digest::Digest;
    use crypto::mac::{Mac, MacResult};
    use rand::OsRng;
    use utils::crypto::srp::{g, k, ServerSRP, generate_server_vals, hash_concat, hash_salt_password, hash_biguint, compute_hmac};
    use utils::misc::nist_prime;

    #[test]
    fn challenge_36() {
        let mut rng = OsRng::new().expect("Can't get rng");
        let N = nist_prime();

        let email = b"testing@test.com";
        let password = b"badpasswordeh";

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        let a = rng.gen_biguint_below(&N);
        thread::spawn(move || {
            // Client
            let A = BigUint::from(g).modpow(&a, &N);
            tx1.send(A.clone()).unwrap();

            let (B, salt) = rx2.recv().unwrap();
            let uh = hash_concat(&A, &B); 

            let x = hash_salt_password(&salt, &password[..]);

            let S = (B - ((k * BigUint::from(g).modpow(&x, &N)) % &N)).modpow(&(&(&a + (&uh * &x) % &N) % &N), &N);

            let K = hash_biguint(&S);

            tx3.send(compute_hmac(&K, &salt)).unwrap();
        });

        // Server
        let N = nist_prime();
        let srp = generate_server_vals(email, password);
        let b = rng.gen_biguint_below(&N);

        let A = rx1.recv().unwrap();
        let B = (((k * &srp.v) % &N) + BigUint::from(g).modpow(&b, &N)) % &N;

        tx2.send((B.clone(), srp.salt.clone())).unwrap();

        let uh = hash_concat(&A, &B); 

        let S = (&(&A * srp.v.modpow(&uh, &N)) % &N).modpow(&b, &N);

        let K = hash_biguint(&S);

        let client_hmac = rx3.recv().unwrap();
        let hmac = compute_hmac(&K, &srp.salt);
        assert!(client_hmac == hmac);
    }
}
