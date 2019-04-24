#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use bigint::{BigUint, RandBigInt};
    use rand::OsRng;
    use utils::crypto::srp::{g, k, ServerSRP, Message, hash_concat, hash_salt_password, hash_biguint, compute_hmac};
    use utils::misc::nist_prime;

    #[test]
    fn challenge_36() {
        let mut rng = OsRng::new().expect("Can't get rng");
        let N = nist_prime();
        let mut login_success = false;

        let email = b"testing@test.com";
        let password = b"badpasswordeh";

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();

        let a = rng.gen_biguint_below(&N);

        ServerSRP::start(rx1);

        tx1.send(Message::Register(email.to_vec(), password.to_vec(), tx2)).unwrap();

        let A = BigUint::from(g).modpow(&a, &N);

        tx1.send(Message::InitiateLogin(email[..].to_vec(), A.clone())).unwrap();

        if let Message::LoginResponse(salt, B) = rx2.recv().unwrap() {
            let uh = hash_concat(&A, &B); 

            let x = hash_salt_password(&salt, &password[..]);

            // TODO: Ensure that B is larger than subtracted value here...
            let S = (B - ((k * BigUint::from(g).modpow(&x, &N)) % &N)).modpow(&(&(&a + (&uh * &x) % &N) % &N), &N);

            let K = hash_biguint(&S);

            tx1.send(Message::AttemptLogin(email.to_vec(), compute_hmac(&K, &salt))).unwrap();

            if let Message::LoginSuccess(success) = rx2.recv().unwrap() {
                login_success = success
            }
        }

        assert!(login_success);
    }
}
