#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use bigint::{BigUint, RandBigInt};
    use rand::OsRng;
    use rayon::prelude::*;
    use utils::crypto::srp::{g, SRPServer, Message, hash_salt_password, hash_biguint, compute_hmac};
    use utils::misc::{generate_password, generate_words, nist_prime};

    #[test]
    fn challenge_38_base() {
        let mut rng = OsRng::new().expect("Can't get rng");
        let N = nist_prime();

        let email = b"testing@test.com";
        let password = generate_password();

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();

        let a = rng.gen_biguint_below(&N);

        SRPServer::start(rx1);


        tx1.send(Message::Register(email.to_vec(), password.to_vec(), tx2)).unwrap();

        let A = BigUint::from(g).modpow(&a, &N);

        let mut login_success = false;
        tx1.send(Message::SimplifiedInitiateLogin(email[..].to_vec(), A.clone())).unwrap();

        if let Message::SimplifiedLoginResponse(salt, B, u) = rx2.recv().unwrap() {
            let x = hash_salt_password(&salt, &password[..]);
            let S = B.modpow(&(&(a + (u * x) % &N) % &N), &N);

            let K = hash_biguint(&S);

            tx1.send(Message::SimplifiedAttemptLogin(email.to_vec(), compute_hmac(&K, &salt))).unwrap();

            if let Message::LoginSuccess(success) = rx2.recv().unwrap() {
                login_success = success
            }
        }

        assert!(login_success);
    }

    #[test]
    fn challenge_38_mitm() {
        let mut rng = OsRng::new().expect("Can't get rng");
        let N = nist_prime();

        let _email = b"testing@test.com";
        // let password = b"abase";
        let password = generate_password();

        println!("password is {:?}", &password);

        // Client sends I, A
        let a = rng.gen_biguint_below(&N);
        let A = BigUint::from(g).modpow(&a, &N);

        // MitM server responds with salt, B, u
        let b = BigUint::from(1 as u32);
        let salt = BigUint::from(1 as u32);
        let B = BigUint::from(g).modpow(&b, &N);
        let u = BigUint::from(1 as u32);

        // Client calculates Hmac(K, salt)
        let x = hash_salt_password(&salt, &password[..]);
        let S = B.modpow(&(&(a + (&u * x) % &N) % &N), &N);

        let K = hash_biguint(&S);

        let hmac = compute_hmac(&K, &salt);

        // MitM server can now take salt, b, u, and A
        // and check passwords for generating valid passwords
        // x = SHA256(salt|password)
        // v = g**x % n
        // S = (A * v ** u)**b % n
        // K = SHA256(S)
        let (mut lines, _) = generate_words();

        let buffered_lines: Vec<String> = lines
            .map(|l| l.expect("Could not parse line"))
            .collect();

        let found_password = buffered_lines.par_iter().find_first(|line| {
            let word = line.as_bytes();
            let x = hash_salt_password(&salt, &word);
            let v = BigUint::from(g).modpow(&x, &N);
            let S = (&(&A * v.modpow(&u, &N)) % &N).modpow(&b, &N);
            let K = hash_biguint(&S);
            let computed_hmac = compute_hmac(&K, &salt);
            computed_hmac == hmac
        });

        assert!(found_password.is_some());
        if let Some(found_password) = found_password {
            println!("found password: {:?}", &found_password);
            assert!(found_password.as_bytes() == &password[..]);
        }
    }
}
