#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use bigint::{BigUint};
    use num_traits::Pow;
    use utils::crypto::srp::{ServerSRP, Message, hash_biguint, compute_hmac};
    use utils::misc::nist_prime;

    #[test]
    fn challenge_37() {
        let N = nist_prime();

        let email = b"testing@test.com";
        let password = b"badpasswordeh";

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();

        ServerSRP::start(rx1);


        tx1.send(Message::Register(email.to_vec(), password.to_vec(), tx2)).unwrap();

        let A = BigUint::from(0 as u32);

        let mut login_success = false;
        tx1.send(Message::InitiateLogin(email[..].to_vec(), A.clone())).unwrap();

        if let Message::LoginResponse(salt, _B) = rx2.recv().unwrap() {
            let S = BigUint::from(0 as u32);

            let K = hash_biguint(&S);

            tx1.send(Message::AttemptLogin(email.to_vec(), compute_hmac(&K, &salt))).unwrap();

            if let Message::LoginSuccess(success) = rx2.recv().unwrap() {
                login_success = success
            }
        }

        assert!(login_success);

        login_success = false;

        let A = N.clone();
        tx1.send(Message::InitiateLogin(email[..].to_vec(), A.clone())).unwrap();

        if let Message::LoginResponse(salt, _B) = rx2.recv().unwrap() {
            let S = BigUint::from(0 as u32);

            let K = hash_biguint(&S);

            tx1.send(Message::AttemptLogin(email.to_vec(), compute_hmac(&K, &salt))).unwrap();

            if let Message::LoginSuccess(success) = rx2.recv().unwrap() {
                login_success = success
            }
        }

        assert!(login_success);

        login_success = false;

        let A: BigUint = N.pow(2 as u32);
        tx1.send(Message::InitiateLogin(email[..].to_vec(), A.clone())).unwrap();

        if let Message::LoginResponse(salt, _B) = rx2.recv().unwrap() {
            let S = BigUint::from(0 as u32);

            let K = hash_biguint(&S);

            tx1.send(Message::AttemptLogin(email.to_vec(), compute_hmac(&K, &salt))).unwrap();

            if let Message::LoginSuccess(success) = rx2.recv().unwrap() {
                login_success = success
            }
        }

        assert!(login_success);
    }
}
