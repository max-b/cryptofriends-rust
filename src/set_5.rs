use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use utils::entity::{Action, Entity, Message};

pub fn message_loop(
    map: &HashMap<usize, Rc<RefCell<Entity>>>,
    a: Rc<RefCell<Entity>>,
    b: Rc<RefCell<Entity>>,
    first_message: Rc<Message>,
) -> () {
    let mut res = b.borrow_mut().receive_message(a.clone(), first_message);

    loop {
        match res {
            Action::SendMessage(sender_id, receiver_id, m) => {
                // Lookup receiver, send message to them
                let receiver = map.get(&receiver_id).unwrap();
                let sender = map.get(&sender_id).unwrap();
                res = receiver
                    .borrow_mut()
                    .receive_message(sender.clone(), m.clone());
            }
            Action::Finish => {
                break;
            }
            Action::Start => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bigint::BigUint;
    use openssl::bn::{BigNum, BigNumContext};
    use std::collections::HashMap;
    use utils::crypto::rsa::{CubeRoot, RSA};
    use utils::crypto::DHKeyPair;
    use utils::entity::{Entity, HonestEntity, Message, MiTMEntity};

    #[test]
    fn challenge_33() {
        let p = BigUint::from(37 as usize);
        let g = BigUint::from(5 as usize);
        let keypair1 = DHKeyPair::new(&p, &g);
        let keypair2 = DHKeyPair::new(&p, &g);

        let pub1 = keypair1.get_public_key();
        let pub2 = keypair2.get_public_key();

        let s1 = keypair1.gen_session_key(&pub2);
        let s2 = keypair2.gen_session_key(&pub1);

        assert_eq!(s1, s2);

        let p = BigUint::parse_bytes(
            b"22405534230753963835153736737\
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        fffffffffffff",
            16,
        ).unwrap();
        let g = BigUint::from(2 as usize);

        let keypair1 = DHKeyPair::new(&p, &g);
        let keypair2 = DHKeyPair::new(&p, &g);

        let pub1 = keypair1.get_public_key();
        println!("public key 1 = {:?}", &pub1);

        let pub2 = keypair2.get_public_key();
        println!("public key 2 = {:?}", &pub2);

        let s1 = keypair1.gen_session_key(&pub2);
        println!("session key 1 = {:?}", &s1);

        let s2 = keypair2.gen_session_key(&pub1);
        println!("session key 2 = {:?}", &s2);

        assert_eq!(s1, s2);
    }

    #[test]
    fn challenge_34() {
        let p = BigUint::parse_bytes(
            b"22405534230753963835153736737\
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        fffffffffffff",
            16,
        ).unwrap();
        let g = BigUint::from(2 as usize);

        let a = HonestEntity::new(0, String::from("A"));
        a.borrow_mut().init(&p, &g);
        let b = HonestEntity::new(1, String::from("B"));

        let init_message = Rc::new(Message::InitSessionWithPublicKey(
            p.clone(),
            g.clone(),
            (*a).borrow().get_public_key(),
        ));

        let mut map: HashMap<usize, Rc<RefCell<Entity>>> = HashMap::new();

        map.insert(0, a.clone());
        map.insert(1, b.clone());

        message_loop(&map, a.clone(), b.clone(), init_message);

        a.borrow_mut()
            .send_encrypted_message("hi from a".as_bytes());

        b.borrow_mut()
            .send_encrypted_message("hi from b".as_bytes());

        println!("\n== Now with a MiTM ==");
        let a = HonestEntity::new(0, String::from("A"));
        a.borrow_mut().init(&p, &g);
        let b = HonestEntity::new(1, String::from("B"));

        let m = MiTMEntity::new(2, String::from("M"), a.clone(), b.clone(), None);

        let mut map: HashMap<usize, Rc<RefCell<Entity>>> = HashMap::new();

        map.insert(0, a.clone());
        map.insert(1, b.clone());
        map.insert(2, m.clone());

        let init_message = Rc::new(Message::InitSessionWithPublicKey(
            p.clone(),
            g.clone(),
            p.clone(),
        ));

        message_loop(&map, a.clone(), m.clone(), init_message);

        a.borrow_mut()
            .send_encrypted_message("hi from a".as_bytes());

        b.borrow_mut()
            .send_encrypted_message("hi from b".as_bytes());
    }

    #[test]
    fn challenge_35() {
        let p = BigUint::parse_bytes(
            b"22405534230753963835153736737\
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        fffffffffffff",
            16,
        ).unwrap();
        let g = BigUint::from(2 as usize);

        let a = HonestEntity::new(0, String::from("A"));
        a.borrow_mut().init(&p, &g);
        let b = HonestEntity::new(1, String::from("B"));

        let init_message = Rc::new(Message::InitSession(p.clone(), g.clone()));

        let mut map: HashMap<usize, Rc<RefCell<Entity>>> = HashMap::new();

        map.insert(0, a.clone());
        map.insert(1, b.clone());

        message_loop(&map, a.clone(), b.clone(), init_message);

        a.borrow_mut()
            .send_encrypted_message("hi from a".as_bytes());

        b.borrow_mut()
            .send_encrypted_message("hi from b".as_bytes());

        println!("\n== Now with a MiTM who sets g to 1 ==");
        let a = HonestEntity::new(0, String::from("A"));
        a.borrow_mut().init(&p, &g);
        let b = HonestEntity::new(1, String::from("B"));

        let m = MiTMEntity::new(
            2,
            String::from("M"),
            a.clone(),
            b.clone(),
            Some(BigUint::from(1 as usize)),
        );

        let mut map: HashMap<usize, Rc<RefCell<Entity>>> = HashMap::new();

        map.insert(0, a.clone());
        map.insert(1, b.clone());
        map.insert(2, m.clone());

        let init_message = Rc::new(Message::InitSession(p.clone(), g.clone()));

        message_loop(&map, a.clone(), m.clone(), init_message);

        a.borrow_mut()
            .send_encrypted_message("hi from a".as_bytes());

        println!("\n== Now with a MiTM who sets g to p ==");
        let a = HonestEntity::new(0, String::from("A"));
        a.borrow_mut().init(&p, &g);
        let b = HonestEntity::new(1, String::from("B"));

        let m = MiTMEntity::new(2, String::from("M"), a.clone(), b.clone(), Some(p.clone()));

        let mut map: HashMap<usize, Rc<RefCell<Entity>>> = HashMap::new();

        map.insert(0, a.clone());
        map.insert(1, b.clone());
        map.insert(2, m.clone());

        let init_message = Rc::new(Message::InitSession(p.clone(), g.clone()));

        message_loop(&map, a.clone(), m.clone(), init_message);

        a.borrow_mut()
            .send_encrypted_message("hi from a".as_bytes());

        println!("\n== Now with a MiTM who sets g to p-1 ==");
        let a = HonestEntity::new(0, String::from("A"));
        a.borrow_mut().init(&p, &g);
        let b = HonestEntity::new(1, String::from("B"));

        let m = MiTMEntity::new(
            2,
            String::from("M"),
            a.clone(),
            b.clone(),
            Some(p.clone() - BigUint::from(1 as usize)),
        );

        let mut map: HashMap<usize, Rc<RefCell<Entity>>> = HashMap::new();

        map.insert(0, a.clone());
        map.insert(1, b.clone());
        map.insert(2, m.clone());

        let init_message = Rc::new(Message::InitSession(p.clone(), g.clone()));

        message_loop(&map, a.clone(), m.clone(), init_message);

        a.borrow_mut()
            .send_encrypted_message("hi from a".as_bytes());
    }

    #[test]
    fn challenge_39() {
        let rsa = RSA::new().expect("RSA::new()");
        let plaintext = "this is a test of the emergency encryption system 💖";
        println!("plaintext = {:?}", &plaintext);
        let ciphertext = rsa.encrypt_string(&plaintext).expect("rsa.encrypt");
        println!("ciphertext = {:?}", &ciphertext);
        let decrypted = rsa.decrypt_string(&ciphertext).expect("rsa.decrypt");
        println!("decrypted = {:?}", &decrypted);
        assert_eq!(&plaintext, &decrypted);
    }

    #[test]
    fn challenge_40() {
        let plaintext = "i like to send the same message to alllllll of my friends, using my handrolled textbook RSA 😎";
        println!("plaintext = {:?}", &plaintext);

        let snooped: Vec<(BigNum, BigNum)> = (0..3)
            .map(|_| {
                let rsa = RSA::new().expect("RSA::new()");
                let ciphertext = rsa.encrypt_string(&plaintext).expect("rsa.encrypt");

                (ciphertext, rsa.n)
            }).collect();

        let N: BigNum = snooped
            .iter()
            .map(|(_c, n)| n)
            .fold(BigNum::from(1), |acc, x| &acc * x);

        let result = &snooped
            .iter()
            .map(|(c, n)| c * &(&(&N / n) * &(RSA::euclidean_algorithm(n, &(&N / n)).1)))
            .fold(BigNum::from(0), |acc, x| &acc + &x)
            % &N;

        println!("result = {:?}", result);

        if let CubeRoot::Exact(cuberoot) = RSA::cube_root(&result) {
            println!("cuberoot = {:?}", &cuberoot);
            let plaintext = RSA::bignum_to_string(&cuberoot);
            println!("plaintext = {:?}", &plaintext);
        }
    }

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
}
