#[allow(non_snake_case)]
pub mod challenge_36;
#[allow(non_snake_case)]
pub mod challenge_37;
pub mod challenge_39;
pub mod challenge_40;

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
    use std::collections::HashMap;
    use utils::crypto::dh::DHKeyPair;
    use utils::misc::nist_prime;
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

        let p = nist_prime();
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
        let p = nist_prime();
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

        a.borrow_mut().send_encrypted_message(b"hi from a");

        b.borrow_mut().send_encrypted_message(b"hi from b");

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

        a.borrow_mut().send_encrypted_message(b"hi from a");

        b.borrow_mut().send_encrypted_message(b"hi from b");
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

        a.borrow_mut().send_encrypted_message(b"hi from a");

        b.borrow_mut().send_encrypted_message(b"hi from b");

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

        a.borrow_mut().send_encrypted_message(b"hi from a");

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

        a.borrow_mut().send_encrypted_message(b"hi from a");

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

        a.borrow_mut().send_encrypted_message(b"hi from a");
    }
}
