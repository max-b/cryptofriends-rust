use rand::{OsRng};
use bigint::{RandBigInt, BigUint};
use std::cell::RefCell;
use std::rc::Rc;


#[derive(Debug)]
pub enum Message {
  InitSession(BigUint, BigUint, BigUint), // p, g, public_key
  AckInit(BigUint), // public key
}

pub trait Entity {
  fn set_keypair(&mut self, DHKeyPair);
  fn set_partner(&mut self, Rc<RefCell<Entity>>);
  // fn get_public_key(&self) -> BigUint;
}
  
pub struct HonestEntity {
  pub keypair: Option<DHKeyPair>,
  pub partner: Option<Rc<RefCell<Entity>>>,
}

fn receive_message(receiver: Rc<RefCell<Entity>>, sender: Rc<RefCell<Entity>>, message: Message) -> () {
  println!("received message {:?}", &message);
  match message {
    Message::InitSession(p, g, public_key) => {
      let keypair = DHKeyPair::new(&p, &g);

      let my_public_key = keypair.public_key.clone();
      (*receiver).borrow_mut().set_keypair(keypair);
      // TODO: This will panic right???
      (*receiver).borrow_mut().set_partner(Rc::clone(&sender));
      let response = Message::AckInit(my_public_key);
      receive_message(Rc::clone(&sender), Rc::clone(&receiver), response);
    },
    Message::AckInit(public_key) => {

    },
  };
}

impl Entity for HonestEntity {
  fn set_partner(&mut self, partner: Rc<RefCell<Entity>>) {

  }

  fn set_keypair(&mut self, keypair: DHKeyPair) {
    self.keypair = Some(keypair);
  }
}

impl HonestEntity {
  pub fn new() -> HonestEntity {
    HonestEntity {
      keypair: None,
      partner: None,
    }
  }
  
  pub fn init(&mut self, p: &BigUint, g: &BigUint) -> () {
    let keypair = DHKeyPair::new(&p, &g);
    self.keypair = Some(keypair);
  }

  pub fn get_public_key(&self) -> BigUint {
    self.keypair.as_ref().unwrap().get_public_key()
  }
}

// pub struct MitMEntity {
//   pub partner1: Option<(&dyn Entity<'a>, &'a BigUint)>,
//   pub partner2: Option<(&dyn Entity<'a>, &'a BigUint)>,
// }

// impl<'a> Entity<'a> for MitMEntity<'a> {
//   fn receive_message(&mut self, sender: &'a mut dyn Entity<'a>, message: Message) -> () {
//     match message {
//       _ => {}
//     }
//   }
// }

// impl<'a> MitMEntity<'a> {
//   pub fn new() -> MitMEntity<'a> {
//     MitMEntity {
//       partner1: None,
//       partner2: None,
//     }
//   }
// }

pub struct DHKeyPair {
  pub private_key: BigUint,
  pub public_key: BigUint,
  pub p: BigUint,
}

impl DHKeyPair {
  pub fn new(p: &BigUint, g: &BigUint)-> DHKeyPair {
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

  pub fn gen_session_key(&self, b: BigUint) -> BigUint {
    let s1 = b.modpow(&self.private_key, &self.p);
    s1
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use bigint::{BigUint};

  #[test]
  fn challenge_33() {

    let p = BigUint::from(37 as usize);
    let g = BigUint::from(5 as usize);
    let keypair1 = DHKeyPair::new(&p, &g);
    let keypair2 = DHKeyPair::new(&p, &g);

    let pub1 = keypair1.get_public_key();
    let pub2 = keypair2.get_public_key();

    let s1 = keypair1.gen_session_key(pub2);
    let s2 = keypair2.gen_session_key(pub1);


    assert_eq!(s1, s2);

    let p = BigUint::parse_bytes(b"22405534230753963835153736737\
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        fffffffffffff", 16).unwrap();
    let g = BigUint::from(2 as usize);

    let keypair1 = DHKeyPair::new(&p, &g);
    let keypair2 = DHKeyPair::new(&p, &g);

    let pub1 = keypair1.get_public_key();
    println!("public key 1 = {:?}", &pub1);

    let pub2 = keypair2.get_public_key();
    println!("public key 2 = {:?}", &pub2);

    let s1 = keypair1.gen_session_key(pub2);
    println!("session key 1 = {:?}", &s1);

    let s2 = keypair2.gen_session_key(pub1);
    println!("session key 2 = {:?}", &s2);

    assert_eq!(s1, s2);
  }

  #[test]
  fn challenge_34() {
    let p = BigUint::parse_bytes(b"22405534230753963835153736737\
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        fffffffffffff", 16).unwrap();
    let g = BigUint::from(2 as usize);

    let mut a = HonestEntity::new();
    a.init(&p, &g);
    let b = HonestEntity::new();

    // let e2 = Entity::new(&p, &g);

    let rc_a = Rc::new(RefCell::new(a));
    let rc_b = Rc::new(RefCell::new(b));

    let init_message = Message::InitSession(p.clone(), g.clone(), (*rc_a).borrow().get_public_key());

    receive_message(rc_a, rc_b, init_message);

  }
}
