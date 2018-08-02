use rand::{OsRng};
use bigint::{RandBigInt, BigUint};
use std::cell::RefCell;
use std::rc::Rc;
use crypto::digest::Digest;
use crypto::sha1::{Sha1};
use utils::crypto::{cbc_encrypt, cbc_decrypt};
use utils::bytes::{generate_random_aes_key};


#[derive(Debug)]
pub enum Message {
  InitSession(BigUint, BigUint, BigUint), // p, g, public_key
  AckInit(BigUint), // public key
  Content(Vec<u8>, Vec<u8>), // ciphertext, iv
}

pub trait Entity {
  fn receive_message(&mut self, Rc<RefCell<Entity>>, Message);
  fn send_encrypted_message(&mut self, &[u8]);
}

pub struct HonestEntity {
  pub rc: Option<Rc<RefCell<HonestEntity>>>,
  pub keypair: Option<DHKeyPair>,
  pub partner: Option<Rc<RefCell<Entity>>>,
  pub session_key: Option<Vec<u8>>,
}

impl Entity for HonestEntity {
  fn receive_message(&mut self, sender: Rc<RefCell<Entity>>, message: Message) -> () {
    println!("received message {:?}", &message);
    match message {
      Message::InitSession(p, g, public_key) => {
        let keypair = DHKeyPair::new(&p, &g);

        self.session_key = Some(keypair.gen_aes_session_key(public_key).clone());

        let my_public_key = keypair.public_key.clone();

        self.keypair = Some(keypair);
        self.partner = Some(sender);

        let response = Message::AckInit(my_public_key);

        self.partner.as_ref().unwrap().borrow_mut().receive_message(self.rc.as_ref().unwrap().clone(), response);
      },
      Message::AckInit(public_key) => {
        self.partner = Some(sender);

        self.session_key = Some(self.keypair.as_ref().unwrap().gen_aes_session_key(public_key).clone());
      },
      Message::Content(ciphertext, iv) => {
        let plaintext = cbc_decrypt(self.session_key.as_ref().unwrap(), &ciphertext, &iv);
        println!("Decrypted plaintext = {:?}", String::from_utf8_lossy(&(plaintext.as_ref().unwrap())));
      },
    };
  }

  fn send_encrypted_message(&mut self, plaintext: &[u8]) {
    let iv = generate_random_aes_key();
    let ciphertext = cbc_encrypt(self.session_key.as_ref().unwrap(), plaintext, &iv[..]);
    let message = Message::Content(ciphertext, iv);
    self.partner.as_ref().unwrap().borrow_mut().receive_message(self.rc.as_ref().unwrap().clone(), message);
  }
}

// impl Entity for HonestEntity {
//   fn set_partner(&mut self, partner: Rc<RefCell<Entity>>) {

//   }

//   fn set_keypair(&mut self, keypair: DHKeyPair) {
//     self.keypair = Some(keypair);
//   }
// }

impl HonestEntity {
  pub fn new() -> Rc<RefCell<HonestEntity>> {
    let entity = Rc::new(RefCell::new(
      HonestEntity {
        rc: None,
        keypair: None,
        partner: None,
        session_key: None,
      }
    ));

    (*entity).borrow_mut().rc = Some(entity.clone());

    entity
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

  pub fn gen_aes_session_key(&self, b: BigUint) -> Vec<u8> {
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

    let a = HonestEntity::new();
    a.borrow_mut().init(&p, &g);
    let b = HonestEntity::new();

    // let e2 = Entity::new(&p, &g);

    let init_message = Message::InitSession(p.clone(), g.clone(), (*a).borrow().get_public_key());

    b.borrow_mut().receive_message(a.clone(), init_message);

    a.borrow_mut().send_encrypted_message("hi from a".as_bytes());

    b.borrow_mut().send_encrypted_message("hi from b".as_bytes());

  }
}
