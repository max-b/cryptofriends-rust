use bigint::BigUint;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;
use utils::bytes::generate_random_aes_key;
use utils::crypto::{cbc_decrypt, cbc_encrypt, DHKeyPair};

#[derive(Debug)]
pub enum Message {
    InitSessionWithPublicKey(BigUint, BigUint, BigUint), // p, g, public_key
    InitSession(BigUint, BigUint),                       // p, g
    AckInitWithPublicKey(BigUint),                       // public key
    SendPublicKey(BigUint),                              // public key
    AckInit,
    Content(Vec<u8>, Vec<u8>), // ciphertext, iv
}

pub enum Action {
    SendMessage(usize, usize, Rc<Message>), // sender id, receiver id, message
    Finish,
    Start,
}

pub trait Entity {
    fn receive_message(&mut self, Rc<RefCell<Entity>>, Rc<Message>) -> Action;
    fn am_honest(&self) -> bool;
    fn get_name(&self) -> &str;
    fn get_id(&self) -> usize;
}

impl fmt::Debug for Entity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.am_honest() {
            true => write!(f, "{}: HonestEntity", self.get_name()),
            false => write!(f, "{}: MiTMEntity", self.get_name()),
        }
    }
}

pub struct HonestEntity {
    pub name: String,
    pub id: usize,
    pub rc: Option<Rc<RefCell<HonestEntity>>>,
    pub keypair: Option<DHKeyPair>,
    pub partner: Option<Rc<RefCell<Entity>>>,
    pub session_key: Option<Vec<u8>>,
    pub sent_public_key: bool,
}

impl fmt::Debug for HonestEntity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HonestEntity")
    }
}

impl Entity for HonestEntity {
    fn receive_message(&mut self, sender: Rc<RefCell<Entity>>, message: Rc<Message>) -> Action {
        println!("Honest received message {:?}", &message);
        match *message {
            Message::InitSessionWithPublicKey(ref p, ref g, ref public_key) => {
                let keypair = DHKeyPair::new(p, g);

                self.session_key = Some(keypair.gen_aes_session_key(public_key).clone());

                let my_public_key = keypair.public_key.clone();

                self.keypair = Some(keypair);
                self.partner = Some(sender);

                let response = Rc::new(Message::AckInitWithPublicKey(my_public_key));

                println!(
                    "self.partner = {:?}",
                    self.partner.as_ref().unwrap().borrow()
                );

                return Action::SendMessage(
                    self.id,
                    self.partner.as_ref().unwrap().borrow().get_id(),
                    response,
                );
            }
            Message::InitSession(ref p, ref g) => {
                let keypair = DHKeyPair::new(p, g);

                self.keypair = Some(keypair);
                self.partner = Some(sender);

                let response = Rc::new(Message::AckInit);

                println!(
                    "self.partner = {:?}",
                    self.partner.as_ref().unwrap().borrow()
                );

                return Action::SendMessage(
                    self.id,
                    self.partner.as_ref().unwrap().borrow().get_id(),
                    response,
                );
            }
            Message::AckInitWithPublicKey(ref public_key) => {
                self.partner = Some(sender);

                self.session_key = Some(
                    self.keypair
                        .as_ref()
                        .unwrap()
                        .gen_aes_session_key(public_key)
                        .clone(),
                );
            }
            Message::SendPublicKey(ref public_key) => {
                self.partner = Some(sender);

                self.session_key = Some(
                    self.keypair
                        .as_ref()
                        .unwrap()
                        .gen_aes_session_key(public_key)
                        .clone(),
                );

                let my_public_key = self.keypair.as_ref().unwrap().public_key.clone();

                if !self.sent_public_key {
                    let response = Rc::new(Message::SendPublicKey(my_public_key));

                    return Action::SendMessage(
                        self.id,
                        self.partner.as_ref().unwrap().borrow().get_id(),
                        response,
                    );
                }
            }
            Message::AckInit => {
                self.partner = Some(sender);

                let my_public_key = self.keypair.as_ref().unwrap().public_key.clone();
                let response = Rc::new(Message::SendPublicKey(my_public_key));

                self.sent_public_key = true;
                return Action::SendMessage(
                    self.id,
                    self.partner.as_ref().unwrap().borrow().get_id(),
                    response,
                );
            }
            Message::Content(ref ciphertext, ref iv) => {
                let plaintext = cbc_decrypt(self.session_key.as_ref().unwrap(), &ciphertext, &iv);
                println!(
                    "Decrypted plaintext = {:?}",
                    String::from_utf8_lossy(&(plaintext.as_ref().unwrap()))
                );
            }
        };

        Action::Finish
    }

    fn am_honest(&self) -> bool {
        true
    }

    fn get_name(&self) -> &str {
        &self.name[..]
    }

    fn get_id(&self) -> usize {
        self.id
    }
}

impl HonestEntity {
    pub fn new(id: usize, name: String) -> Rc<RefCell<HonestEntity>> {
        let entity = Rc::new(RefCell::new(HonestEntity {
            id,
            name,
            rc: None,
            keypair: None,
            partner: None,
            session_key: None,
            sent_public_key: false,
        }));

        (*entity).borrow_mut().rc = Some(entity.clone());

        entity
    }

    pub fn send_encrypted_message(&mut self, plaintext: &[u8]) {
        let iv = generate_random_aes_key();
        let ciphertext = cbc_encrypt(self.session_key.as_ref().unwrap(), plaintext, &iv[..]);
        let message = Rc::new(Message::Content(ciphertext, iv));
        self.partner
            .as_ref()
            .unwrap()
            .borrow_mut()
            .receive_message(self.rc.as_ref().unwrap().clone(), message);
    }

    pub fn init(&mut self, p: &BigUint, g: &BigUint) -> () {
        let keypair = DHKeyPair::new(&p, &g);
        self.keypair = Some(keypair);
    }

    pub fn get_public_key(&self) -> BigUint {
        self.keypair.as_ref().unwrap().get_public_key()
    }
}

pub struct MiTMEntity {
    pub id: usize,
    pub name: String,
    pub rc: Option<Rc<RefCell<MiTMEntity>>>,
    pub partner1: Option<Rc<RefCell<Entity>>>,
    pub partner2: Option<Rc<RefCell<Entity>>>,
    pub p: Option<BigUint>,
    pub g: Option<BigUint>,
}

impl fmt::Debug for MiTMEntity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MiTMEntity")
    }
}

impl Entity for MiTMEntity {
    fn receive_message(&mut self, sender: Rc<RefCell<Entity>>, message: Rc<Message>) -> Action {
        println!("MiTM received message {:?}", &message);
        match *message {
            Message::InitSessionWithPublicKey(ref p, ref g, ref _public_key) => {
                self.p = Some(p.clone());
                let forged = Rc::new(Message::InitSessionWithPublicKey(
                    p.clone(),
                    g.clone(),
                    p.clone(),
                ));

                return Action::SendMessage(
                    self.id,
                    self.partner2.as_ref().unwrap().borrow().get_id(),
                    forged,
                );
            }
            Message::InitSession(ref p, ref g) => {
                self.p = Some(p.clone());
                let forged = if self.g.is_none() {
                    Rc::new(Message::InitSession(p.clone(), g.clone()))
                } else {
                    Rc::new(Message::InitSession(
                        p.clone(),
                        self.g.as_ref().unwrap().clone(),
                    ))
                };

                return Action::SendMessage(
                    self.id,
                    self.partner2.as_ref().unwrap().borrow().get_id(),
                    forged,
                );
            }
            Message::AckInitWithPublicKey(ref _public_key) => {
                let response = Rc::new(Message::AckInitWithPublicKey(
                    self.p.as_ref().unwrap().clone(),
                ));

                return Action::SendMessage(
                    self.id,
                    self.partner1.as_ref().unwrap().borrow().get_id(),
                    response,
                );
            }
            Message::AckInit => {
                let response = Rc::new(Message::AckInit);

                return Action::SendMessage(
                    self.id,
                    self.partner1.as_ref().unwrap().borrow().get_id(),
                    response,
                );
            }
            Message::SendPublicKey(ref public_key) => {
                let response = Rc::new(Message::SendPublicKey(public_key.clone()));

                let receiver_id = if sender.borrow().get_id()
                    == self.partner1.as_ref().unwrap().borrow().get_id()
                {
                    self.partner2.as_ref().unwrap().borrow().get_id()
                } else {
                    self.partner1.as_ref().unwrap().borrow().get_id()
                };

                return Action::SendMessage(self.id, receiver_id, response);
            }
            Message::Content(ref ciphertext, ref iv) => {
                let mut hasher = Sha1::new();

                if self.g.is_none() {
                    hasher.input(&[0]);
                } else if *(self.g.as_ref().unwrap()) == BigUint::from(1 as usize) {
                    hasher.input(&[1]);
                } else if *(self.g.as_ref().unwrap()) == *(self.p.as_ref().unwrap()) {
                    hasher.input(&[0]);
                } else if *(self.g.as_ref().unwrap())
                    == (self.p.as_ref().unwrap() - BigUint::from(1 as usize))
                {
                    hasher.input(&[1]);
                }

                let output_size = hasher.output_bits();
                let mut session_key = vec![0; output_size / 8];

                hasher.result(&mut session_key);
                // TODO: keep some more global notion of aes keysize!
                session_key.truncate(16);
                let plaintext = cbc_decrypt(&session_key[..], &ciphertext, &iv);
                println!(
                    "Decrypted plaintext = {:?}",
                    String::from_utf8_lossy(&(plaintext.as_ref().unwrap()))
                );
            }
        };

        Action::Finish
    }

    fn am_honest(&self) -> bool {
        false
    }

    fn get_name(&self) -> &str {
        &self.name[..]
    }

    fn get_id(&self) -> usize {
        self.id
    }
}

impl MiTMEntity {
    pub fn new(
        id: usize,
        name: String,
        partner1: Rc<RefCell<Entity>>,
        partner2: Rc<RefCell<Entity>>,
        g: Option<BigUint>,
    ) -> Rc<RefCell<MiTMEntity>> {
        let entity = Rc::new(RefCell::new(MiTMEntity {
            id,
            name,
            p: None,
            g,
            rc: None,
            partner1: Some(partner1),
            partner2: Some(partner2),
        }));

        (*entity).borrow_mut().rc = Some(entity.clone());

        entity
    }
}
