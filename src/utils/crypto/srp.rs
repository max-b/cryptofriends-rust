use std::thread;
use std::sync::mpsc::{Receiver, Sender};
use std::collections::HashMap;
use bigint::{BigUint, RandBigInt};
use rand::OsRng;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use crypto::mac::{Mac, MacResult};
use crypto::hmac::Hmac;
use utils::misc::nist_prime;

pub static g: u32 = 2;
pub static k: u32 = 3;


pub enum Message {
    Register(Vec<u8>, Vec<u8>, Sender<Message>), // email, password
    InitiateLogin(Vec<u8>, BigUint), // email, A
    SimplifiedInitiateLogin(Vec<u8>, BigUint), // email, A
    LoginResponse(BigUint, BigUint), // salt, B
    SimplifiedLoginResponse(BigUint, BigUint, BigUint), // salt, B, u
    AttemptLogin(Vec<u8>, MacResult), // email, Mac
    SimplifiedAttemptLogin(Vec<u8>, MacResult), // email, Mac
    LoginSuccess(bool),
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SessionStatus {
    Registered,
    LoginInitiated,
}

pub struct ClientState {
    pub status: SessionStatus,
    pub salt: BigUint,
    pub v: BigUint,
    pub b: BigUint,
    pub sender: Sender<Message>,
    pub A: Option<BigUint>,
    pub B: Option<BigUint>,
    pub u: Option<BigUint>,
}

pub struct SRPServer {
    pub clients: HashMap<Vec<u8>, ClientState>,
}

impl SRPServer {
    pub fn start(receiver: Receiver<Message>) {
        let mut rng = OsRng::new().expect("Can't get rng");
        let mut server = SRPServer {
            clients: HashMap::new(),
        };
        let N = nist_prime();

        thread::spawn(move || {
            for received in receiver {
                match received {
                    Message::Register(email, password, sender) => {
                        if server.clients.contains_key(&email) {
                            println!("Email already registered: {:x?}", &email);
                        } else {
                            let (salt, v) = generate_vals(&password);
                            let b = rng.gen_biguint_below(&N);
                            server.clients.insert(email, ClientState {
                                status: SessionStatus::Registered,
                                b,
                                salt,
                                v,
                                sender,
                                A: None,
                                B: None,
                                u: None,
                            });
                        }
                    },
                    Message::SimplifiedInitiateLogin(email, A) => {
                        match server.clients.get_mut(&email) {
                            Some(client) => {
                                if client.status == SessionStatus::Registered {
                                    let B = BigUint::from(g).modpow(&client.b, &N);
                                    let u = rng.gen_biguint(128);
                                    client.sender.send(Message::SimplifiedLoginResponse(client.salt.clone(), B.clone(), u.clone())).unwrap();
                                    client.B = Some(B);
                                    client.A = Some(A);
                                    client.u = Some(u);
                                    client.status = SessionStatus::LoginInitiated;
                                } else {
                                    println!("Client not in registered state: {:x?}", &email);
                                }
                            },
                            None => {
                                println!("Email not registered: {:x?}", &email);
                            }
                        }
                    },
                    Message::InitiateLogin(email, A) => {
                        match server.clients.get_mut(&email) {
                            Some(client) => {
                                if client.status == SessionStatus::Registered {
                                    let B = (((k * &client.v) % &N) + BigUint::from(g).modpow(&client.b, &N)) % &N;
                                    client.sender.send(Message::LoginResponse(client.salt.clone(), B.clone())).unwrap();
                                    client.B = Some(B);
                                    client.A = Some(A);
                                    client.status = SessionStatus::LoginInitiated;
                                } else {
                                    println!("Client not in registered state: {:x?}", &email);
                                }
                            },
                            None => {
                                println!("Email not registered: {:x?}", &email);
                            }
                        }
                    },
                    Message::SimplifiedAttemptLogin(email, mac_input) => {
                        match server.clients.get_mut(&email) {
                            Some(client) => {
                                if client.status == SessionStatus::LoginInitiated {
                                    if let (Some(A), Some(u)) = (&client.A, &client.u) {
                                        let S = (&(A * client.v.modpow(&u, &N)) % &N).modpow(&client.b, &N);

                                        let K = hash_biguint(&S);
                                        let computed_hmac = compute_hmac(&K, &client.salt);

                                        client.sender.send(Message::LoginSuccess(computed_hmac == mac_input)).unwrap();
                                        // Reset status to Registered
                                        client.status = SessionStatus::Registered;
                                    }
                                } else {
                                    println!("Client not in login initiated state: {:x?}", &email);
                                }
                            }
                            None => {
                                println!("Email not registered: {:x?}", &email);
                            }
                        }
                    }
                    Message::AttemptLogin(email, mac_input) => {
                        match server.clients.get_mut(&email) {
                            Some(client) => {
                                if client.status == SessionStatus::LoginInitiated {
                                    if let (Some(A), Some(B)) = (&client.A, &client.B) {
                                        let uh = hash_concat(A, B);

                                        let S = (&(A * client.v.modpow(&uh, &N)) % &N).modpow(&client.b, &N);

                                        let K = hash_biguint(&S);
                                        let computed_hmac = compute_hmac(&K, &client.salt);

                                        client.sender.send(Message::LoginSuccess(computed_hmac == mac_input)).unwrap();
                                        // Reset status to Registered
                                        client.status = SessionStatus::Registered;
                                    }
                                } else {
                                    println!("Client not in login initiated state: {:x?}", &email);
                                }
                            }
                            None => {
                                println!("Email not registered: {:x?}", &email);
                            }
                        }
                    }
                    _ => {
                        // This means we've received a message that
                        // really shouldn't be coming to server
                        panic!("Server received unknown message");
                    }
                }
            }
        });
    }

}

pub fn generate_vals(password: &[u8]) -> (BigUint, BigUint) {
    let N = nist_prime();
    let mut rng = OsRng::new().expect("Can't get rng");
    let salt = rng.gen_biguint_below(&N);

    let x = hash_salt_password(&salt, &password);

    let v = BigUint::from(g).modpow(&x, &N);

    (salt, v)
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
