use rand::{OsRng};
use bigint::{RandBigInt, BigUint};

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
}
