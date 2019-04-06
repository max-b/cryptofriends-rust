use utils::crypto::rsa::RSA;
use openssl::bn::{BigNum};

#[derive(PartialEq)]
pub enum Parity {
    Even,
    Odd,
}

pub fn plaintext_parity(ciphertext: &BigNum, rsa: &RSA) -> Parity {
    let decrypt = rsa.decrypt(ciphertext).expect("error decrypting");

    if decrypt.is_bit_set(0) {
        Parity::Even
    } else {
        Parity::Odd
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::bn::{BigNum, BigNumContext};
    use utils::crypto::rsa::RSA;
    use utils::bigint;
    use utils::bytes::{base64_to_bytes};

    #[test]
    fn challenge_46() {
        let actual_plaintext = "That\'s why I found you don\'t play around with the Funky Cold Medin";
        let rsa = RSA::new().expect("RSA::new()");
        let plaintext = BigNum::from_slice(&base64_to_bytes("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")).unwrap();

        let ciphertext = rsa.encrypt(&plaintext).unwrap();

        let zero = BigNum::from(0);
        let two = BigNum::from(2);

        // So much hacky cloning
        let mut ctx = BigNumContext::new().expect("BugNum new()");
        let mut c = &zero + &ciphertext;
        let mut tmp = BigNum::new().expect("BugNum new()");
        let mut higher_bound = &zero + &rsa.n;
        let mut lower_bound = &zero + &zero;

        while &higher_bound > &zero {
            tmp.mod_exp(&two, &rsa.e, &rsa.n, &mut ctx)
                .expect("mod_exp");
            let c2 = &(&c * &tmp) % &rsa.n;
            c = &zero + &c2;

            let parity = plaintext_parity(&c2, &rsa);

            let diff = &higher_bound - &lower_bound;
            let delta = &diff / &two;
            if parity == Parity::Odd {
                higher_bound = &higher_bound - &delta;
            } else {
                lower_bound = &lower_bound + &delta;
            }

            let high_guess_string = bigint::bignum_to_string(&higher_bound);
            let low_guess_string = bigint::bignum_to_string(&lower_bound);
            println!("guess = {:?}", &high_guess_string);
            println!("guess = {:?}", &low_guess_string);
            if high_guess_string.contains(actual_plaintext) {
                println!("FOUND = {:?}", &high_guess_string);
                break;
            }
            if low_guess_string.contains(actual_plaintext) {
                println!("FOUND = {:?}", &low_guess_string);
                break;
            }
        }
    }
}
