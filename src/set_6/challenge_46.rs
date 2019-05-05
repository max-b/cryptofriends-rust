use bigint::BigUint;
use num_traits::One;
use utils::crypto::rsa::RSA;

#[derive(PartialEq)]
pub enum Parity {
    Even,
    Odd,
}

pub fn plaintext_parity(ciphertext: &BigUint, rsa: &RSA) -> Parity {
    let decrypt = rsa.decrypt(ciphertext);

    if decrypt & BigUint::one() == BigUint::one() {
        Parity::Odd
    } else {
        Parity::Even
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bigint::BigUint;
    use num_traits::Zero;
    use utils::bigint;
    use utils::bytes::base64_to_bytes;
    use utils::crypto::rsa::RSA;

    #[test]
    fn challenge_46() {
        let actual_plaintext =
            "That\'s why I found you don\'t play around with the Funky Cold Medin";
        let rsa = RSA::new();
        let plaintext = BigUint::from_bytes_be(&base64_to_bytes("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="));

        let ciphertext = rsa.encrypt(&plaintext);

        let two = BigUint::from(2 as u32);

        let mut c = ciphertext.clone();
        let mut higher_bound = rsa.n.clone();
        let mut lower_bound = BigUint::zero().clone();
        let two_to_e = two.modpow(&rsa.e, &rsa.n);

        while &higher_bound > &BigUint::zero() {
            let c2 = (&c * &two_to_e) % &rsa.n;
            c = c2;

            let parity = plaintext_parity(&c, &rsa);

            let diff = &higher_bound - &lower_bound;
            let delta = &diff / &two;
            if parity == Parity::Even {
                higher_bound = &higher_bound - &delta;
            } else {
                lower_bound = &lower_bound + &delta;
            }

            let high_guess_string = bigint::biguint_to_string(&higher_bound);
            let low_guess_string = bigint::biguint_to_string(&lower_bound);
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
