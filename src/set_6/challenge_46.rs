use utils::crypto::rsa::RSA;
use num_traits::{One};
use bigint::BigUint;

#[derive(PartialEq)]
pub enum Parity {
    Even,
    Odd,
}

pub fn plaintext_parity(ciphertext: &BigUint, rsa: &RSA) -> Parity {
    let decrypt = rsa.decrypt(ciphertext);

    println!("decrypt = {:?}", &decrypt);
    println!("decrypt bytes = {:?}", &decrypt.to_bytes_be());

    if decrypt & BigUint::from(1 as u32) == BigUint::one() {
        println!("Odd");
        Parity::Odd
    } else {
        println!("Even");
        Parity::Even
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bigint::BigUint;
    use utils::crypto::rsa::RSA;
    use utils::bigint;
    use num_traits::{Zero};
    use utils::bytes::{base64_to_bytes};

    #[test]
    fn challenge_46() {
        let actual_plaintext = "That\'s why I found you don\'t play around with the Funky Cold Medin";
        let rsa = RSA::new();
        let plaintext = BigUint::from_bytes_be(&base64_to_bytes("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="));

        let ciphertext = rsa.encrypt(&plaintext);

        let two = BigUint::from(2 as u32);

        let mut c = ciphertext.clone();
        let mut higher_bound = rsa.n.clone();
        let mut lower_bound = BigUint::zero().clone();

        while &higher_bound > &BigUint::zero() {
            let tmp = two.modpow(&rsa.e, &rsa.n);

            let c2 = (&c * &tmp) % &rsa.n;
            c = c2;

            let parity = plaintext_parity(&c, &rsa);

            let diff = &higher_bound - &lower_bound;
            let delta = &diff / &two;
            if parity == Parity::Odd {
                higher_bound = &higher_bound - &delta;
            } else {
                lower_bound = &lower_bound + &delta;
            }

            let high_guess_string = bigint::biguint_to_string(&higher_bound);
            let low_guess_string = bigint::biguint_to_string(&lower_bound);
            println!("actual bytes = {:?}", &base64_to_bytes("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="));
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
