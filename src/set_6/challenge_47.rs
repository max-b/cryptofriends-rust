use bigint::BigUint;
use utils::crypto::rsa::RSA;
use num_traits::{One};

#[derive(Debug)]
pub struct Range {
    pub min: BigUint,
    pub max: BigUint,
}

impl Range {
    fn contains(&self, other: &Range) -> bool {
        self.min <= other.min && self.max >= other.max
    }
}

pub fn bleichenbacher_oracle(ciphertext: &BigUint, rsa: &RSA) -> bool {
    let k = rsa.n.bits() / 8;
    let mut decrypt_bytes = rsa.decrypt(ciphertext).to_bytes_be();
    while decrypt_bytes.len() < k {
        decrypt_bytes.insert(0, 0);
    }
    
    decrypt_bytes[0] == 0 && decrypt_bytes[1] == 2
}

#[allow(non_snake_case)]
pub fn bleichenbacher_step_2(i: usize, c0: &BigUint, s: &mut Vec<BigUint>, M: &Vec<Vec<Range>>, B: &BigUint, rsa: &RSA, _m: &BigUint) {

    let one = BigUint::one();
    let two = BigUint::from(2 as u32);
    let three = BigUint::from(3 as u32);

    if i == 1  || M[i - 1].len() > 1 {
        // search for smallest s >= n/3B such that c0(s[i]^e) % n is pkcs conforming
        let mut s_new = ceil_div(&rsa.n, &(&three * B));

        if i > 1 {
            println!("STEP 2b");
            s_new = &s[i - 1] + &one;
        } else {
            println!("STEP 2a");
        }
        // search for smallest integer s[i] > s[i-1] such that c0(s[i]^e) % n is pkcs conforming
        
        let mut s_e_mod_n = s_new.modpow(&rsa.e, &rsa.n);
        while !bleichenbacher_oracle(&((c0 * &s_e_mod_n) % &rsa.n), &rsa) {
            s_new = &s_new + &one;
            s_e_mod_n = s_new.modpow(&rsa.e, &rsa.n);
        }

        s.push(s_new)
    } else {
        println!("STEP 2c");
        // search for s[i] r[i] such that 
        // r[i] >= (2 * (b*s[i - 1] - 2B)) / n
        // s[i] >= (2B + r[i]*n) / b && s[i] < (2B + r[i]*n)  a
        let a = &M[i - 1][0].min.clone();
        let b = &M[i - 1][0].max.clone();

        let mut r = ceil_div(&(&two * &(&(b * &s[i - 1]) - &(&two * B))), &rsa.n);
        let mut s_new = ceil_div(&(&(&two * B) + &(&r * &rsa.n)), &b);

        let mut s_e_mod_n = s_new.modpow(&rsa.e, &rsa.n);

        while !bleichenbacher_oracle(&(&(c0 * &s_e_mod_n) % &rsa.n), &rsa) {
            s_new = &s_new + &one;
            if s_new > &(&(&three * B) + &(&r * &rsa.n)) / a {
                r = &r + &one;
                s_new = ceil_div(&(&(&two * B) + &(&r * &rsa.n)), &b);
            }
            s_e_mod_n = s_new.modpow(&rsa.e, &rsa.n);
        }

        s.push(s_new)
    }
}

pub fn ceil_div(num: &BigUint, den: &BigUint) -> BigUint {
    (&(num + den) - BigUint::one()) / den
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp;
    use utils::bytes::{random_bytes};
    use utils::crypto::rsa::RSA;
    use num_traits::pow;
    use num_traits::{One, Zero};

    #[test]
    fn challenge_47() {
        // We're going to re-use these a bunch, so might as well
        let zero = BigUint::zero();
        let one = BigUint::one();
        let two = BigUint::from(2 as u32);
        let three = BigUint::from(3 as u32);

        let rsa = RSA::new_with_size(384);
        let k = rsa.n.bits() / 8;

        #[allow(non_snake_case)]
        let B = pow(two.clone(), 8 * (k - 2) as usize);
        let plaintext_bytes = "kick it, CC".as_bytes();

        let n_min = pow(two.clone(), (8 * (k - 1)) as usize);
        assert!(&n_min <= &rsa.n);
        let n_max = pow(two.clone(), (8 * k) as usize);
        assert!(&n_max > &rsa.n);

        // TODO: refactor pkcs padding into library
        let padding_bytes = random_bytes((k - 3 - plaintext_bytes.len()) as u32);
        let mut padded_plaintext = vec![0x00, 0x02];
        padded_plaintext.extend_from_slice(&padding_bytes);
        padded_plaintext.extend_from_slice(&[0x00]);
        padded_plaintext.extend_from_slice("kick it, CC".as_bytes());
        let plaintext_num = BigUint::from_bytes_be(&padded_plaintext);
        let ciphertext = rsa.encrypt(&plaintext_num);

        // Step 1
        let mut s = vec![one.clone()];
        let c0 = ciphertext.clone();

        #[allow(non_snake_case)]
        let mut M = vec![
            vec![
                Range { 
                    min: &two * &B,
                    max: (&three * &B) - &one,
                }
            ]
        ];

        let mut found = false;
        let mut i: usize = 0;

        while !found {
            i = i + 1;
            
            bleichenbacher_step_2(i, &c0, &mut s, &M, &B, &rsa, &plaintext_num);

            // Step 3
            println!("STEP 3");
            let mut m_new: Vec<Range> = Vec::new();
            for range in &M[i - 1] {
                let a = range.min.clone();
                let b = range.max.clone();

                // We're taking a ceiling here because r >= the computed (float) r_min value
                let r_min = ceil_div(&(&(&(&a * &s[i]) - &(&three * &B)) + &one), &rsa.n);
                let r_max = &(&(&b * &s[i]) - &(&two * &B)) / &rsa.n;

                // For now only handle r_max == r_min
                // assert!(r_max == r_min);

                let mut r = r_min.clone();
                while r <= r_max {

                    let new_min = cmp::max(
                        a.clone(), 
                        ceil_div(&(&(&two * &B) + &(&r * &rsa.n)), &s[i])
                    );

                    let new_max = cmp::min(
                        b.clone(),
                        &(&(&(&three * &B) - &one) + &(&r * &rsa.n)) / &s[i]
                    );

                    let mut contains = false;
                    let new_range = Range {
                        min: new_min,
                        max: new_max,
                    };

                    // TODO: fix overlapping issue???
                    for range in &m_new {
                        contains = contains || range.contains(&new_range);
                    }

                    if !contains && 
                        new_range.min <= new_range.max &&
                        new_range.min >= &two * &B &&
                        new_range.max <= &three * &B {

                        m_new.push(new_range);
                    }

                    r = &r + &one;
                }
            }

            M.push(m_new);
            println!("i = {:?}", i);

            // Step 4
            // i <- i + 1
            if M[i].len() == 1 && M[i][0].min == M[i][0].max {
                found = true;
            }
        }

        assert!(&M[i][0].min == &plaintext_num);
        println!("FOUND :)");
    }
}
