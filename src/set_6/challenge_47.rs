use openssl::bn::{BigNum, BigNumContext};
use utils::crypto::rsa::RSA;

#[derive(Debug)]
pub struct Range {
    pub min: BigNum,
    pub max: BigNum,
}

impl Range {
    fn contains(&self, other: &Range) -> bool {
        self.min <= other.min && self.max >= other.max
    }
}

pub fn bleichenbacher_oracle(ciphertext: &BigNum, rsa: &RSA) -> bool {
    let k = rsa.n.to_vec().len();
    let mut decrypt_bytes = rsa.decrypt(ciphertext).expect("error decrypting").to_vec();
    while decrypt_bytes.len() < k {
        decrypt_bytes.insert(0, 0);
    }
    
    decrypt_bytes[0] == 2 && decrypt_bytes[1] == 2
}

#[allow(non_snake_case)]
pub fn bleichenbacher_step_2(i: usize, c0: &BigNum, s: &mut Vec<BigNum>, M: &Vec<Vec<Range>>, B: &BigNum, rsa: &RSA, _m: &BigNum) {

    let zero = BigNum::from(0);
    let one = BigNum::from(1);
    let two = BigNum::from(2);
    let three = BigNum::from(3);
    let mut ctx = BigNumContext::new().expect("BigNumContext::new()");

    println!("s = {:?}", &s);
    println!("B = {:?}", &B);
    println!("n = {:?}", &rsa.n);
    println!("c0 = {:?}", c0);

    if i == 1  || M[i - 1].len() > 1 {
        // search for smallest s >= n/3B such that c0(s[i]^e) % n is pkcs conforming
        let mut s_new = ceil_div(&rsa.n, &(&three * B));

        if i > 1 {
            s_new = &s[i - 1] + &one;
        }
        // search for smallest integer s[i] > s[i-1] such that c0(s[i]^e) % n is pkcs conforming
        
        let mut s_e_mod_n = BigNum::new().expect("BigNum::new()");
        s_e_mod_n.mod_exp(&s_new, &rsa.e, &rsa.n, &mut ctx).unwrap();
        while !bleichenbacher_oracle(&(&(c0 * &s_e_mod_n) % &rsa.n), &rsa) {
            // println!("s_new = {:?}", &s_new);
            // println!("s_e_mod_n = {:?}", &s_e_mod_n);
            s_new = &s_new + &one;
            s_e_mod_n.mod_exp(&s_new, &rsa.e, &rsa.n, &mut ctx).unwrap();
        }

        s.push(s_new)
    } else {
        // search for s[i] r[i] such that 
        // r[i] >= (2 * (b*s[i - 1] - 2B)) / n
        // s[i] >= (2B + r[i]*n) / b && s[i] < (2B + r[i]*n)  a
        let a = &M[i - 1][0].min + &zero;
        let b = &M[i - 1][0].max + &zero;

        let mut r = ceil_div(&(&two * &(&(&b * &s[i - 1]) - &(&two * B))), &rsa.n);
        let mut s_new = ceil_div(&(&(&two * B) + &(&r * &rsa.n)), &b);

        let mut s_e_mod_n = BigNum::new().expect("BigNum::new()");
        s_e_mod_n.mod_exp(&s_new, &rsa.e, &rsa.n, &mut ctx).unwrap();

        while !bleichenbacher_oracle(&(&(c0 * &s_e_mod_n) % &rsa.n), &rsa) {
            // println!("STEP 2c");
            // println!("i = {}", i);
            // println!("a = {:?}", a);
            // println!("b = {:?}", b);
            // println!("m = {:?}", &m);
            // println!("r = {:?}", &s_new);
            // println!("s_new = {:?}", &s_new);
            // println!("s_e_mod_n = {:?}", &s_e_mod_n);
            s_new = &s_new + &one;
            if s_new > &(&(&three * B) + &(&r * &rsa.n)) / &a {
                r = &r + &one;
                s_new = ceil_div(&(&(&two * B) + &(&r * &rsa.n)), &b);
            }
            s_e_mod_n.mod_exp(&s_new, &rsa.e, &rsa.n, &mut ctx).unwrap();
        }

        s.push(s_new)
    }
}

pub fn ceil_div(num: &BigNum, den: &BigNum) -> BigNum {
    &(&(num + den) - &BigNum::from(1)) / den
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp;
    use openssl::bn::{BigNum, BigNumContext};
    use utils::bytes::{random_bytes};
    use utils::crypto::rsa::RSA;

    #[test]
    fn challenge_47() {
        // We're going to re-use these a bunch, so might as well
        let zero = BigNum::from(0);
        let one = BigNum::from(1);
        let two = BigNum::from(2);
        let three = BigNum::from(3);

        let rsa = RSA::new_with_size(128).expect("RSA::new_with_size(128)");
        let k = rsa.n.to_vec().len();
        #[allow(non_snake_case)]
        let mut B = BigNum::new().expect("BigNum::new()");
        let mut ctx = BigNumContext::new().expect("BigNumContext::new()");
        B.exp(&two, &BigNum::from((8 * (k - 2)) as u32), &mut ctx).expect("B.exp()");
        let plaintext_bytes = "kick it, CC".as_bytes();

        let mut n_min = BigNum::new().expect("BigNum::new()");
        n_min.exp(&two, &BigNum::from((8 * (k - 1)) as u32), &mut ctx).expect("n_min.exp()");
        assert!(n_min <= rsa.n);
        let mut n_max = BigNum::new().expect("BigNum::new()");
        n_max.exp(&two, &BigNum::from((8 * k) as u32), &mut ctx).expect("n_max.exp()");
        assert!(n_max > rsa.n);
        // TODO: refactor pkcs padding into library
        let padding_bytes = random_bytes((k - 3 - plaintext_bytes.len()) as u32);
        println!("padding_bytes.len() = {:?}", padding_bytes.len());
        let mut padded_plaintext = vec![0x00, 0x02];
        padded_plaintext.extend_from_slice(&padding_bytes);
        padded_plaintext.extend_from_slice(&[0x00]);
        padded_plaintext.extend_from_slice("kick it, CC".as_bytes());
        let plaintext_num = BigNum::from_slice(&padded_plaintext).expect("BigNum::from_slice()");
        let ciphertext = rsa.encrypt(&plaintext_num).expect("rsa.encrypt()");

        let decryption = rsa.decrypt(&ciphertext).unwrap();

        println!("k = {:?}", k);
        println!("n = {:?}", rsa.n.to_vec());
        println!("plaintext = {:?}", &padded_plaintext);
        println!("decryption = {:?}", &decryption.to_vec());

        // Step 1
        let mut s = vec![&one + &zero];
        let c0 = &ciphertext * &one;

        #[allow(non_snake_case)]
        let mut M = vec![
            vec![
                Range { 
                    min: &two * &B,
                    max: &(&three * &B) - &one,
                }
            ]
        ];

        let mut found = false;
        let mut i: usize = 1;

        while !found {
            
            bleichenbacher_step_2(i, &c0, &mut s, &M, &B, &rsa, &plaintext_num);

            println!("s = {:?}", &s);
            assert!(s.len() > 1);

            // Step 3
            // Not yet handling the case of M containing multiple ranges
            assert!(M[i - 1].len() == 1);

            let a = &M[i - 1][0].min + &zero;
            let b = &M[i - 1][0].max + &zero;

            // We're taking a ceiling here because r >= the computed (float) r_min value
            let r_min = ceil_div(&(&(&(&a * &s[i]) - &(&three * &B)) + &one), &rsa.n);
            let r_max = &(&(&b * &s[i]) - &(&two * &B)) / &rsa.n;

            // For now only handle r_max == r_min
            assert!(r_max == r_min);
            println!("i = {:?}", i);
            println!("M[i - 1] = {:?}", &M[i - 1]);
            println!("a = {:?}", &a);
            println!("b = {:?}", &b);
            println!("r_min = {:?}", &r_min);
            println!("r_max = {:?}", &r_max);
            let mut m_new: Vec<Range> = Vec::new();

            let mut r = &r_min + &zero;
            // while r <= r_max {

            println!("r = {:?}", &r);
            let new_min = cmp::max(
                &a + &zero, 
                ceil_div(&(&(&two * &B) + &(&r * &rsa.n)), &s[i])
            );
            println!("a =          {:?}", &a);
            println!("2B + n / s = {:?}", &ceil_div(&(&(&two * &B) + &(&r * &rsa.n)), &s[i]));
            println!("new_min =    {:?}", &new_min);

            let new_max = cmp::min(
                &b + &zero,
                &(&(&(&three * &B) - &one) + &(&r * &rsa.n)) / &s[i]
            );
            println!("b =               {:?}", &b);
            println!("3B - 1 + rn / s = {:?}", &(&(&(&three * &B) - &one) + &(&r * &rsa.n)) / &s[i]);
            println!("new_max =         {:?}", &new_max);

            let mut contains = false;
            let new_range = Range {
                min: new_min,
                max: new_max,
            };

            // TODO: fix overlapping issue???
            for range in &m_new {
                contains = contains || range.contains(&new_range);
            }

            println!("new_range = {:?}", &new_range);
            if !contains && new_range.min <= new_range.max {
                m_new.push(new_range);
            }

            r = &r + &one;
            // }

            M.push(m_new);
            println!("i = {:?}", i);
            println!("B        = {:?}", &B);
            println!("n        = {:?}", &rsa.n);
            println!("M[i].min = {:?}", &M[i][0].min);
            println!("M[i].max = {:?}", &M[i][0].max);
            println!("m =        {:?}", &plaintext_num);
            assert!(M[i].len() == 1);
            assert!(&M[i][0].min < &plaintext_num);
            assert!(&M[i][0].max > &plaintext_num);

            // Step 4
            // i <- i + 1
            if M[i].len() == 1 && M[i][0].min == M[i][0].max {
                found = true;
            }
            i = i + 1;
            assert!(i < 4);
        }

        println!("FOUND :)");
    }
}
