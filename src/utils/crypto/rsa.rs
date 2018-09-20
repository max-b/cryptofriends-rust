use openssl;
use openssl::bn::{BigNum, BigNumContext};
use std::{ops, cmp};

#[derive(Debug)]
struct RSA {
    e: BigNum,
    private_key: BigNum,
    n: BigNum
}

#[derive(Debug)]
enum CubeRoot<T> {
    Exact(T),
    Nearest(T),
}

impl RSA {
    fn division_algorithm<T>(a: &T, b: &T) -> (T, T)
        where T:
            From<u32> +
            cmp::PartialEq,
            for<'a> &'a T: ops::Div<Output = T>,
            for<'a> &'a T: ops::Sub<Output = T>,
            for<'a> &'a T: ops::Rem<Output = T>,
    {
        let zero = T::from(0);
        if b == &zero {
            panic!("Attempted to divide by zero");
        }
        let q = a / b;
        let r = a % b;
        (q, r)
    }

    /// The following function takes as input a pair (a, b)
    /// and outputs a pair (d, x), satisfying
    ///      d = gcd( a, b )
    ///      bx % a = d
    /// In particular, if gcd(a, b) == 1,
    /// then x is the multiplicative inverse of b modulo a.
    /// Returns:
    ///      (1, modinv) if (a, b) are relatively prime
    fn euclidean_algorithm<T>(a: &T, b: &T) -> (T, T) 
        where T:
            cmp::PartialEq + 
            From<u32>,
            for<'a> &'a T: ops::Div<Output = T>,
            for<'a> &'a T: ops::Rem<Output = T>,
            for<'a> &'a T: ops::Mul<Output = T>,
            for<'a> &'a T: ops::Add<Output = T>,
            for<'a> &'a T: ops::Sub<Output = T>,
    {
        let zero = T::from(0);
        if b == &zero {
            panic!("Attempted to divide by zero");
        }
        let (q, r) = Self::division_algorithm(a, b);
        // Adding with zero is a hacky clone
        let mut ab = (b + &zero, r);
        let mut numers = (T::from(1), q);
        let mut counter = T::from(0);
        while &ab.1 != &zero {
            let (q, r) = Self::division_algorithm(&ab.0, &ab.1);
            let tmp = &ab.1 + &zero;
            ab.0 = tmp;
            ab.1 = &r + &zero;
            let numers_1 = &numers.1 + &zero;
            numers = (numers.1, (&(&q * &numers_1) + &numers.0));
            counter = &counter + &T::from(1);
        }

        if &counter % &T::from(2) == zero {
            (ab.0, numers.0)
        } else {
            (ab.0, a - &numers.0)
        }
    }

    pub fn new() -> Result<RSA, openssl::error::ErrorStack> {
        let (mut p, mut q) = (BigNum::new()?, BigNum::new()?);
        p.generate_prime(1024, false, None, None)?;
        q.generate_prime(1024, false, None, None)?;
        let e = BigNum::from_u32(3)?;
        let n = &p * &q;
        let et = &(&p - &BigNum::from_u32(1)?) * &(&q - &BigNum::from_u32(1)?);
        let mut ctx = BigNumContext::new()?;
        let mut d = BigNum::new()?;
        d.mod_inverse(&e, &et, &mut ctx)?;

        Ok(RSA {
            e,
            private_key: d,
            n
        })
    }

    pub fn string_to_bignum(string: &str) -> Result<BigNum, openssl::error::ErrorStack> {
        BigNum::from_slice(string.as_bytes())
    }

    pub fn bignum_to_string(num: &BigNum) -> String {
        let bytes = num.to_vec();
        String::from_utf8_lossy(&bytes[..]).to_string()
    }

    pub fn encrypt(&self, plaintext: &BigNum) -> Result<BigNum, openssl::error::ErrorStack> {
        let mut c = BigNum::new()?;
        let mut ctx = BigNumContext::new()?;
        c.mod_exp(plaintext, &self.e, &self.n, &mut ctx).expect("mod_exp");

        Ok(c)
    }

    pub fn decrypt(&self, ciphertext: &BigNum) -> Result<BigNum, openssl::error::ErrorStack> {
        let mut m = BigNum::new()?;
        let mut ctx = BigNumContext::new()?;
        m.mod_exp(ciphertext, &self.private_key, &self.n, &mut ctx).expect("mod_exp");

        Ok(m)
    }

    pub fn encrypt_string(&self, plaintext: &str) -> Result<BigNum, openssl::error::ErrorStack> {
        self.encrypt(&RSA::string_to_bignum(plaintext)?)
    }

    pub fn decrypt_string(&self, ciphertext: &BigNum) -> Result<String, openssl::error::ErrorStack> {
        let plaintext = self.decrypt(ciphertext)?;
        Ok(RSA::bignum_to_string(&plaintext))
    }

    pub fn cube_root(n: &BigNum) -> CubeRoot<BigNum> {
        // Do a cube root via binary search, since it's not implemented in OpenSSL BigNum :D

        let mut left = BigNum::from(1);
        let mut right = n + &BigNum::from(0); // "clone"

        while left != right {
            let midpoint = &(&left + &right)/&BigNum::from(2);

            let mut cube = BigNum::new().unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            cube.exp(&midpoint, &BigNum::from(3), &mut ctx).expect("exp");

            if &cube == n {
                return CubeRoot::Exact(midpoint);
            }

            if &(&right - &left) == &BigNum::from(1) {
                let mut right_cube = BigNum::new().unwrap();
                let mut ctx = BigNumContext::new().unwrap();
                right_cube.exp(&right, &BigNum::from(3), &mut ctx).expect("exp");
                if &right_cube == n {
                    return CubeRoot::Exact(right);
                } else {
                    if (n - &cube) < (&right_cube - n) {
                        return CubeRoot::Nearest(left);
                    } else {
                        return CubeRoot::Nearest(right);
                    }
                }
            }

            if &cube > n {
                right = midpoint;
            } else {
                left = midpoint;
            }
        }
        CubeRoot::Nearest(left)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_div_alg() {
        assert_eq!(RSA::division_algorithm(&10u32, &3u32), (3, 1));
    }

    #[test]
    #[should_panic]
    fn test_div_alg_zero() {
        RSA::division_algorithm(&10u32, &0u32);
    }

    #[test]
    fn test_e_a() {
        assert_eq!(RSA::euclidean_algorithm(&55u32, &12u32), (1, 23));
        assert_eq!(RSA::euclidean_algorithm(&7u32, &5u32), (1, 3));
        assert_eq!(RSA::euclidean_algorithm(&7u32, &6u32), (1, 6));
    }

    #[test]
    fn test_invmod() {
        assert_eq!(RSA::euclidean_algorithm(&3120u32, &17u32), (1, 2753));
    }

    #[test]
    fn test_ch_40() {
        let plaintext = "i like to send the same message to alllllll of my friends, using my handrolled textbook RSA 😎";
        println!("plaintext = {:?}", &plaintext);

        let snooped: Vec<(BigNum, BigNum)> = (0..3).map(|_| { 
            let rsa = RSA::new().expect("RSA::new()");
            let ciphertext = rsa.encrypt_string(&plaintext).expect("rsa.encrypt");

            (ciphertext, rsa.n)
        }).collect();

        let N: BigNum = snooped.iter().map(|(_c, n)| n)
                               .fold(BigNum::from(1), |acc, x| &acc * x);

        let result = &snooped.iter().map(|(c, n)| {
            c * &(&(&N/n) * &(RSA::euclidean_algorithm(n, &(&N/n)).1))
        }).fold(BigNum::from(0), |acc, x| &acc + &x) % &N;

        println!("result = {:?}", result);

        if let CubeRoot::Exact(cuberoot) = RSA::cube_root(&result) {
            println!("cuberoot = {:?}", &cuberoot);
            let plaintext = RSA::bignum_to_string(&cuberoot);
            println!("plaintext = {:?}", &plaintext);
        }
    }

    #[test]
    fn test_ch_41() {
        let rsa = RSA::new().expect("RSA::new()");
        let plaintext = "I'll meet you at the place at the time, near the thing.  Don't be late, or early. Bring snacks.";
        println!("plaintext = {:?}", &plaintext);

        let ciphertext = rsa.encrypt_string(&plaintext).expect("rsa.encrypt");
        println!("ciphertext = {:?}", &ciphertext);

        let s = BigNum::from(0xb33fc4f3);
        let mut c_prime = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();

        c_prime.mod_exp(&s, &rsa.e, &rsa.n, &mut ctx).expect("mod_exp");
        c_prime = &(&c_prime * &ciphertext) % &rsa.n;

        let p_prime = rsa.decrypt(&c_prime).expect("rsa.decrypt");
        let (_, s_inv) = RSA::euclidean_algorithm(&rsa.n, &s);
        let p = &(&p_prime * &s_inv) % &rsa.n;

        let recovered_plaintext = RSA::bignum_to_string(&p);

        println!("recovered plaintext = {:?}", &recovered_plaintext);
        assert_eq!(&plaintext, &recovered_plaintext);
    }

    #[test]
    fn test_ch_42() {
        let mut forged_plaintext = vec![0x00, 0x01, 0xff, 0x00];
        forged_plaintext.extend_from_slice(&"hello".as_bytes());
        println!("forged plaintext = {:?}", &forged_plaintext);
        let mut num_pad = 20;

        loop {
            let mut test_plaintext = Vec::new();
            test_plaintext.extend_from_slice(&forged_plaintext);
            let mut right_pad = vec![0x00; num_pad];
            test_plaintext.extend_from_slice(&right_pad);
            let cuberoot = RSA::cube_root(&BigNum::from_slice(&test_plaintext).unwrap());

            let test_ciphertext = match cuberoot {
                CubeRoot::Exact(n) => n,
                CubeRoot::Nearest(n) => n,
            };

            println!("test ciphertext = {:?}", test_ciphertext);

            let mut cube = BigNum::new().unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            cube.exp(&test_ciphertext, &BigNum::from(3), &mut ctx);

            let cube_bytes = cube.to_vec();

            println!("forged plaintext = {:?}", &forged_plaintext);
            println!("resulting plaintext = {:?}", &cube_bytes);

            if &cube_bytes[0..8] == &forged_plaintext[1..9] {
                println!("found match");
                break;
            }
            num_pad += 1;
        }
    }

    #[test]
    fn test_ch_41() {
        let rsa = RSA::new().expect("RSA::new()");
        let plaintext = "I'll meet you at the place at the time, near the thing.  Don't be late, or early. Bring snacks.";
        println!("plaintext = {:?}", &plaintext);

        let ciphertext = rsa.encrypt_string(&plaintext).expect("rsa.encrypt");
        println!("ciphertext = {:?}", &ciphertext);

        let s = BigNum::from(0xb33fc4f3);

        let mut c_prime = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        c_prime.mod_exp(&s, &rsa.e, &rsa.n, &mut ctx).expect("mod_exp");
        c_prime = &(&c_prime * &ciphertext) % &rsa.n;

        let p_prime = rsa.decrypt(&c_prime).expect("rsa.decrypt");
        let (_, s_inv) = RSA::euclidean_algorithm(&rsa.n, &s);
        let p = &(&p_prime * &s_inv) % &rsa.n;

        let recovered_plaintext = RSA::bignum_to_string(&p);
        println!("recovered plaintext = {:?}", &recovered_plaintext);

        assert_eq!(&plaintext, &recovered_plaintext);
    }

    #[test]
    fn test_rsa() {
        let rsa = RSA::new().expect("RSA::new()");
        let plaintext = BigNum::from(1234567890);
        println!("plaintext = {:?}", &plaintext);

        let ciphertext = rsa.encrypt(&plaintext).expect("rsa.encrypt");
        println!("ciphertext = {:?}", &ciphertext);

        let decrypted = rsa.decrypt(&ciphertext).expect("rsa.decrypt");
        println!("decrypted = {:?}", &decrypted);

        assert_eq!(&plaintext, &decrypted);
    }

    #[test]
    fn test_rsa_string() {
        let rsa = RSA::new().expect("RSA::new()");
        let plaintext = "this is a test of the emergency encryption system 💖";
        println!("plaintext = {:?}", &plaintext);

        let ciphertext = rsa.encrypt_string(&plaintext).expect("rsa.encrypt");
        println!("ciphertext = {:?}", &ciphertext);

        let decrypted = rsa.decrypt_string(&ciphertext).expect("rsa.decrypt");
        println!("decrypted = {:?}", &decrypted);

        assert_eq!(&plaintext, &decrypted);
    }
}
