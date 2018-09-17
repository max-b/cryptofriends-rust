use openssl;
use openssl::bn::{BigNum, BigNumContext};
use std::{ops, cmp};

#[derive(Debug)]
struct RSA {
    e: BigNum,
    private_key: BigNum,
    n: BigNum
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
}
