use bigint::{BigUint};
use openssl::bn::{BigNum, BigNumContext};
use std::{cmp, ops};

pub fn bignum_to_biguint(bignum: &BigNum) -> BigUint {
    BigUint::from_bytes_be(&bignum.to_vec())
}

pub fn biguint_to_bignum(biguint: &BigUint) -> BigNum {
    BigNum::from_slice(&biguint.to_bytes_be()).expect("BigNum::from_slice")
}

fn division_algorithm<T>(a: &T, b: &T) -> (T, T)
where
    T: From<u32> + cmp::PartialEq,
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
pub fn euclidean_algorithm<T>(a: &T, b: &T) -> (T, T)
where
    T: cmp::PartialEq + From<u32>,
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
    let (q, r) = division_algorithm(a, b);
    // Adding with zero is a hacky clone
    let mut ab = (b + &zero, r);
    let mut numers = (T::from(1), q);
    let mut counter = T::from(0);
    while ab.1 != zero {
        let (q, r) = division_algorithm(&ab.0, &ab.1);
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

#[derive(Debug)]
pub enum CubeRoot<T> {
    Exact(T),
    Nearest(T),
}

pub fn cube_root(n: &BigNum) -> CubeRoot<BigNum> {
    // Do a cube root via binary search, since it's not implemented in OpenSSL BigNum :D

    let mut left = BigNum::from(1);
    let mut right = n + &BigNum::from(0); // "clone"

    while left != right {
        let midpoint = &(&left + &right) / &BigNum::from(2);

        let mut cube = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        cube.exp(&midpoint, &BigNum::from(3), &mut ctx)
            .expect("exp");

        if &cube == n {
            return CubeRoot::Exact(midpoint);
        }

        if (&right - &left) == BigNum::from(1) {
            let mut right_cube = BigNum::new().unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            right_cube
                .exp(&right, &BigNum::from(3), &mut ctx)
                .expect("exp");
            if &right_cube == n {
                return CubeRoot::Exact(right);
            } else if (n - &cube) < (&right_cube - n) {
                return CubeRoot::Nearest(left);
            } else {
                return CubeRoot::Nearest(right);
            }
        }

        if cube > *n {
            right = midpoint;
        } else {
            left = midpoint;
        }
    }
    CubeRoot::Nearest(left)
}

pub fn string_to_bignum(string: &str) -> Result<BigNum, openssl::error::ErrorStack> {
    BigNum::from_slice(string.as_bytes())
}

pub fn bignum_to_string(num: &BigNum) -> String {
    let bytes = num.to_vec();
    String::from_utf8_lossy(&bytes[..]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]

    #[test]
    fn test_div_alg() {
        assert_eq!(division_algorithm(&10u32, &3u32), (3, 1));
    }

    #[test]
    #[should_panic]
    fn test_div_alg_zero() {
        division_algorithm(&10u32, &0u32);
    }

    #[test]
    fn test_e_a() {
        assert_eq!(euclidean_algorithm(&55u32, &12u32), (1, 23));
        assert_eq!(euclidean_algorithm(&7u32, &5u32), (1, 3));
        assert_eq!(euclidean_algorithm(&7u32, &6u32), (1, 6));
    }

    #[test]
    fn test_e_a_biguint() {
        let a = BigUint::from(55 as u32);
        let b = BigUint::from(12 as u32);
        let c = BigUint::from(1 as u32);
        let d = BigUint::from(23 as u32);
        assert_eq!(euclidean_algorithm(&a, &b), (c, d));
    }

    #[test]
    fn test_e_a_bignum() {
        let a = BigNum::from(55);
        let b = BigNum::from(12);
        let c = BigNum::from(1);
        let d = BigNum::from(23);
        assert_eq!(euclidean_algorithm(&a, &b), (c, d));
    }

    #[test]
    fn test_invmod() {
        assert_eq!(euclidean_algorithm(&3120u32, &17u32), (1, 2753));
    }

    #[test]
    fn test_biguint_to_bignum() {
        let biguint = BigUint::from(123456789 as u32);
        assert_eq!(biguint_to_bignum(&biguint), BigNum::from(123456789));
    }

    #[test]
    fn test_bignum_to_biguint() {
        let bignum = BigNum::from(123456789 as u32);
        assert_eq!(bignum_to_biguint(&bignum), BigUint::from(123456789 as u32));
    }
}

