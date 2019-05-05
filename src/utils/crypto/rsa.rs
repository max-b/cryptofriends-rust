use bigint::BigUint;
use openssl::bn::BigNum;
use utils::bigint;

#[derive(Debug)]
pub struct RSA {
    pub e: BigUint,
    private_key: BigUint,
    pub n: BigUint,
}

impl RSA {
    pub fn new() -> RSA {
        Self::new_with_size(1024)
    }

    pub fn new_with_size(size: i32) -> RSA {
        let (mut p, mut q) = (
            BigNum::new().expect("BigNum::new()"),
            BigNum::new().expect("BigNum::new()"),
        );

        p.generate_prime(size, false, None, None)
            .expect("generate_prime");
        q.generate_prime(size, false, None, None)
            .expect("generate_prime");

        let (p, q) = (bigint::bignum_to_biguint(&p), bigint::bignum_to_biguint(&q));

        let e = BigUint::from(3 as u32);
        let n = &p * &q;
        let et = (&p - 1 as u32) * (&q - 1 as u32);

        let (_, d) = bigint::euclidean_algorithm(&et, &e);

        RSA {
            e,
            private_key: d,
            n,
        }
    }

    pub fn encrypt(&self, plaintext: &BigUint) -> BigUint {
        plaintext.modpow(&self.e, &self.n)
    }

    pub fn decrypt(&self, ciphertext: &BigUint) -> BigUint {
        ciphertext.modpow(&self.private_key, &self.n)
    }

    pub fn encrypt_string(&self, plaintext: &str) -> BigUint {
        self.encrypt(&bigint::string_to_biguint(plaintext))
    }

    pub fn decrypt_string(&self, ciphertext: &BigUint) -> String {
        let plaintext = self.decrypt(ciphertext);
        bigint::biguint_to_string(&plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rsa() {
        let rsa = RSA::new();
        let plaintext = BigUint::from(1234567890 as usize);
        println!("plaintext = {:?}", &plaintext);
        let ciphertext = rsa.encrypt(&plaintext);
        println!("ciphertext = {:?}", &ciphertext);
        let decrypted = rsa.decrypt(&ciphertext);
        println!("decrypted = {:?}", &decrypted);
        assert_eq!(&plaintext, &decrypted);
    }

    #[test]
    fn test_rsa_string() {
        let rsa = RSA::new();
        let plaintext = "this is a test of the emergency encryption system 💖";
        println!("plaintext = {:?}", &plaintext);
        let ciphertext = rsa.encrypt_string(&plaintext);
        println!("ciphertext = {:?}", &ciphertext);
        let decrypted = rsa.decrypt_string(&ciphertext);
        println!("decrypted = {:?}", &decrypted);
        assert_eq!(&plaintext, &decrypted);
    }
}
