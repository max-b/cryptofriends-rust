use openssl;
use openssl::bn::{BigNum, BigNumContext};
use utils::bigint;

#[derive(Debug)]
pub struct RSA {
    pub e: BigNum,
    private_key: BigNum,
    pub n: BigNum,
}

impl RSA {
    pub fn new() -> Result<RSA, openssl::error::ErrorStack> {
        Self::new_with_size(1024)
    }

    pub fn new_with_size(size: i32) -> Result<RSA, openssl::error::ErrorStack> {
        let (mut p, mut q) = (BigNum::new()?, BigNum::new()?);
        p.generate_prime(size, false, None, None)?;
        q.generate_prime(size, false, None, None)?;
        let e = BigNum::from_u32(3)?;
        let n = &p * &q;
        let et = &(&p - &BigNum::from_u32(1)?) * &(&q - &BigNum::from_u32(1)?);

        let (_, d) = bigint::euclidean_algorithm(&et, &e);

        Ok(RSA {
            e,
            private_key: d,
            n,
        })
    }

    pub fn encrypt(&self, plaintext: &BigNum) -> Result<BigNum, openssl::error::ErrorStack> {
        let mut c = BigNum::new()?;
        let mut ctx = BigNumContext::new()?;
        c.mod_exp(plaintext, &self.e, &self.n, &mut ctx)
            .expect("mod_exp");

        Ok(c)
    }

    pub fn decrypt(&self, ciphertext: &BigNum) -> Result<BigNum, openssl::error::ErrorStack> {
        let mut m = BigNum::new()?;
        let mut ctx = BigNumContext::new()?;
        m.mod_exp(ciphertext, &self.private_key, &self.n, &mut ctx)
            .expect("mod_exp");
        Ok(m)
    }

    pub fn encrypt_string(&self, plaintext: &str) -> Result<BigNum, openssl::error::ErrorStack> {
        self.encrypt(&bigint::string_to_bignum(plaintext)?)
    }

    pub fn decrypt_string(
        &self,
        ciphertext: &BigNum,
    ) -> Result<String, openssl::error::ErrorStack> {
        let plaintext = self.decrypt(ciphertext)?;
        Ok(bigint::bignum_to_string(&plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
