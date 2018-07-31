#[cfg(test)]
mod tests {
    use rand::{Rng, OsRng};
    use bigint::{RandBigInt, BigUint};

    #[test]
    fn challenge_33() {

        let mut rng = OsRng::new().expect("Can't get rng");
        let p = 37;
        let g = BigUint::from(5 as usize);

        let a = BigUint::from(rng.gen_range(0, p) as usize);
        let b = BigUint::from(rng.gen_range(0, p) as usize);

        let p = BigUint::from(p as usize);
        #[allow(non_snake_case)]
        let A = g.modpow(&a, &p);

        #[allow(non_snake_case)]
        let B = g.modpow(&b, &p);

        let s1 = B.modpow(&a, &p);
        let s2 = A.modpow(&b, &p);

        assert_eq!(s1, s2);

        let p = BigUint::parse_bytes(b"22405534230753963835153736737\
          ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
          e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
          3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
          6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
          24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
          c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
          bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
          fffffffffffff", 16).unwrap();
        let g = BigUint::from(2 as usize);

        println!("p = {:?}", &p);

        let a = rng.gen_biguint_below(&p);

        println!("a = {:?}", &a);
        #[allow(non_snake_case)]
        let A = g.modpow(&a, &p);

        let b = rng.gen_biguint_below(&p);
        println!("b = {:?}", &b);

        #[allow(non_snake_case)]
        let B = g.modpow(&b, &p);

        let s1 = B.modpow(&a, &p);
        let s2 = A.modpow(&b, &p);

        assert_eq!(s1, s2);
    }
}
