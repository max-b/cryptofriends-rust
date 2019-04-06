#[cfg(test)]
mod tests {
    use bigint::BigUint;
    use utils::crypto::rsa::RSA;
    use utils::bigint;

    #[test]
    fn challenge_40() {
        let plaintext = "i like to send the same message to alllllll of my friends, using my handrolled textbook RSA 😎";
        println!("plaintext = {:?}", &plaintext);

        let snooped: Vec<(BigUint, BigUint)> = (0..3)
            .map(|_| {
                let rsa = RSA::new();
                let ciphertext = rsa.encrypt_string(&plaintext);

                (ciphertext, rsa.n)
            }).collect();

        #[allow(non_snake_case)]
        let N: BigUint = snooped
            .iter()
            .map(|(_c, n)| n)
            .fold(BigUint::from(1 as u32), |acc, x| &acc * x);

        let result = &snooped
            .iter()
            .map(|(c, n)| c * &(&(&N / n) * &(bigint::euclidean_algorithm(n, &(&N / n)).1)))
            .fold(BigUint::from(0 as u32), |acc, x| &acc + &x)
            % &N;

        println!("result = {:?}", result);

        if let bigint::CubeRoot::Exact(cuberoot) = bigint::cube_root(&result) {
            println!("cuberoot = {:?}", &cuberoot);
            let plaintext = bigint::biguint_to_string(&cuberoot);
            println!("plaintext = {:?}", &plaintext);
        }
    }
}
