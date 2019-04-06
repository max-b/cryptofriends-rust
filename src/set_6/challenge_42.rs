#[cfg(test)]
mod tests {
    use openssl::bn::{BigNum, BigNumContext};
    use utils::bigint;

    #[test]
    fn challenge_42() {
        let mut forged_plaintext = vec![0x00, 0x01, 0xff, 0x00];
        forged_plaintext.extend_from_slice(b"hello");
        println!("forged plaintext = {:?}", &forged_plaintext);
        let mut num_pad = 20;
        let three = BigNum::from(3);

        loop {
            let mut test_plaintext = Vec::new();
            test_plaintext.extend_from_slice(&forged_plaintext);
            let right_pad = vec![0x00; num_pad];
            test_plaintext.extend_from_slice(&right_pad);
            let cuberoot = bigint::cube_root(&BigNum::from_slice(&test_plaintext).unwrap());

            let test_ciphertext = match cuberoot {
                bigint::CubeRoot::Exact(n) => n,
                bigint::CubeRoot::Nearest(n) => n,
            };

            println!("test ciphertext = {:?}", test_ciphertext);

            let mut cube = BigNum::new().unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            cube.exp(&test_ciphertext, &three, &mut ctx)
                .expect("cube exponentiation failed");

            let cube_bytes = cube.to_vec();

            println!("forged plaintext = {:?}", &forged_plaintext);
            println!("resulting plaintext = {:?}", &cube_bytes);

            if cube_bytes[0..8] == forged_plaintext[1..9] {
                println!("found match");
                break;
            }
            num_pad += 1;
        }
    }
}
