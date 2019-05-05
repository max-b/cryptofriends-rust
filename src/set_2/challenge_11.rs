use rand::{OsRng, Rng};
use utils::bytes::*;
use utils::crypto::{cbc_encrypt, ecb_encrypt};

#[derive(Debug, PartialEq)]
pub enum EncryptionType {
    CBC,
    ECB,
}

pub fn random_key_encryption_oracle(plaintext: &[u8]) -> (Vec<u8>, EncryptionType) {
    let random_key = generate_random_aes_key();

    let mut rng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e),
    };

    let left_junk = random_bytes(rng.gen_range(5, 11));
    let right_junk = random_bytes(rng.gen_range(5, 11));

    let mut junked_plaintext = Vec::new();
    junked_plaintext.extend_from_slice(&left_junk[..]);
    junked_plaintext.extend_from_slice(plaintext);
    junked_plaintext.extend_from_slice(&right_junk[..]);

    let random_iv = random_bytes(16);

    let use_cbc = rng.gen();

    if use_cbc {
        (
            cbc_encrypt(&random_key[..], &junked_plaintext[..], &random_iv[..]),
            EncryptionType::CBC,
        )
    } else {
        (
            ecb_encrypt(&random_key[..], &junked_plaintext[..]),
            EncryptionType::ECB,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_11() {
        for _ in 0..10 {
            let chosen_plaintext = vec![0; 64];
            let (output, encryption_type) = random_key_encryption_oracle(&chosen_plaintext[..]);

            let mut encryption_type_guess = None;

            for i in 0..output.len() - 32 {
                if output[i..i + 16] == output[i + 16..i + 32] {
                    encryption_type_guess = Some(EncryptionType::ECB);
                }
            }

            if let Some(guess) = encryption_type_guess {
                assert_eq!(encryption_type, guess);
            } else {
                assert_eq!(encryption_type, EncryptionType::CBC);
            }
        }
    }
}
