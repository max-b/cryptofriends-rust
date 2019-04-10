use utils::crypto::{ecb_encrypt};
use utils::bytes::*;
use super::{CONSISTENT_RANDOM_KEY};

pub fn consistent_key_encryption_oracle(plaintext: &[u8]) -> Vec<u8> {
    let append_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    let append_bytes = base64_to_bytes(append_string);

    let mut appended_plaintext: Vec<u8> = plaintext.to_vec();
    appended_plaintext.extend_from_slice(&append_bytes[..]);

    CONSISTENT_RANDOM_KEY.with(|k| ecb_encrypt(&k[..], &appended_plaintext[..]))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::str;
    use set_2::{find_block_size};

    #[test]
    fn challenge_12() {
        let original_ciphertext = consistent_key_encryption_oracle(&[]);
        let len = original_ciphertext.len();

        let mut unknown_bytes: Vec<u8> = Vec::with_capacity(len);
        let mut chunk_index = 0;

        let block_size = find_block_size(&consistent_key_encryption_oracle);

        while chunk_index < len {
            let mut discovered_block: Vec<u8> = Vec::with_capacity(block_size);

            for i in 0..block_size {
                let block_index = block_size - i - 1; // also # to pad

                let padded_plaintext: Vec<u8> = vec![b'A'; block_index];

                let oracle_output_1 = consistent_key_encryption_oracle(&padded_plaintext[..]);

                let mut test_plaintext: Vec<u8> = vec![b'A'; block_index];
                test_plaintext.extend_from_slice(&unknown_bytes[..]);
                test_plaintext.extend_from_slice(&discovered_block[..]);

                test_plaintext.push(0);

                for j in 0..256 {
                    let byte = j as u8;
                    let len = test_plaintext.len();
                    test_plaintext[len - 1] = byte;
                    let oracle_output_test = consistent_key_encryption_oracle(&test_plaintext[..]);

                    if oracle_output_1[chunk_index..chunk_index + block_size]
                        == oracle_output_test[chunk_index..chunk_index + block_size]
                    {
                        discovered_block.push(byte);
                        break;
                    }
                }
            }

            unknown_bytes.extend_from_slice(&discovered_block[..]);
            chunk_index += block_size;
        }

        let solved_plaintext = str::from_utf8(&unknown_bytes[..]).expect("couldn't decode string");

        println!("solved = {:?}", solved_plaintext);
        println!("solved len = {:?}", solved_plaintext.len());
        assert!(solved_plaintext.contains("With my rag-top down so my hair can blow"));
    }
}
