use super::{CONSISTENT_RANDOM_KEY, CONSISTENT_RANDOM_PREFIX};
use utils::bytes::*;
use utils::crypto::ecb_encrypt;

pub fn challenge_14_encryption_oracle(input_plaintext: &[u8]) -> Vec<u8> {
    let append_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    let append_bytes = base64_to_bytes(append_string);

    let mut plaintext = Vec::new();

    CONSISTENT_RANDOM_PREFIX.with(|p| {
        plaintext.extend_from_slice(&p[..]);
    });

    plaintext.extend_from_slice(&input_plaintext[..]);
    plaintext.extend_from_slice(&append_bytes[..]);

    CONSISTENT_RANDOM_KEY.with(|k| ecb_encrypt(&k[..], &plaintext[..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use set_2::{find_block_size, CONSISTENT_RANDOM_PREFIX};
    use std::str;

    #[test]
    fn challenge_14() {
        let block_size = find_block_size(&challenge_14_encryption_oracle);

        println!("block_size = {}", block_size);

        CONSISTENT_RANDOM_PREFIX.with(|p| {
            println!("actual prefix len = {}", p.len());
        });

        // start by finding prefix size
        let mut prefix_offset = 0;
        let mut prefix_size = 0;

        'outer: while prefix_offset < 256 {
            let chosen_plaintext = vec![0; block_size * 2 + prefix_offset];

            let output = challenge_14_encryption_oracle(&chosen_plaintext[..]);

            for i in 0..output.len() - (block_size * 2) {
                if output[i..i + block_size] == output[i + block_size..i + (block_size * 2)] {
                    prefix_size = i - prefix_offset;
                    break 'outer;
                }
            }
            prefix_offset += 1;
        }

        let prefix_alignment_padding_size = block_size - prefix_size % block_size;
        let prefix_alignment_padding = vec![b'A'; prefix_alignment_padding_size];

        let original_ciphertext = challenge_14_encryption_oracle(&prefix_alignment_padding[..]);
        let len = original_ciphertext.len();

        let mut chunk_index = prefix_size + prefix_alignment_padding_size;

        let mut unknown_bytes: Vec<u8> = Vec::with_capacity(len);

        while chunk_index < len {
            let mut discovered_block: Vec<u8> = Vec::with_capacity(block_size);

            for i in 0..block_size {
                let block_index = prefix_alignment_padding_size + block_size - i - 1; // also # to pad

                let padded_plaintext: Vec<u8> = vec![b'A'; block_index];

                let oracle_output_1 = challenge_14_encryption_oracle(&padded_plaintext[..]);

                let mut test_plaintext: Vec<u8> = vec![b'A'; block_index];
                test_plaintext.extend_from_slice(&unknown_bytes[..]);
                test_plaintext.extend_from_slice(&discovered_block[..]);

                test_plaintext.push(0);

                for j in 0..256 {
                    let byte = j as u8;
                    let len = test_plaintext.len();
                    test_plaintext[len - 1] = byte;
                    let oracle_output_test = challenge_14_encryption_oracle(&test_plaintext[..]);

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

        println!("solved len = {:?}", solved_plaintext.len());
        assert!(solved_plaintext.contains("With my rag-top down so my hair can blow"));
    }
}
