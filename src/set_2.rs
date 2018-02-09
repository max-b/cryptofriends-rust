use std::str;
use utils;
use std::path::PathBuf;
use rand::distributions::{IndependentSample, Range};
use rand::{OsRng, Rng};


pub fn pkcs_7_pad_string(input: &str, size: usize) -> String {
    assert!(input.len() <= size);

    let input = String::from(input);
    let input_as_bytes = input.as_bytes();

    let padded_bytes = utils::pkcs_7_pad(input_as_bytes, size);

    match str::from_utf8(&padded_bytes) {
        Ok(string) => {
            string.to_string()
        },
        Err(_) => { "nope".to_string() },
    }
}

pub fn aes_cbc() -> String {
    let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ciphertext_path.push("data");
    ciphertext_path.push("set_2");
    ciphertext_path.push("10.txt");

    let base64_decoded_ciphertext = utils::read_base64_file_as_bytes(&ciphertext_path);

    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = [0u8; 16];

    let decrypted = utils::cbc_decrypt(key, &base64_decoded_ciphertext[..], &iv[..]);

    let decrypted = str::from_utf8(&decrypted).expect("Error converting decrypted bytes to string");

    decrypted.to_string()
}

#[derive(Debug,PartialEq)]
pub enum EncryptionType {
    CBC,
    ECB,
}

pub fn random_key_encryption_oracle(plaintext: &[u8]) -> (Vec<u8>, EncryptionType) {
    let random_key = utils::generate_random_aes_key();

    let mut rng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e)
    };

    let junk_size = Range::new(5, 11);
    let left_junk = utils::random_bytes(junk_size.ind_sample(&mut rng));
    let right_junk = utils::random_bytes(junk_size.ind_sample(&mut rng));

    let mut junked_plaintext = Vec::new();
    junked_plaintext.extend_from_slice(&left_junk[..]);
    junked_plaintext.extend_from_slice(plaintext);
    junked_plaintext.extend_from_slice(&right_junk[..]);

    let random_iv = utils::random_bytes(16);

    let use_cbc = rng.gen();

    if use_cbc {
        (utils::cbc_encrypt(&random_key[..], plaintext, &random_iv[..]), EncryptionType::CBC)
    } else {
        (utils::ecb_encrypt(&random_key[..], plaintext), EncryptionType::ECB)
    }
}

thread_local!(static CONSISTENT_RANDOM_KEY: Vec<u8> = utils::generate_random_aes_key());

pub fn consistent_key_encryption_oracle(plaintext: &[u8]) -> Vec<u8> {
    let append_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    let append_bytes = utils::base64_to_bytes(append_string);

    let mut appended_plaintext: Vec<u8> = plaintext.to_vec();
    appended_plaintext.extend_from_slice(&append_bytes[..]);

    CONSISTENT_RANDOM_KEY.with(|k| {
        utils::ecb_encrypt(&k[..], &appended_plaintext[..])
    })
}

pub fn challenge_14_encryption_oracle(input_plaintext: &[u8]) -> Vec<u8> {
    let append_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    let append_bytes = utils::base64_to_bytes(append_string);

    let mut rng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e)
    };

    let prefix_size = Range::new(0, 256);

    let mut plaintext = utils::random_bytes(prefix_size.ind_sample(&mut rng));

    plaintext.extend_from_slice(&input_plaintext[..]);
    plaintext.extend_from_slice(&append_bytes[..]);

    println!("plaintext = {:?}", plaintext);

    CONSISTENT_RANDOM_KEY.with(|k| {
        utils::ecb_encrypt(&k[..], &plaintext[..])
    })
}

pub fn key_value_parser(s: &str) -> Vec<(String, String)> {
    let input = s.to_string();
    let mut result: Vec<(String, String)> = Vec::new();
    let pairs = input.split("&");

    for pair in pairs {
        let mut key_value = pair.split("=");
        let key = key_value.next().expect("no key found");
        let value = key_value.next().expect("no value found");

        result.push((key.to_string(), value.to_string()));
    }

    result
}

pub fn profile_for(s: &str) -> String {
    let stripped = s.to_string().replace("&", "");
    let stripped = stripped.replace("=", "");

    "email=".to_string() + &stripped + "&uid=10&role=user"
}

pub fn encrypted_profile_for(s: &str) -> Vec<u8> {
    let plaintext = profile_for(s);
    let plaintext_bytes = plaintext.as_bytes();

    CONSISTENT_RANDOM_KEY.with(|k| {
        utils::ecb_encrypt(&k[..], &plaintext_bytes[..])
    })
}

pub fn decrypt_and_parse_profile(ciphertext: &[u8]) -> Vec<(String, String)> {

    CONSISTENT_RANDOM_KEY.with(|k| {
        let plaintext_bytes = utils::ecb_decrypt(&k[..], &ciphertext[..]);
        let plaintext = str::from_utf8(&plaintext_bytes).expect("Cannot create string from decrypted plaintext bytes.").trim();
        key_value_parser(&plaintext[..])
    })
}

pub fn find_block_size(oracle: &Fn(&[u8]) -> Vec<u8>) -> usize {
    let mut test_plaintext = vec![b'A'; 16];
    let mut block_size = 0;

    'outer: for i in 4..256 { // assume 4 < block size < 256
        test_plaintext.push(b'A');
        test_plaintext.push(b'A');
        test_plaintext.push(b'A');
        test_plaintext.push(b'A');

        let oracle_output = oracle(&test_plaintext [..]);


        for j in 0..oracle_output.len() - ((i+1)*2) {

            if &oracle_output[j..j+i+1] == &oracle_output[j+i+1..j+((i+1)*2)] {
                block_size = i+1;
                break 'outer;
            }
        }
    }

    // TODO: change this to Result
    assert!(block_size > 0);
    block_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_9() {
        let padded_string = pkcs_7_pad_string("YELLOW SUBMARINE", 20);
        println!("padded string = {}", padded_string);
        assert_eq!(padded_string.len(), 20);

        let padded_string_2 = pkcs_7_pad_string("YELLOW SUBMARINE", 16);
        println!("padded string2 = {}", padded_string_2);
        assert_eq!(padded_string_2.len(), 32);
    }


    #[test]
    fn challenge_10() {
        let cbc_decrypted = aes_cbc();

        // TODO: Do I want to copy the full text from the set_1 tests?
        // or maybe refactor all the challenge tests entirely?
        assert!(cbc_decrypted.as_str().contains("Play that funky music white boy you say it,"));
    }

    #[test]
    fn aes_cbc_encrypt() {
        let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ciphertext_path.push("data");
        ciphertext_path.push("set_2");
        ciphertext_path.push("10.txt");

        println!("{:?}", ciphertext_path);

        let base64_decoded_ciphertext = utils::read_base64_file_as_bytes(&ciphertext_path);

        let key = "YELLOW SUBMARINE".as_bytes();
        let iv: Vec<u8> = vec![0; 16];

        let decrypted = utils::cbc_decrypt(key, &base64_decoded_ciphertext[..], &iv[..]);

        let encrypted = utils::cbc_encrypt(key, &decrypted[..], &iv[..]);

        assert_eq!(&encrypted[..base64_decoded_ciphertext.len()], &base64_decoded_ciphertext[..]);

        let mut plaintext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        plaintext_path.push("src");
        plaintext_path.push("set_1.rs");

        let plaintext_bytes = utils::read_file_as_bytes(&plaintext_path);

        let key = "YELLOW SUBMARINE".as_bytes();
        let iv: Vec<u8> = vec![0; 16];

        let encrypted = utils::cbc_encrypt(key, &plaintext_bytes[..], &iv[..]);

        let decrypted = utils::cbc_decrypt(key, &encrypted[..], &iv[..]);

        assert_eq!(decrypted[..plaintext_bytes.len()], plaintext_bytes[..]);
    }

    #[test]
    fn challenge_11() {

        for _ in 0..10 {
            let chosen_plaintext = vec![0; 32];
            let (output, encryption_type) = random_key_encryption_oracle(&chosen_plaintext[..]);
            if output[0..16] == output[16..32] {
                assert_eq!(encryption_type, EncryptionType::ECB);
            } else {
                assert_eq!(encryption_type, EncryptionType::CBC);
            }
        }
    }

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
                    let oracle_output_test = consistent_key_encryption_oracle(&test_plaintext [..]);

                    if &oracle_output_1[chunk_index..chunk_index+block_size] == &oracle_output_test[chunk_index..chunk_index+block_size] {
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
        assert!(solved_plaintext.contains("With my rag-top down so my hair can blow"));
    }

    #[test]
    fn key_value_parser_test() {
        let result = key_value_parser("foo=bar&baz=qux&zap=zazzle");
        println!("result = {:?}", result);
    }

    #[test]
    fn profile_for_test() {
        let result = profile_for("foo@bar.com");
        assert_eq!(result, "email=foo@bar.com&uid=10&role=user");
        let result = profile_for("foo@bar.com&test=value");
        assert_eq!(result, "email=foo@bar.comtestvalue&uid=10&role=user");
    }

    #[test]
    fn encrypt_and_decrypt_profile() {
        let result = encrypted_profile_for("foo@bar.co");
        println!("encrypted profile = {:?}", result);
        let parsed = decrypt_and_parse_profile(&result[..]);
        println!("parsed = {:?}", parsed);
    }

    #[test]
    fn challenge_13() {

        let junk1: Vec<u8> = vec![b'A'; 10];
        let junk2: Vec<u8> = vec![b'A'; 4];

        let mut admin_with_padding = "admin".as_bytes().to_vec();
        let padding = vec![11; 11];

        admin_with_padding.extend_from_slice(&padding[..]);

        let total_length = junk1.len() + junk2.len() + admin_with_padding.len();
        let mut test_bytes = Vec::with_capacity(total_length);

        test_bytes.extend_from_slice(&junk1[..]);
        test_bytes.extend_from_slice(&admin_with_padding[..]);
        test_bytes.extend_from_slice(&junk2[..]);

        let test_plaintext = str::from_utf8(&test_bytes[..]).expect("cannot convert bytes to string");

        let ciphertext = encrypted_profile_for(test_plaintext);

        let test_plaintext = "foooo@bar.com";
        let mut ciphertext2 = encrypted_profile_for(test_plaintext);

        // truncate last 16 bytes of ciphertext2
        ciphertext2.truncate(32);

        ciphertext2.extend_from_slice(&ciphertext[16..32]);

        let decrypted = decrypt_and_parse_profile(&ciphertext2[..]);

        let admin_parsed = key_value_parser("email=foooo@bar.com&uid=10&role=admin");
        assert_eq!(decrypted, admin_parsed);
    }


    #[test]
    fn challenge_14() {

        let block_size = find_block_size(&challenge_14_encryption_oracle);

        println!("block_size = {}", block_size);
    }
}
