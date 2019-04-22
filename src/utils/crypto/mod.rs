pub mod dsa;
pub mod prng;
pub mod rsa;

use super::bytes::{pad_bytes, xor, random_bytes};
use bigint::{BigUint, RandBigInt};
use byteorder::{ByteOrder, LittleEndian, BigEndian, WriteBytesExt};
use crypto::aessafe;
use crypto::cryptoutil::{write_u32_be, write_u32_le};
use crypto::digest::Digest as CryptoDigest;
use crypto::sha1::Sha1;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};
use md4;
use md4::Digest as Md4Digest;
use rand::OsRng;

use self::prng::Prng;

static HASH_PAD_TO_BYTE_LENGTH: usize = 64;

pub fn pkcs_7_unpad(input: &[u8]) -> Vec<u8> {
    let amount_padded = input[input.len() - 1];
    input[..input.len() - amount_padded as usize].to_vec()
}

pub fn strip_pkcs_padding(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let last = match input.last() {
        None => return Err("input must be nonzero length"),
        Some(&l) => l,
    };

    if last as usize > input.len() || last == 0 {
        return Err("Invalid pkcs");
    }

    let mut padding = Vec::new();
    padding.extend_from_slice(&input[input.len() - last as usize..]);

    for i in padding {
        if i != last {
            return Err("Invalid pkcs");
        }
    }

    Ok(pkcs_7_unpad(input))
}

pub fn pkcs_7_pad(input: &[u8], size: usize) -> Vec<u8> {
    let mut difference = if input.len() < size {
        size - input.len()
    } else {
        size - (input.len() % size)
    };

    if difference == 0 {
        difference = size;
    }

    pad_bytes(input, difference as u8, difference)
}

pub fn pkcs_1_pad(input: &[u8], k: usize) -> Vec<u8> {
    let padding_bytes = random_bytes((k - 3 - input.len()) as u32);
    let mut output = vec![0x00, 0x02];
    output.extend_from_slice(&padding_bytes);
    output.extend_from_slice(&[0x00]);
    output.extend_from_slice(input);

    output
}

pub fn pkcs_1_unpad(input: &[u8]) -> Vec<u8> {
    let mut i = 2;
    while input[i] != 0 {
        i += 1;
    }
    let mut output = vec![];
    output.extend_from_slice(&input[i+1..]);
    output
}

pub fn ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let decryptor = aessafe::AesSafe128Decryptor::new(&key);

    let mut decrypted: Vec<u8> = vec![0; ciphertext.len()];

    let block_size = decryptor.block_size();

    let mut chunk_index = 0;

    while chunk_index < ciphertext.len() {
        decryptor.decrypt_block(
            &ciphertext[chunk_index..chunk_index + block_size],
            &mut decrypted[chunk_index..chunk_index + block_size],
        );
        chunk_index += block_size;
    }

    pkcs_7_unpad(&decrypted[..])
}

pub fn ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let encryptor = aessafe::AesSafe128Encryptor::new(&key);

    let block_size = encryptor.block_size();

    let plaintext = pkcs_7_pad(plaintext, block_size);
    let mut encrypted: Vec<u8> = vec![0; plaintext.len()];

    let mut chunk_index = 0;

    for block in plaintext.chunks(block_size) {
        encryptor.encrypt_block(
            &block,
            &mut encrypted[chunk_index..chunk_index + block_size],
        );
        chunk_index += block_size;
    }

    encrypted
}

pub fn cbc_decrypt(key: &[u8], ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>, &'static str> {
    let decryptor = aessafe::AesSafe128Decryptor::new(&key);

    let block_size = decryptor.block_size();

    assert!(ciphertext.len() % block_size == 0);

    let mut decrypted: Vec<u8> = vec![0; ciphertext.len()];

    let mut chunk_index = 0;

    let mut decrypt_output: Vec<u8> = vec![0; block_size];

    while chunk_index < ciphertext.len() {
        let decryption_slice: &mut [u8] = &mut decrypted[chunk_index..chunk_index + block_size];

        decryptor.decrypt_block(
            &ciphertext[chunk_index..chunk_index + block_size],
            &mut decrypt_output[..],
        );

        let plaintext = if chunk_index == 0 {
            xor(&decrypt_output[..], iv)
        } else {
            let previous_ciphertext = &ciphertext[chunk_index - block_size..chunk_index];
            xor(&decrypt_output[..], previous_ciphertext)
        };

        decryption_slice.copy_from_slice(&plaintext[..]);

        chunk_index += block_size;
    }

    strip_pkcs_padding(&decrypted[..])
}

pub fn cbc_encrypt(key: &[u8], plaintext: &[u8], iv: &[u8]) -> Vec<u8> {
    let encryptor = aessafe::AesSafe128Encryptor::new(&key);

    let block_size = encryptor.block_size();

    let plaintext = pkcs_7_pad(plaintext, block_size);

    let mut encrypted: Vec<u8> = vec![0; plaintext.len()];

    let mut chunk_index = 0;

    let mut plaintext_slice: Vec<u8> = vec![0; block_size];
    let mut previous_ciphertext_block: Vec<u8> = iv.to_vec();

    while chunk_index < plaintext.len() {
        plaintext_slice.copy_from_slice(&plaintext[chunk_index..chunk_index + block_size]);

        let iv_xor_plaintext = xor(&plaintext_slice[..], &previous_ciphertext_block[..]);

        encryptor.encrypt_block(
            &iv_xor_plaintext[..],
            &mut encrypted[chunk_index..chunk_index + block_size],
        );

        previous_ciphertext_block
            .copy_from_slice(&encrypted[chunk_index..chunk_index + block_size]);

        chunk_index += block_size;
    }

    encrypted
}

pub fn aes_ctr(key: &[u8], input: &[u8], nonce: &[u8]) -> Vec<u8> {
    let block_size = key.len();
    let encryptor = aessafe::AesSafe128Encryptor::new(&key);

    let mut output = Vec::new();

    let input_blocks = input.chunks(block_size);

    let mut keystream = vec![0; block_size];
    for (count, block) in input_blocks.enumerate() {
        let mut nonce_count = Vec::new();
        nonce_count.extend_from_slice(&nonce[..]);
        nonce_count
            .write_u64::<LittleEndian>(count as u64)
            .expect("Error writing count as u64 -> little endian bytes.");

        encryptor.encrypt_block(&nonce_count[..], &mut keystream[..]);

        let xor_result = xor(&keystream[0..block.len()], &block[..]);
        output.extend_from_slice(&xor_result[..]);
    }
    output
}

pub fn edit_aes_ctr(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    offset: usize,
    newtext: &[u8],
) -> Vec<u8> {
    let block_size = key.len();

    let mut output = Vec::new();
    let encryptor = aessafe::AesSafe128Encryptor::new(&key);

    output.extend_from_slice(&ciphertext[..]);

    let start_block = offset / block_size;
    let mut end_of_ciphertext_to_edit = offset + newtext.len();
    if end_of_ciphertext_to_edit % block_size != 0 {
        let remainder = block_size - (end_of_ciphertext_to_edit % block_size);
        if end_of_ciphertext_to_edit + remainder < ciphertext.len() {
            end_of_ciphertext_to_edit += remainder;
        }
    }

    assert!(end_of_ciphertext_to_edit <= ciphertext.len());

    let block_offset = offset % block_size;

    let mut block_count = start_block as u64;

    let mut ciphertext_to_edit = Vec::new();
    ciphertext_to_edit
        .extend_from_slice(&ciphertext[start_block * block_size..end_of_ciphertext_to_edit]);

    let ciphertext_blocks = ciphertext_to_edit.chunks(block_size);

    let mut keystream = vec![0; block_size];

    for ciphertext_block in ciphertext_blocks {
        let mut nonce_count = Vec::new();

        nonce_count.extend_from_slice(&nonce[..]);
        nonce_count
            .write_u64::<LittleEndian>(block_count)
            .expect("Error writing count as u64 -> little endian bytes.");

        encryptor.encrypt_block(&nonce_count[..], &mut keystream[..]);

        let mut plaintext = xor(&keystream[0..ciphertext_block.len()], &ciphertext_block[..]);
        let plaintext_len = plaintext.len();

        let mut newtext_to_splice = Vec::new();

        let newtext_start = match block_count as usize {
            count if count == start_block => 0,
            count => ((count * block_size) - offset),
        };

        let newtext_end = {
            if block_count as usize == start_block {
                if block_offset + newtext.len() < block_size {
                    newtext.len()
                } else {
                    (newtext_start + plaintext_len) - block_offset
                }
            } else if newtext_start + plaintext_len > newtext.len() {
                newtext.len()
            } else {
                newtext_start + plaintext_len
            }
        };

        newtext_to_splice.extend_from_slice(&newtext[newtext_start..newtext_end]);
        if block_count as usize == start_block {
            plaintext.splice(
                block_offset..newtext_to_splice.len() + block_offset,
                newtext_to_splice.into_iter(),
            );
        } else {
            plaintext.splice(0..newtext_to_splice.len(), newtext_to_splice.into_iter());
        }

        let xor_result = xor(&keystream[0..plaintext_len], &plaintext[..]);
        output.splice(
            block_count as usize * block_size..block_count as usize * block_size + xor_result.len(),
            xor_result.into_iter(),
        );
        block_count += 1;
    }

    output
}

pub fn prng_cipher<T: Prng>(seed: u16, input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut prng: T = T::new(seed.into());
    for byte in input {
        let keystream_byte = prng.gen_rand_byte();
        output.push(byte ^ keystream_byte);
    }
    output
}

pub fn keyed_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut concated_bytes = Vec::new();
    concated_bytes.extend_from_slice(&key[..]);
    concated_bytes.extend_from_slice(&message[..]);

    let mut hasher = Sha1::new();

    hasher.input(&concated_bytes[..]);

    let output_size = hasher.output_bits();
    let mut output_bytes = vec![0; output_size / 8];

    hasher.result(&mut output_bytes);

    output_bytes
}

pub fn keyed_md4(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut concated_bytes = Vec::new();
    concated_bytes.extend_from_slice(&key[..]);
    concated_bytes.extend_from_slice(&message[..]);

    let mut hasher = md4::Md4::new();

    hasher.input(&concated_bytes[..]);

    let mut output_bytes = Vec::new();

    output_bytes.extend_from_slice(&hasher.result());

    output_bytes
}

// In order to use this function, message must be already padded
// to block size
pub fn sha1_unpadded(message: &[u8]) -> Vec<u8> {
    let mut sha_object = Sha1::new();

    let output_size = sha_object.output_bits();
    let mut output_bytes = vec![0; output_size / 8];

    sha_object.input(&message[..]);
    sha_object.computed = true;

    write_u32_be(&mut output_bytes[0..4], sha_object.h[0]);
    write_u32_be(&mut output_bytes[4..8], sha_object.h[1]);
    write_u32_be(&mut output_bytes[8..12], sha_object.h[2]);
    write_u32_be(&mut output_bytes[12..16], sha_object.h[3]);
    write_u32_be(&mut output_bytes[16..20], sha_object.h[4]);

    output_bytes
}

pub fn compute_sha1_from_registers(a: u32, b: u32, c: u32, d: u32, e: u32, message: &[u8]) -> Vec<u8> {
    let mut sha_object = Sha1::new();
    sha_object.h = [a, b, c, d, e];

    // As can be seen from a few lines below,
    // hash output size is always 20 bytes
    let output_size = sha_object.output_bits();
    let mut output_bytes = vec![0; output_size / 8];

    sha_object.input(&message[..]);
    sha_object.computed = true;

    write_u32_be(&mut output_bytes[0..4], sha_object.h[0]);
    write_u32_be(&mut output_bytes[4..8], sha_object.h[1]);
    write_u32_be(&mut output_bytes[8..12], sha_object.h[2]);
    write_u32_be(&mut output_bytes[12..16], sha_object.h[3]);
    write_u32_be(&mut output_bytes[16..20], sha_object.h[4]);

    output_bytes
}

pub fn compute_md4_from_registers(a: u32, b: u32, c: u32, d: u32, message: &[u8]) -> Vec<u8> {
    let mut md4_object = md4::Md4::new();
    md4_object.state = md4::Md4State {
        s: md4::simd::u32x4(a, b, c, d)
    };

    md4_object.input(&message[..]);
    // md4_object.finalize();

    let mut output_bytes = vec![0; 16];
    write_u32_le(&mut output_bytes[0..4], md4_object.state.s.0);
    write_u32_le(&mut output_bytes[4..8], md4_object.state.s.1);
    write_u32_le(&mut output_bytes[8..12], md4_object.state.s.2);
    write_u32_le(&mut output_bytes[12..16], md4_object.state.s.3);

    output_bytes
}

pub enum Endianness {
    Little,
    Big
}

pub fn md_padding(input_len: usize, e: Endianness) -> Vec<u8> {
    let block_size = HASH_PAD_TO_BYTE_LENGTH;

    let diff = block_size - (input_len % block_size);
    let input_len_bits = (input_len * 8) as u64;

    let mut padding: Vec<u8> = vec![0; diff];

    // 128 represents a 1 (in binary) digit immediately after
    // previous byte (1000 0000)
    padding[0] = 128;

    if let Endianness::Big = e {
        BigEndian::write_u64(
            &mut padding[diff - 8..diff],
            input_len_bits,
        );
    } else {
        LittleEndian::write_u64(
            &mut padding[diff - 8..diff],
            input_len_bits
        );
    }

    padding
}

pub fn sha1_md_pad(input: &[u8]) -> Vec<u8> {
    let padding = md_padding(input.len(), Endianness::Big);
    let mut output = Vec::new();
    output.extend_from_slice(&input[..]);
    output.extend_from_slice(&padding[..]);

    output
}

pub struct DHKeyPair {
    pub private_key: BigUint,
    pub public_key: BigUint,
    pub p: BigUint,
}

impl DHKeyPair {
    pub fn new(p: &BigUint, g: &BigUint) -> DHKeyPair {
        let mut rng = OsRng::new().expect("Can't get rng");
        let private_key = rng.gen_biguint_below(&p);

        let public_key = g.modpow(&private_key, &p);

        DHKeyPair {
            private_key,
            public_key,
            p: p.clone(),
        }
    }

    pub fn get_public_key(&self) -> BigUint {
        self.public_key.clone()
    }

    pub fn gen_session_key(&self, b: &BigUint) -> BigUint {
        let b = b.clone();
        let s1 = b.modpow(&self.private_key, &self.p);
        println!("session key (before aes) = {:?}", &s1);
        s1
    }

    pub fn gen_aes_session_key(&self, b: &BigUint) -> Vec<u8> {
        let s = self.gen_session_key(b);
        let mut hasher = Sha1::new();

        hasher.input(&s.to_bytes_le()[..]);

        let output_size = hasher.output_bits();
        let mut output_bytes = vec![0; output_size / 8];

        hasher.result(&mut output_bytes);
        // TODO: keep some more global notion of aes keysize!
        output_bytes.truncate(16);
        output_bytes
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use utils::bytes::*;

    #[test]
    fn aes_ctr_seek_edit() {
        let key = generate_random_aes_key();
        let initial_plaintext = b"Say -- Play that funky music Say, go white boy, go white boy go
        play that funky music Go white boy, go white boy, go
        Lay down and boogie and play that funky music till you die.";

        let nonce: Vec<u8> = vec![0; 8];
        let initial_ciphertext = aes_ctr(&key[..], &initial_plaintext[..], &nonce[..]);

        let text_to_insert = b"HIHIHIHIHIHIHIHI";
        let offset = 101;
        let new_ciphertext = edit_aes_ctr(
            &initial_ciphertext[..],
            &key[..],
            &nonce[..],
            offset,
            text_to_insert,
        );

        let plaintext = aes_ctr(&key[..], &new_ciphertext[..], &nonce[..]);

        assert_eq!(
            &plaintext[offset..offset + text_to_insert.len()],
            &text_to_insert[..]
        );

        let text_to_insert = b"HIHI";
        let offset = new_ciphertext.len() - text_to_insert.len() - 1;
        let new_ciphertext = edit_aes_ctr(
            &initial_ciphertext[..],
            &key[..],
            &nonce[..],
            offset,
            text_to_insert,
        );

        let plaintext = aes_ctr(&key[..], &new_ciphertext[..], &nonce[..]);

        assert_eq!(
            &plaintext[offset..offset + text_to_insert.len()],
            &text_to_insert[..]
        );

        let text_to_insert = b"A";
        let offset = new_ciphertext.len() - text_to_insert.len() - 1;
        let new_ciphertext = edit_aes_ctr(
            &initial_ciphertext[..],
            &key[..],
            &nonce[..],
            offset,
            text_to_insert,
        );

        let plaintext = aes_ctr(&key[..], &new_ciphertext[..], &nonce[..]);

        assert_eq!(
            &plaintext[offset..offset + text_to_insert.len()],
            &text_to_insert[..]
        );

        let text_to_insert = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let offset = new_ciphertext.len() - text_to_insert.len() - 1;
        let new_ciphertext = edit_aes_ctr(
            &initial_ciphertext[..],
            &key[..],
            &nonce[..],
            offset,
            text_to_insert,
        );

        let plaintext = aes_ctr(&key[..], &new_ciphertext[..], &nonce[..]);

        assert_eq!(
            &plaintext[offset..offset + text_to_insert.len()],
            &text_to_insert[..]
        );
    }

    #[test]
    fn pad_test() {
        let padded = sha1_md_pad(b"123testingtesting\n");
        let unpadded = b"123testingtesting\n";
        let null_bytes = [];
        let padded_sha1 = sha1_unpadded(&padded[..]);
        let unpadded_sha1 = keyed_sha1(&null_bytes, &unpadded[..]);
        assert_eq!(padded_sha1, unpadded_sha1);
    }
}
