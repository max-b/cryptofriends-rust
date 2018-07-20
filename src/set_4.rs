extern crate reqwest;

use std::fs;
use rand::distributions::{IndependentSample, Range};
use std::path::PathBuf;
use std::io::{BufReader};
use std::io::prelude::*;
use std::thread::{sleep};
use std::time::{Duration};
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::rt::{Future, run};
use hyper::service::service_fn_ok;
use url::Url;
use utils::bytes::*;
use utils::files::*;
use utils::crypto::{aes_ctr, ecb_decrypt, sha1};
use rand::{OsRng};
use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::Mac;


thread_local!(static CONSISTENT_RANDOM_KEY: Vec<u8> = generate_random_aes_key());

pub fn challenge_25_encrypt() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {

    let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ciphertext_path.push("data");
    ciphertext_path.push("set_4");
    ciphertext_path.push("25.txt");

    let base64_decoded_ciphertext = read_base64_file_as_bytes(&ciphertext_path);

    let key = "YELLOW SUBMARINE".as_bytes();

    let plaintext = ecb_decrypt(key, &base64_decoded_ciphertext[..]);

    let nonce: Vec<u8> = vec![0; 8];

    CONSISTENT_RANDOM_KEY.with(|k| {
        let ciphertext = aes_ctr(&k[..], &plaintext[..], &nonce[..]);

        (ciphertext, plaintext,  k.clone(), nonce)
    })
}

pub fn generate_mac_secret() -> Vec<u8> {
    let words_path = PathBuf::from("/usr/share/dict/words");

    let mut rng = match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e),
    };

    let file = fs::File::open(&words_path).expect("Error opening words file.");
    let buf_reader = BufReader::new(file);
    let num_lines = buf_reader.lines().count();

    let random_range = Range::new(0, num_lines);
    let choice = random_range.ind_sample(&mut rng);

    // It seems like BufReader consumes the file object,
    // so I *think* re-opening is necessary
    let file = fs::File::open(&words_path).expect("Error opening words file.");
    let buf_reader = BufReader::new(file);
    let word = buf_reader.lines().nth(choice).unwrap().unwrap();

    let mut output = Vec::new();
    output.extend_from_slice(word.as_bytes());
    output
}

fn check_signature(valid: &[u8], test: &[u8]) -> bool {
    let sleep_time = Duration::new(0, 5000000);

    for i in 0..valid.len() {
        let valid_byte = valid.get(i).unwrap();
        let test_byte = test.get(i);
        match test_byte {
            None => { return false },
            Some(b) => {
                if b != valid_byte {
                    return false;
                }
            }
        };
        sleep(sleep_time);
    }
    true
}

fn handle_request(req: Request<Body>) -> Response<Body> {
    let uri = req.uri();
    // We have to manually add the protocol and host because of the parser
    // it doesn't really matter anyways...
    let parsed_url = Url::parse(&format!("http://thisisaninsanehack.com{}", uri)).unwrap();
    let queries = parsed_url.query_pairs();
    let mut file = None;
    let mut signature = None;

    for query in queries.into_owned() {
        // println!("query = {:?}", query);
        let (key, val) = query;
        if key == "file" {
            file = Some(val.clone());
        } else if key == "signature" {
            signature = Some(val.clone());
        }
    }

    let hasher = Sha1::new();
    let mut hmac = Hmac::new(hasher, "password".as_bytes());
    hmac.input(file.unwrap().as_bytes());
    let result = hmac.result();
    let code = result.code();
    // let hmac_hex_string = bytes_to_hex(&code);
    // println!("code {:?}", &hmac_hex_string);

    let signature_bytes = hex_to_bytes(&signature.unwrap());
    if check_signature(&code[..], &signature_bytes[..]) {
        Response::new(Body::from("pass\n"))
    } else {
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("fail\n")).unwrap()
    }
}

pub fn start_web_server() {
    println!("Starting web server");
    let addr = ([127, 0, 0, 1], 3000).into();

    // A `Service` is needed for every connection, so this
    // creates on of our `hello_world` function.
    let new_svc = || {
        // service_fn_ok converts our function into a `Service`
        service_fn_ok(handle_request)
    };

    let server = Server::bind(&addr)
        .serve(new_svc)
        .map_err(|e| eprintln!("server error: {}", e));

    // Run this server for... forever!
    run(server);

}

thread_local!(static CONSISTENT_MAC_SECRET: Vec<u8> = generate_mac_secret());

pub fn secret_prefix_mac(message: &[u8]) -> Vec<u8> {

    CONSISTENT_MAC_SECRET.with(|s| {
        let digest = sha1(&s, &message);
        digest
    })
}

pub fn validate_mac(message: &[u8], mac: &[u8]) -> bool {
    let actual_mac = secret_prefix_mac(&message);
    (actual_mac == mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::crypto::{md_padding, md_padding_with_length, sha1_registers, sha1, edit_aes_ctr};
    use utils::misc::*;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn challenge_25() {
        let (ciphertext, actual_plaintext, actual_key, nonce) = challenge_25_encrypt();

        let mut discovered_plaintext = Vec::new();
        for i in 0..ciphertext.len() {
            let mut found_byte = None;
            for byte in 0..255 {
                let new_ciphertext = edit_aes_ctr(&ciphertext[..], &actual_key[..], &nonce[..], i, &[byte]);
                if &new_ciphertext[..] == &ciphertext[..] {
                    found_byte = Some(byte);
                    break;
                }
            }
            let byte = found_byte.expect(&format!("Error finding byte at position {:?}", i));
            discovered_plaintext.push(byte);
        }

        let discovered_plaintext_string = String::from_utf8_lossy(&discovered_plaintext[..]);
        println!("Discovered plaintext string: {:?}", discovered_plaintext_string);

        assert_eq!(&actual_plaintext[..], &discovered_plaintext[..]);
    }

    #[test]
    fn challenge_26() {
        let iv: Vec<u8> = vec![0; 8];
        let encrypted = admin_string_encrypt_challenge("testing 123;admin=true;blah", &iv[..], &aes_ctr);
        let decrypted_contains_admin = admin_string_decrypt_and_check(&encrypted[..], &iv[..], &|key, ciphertext, nonce | { Ok(aes_ctr(&key[..], &ciphertext[..], &nonce[..])) });
        assert!(!decrypted_contains_admin);

        // prepend string is 32 bytes
        let mut encrypted = admin_string_encrypt_challenge("\x00admin\x00true", &iv[..], &aes_ctr);
        encrypted[32] ^= 59; // ascii ";"
        encrypted[38] ^= 61; // ascii "="

        let decrypted_contains_admin = admin_string_decrypt_and_check(&encrypted[..], &iv[..], &|key, ciphertext, nonce | { Ok(aes_ctr(&key[..], &ciphertext[..], &nonce[..])) });
        assert!(decrypted_contains_admin);
    }

    #[test]
    fn challenge_28() {
        let hashed = sha1("".as_bytes(), "hello world".as_bytes());
        let hashed_str = bytes_to_hex(&hashed);
        assert_eq!(hashed_str, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");

        let hashed = sha1("key".as_bytes(), "message".as_bytes());
        let hashed_str = bytes_to_hex(&hashed);
        assert_eq!(hashed_str, "7d89ca5f9535d3bd925ca99f484ae4413a14fe2d");

        let hashed = sha1("notthekey".as_bytes(), "message".as_bytes());
        let hashed_str = bytes_to_hex(&hashed);
        assert_ne!(hashed_str, "7d89ca5f9535d3bd925ca99f484ae4413a14fe2d");
    }

    #[test]
    fn challenge_29() {

        let hashed_message = secret_prefix_mac("testing".as_bytes());

        let hashed_message2 = secret_prefix_mac("testing".as_bytes());

        assert_eq!(hashed_message, hashed_message2);

        let original_string = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".as_bytes();

        let original_hash = secret_prefix_mac(&original_string);

        let (mut a, mut b, mut c, mut d, mut e) = (0u32, 0u32, 0u32, 0u32, 0u32);

        for i in 0..4 {
            a = a | ((original_hash[i] as u32) << (8 * i));
            b = b | ((original_hash[i + 4] as u32) << (8 * i));
            c = c | ((original_hash[i + 8] as u32) << (8 * i));
            d = d | ((original_hash[i + 12] as u32) << (8 * i));
            e = e | ((original_hash[i + 16] as u32) << (8 * i));
        }

        let mut found_signature = None;
        let mut test_password = String::new();
        for _i in 1..20 { // check up to 20 character long secrets
            test_password.push('A');
            let mut check_padding_bytes = Vec::new();
            check_padding_bytes.extend_from_slice(test_password.as_bytes());
            check_padding_bytes.extend_from_slice(&original_string);

            let padding = md_padding(&check_padding_bytes);

            let mut forged_bytes = Vec::new();
            forged_bytes.extend_from_slice(&original_string);
            forged_bytes.extend_from_slice(&padding);
            forged_bytes.extend_from_slice(";admin=true".as_bytes());

            let forged_bytes_len = forged_bytes.len();
            let mut new_message = Vec::new();
            new_message.extend_from_slice(";admin=true".as_bytes());
            let new_message_padding = md_padding_with_length(&forged_bytes, forged_bytes_len + test_password.len());
            new_message.extend_from_slice(&new_message_padding);

            let forged_mac = sha1_registers(a.to_be(), b.to_be(), c.to_be(), d.to_be(), e.to_be(), &new_message);

            if validate_mac(&forged_bytes, &forged_mac) {
                found_signature = Some(forged_mac);
            }
        }
        assert!(found_signature.is_some());
        println!("found_signature = {:?}", found_signature.unwrap());
    }

    #[test]
    fn challenge_31_32() {
        thread::spawn(|| {
            start_web_server();
        });

        let client = reqwest::Client::new();
        let filename = "afile";

        let mut discovered_signature = None;
        let mut test_signature = String::new();

        'outer: while discovered_signature.is_none() {
            let mut best_time = Duration::new(0, 0);
            let mut best_hex = String::new();

            // First check to see if we've already found the signature with our current string
            let resp = client.get(format!("http://localhost:3000?file={}&signature={}", filename, &test_signature[..]).as_str())
                .send()
                .expect("Can't send");

            if let reqwest::StatusCode::BadRequest = resp.status() {} else {
                println!("good request");
                discovered_signature = Some(test_signature);
                break;
            };

            for i in 0..255 {
                // TODO: We should probably be doing this all in bytes instead of an actual
                // string...
                let mut hex_string = format!("{:02x}", i);

                test_signature.push_str(&hex_string);
                test_signature.push_str("00");

                let now = Instant::now();
                for _ in 0..20 {
                    let resp = client.get(format!("http://localhost:3000?file={}&signature={}", filename, &test_signature[..]).as_str())
                        .send()
                        .expect("Can't send");

                    match resp.status() {
                        reqwest::StatusCode::BadRequest => {
                            // println!("status error");
                        },
                        _ => {
                            println!("good request");
                            discovered_signature = Some(test_signature);
                            break 'outer;
                        }
                    };

                    let elapsed = now.elapsed();
                    if elapsed > best_time {
                        best_time = elapsed;
                        best_hex.clear();
                        best_hex.push_str(&hex_string[..]);
                    }
                }

                // have to pop twice for each hex digit we want to remove
                test_signature.pop();
                test_signature.pop();
                test_signature.pop();
                test_signature.pop();
            }


            println!("Found a byte!: {}", &best_hex[..]);
            test_signature.push_str(&best_hex[..]);
        }

        assert!(discovered_signature.is_some());
        println!("Found signature!: {}", &(discovered_signature.unwrap()));
    }
}
