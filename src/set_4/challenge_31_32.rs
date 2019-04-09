use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha1::Sha1;
use hyper::rt::{run, Future};
use hyper::service::service_fn_ok;
use hyper::{Body, Request, Response, Server, StatusCode};
use std::thread::sleep;
use std::time::Duration;
use url::Url;
use utils::bytes::*;


fn check_signature(valid: &[u8], test: &[u8]) -> bool {
    let sleep_time = Duration::new(0, 5000000);

    for (i, valid_byte) in valid.iter().enumerate() {
        let test_byte = test.get(i);
        match test_byte {
            None => return false,
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
    let mut hmac = Hmac::new(hasher, b"password");
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
            .body(Body::from("fail\n"))
            .unwrap()
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


#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::{Duration, Instant};

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
            let resp = client
                .get(
                    format!(
                        "http://localhost:3000?file={}&signature={}",
                        filename,
                        &test_signature[..]
                    ).as_str(),
                ).send()
                .expect("Can't send");

            if let reqwest::StatusCode::BadRequest = resp.status() {
            } else {
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
                    let resp = client
                        .get(
                            format!(
                                "http://localhost:3000?file={}&signature={}",
                                filename,
                                &test_signature[..]
                            ).as_str(),
                        ).send()
                        .expect("Can't send");

                    match resp.status() {
                        reqwest::StatusCode::BadRequest => {
                            // println!("status error");
                        }
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
