use std::str;
use std::io::prelude::*;
use std::path::PathBuf;
use std::fs::File;
use super::bytes::{base64_to_bytes};

pub fn read_file_as_bytes(path: &PathBuf) -> Vec<u8> {
    println!("{:?}", path);
    let mut file = File::open(&path).expect("Error opening ciphertext file.");

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Error reading ciphertext file.");

    buffer
}

pub fn read_base64_file_as_bytes(path: &PathBuf) -> Vec<u8>  {
    let buffer = read_file_as_bytes(&path);

    base64_to_bytes(&str::from_utf8(&buffer).expect("Error reading string from_utf8 bytes").replace('\n', ""))
}
