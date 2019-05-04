pub mod challenge_25;
pub mod challenge_26;
pub mod challenge_27;
pub mod challenge_28;
pub mod challenge_29;
pub mod challenge_30;
pub mod challenge_31_32;

extern crate reqwest;

use utils::misc::generate_password;

thread_local!(static CONSISTENT_MAC_SECRET: Vec<u8> = generate_password());

pub fn secret_prefix_mac(message: &[u8], hash: &Fn(&[u8], &[u8]) -> Vec<u8>) -> Vec<u8> {
    CONSISTENT_MAC_SECRET.with(|s| hash(&s, &message))
}

pub fn validate_mac(message: &[u8], mac: &[u8], hash: &Fn(&[u8], &[u8]) -> Vec<u8>) -> bool {
    let actual_mac = secret_prefix_mac(&message, hash);
    (actual_mac == mac)
}
