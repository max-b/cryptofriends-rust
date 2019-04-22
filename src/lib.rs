#![cfg_attr(feature = "cargo-clippy", feature(tool_lints))]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(
        clippy::needless_pass_by_value,
        clippy::type_complexity,
        clippy::many_single_char_names,
        clippy::unreadable_literal
    )
)]

extern crate base64;
extern crate byteorder;
extern crate crypto;
extern crate hyper;
extern crate itertools;
extern crate num_bigint as bigint;
extern crate num_integer;
extern crate num_traits;
extern crate openssl;
extern crate rand;
extern crate reqwest;
extern crate url;
extern crate md4;

pub mod utils;

pub mod set_1;
pub mod set_2;
pub mod set_3;
pub mod set_4;
pub mod set_5;
pub mod set_6;
