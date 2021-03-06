pub mod mt19937;

pub trait Prng {
    fn new(seed: u32) -> Self;
    fn gen_rand(&mut self) -> u32;
    fn gen_rand_byte(&mut self) -> u8;
}
