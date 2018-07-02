pub mod mt19937;

pub trait Prng {
    fn new(seed: u32) -> Self;
    fn gen_rand(&mut self) -> u32;
}
