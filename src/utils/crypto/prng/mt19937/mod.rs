pub const W: u32 = 32;
pub const N: usize = 624;
const M: usize = 397;
const F: u32 = 1812433253;
const A: u32 = 0x9908b0df;
pub const C: u32 = 0xefc60000;
pub const B: u32 = 0x9d2c5680;
pub const U: u32 = 11;
pub const S: u32 = 7;
pub const T: u32 = 15;
pub const L: u32 = 18;
const UPPER_MASK: u32 = 0x80000000;
const LOWER_MASK: u32 = 0x7fffffff;

use super::Prng;

#[derive(Default)]
pub struct MT19937 {
    pub mti: usize,
    pub mt: Vec<u32>,
    pub initialized: bool,
    pub byte_array: Option<Vec<u8>>,
    pub byte_counter: Option<usize>,
}

impl Prng for MT19937 {
    fn new(seed: u32) -> MT19937 {
        let mut mt: Vec<u32> = vec![0; N];

        mt[0] = seed;
        for i in 1..N {
            let (x, _) = F.overflowing_mul(mt[i - 1] ^ (mt[i - 1] >> (W - 2)));
            mt[i] = x.wrapping_add(i as u32);
        }
        MT19937 {
            mt,
            mti: N,
            initialized: true,
            ..Default::default()
        }
    }

    fn gen_rand(&mut self) -> u32 {
        let mut y: u32;
        let mag01 = [0, A];

        if !self.initialized {
            panic!("Must initialize before using");
        }

        if self.mti >= N {
            for kk in 0..(N - M) {
                y = (self.mt[kk] & UPPER_MASK) | (self.mt[kk + 1] & LOWER_MASK);
                self.mt[kk] = self.mt[kk + M] ^ (y >> 1) ^ mag01[y as usize & 0x1];
            }

            for kk in (N - M)..(N - 1) {
                y = (self.mt[kk] & UPPER_MASK) | (self.mt[kk + 1] & LOWER_MASK);
                let m_sub_n: isize = M as isize - N as isize;
                let index = kk as isize + m_sub_n;
                self.mt[kk] = self.mt[index as usize] ^ (y >> 1) ^ mag01[y as usize & 0x1];
            }
            y = (self.mt[N - 1] & UPPER_MASK) | (self.mt[0] & LOWER_MASK);
            self.mt[N - 1] = self.mt[M - 1] ^ (y >> 1) ^ mag01[y as usize & 0x1];
            self.mti = 0;
        }

        y = self.mt[self.mti];

        self.mti += 1;

        y ^= y >> U;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;

        y
    }

    fn gen_rand_byte(&mut self) -> u8 {
        if self.byte_array.as_ref().is_none() {
            let rand = self.gen_rand();
            let mut byte_array: Vec<u8> = Vec::new();

            for i in 0..4 {
                byte_array.push(((rand >> (i * 8)) & 0xff) as u8);
            }
            let first_byte = byte_array[0];
            self.byte_array = Some(byte_array);
            self.byte_counter = Some(0);

            first_byte
        } else {
            let mut counter = self.byte_counter.unwrap();
            counter += 1;
            if counter == 4 {
                self.byte_counter = None;
                self.byte_array = None;
                self.gen_rand_byte()
            } else {
                self.byte_counter = Some(counter);
                self.byte_array.as_mut().unwrap()[counter]
            }
        }
    }
}

impl MT19937 {
    pub fn get_state(&self) -> &[u32] {
        &self.mt[..]
    }

    pub fn set_state(&mut self, new_state: &[u32], new_index: usize) -> () {
        self.mt = vec![0; N];
        self.mt.extend_from_slice(&new_state[..]);
        self.mti = new_index;
    }

    pub fn get_state_val(&self, i: usize) -> u32 {
        self.mt[i]
    }

    pub fn get_index(&self) -> usize {
        self.mti
    }
}

#[cfg(test)]
mod tests;
