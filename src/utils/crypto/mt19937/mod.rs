
const W: u32 = 32;
const N: usize = 624;
const M: usize = 397;
const F: u32 = 1812433253;
const A: u32 = 0x9908b0df;
const C: u32 = 0xefc60000;
const B: u32 = 0x9d2c5680;
const U: u32 = 11;
const S: u32 = 7;
const T: u32 = 15;
const L: u32 = 18;
const UPPER_MASK: u32 = 0x80000000;
const LOWER_MASK: u32 = 0x7fffffff;

pub struct MT19937 {
    mti: usize,
    mt: Vec<u32>,
    initialized: bool,
}

impl MT19937 {
    pub fn new(seed: u32) -> MT19937 {
        let mut mt: Vec<u32> = vec![0; N];

        mt[0] = seed;
        for i in 1..N {
            let (x, _) = F.overflowing_mul(mt[i-1] ^ (mt[i-1] >> (W-2)));
            mt[i] = x + i as u32;
        }
        MT19937 { mt, mti: N, initialized: true }
    }

    pub fn gen_rand(&mut self) -> u32 {
        let mut y: u32;
        let mag01 = [0, A];

        if !self.initialized {
            panic!("Must initialize before using");
        }

        if self.mti >= N {
            for kk in 0..(N-M) {
                y = (self.mt[kk] & UPPER_MASK) | (self.mt[kk+1] & LOWER_MASK);
                self.mt[kk] = self.mt[kk+M] ^ (y >> 1) ^ mag01[y as usize & 0x1];
            }

            for kk in (N-M)..(N-1) {
                y = (self.mt[kk] & UPPER_MASK) | (self.mt[kk+1] & LOWER_MASK);
                let m_sub_n: isize = M as isize - N as isize;
                let index = kk as isize + m_sub_n;
                self.mt[kk] = self.mt[index as usize] ^ (y >> 1) ^ mag01[y as usize & 0x1];
            }
            y = (self.mt[N-1] & UPPER_MASK) | (self.mt[0] & LOWER_MASK);
            self.mt[N-1] = self.mt[M-1] ^ (y >> 1) ^ mag01[y as usize & 0x1];
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
}

#[cfg(test)]
mod tests;
