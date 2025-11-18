#[allow(dead_code)]
const WORD_SIZE :u32= 32; //w
const DEGREE_OF_RECURENCE :usize = 256; //n 
const MIDDLE_WORD :usize = 57; //m 
#[allow(dead_code)]
const LOWER_BITMASK_SIZE :u32 =1; //r
const COEFFICIENT :u32 =0x9908b0df ; //a 
const U :u32 =11;
const S :u32 =7;
const T :u32 =15;
const L :u32 =18;
const B :u32 =0x9d2c5680;
const C :u32 =0xefc60000;
const F :u32 =1812433253;
const LOWER_MASK: u32 = 0x7FFFFFFF; // lowest w-r bits
const UPPER_MASK: u32 = 0x80000000; // highest r bits

pub struct Mt19937 {
    mt: [u32; DEGREE_OF_RECURENCE],
    index: usize,
}

impl Mt19937 {
    pub fn new(seed: u32) -> Self {
        let mut mt = [0u32; DEGREE_OF_RECURENCE];
        mt[0] = seed;
        for i in 1..DEGREE_OF_RECURENCE {
            mt[i] = F
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        Self { mt, index: 0 }
    }

    pub fn next_u32(&mut self) -> u32 {
        if self.index == 0 {
            self.twist();
        }

        let mut y = self.mt[self.index];
        y ^= y >> U;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;

        self.index = (self.index + 1) % DEGREE_OF_RECURENCE;
        y
    }

    fn twist(&mut self) {
        for i in 0..DEGREE_OF_RECURENCE {
            let x = (self.mt[i] & UPPER_MASK) + (self.mt[(i + 1) % DEGREE_OF_RECURENCE] & LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= COEFFICIENT;
            }
            self.mt[i] = self.mt[(i + MIDDLE_WORD) % DEGREE_OF_RECURENCE] ^ x_a;
        }
    }
}


pub struct ReverseMt19937{
    mt: [u32; DEGREE_OF_RECURENCE],
    index: usize,
    last_output: u32,
}


impl ReverseMt19937{

    pub fn new(seed: u32) -> Self {
        let mut mt = [0u32; DEGREE_OF_RECURENCE];
        mt[0] = seed;
        for i in 1..DEGREE_OF_RECURENCE {
            mt[i] = F
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        Self { mt, index: 0 ,last_output:0 }
    }

    pub fn next_u32(&mut self) -> u32 {
        if self.index == 0 {
            self.twist();
        }

        let mut y = self.mt[self.index];

        y ^= y >> U;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;


        self.index = (self.index + 1) % DEGREE_OF_RECURENCE;
        self.last_output = y;
        y
    }



    pub fn from_state(mt: [u32; 256]) -> Self {
        Self {
            mt,
            index: 0, // ensure it twists before generating
            last_output: 0,
        }
    }

    fn twist(&mut self) {
        for i in 0..DEGREE_OF_RECURENCE {
            let x = (self.mt[i] & UPPER_MASK) + (self.mt[(i + 1) % DEGREE_OF_RECURENCE] & LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= COEFFICIENT;
            }
            self.mt[i] = self.mt[(i + MIDDLE_WORD) % DEGREE_OF_RECURENCE] ^ x_a;
        }
    }



}


pub fn untemper(mut y:u32)->u32{

    y = invert_right_shift_xor(y,L);//4
    y = invert_xor_left_shift_and(y,T,C);//3
    y = invert_xor_left_shift_and(y,S,B);//2
    y = invert_right_shift_xor(y,U);//1

    y
}

fn invert_right_shift_xor(y: u32, shift: u32) -> u32 {
    let mut result = y;
    let mut i = 1;
    while i * shift < 32 {
        result ^= y >> (i * shift);
        i += 1;
    }
    result
}


fn invert_xor_left_shift_and(y: u32, shift: u32, mask: u32) -> u32 {
    let mut result = 0u32;
    for i in 0..32 {
        let bit = 1 << i;
        let mut orig_bit = (y & bit) != 0;

        if i >= shift {
            let shifted_bit = 1 << (i - shift);
            if (mask & bit) != 0 && (result & shifted_bit) != 0 {
                orig_bit ^= true;
            }
        }

        if orig_bit {
            result |= bit;
        }
    }
    result
}
