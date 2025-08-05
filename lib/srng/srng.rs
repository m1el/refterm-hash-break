#![feature(portable_simd)]
use core::simd::*;
use core::simd::cmp::SimdPartialOrd;
use core::simd::num::SimdUint;

const LANES: usize = 4;
/// A basic random number generator based on xorshift64 with 64-bits of state
pub struct SRng {
    /// The RNG's seed and state
    seed: Simd<u64, LANES>,
}

impl SRng {
    /// Construct RNG with a given seed
    pub fn new(seed: Simd<u64, LANES>) -> Self {
        Self {
            seed,
        }
    }
    /// Generate a random number using mxm from "The construct of a bit mixer"
    /// http://jonkagstrom.com/bit-mixer-construction/
    #[inline]
    pub fn next(&mut self) -> Simd<u64, LANES> {
        // let mulc = Simd::splat(0x94d049bb133111eb);
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 17;
        self.seed ^= self.seed << 43;
        // self.seed += mulc;
        // self.seed *= mulc;
        // self.seed ^= self.seed >> 56;
        // self.seed *= mulc;
        self.seed
    }

    /// Generates 4*LANES random ASCII characters
    pub fn random_ascii(&mut self) -> [u8; 4 * LANES] {
        let max = Simd::<u32, {4*LANES}>::splat(0x7f - 0x20);
        let space = Simd::splat(0x20);
        let random1 = Simd::<u16, {4*LANES}>::from_ne_bytes(self.next().to_ne_bytes());
        let result = random1.cast::<u32>() * max;
        ((result >> 16).cast::<u8>() + space).to_array()
    }

    /// Generates 4*LANES random alphanumeric characters
    pub fn random_alphanum(&mut self) -> [u8; 4 * LANES] {
        let max = Simd::<u32, {4*LANES}>::splat(10 + 26 + 26);
        let random1 = Simd::<u16, {4*LANES}>::from_ne_bytes(self.next().to_ne_bytes());
        let result = random1.cast::<u32>() * max;
        let mut result = (result >> 16).cast::<u8>() + Simd::splat(b'0');
        let skip_ranges = [
            (b'9', b'A' - b'9' - 1),
            (b'Z', b'a' - b'Z' - 1),
        ];
        for (start, shift) in skip_ranges {
            let mask = result.simd_gt(Simd::splat(start));
            let shifted = result + Simd::splat(shift);
            result = mask.select(shifted, result);
        }
        result.to_array()
    }

    /// Generates 8*LANES url-safe base64 digits
    pub fn random_ub64(&mut self) -> [u8; 8 * LANES] {
        let mask = Simd::splat(0x3f);
        let mut result = self.next().to_ne_bytes() & mask;
        result += Simd::splat(b'+');
        let skip_ranges = [
            (b'-', b'0' - b'-' - 1),
            (b'9', b'A' - b'9' - 1),
            (b'Z', b'_' - b'Z' - 1),
            (b'_', b'a' - b'_' - 1),
        ];
        for (start, shift) in skip_ranges {
            let mask = result.simd_gt(Simd::splat(start));
            let shifted = result + Simd::splat(shift);
            result = mask.select(shifted, result);
        }
        result.to_array()
    }

    /// Generates 8*LANES base64 digits
    pub fn random_b64(&mut self) -> [u8; 8 * LANES] {
        let mask = Simd::splat(0x3f);
        let mut result = self.next().to_ne_bytes() & mask;
        result += Simd::splat(b'+');
        let skip_ranges = [
            (b'+', b'/' - b'+' - 1),
            (b'9', b'A' - b'9' - 1),
            (b'Z', b'a' - b'Z' - 1),
        ];
        for (start, shift) in skip_ranges {
            let mask = result.simd_gt(Simd::splat(start));
            let shifted = result + Simd::splat(shift);
            result = mask.select(shifted, result);
        }
        result.to_array()
    }
}
