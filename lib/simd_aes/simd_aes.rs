#![feature(portable_simd)]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i,
    _mm_aesenc_si128,
    _mm_aesenclast_si128,
    _mm_aesdec_si128,
    _mm_aesdeclast_si128,
};

use core::simd::{Simd};

#[cfg(target_arch="x86_64")]
use core::simd::{LaneCount, SimdElement, SupportedLaneCount};

pub trait SimdAes {
    #[cfg(target_arch = "aarch64")]
    fn shift_rows(self) -> Self;
    #[cfg(target_arch = "aarch64")]
    fn inv_shift_rows(self) -> Self;
    fn aes_enc(self, key: Self) -> Self;
    fn aes_enc_last(self, key: Self) -> Self;
    fn aes_dec(self, key: Self) -> Self;
    fn aes_dec_last(self, key: Self) -> Self;
}

#[cfg(target_arch = "x86_64")]
impl<T, const N: usize> SimdAes for Simd<T, N>
where LaneCount<N>: SupportedLaneCount,
      T: SimdElement,
      Simd<T, N>: Into::<__m128i>,
      Simd<T, N>: From::<__m128i>
{
    #[inline]
    fn aes_enc(self, key: Self) -> Self {
        unsafe { Self::from(_mm_aesenc_si128(self.into(), key.into())) }
    }

    #[inline]
    fn aes_enc_last(self, key: Self) -> Self {
        unsafe { Self::from(_mm_aesenclast_si128(self.into(), key.into())) }
    }

    #[inline]
    fn aes_dec(self, key: Self) -> Self {
        unsafe { Self::from(_mm_aesdec_si128(self.into(), key.into())) }
    }

    #[inline]
    fn aes_dec_last(self, key: Self) -> Self {
        unsafe { Self::from(_mm_aesdeclast_si128(self.into(), key.into())) }
    }
}

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::{
    // uint8x16_t,
    vld1q_u8,
    vst1q_u8,
    vaesdq_u8,
    vaeseq_u8,
    vaesimcq_u8,
    vaesmcq_u8,
};

#[cfg(target_arch = "aarch64")]
impl SimdAes for Simd<u8, 16> {
    #[inline]
    fn shift_rows(self) -> Self {
        // AES state as 4x4 byte matrix (row-major):
        // [ 0  1  2  3 ]
        // [ 4  5  6  7 ]
        // [ 8  9 10 11 ]
        // [12 13 14 15 ]
        // After ShiftRows:
        // [ 0  1  2  3 ]  (no shift)
        // [ 5  6  7  4 ]  (left shift by 1)
        // [10 11  8  9 ]  (left shift by 2)
        // [15 12 13 14 ]  (left shift by 3)
        let indices = Simd::from_array([
            0, 1, 2, 3,    // Row 0
            5, 6, 7, 4,    // Row 1
            10, 11, 8, 9,  // Row 2
            15, 12, 13, 14 // Row 3
        ]);
        self.swizzle_dyn(indices)
    }

    #[inline]
    fn inv_shift_rows(self) -> Self {
        // Inverse ShiftRows:
        // [ 0  1  2  3 ]  (no shift)
        // [ 7  4  5  6 ]  (right shift by 1 = left shift by 3)
        // [10 11  8  9 ]  (right shift by 2 = left shift by 2)
        // [13 14 15 12 ]  (right shift by 3 = left shift by 1)
        let indices = Simd::from_array([
            0, 1, 2, 3,    // Row 0
            7, 4, 5, 6,    // Row 1
            10, 11, 8, 9,  // Row 2
            13, 14, 15, 12 // Row 3
        ]);
        self.swizzle_dyn(indices)
    }

    #[inline]
    fn aes_enc(self, key: Self) -> Self {
        unsafe {
            let state = vld1q_u8(self.as_array().as_ptr());
            let key = vld1q_u8(key.as_array().as_ptr());
            let result = vaesmcq_u8(vaeseq_u8(state, key));
            let mut output = [0u8; 16];
            vst1q_u8(output.as_mut_ptr(), result);
            Simd::from_array(output)
        }
    }

    #[inline]
    fn aes_enc_last(self, key: Self) -> Self {
        unsafe {
            let state = vld1q_u8(self.as_array().as_ptr());
            let key = vld1q_u8(key.as_array().as_ptr());
            let result = vaeseq_u8(state, key);
            let mut output = [0u8; 16];
            vst1q_u8(output.as_mut_ptr(), result);
            Simd::from_array(output)
        }
    }

    #[inline]
    fn aes_dec(self, key: Self) -> Self {
        unsafe {
            let state = vld1q_u8(self.as_array().as_ptr());
            let key = vld1q_u8(key.as_array().as_ptr());
            let result = vaesimcq_u8(vaesdq_u8(state, key));
            let mut output = [0u8; 16];
            vst1q_u8(output.as_mut_ptr(), result);
            Simd::from_array(output)
        }
    }

    #[inline]
    fn aes_dec_last(self, key: Self) -> Self {
        unsafe {
            let state = vld1q_u8(self.as_array().as_ptr());
            let key = vld1q_u8(key.as_array().as_ptr());
            let result = vaesdq_u8(state, key);
            let mut output = [0u8; 16];
            vst1q_u8(output.as_mut_ptr(), result);
            Simd::from_array(output)
        }
    }
}