#![feature(platform_intrinsics)]
#![feature(portable_simd)]

use core::arch::x86_64::{
    __m128i,
    _mm_aesenc_si128,
    _mm_aesenclast_si128,
    _mm_aesdec_si128,
    _mm_aesdeclast_si128,
};
use core_simd::{LaneCount, Simd, SimdElement, SupportedLaneCount};

pub trait SimdAes {
    fn aes_enc(self, key: Self) -> Self;
    fn aes_enc_last(self, key: Self) -> Self;
    fn aes_dec(self, key: Self) -> Self;
    fn aes_dec_last(self, key: Self) -> Self;
}

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
