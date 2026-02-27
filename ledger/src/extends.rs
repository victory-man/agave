use crate::shred::{CodingShredHeader, ShredCommonHeader};
use std::ptr;

impl ShredCommonHeader {
    pub fn to_bytes(&self) -> [u8; 83] {
        //     signature: Signature, // 0..64
        //     shred_variant: ShredVariant, 64..65
        //     slot: Slot, // 65..73
        //     index: u32, // 73..77
        //     version: u16, // 77..79
        //     fec_set_index: u32, // 79..83
        let mut value = [0u8; 83];
        unsafe {
            SIMDMemoryOps::memcpy_simd_optimized(
                (&mut value[..64]).as_mut_ptr(),
                self.signature.as_ref().as_ptr(),
                64,
            );
            value[64] = u8::from(self.shred_variant);
            SIMDMemoryOps::memcpy_simd_optimized(
                (&mut value[65..73]).as_mut_ptr(),
                self.slot.to_le_bytes().as_ptr(),
                8,
            );
            SIMDMemoryOps::memcpy_simd_optimized(
                (&mut value[73..77]).as_mut_ptr(),
                self.index.to_le_bytes().as_ptr(),
                4,
            );
            SIMDMemoryOps::memcpy_simd_optimized(
                (&mut value[77..79]).as_mut_ptr(),
                self.version.to_le_bytes().as_ptr(),
                2,
            );
            SIMDMemoryOps::memcpy_simd_optimized(
                (&mut value[79..83]).as_mut_ptr(),
                self.fec_set_index.to_le_bytes().as_ptr(),
                4,
            );
        }
        value
    }
}

impl CodingShredHeader {
    pub fn to_bytes(&self) -> [u8; 6] {
        let mut value = [0u8; 6];
        unsafe {
            SIMDMemoryOps::memcpy_simd_optimized(
                (&mut value[..2]).as_mut_ptr(),
                self.num_data_shreds.to_le_bytes().as_ptr(),
                2,
            );
            SIMDMemoryOps::memcpy_simd_optimized(
                (&mut value[2..4]).as_mut_ptr(),
                self.num_coding_shreds.to_le_bytes().as_ptr(),
                2,
            );
            SIMDMemoryOps::memcpy_simd_optimized(
                (&mut value[4..6]).as_mut_ptr(),
                self.position.to_le_bytes().as_ptr(),
                2,
            );
        }
        value
    }
}

/// 🚀 SIMD优化的内存操作
pub struct SIMDMemoryOps;

impl SIMDMemoryOps {
    /// 🚀 SIMD加速的内存拷贝 - 针对小数据包优化
    ///
    /// # Safety
    ///
    /// This function is unsafe because it performs raw pointer operations.
    /// Callers must ensure that:
    /// - `dst` points to a mutable buffer with at least `len` bytes available
    /// - `src` points to a readable buffer with at least `len` bytes available
    /// - The memory regions pointed to by `dst` and `src` do not overlap (use `ptr::copy` for overlapping regions)
    /// - Both `dst` and `src` are properly aligned for the operations being performed
    #[inline(always)]
    pub unsafe fn memcpy_simd_optimized(dst: *mut u8, src: *const u8, len: usize) {
        // Basic validation to prevent obvious errors
        if len == 0 {
            return;
        }

        // Check for null pointers and panic on invalid input to prevent silent failures
        if dst.is_null() {
            panic!("Destination pointer is null");
        }
        if src.is_null() {
            panic!("Source pointer is null");
        }

        match len {
            // 针对不同数据大小使用不同优化策略
            0 => return,
            1..=8 => Self::memcpy_small(dst, src, len),
            9..=16 => Self::memcpy_sse(dst, src, len),
            17..=32 => Self::memcpy_avx(dst, src, len),
            33..=64 => Self::memcpy_avx2(dst, src, len),
            _ => Self::memcpy_avx512_or_fallback(dst, src, len),
        }
    }

    /// 小数据拷贝优化 (1-8字节)
    #[inline(always)]
    unsafe fn memcpy_small(dst: *mut u8, src: *const u8, len: usize) {
        match len {
            1 => *dst = *src,
            2 => *(dst as *mut u16) = *(src as *const u16),
            3 => {
                *(dst as *mut u16) = *(src as *const u16);
                *dst.add(2) = *src.add(2);
            }
            4 => *(dst as *mut u32) = *(src as *const u32),
            5 => {
                // Copy 4 bytes + 1 byte
                *(dst as *mut u32) = *(src as *const u32);
                *dst.add(4) = *src.add(4);
            }
            6 => {
                // Copy 4 bytes + 2 bytes
                *(dst as *mut u32) = *(src as *const u32);
                *(dst.add(4) as *mut u16) = *(src.add(4) as *const u16);
            }
            7 => {
                // Copy 4 bytes + 2 bytes + 1 byte
                *(dst as *mut u32) = *(src as *const u32);
                *(dst.add(4) as *mut u16) = *(src.add(4) as *const u16);
                *dst.add(6) = *src.add(6);
            }
            8 => {
                // Copy all 8 bytes at once
                *(dst as *mut u64) = *(src as *const u64);
            }
            _ => unreachable!(),
        }
    }

    /// SSE优化拷贝 (9-16字节)
    #[inline(always)]
    unsafe fn memcpy_sse(dst: *mut u8, src: *const u8, len: usize) {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("sse2") {
                use std::arch::x86_64::{__m128i, _mm_loadu_si128, _mm_storeu_si128};

                if len <= 16 {
                    let chunk = _mm_loadu_si128(src as *const __m128i);
                    _mm_storeu_si128(dst as *mut __m128i, chunk);
                }
            } else {
                // Fallback to standard copy if SSE2 not available
                ptr::copy_nonoverlapping(src, dst, len);
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            ptr::copy_nonoverlapping(src, dst, len);
        }
    }

    /// AVX优化拷贝 (17-32字节)
    #[inline(always)]
    unsafe fn memcpy_avx(dst: *mut u8, src: *const u8, len: usize) {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx") {
                use std::arch::x86_64::{__m256i, _mm256_loadu_si256, _mm256_storeu_si256};

                if len <= 32 {
                    let chunk = _mm256_loadu_si256(src as *const __m256i);
                    _mm256_storeu_si256(dst as *mut __m256i, chunk);
                }
            } else {
                // Fallback to standard copy if AVX not available
                ptr::copy_nonoverlapping(src, dst, len);
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            ptr::copy_nonoverlapping(src, dst, len);
        }
    }

    /// AVX2优化拷贝 (33-64字节)
    #[inline(always)]
    unsafe fn memcpy_avx2(dst: *mut u8, src: *const u8, len: usize) {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                use std::arch::x86_64::{__m256i, _mm256_loadu_si256, _mm256_storeu_si256};

                // 拷贝前32字节
                let chunk1 = _mm256_loadu_si256(src as *const __m256i);
                _mm256_storeu_si256(dst as *mut __m256i, chunk1);

                if len > 32 {
                    // 拷贝剩余字节
                    let remaining = len - 32;
                    if remaining <= 32 {
                        let chunk2 = _mm256_loadu_si256(src.add(32) as *const __m256i);
                        _mm256_storeu_si256(dst.add(32) as *mut __m256i, chunk2);
                    }
                }
            } else {
                // Fallback to standard copy if AVX2 not available
                ptr::copy_nonoverlapping(src, dst, len);
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            ptr::copy_nonoverlapping(src, dst, len);
        }
    }

    /// AVX512或回退拷贝 (>64字节)
    #[inline(always)]
    unsafe fn memcpy_avx512_or_fallback(dst: *mut u8, src: *const u8, len: usize) {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx512f") {
                use std::arch::x86_64::{__m512i, _mm512_loadu_si512, _mm512_storeu_si512};

                let chunks = len / 64;
                let mut offset = 0;

                // 使用AVX512处理64字节块
                for _ in 0..chunks {
                    let chunk = _mm512_loadu_si512(src.add(offset) as *const __m512i);
                    _mm512_storeu_si512(dst.add(offset) as *mut __m512i, chunk);
                    offset += 64;
                }

                // 处理剩余字节
                let remaining = len % 64;
                if remaining > 0 {
                    Self::memcpy_avx2(dst.add(offset), src.add(offset), remaining);
                }
            } else {
                // 回退到AVX2分块处理
                let chunks = len / 32;
                let mut offset = 0;

                for _ in 0..chunks {
                    Self::memcpy_avx2(dst.add(offset), src.add(offset), 32);
                    offset += 32;
                }

                let remaining = len % 32;
                if remaining > 0 {
                    Self::memcpy_avx(dst.add(offset), src.add(offset), remaining);
                }
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            // 完全不支持SIMD的平台，使用标准拷贝
            ptr::copy_nonoverlapping(src, dst, len);
        }
    }

    /// 🚀 SIMD加速的内存比较
    #[inline(always)]
    pub unsafe fn memcmp_simd_optimized(a: *const u8, b: *const u8, len: usize) -> bool {
        match len {
            0 => true,
            1..=8 => Self::memcmp_small(a, b, len),
            9..=16 => Self::memcmp_sse(a, b, len),
            17..=32 => Self::memcmp_avx2(a, b, len),
            _ => Self::memcmp_large(a, b, len),
        }
    }

    /// 小数据比较
    #[inline(always)]
    unsafe fn memcmp_small(a: *const u8, b: *const u8, len: usize) -> bool {
        match len {
            1 => *a == *b,
            2 => *(a as *const u16) == *(b as *const u16),
            3 => *(a as *const u16) == *(b as *const u16) && *a.add(2) == *b.add(2),
            4 => *(a as *const u32) == *(b as *const u32),
            5..=8 => *(a as *const u64) == *(b as *const u64),
            _ => unreachable!(),
        }
    }

    /// SSE比较
    #[inline(always)]
    unsafe fn memcmp_sse(a: *const u8, b: *const u8, len: usize) -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("sse2") {
                use std::arch::x86_64::{
                    __m128i, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8,
                };

                let chunk_a = _mm_loadu_si128(a as *const __m128i);
                let chunk_b = _mm_loadu_si128(b as *const __m128i);
                let cmp_result = _mm_cmpeq_epi8(chunk_a, chunk_b);
                let mask = _mm_movemask_epi8(cmp_result) as u32;

                // 检查前len字节是否相等
                let valid_mask = if len >= 16 { 0xFFFF } else { (1u32 << len) - 1 };
                (mask & valid_mask) == valid_mask
            } else {
                // Fallback to standard comparison if SSE2 not available
                (0..len).all(|i| *a.add(i) == *b.add(i))
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            (0..len).all(|i| *a.add(i) == *b.add(i))
        }
    }

    /// AVX2比较
    #[inline(always)]
    unsafe fn memcmp_avx2(a: *const u8, b: *const u8, len: usize) -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                use std::arch::x86_64::{
                    __m256i, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8,
                };

                let chunk_a = _mm256_loadu_si256(a as *const __m256i);
                let chunk_b = _mm256_loadu_si256(b as *const __m256i);
                let cmp_result = _mm256_cmpeq_epi8(chunk_a, chunk_b);
                let mask = _mm256_movemask_epi8(cmp_result) as u32;

                let valid_mask = if len >= 32 {
                    0xFFFFFFFF
                } else {
                    (1u32 << len) - 1
                };
                (mask & valid_mask) == valid_mask
            } else {
                // Fallback to standard comparison if AVX2 not available
                (0..len).all(|i| *a.add(i) == *b.add(i))
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            (0..len).all(|i| *a.add(i) == *b.add(i))
        }
    }

    /// 大数据比较
    #[inline(always)]
    unsafe fn memcmp_large(a: *const u8, b: *const u8, len: usize) -> bool {
        let chunks = len / 32;

        for i in 0..chunks {
            let offset = i * 32;
            if !Self::memcmp_avx2(a.add(offset), b.add(offset), 32) {
                return false;
            }
        }

        let remaining = len % 32;
        if remaining > 0 {
            return Self::memcmp_avx2(a.add(chunks * 32), b.add(chunks * 32), remaining);
        }

        true
    }

    /// 🚀 SIMD加速的内存清零
    #[inline(always)]
    pub unsafe fn memzero_simd_optimized(ptr: *mut u8, len: usize) {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                use std::arch::x86_64::{__m256i, _mm256_setzero_si256, _mm256_storeu_si256};

                let zero = _mm256_setzero_si256();
                let chunks = len / 32;
                let mut offset = 0;

                for _ in 0..chunks {
                    _mm256_storeu_si256(ptr.add(offset) as *mut __m256i, zero);
                    offset += 32;
                }

                // 处理剩余字节
                let remaining = len % 32;
                for i in 0..remaining {
                    *ptr.add(offset + i) = 0;
                }
            } else {
                // Fallback to standard zeroing if AVX2 not available
                ptr::write_bytes(ptr, 0, len);
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            ptr::write_bytes(ptr, 0, len);
        }
    }
}
