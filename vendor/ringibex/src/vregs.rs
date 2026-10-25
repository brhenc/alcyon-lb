// Copyright 2026 Ibex contributors.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Clearing the vector registers after the assembly that held key material
//! in them (ring-ibex, feature `zeroize`; ZEROIZE.md section 2).
//!
//! AES-NI keeps round keys in xmm registers, GHASH keeps H and its powers,
//! ChaCha20 its key words, the P-256/P-384/X25519 ladders their scalars and
//! coordinates. The assembly does not clear them on return, and nothing in
//! Rust overwrites all of them before the next context switch saves them.
//! [`clear`] is called once at the end of each public operation that ran such
//! assembly (an AEAD key setup, seal or open, a key agreement, a signature, an
//! HMAC), not after each assembly call inside it: in between, ring's own code
//! runs, and the last call's registers are the ones that remain.
//!
//! General-purpose registers are left alone: they are overwritten within a
//! few instructions of the return, and the assembly keeps only addresses and
//! loop counters there in the hot loops.

use crate::cpu;

/// Zeroes the vector registers: `vzeroall` (ymm0-15, which includes the xmm
/// halves) when the CPU and OS support AVX, else `pxor` on xmm0-15; on
/// AArch64 `eor` on v0-v31. Elsewhere (and on 32-bit x86 for xmm8-15, which
/// do not exist) there is nothing to do.
///
/// Cost: one feature-flag load and either one `vzeroall` or 16 `pxor`s (32
/// `eor`s on AArch64).
#[cfg_attr(not(feature = "zeroize"), allow(dead_code))]
#[inline]
pub(crate) fn clear(cpu_features: cpu::Features) {
    #[cfg(target_arch = "x86_64")]
    {
        use cpu::{intel::Avx, GetFeature as _};
        let avx: Option<Avx> = cpu_features.get_feature();
        if avx.is_some() {
            // SAFETY: AVX is supported (CPUID and XGETBV, as for ring's own
            // AVX code). `vzeroall` writes only the registers declared below.
            // Without the `avx` target feature the compiler keeps nothing in
            // the upper halves, so declaring the xmm halves is enough (the
            // ymm register class needs that target feature).
            #[cfg(target_feature = "avx")]
            unsafe {
                core::arch::asm!(
                    "vzeroall",
                    out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
                    out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
                    out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
                    out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
                    options(nomem, nostack, preserves_flags),
                );
            }
            #[cfg(not(target_feature = "avx"))]
            unsafe {
                core::arch::asm!(
                    "vzeroall",
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                    out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                    out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                    out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
                    options(nomem, nostack, preserves_flags),
                );
            }
        } else {
            // SAFETY: SSE2 is part of the x86_64 baseline. Writes only the
            // registers declared below.
            unsafe {
                core::arch::asm!(
                    "pxor xmm0, xmm0", "pxor xmm1, xmm1", "pxor xmm2, xmm2", "pxor xmm3, xmm3",
                    "pxor xmm4, xmm4", "pxor xmm5, xmm5", "pxor xmm6, xmm6", "pxor xmm7, xmm7",
                    "pxor xmm8, xmm8", "pxor xmm9, xmm9", "pxor xmm10, xmm10", "pxor xmm11, xmm11",
                    "pxor xmm12, xmm12", "pxor xmm13, xmm13", "pxor xmm14, xmm14", "pxor xmm15, xmm15",
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                    out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                    out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                    out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
                    options(nomem, nostack, preserves_flags),
                );
            }
        }
    }
    #[cfg(all(target_arch = "x86", target_feature = "sse2"))]
    {
        let _ = cpu_features;
        // SAFETY: SSE2 is enabled for the target. Writes only the registers
        // declared below.
        unsafe {
            core::arch::asm!(
                "pxor xmm0, xmm0", "pxor xmm1, xmm1", "pxor xmm2, xmm2", "pxor xmm3, xmm3",
                "pxor xmm4, xmm4", "pxor xmm5, xmm5", "pxor xmm6, xmm6", "pxor xmm7, xmm7",
                out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    {
        let _ = cpu_features;
        // SAFETY: NEON (AdvSIMD) is part of the AArch64 baseline. Writes only
        // the registers declared below.
        unsafe {
            core::arch::asm!(
                "eor v0.16b, v0.16b, v0.16b", "eor v1.16b, v1.16b, v1.16b",
                "eor v2.16b, v2.16b, v2.16b", "eor v3.16b, v3.16b, v3.16b",
                "eor v4.16b, v4.16b, v4.16b", "eor v5.16b, v5.16b, v5.16b",
                "eor v6.16b, v6.16b, v6.16b", "eor v7.16b, v7.16b, v7.16b",
                "eor v8.16b, v8.16b, v8.16b", "eor v9.16b, v9.16b, v9.16b",
                "eor v10.16b, v10.16b, v10.16b", "eor v11.16b, v11.16b, v11.16b",
                "eor v12.16b, v12.16b, v12.16b", "eor v13.16b, v13.16b, v13.16b",
                "eor v14.16b, v14.16b, v14.16b", "eor v15.16b, v15.16b, v15.16b",
                "eor v16.16b, v16.16b, v16.16b", "eor v17.16b, v17.16b, v17.16b",
                "eor v18.16b, v18.16b, v18.16b", "eor v19.16b, v19.16b, v19.16b",
                "eor v20.16b, v20.16b, v20.16b", "eor v21.16b, v21.16b, v21.16b",
                "eor v22.16b, v22.16b, v22.16b", "eor v23.16b, v23.16b, v23.16b",
                "eor v24.16b, v24.16b, v24.16b", "eor v25.16b, v25.16b, v25.16b",
                "eor v26.16b, v26.16b, v26.16b", "eor v27.16b, v27.16b, v27.16b",
                "eor v28.16b, v28.16b, v28.16b", "eor v29.16b, v29.16b, v29.16b",
                "eor v30.16b, v30.16b, v30.16b", "eor v31.16b, v31.16b, v31.16b",
                out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                out("v28") _, out("v29") _, out("v30") _, out("v31") _,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        all(target_arch = "x86", target_feature = "sse2"),
        all(target_arch = "aarch64", target_endian = "little")
    )))]
    {
        let _ = cpu_features;
    }
}

/// [`clear`] under feature `zeroize`; nothing without it.
#[inline(always)]
pub(crate) fn clear_if_zeroize(cpu_features: cpu::Features) {
    #[cfg(feature = "zeroize")]
    clear(cpu_features);
    #[cfg(not(feature = "zeroize"))]
    let _ = cpu_features;
}

/// Calls [`clear_if_zeroize`] when dropped: for an operation with several exit
/// paths.
pub(crate) struct ClearOnDrop(pub(crate) cpu::Features);

impl Drop for ClearOnDrop {
    #[inline(always)]
    fn drop(&mut self) {
        clear_if_zeroize(self.0);
    }
}
