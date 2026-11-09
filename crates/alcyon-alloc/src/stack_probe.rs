// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Test-only (feature `test-probe`, T462): reading and painting the stack below the caller, to
//! find what a call left there ([`crate::scrub_stack`]'s tests in `alcyon-tls`). Never built into
//! Alcyon: only dev-dependencies turn the feature on.
//!
//! Both functions work on `[rsp - len, rsp)` of their own frame. Called from one frame, one after
//! the other, they see the same bytes: what the calls that frame made in between left below it.
//! `x86_64` only.

/// Fills the `len` bytes below this call's stack pointer with `byte`.
///
/// `len` must be well under what is left of the thread's stack (the guard page is not checked).
#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub fn paint_below(len: usize, byte: u8) {
    // SAFETY: writes only `[rsp - len, rsp)`, stack no live frame uses: this function makes no
    // call, and without `nostack` the compiler keeps nothing in the red zone across the asm.
    // `rep stosb` counts up (the ABI keeps the direction flag clear).
    unsafe {
        core::arch::asm!(
            "mov rdi, rsp",
            "sub rdi, rcx",
            "rep stosb",
            inout("rcx") len => _,
            in("al") byte,
            out("rdi") _,
        );
    }
}

/// Copies the `out.len()` bytes below this call's stack pointer into `out` (lowest address first).
#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub fn copy_below(out: &mut [u8]) {
    // SAFETY: reads `[rsp - len, rsp)` (mapped: the caller keeps `len` under the stack left) and
    // writes `out`, which does not overlap the stack below this frame.
    unsafe {
        core::arch::asm!(
            "mov rsi, rsp",
            "sub rsi, rcx",
            "rep movsb",
            inout("rcx") out.len() => _,
            inout("rdi") out.as_mut_ptr() => _,
            out("rsi") _,
        );
    }
}

/// Sets this thread's copy of `tune.alcyon.ssl-zero-buffers` only (until the next settings change),
/// so that a test can run [`crate::scrub_stack`] off without changing the setting for the other
/// tests of its process.
pub fn set_thread_ssl_zero_buffers(on: bool) {
    crate::pool::set_thread_wipe_ssl(on);
}

/// Sets this thread's copy of the `on-free` mode of `tune.alcyon.ssl-zero-buffers` only.
pub fn set_thread_ssl_zero_on_free(on: bool) {
    crate::pool::set_thread_wipe_ssl_free(on);
}
