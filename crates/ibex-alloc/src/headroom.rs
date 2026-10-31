// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Whether a new thread fits under `-m` (`RLIMIT_DATA`) before it is spawned.
//!
//! A thread costs two private writable mappings, both counted against `RLIMIT_DATA`: its stack,
//! mapped by `pthread_create` (a failure there is an `Err` from `std::thread::Builder::spawn`),
//! and the alternative signal stack std maps in the new thread before the thread's closure runs.
//! A failure of the second is a panic in std ("failed to allocate an alternative stack"), which
//! Ibex cannot catch: the process aborts. It happens when what is left under the limit holds the
//! stack and not the few pages after it (T540's gate, `-m 6`, a build 244 kB larger). Mapping
//! both at once, and unmapping them, before the spawn turns that edge into the clean refusal the
//! stack alone gets.

/// What a thread maps beside its stack: std's alternative signal stack (`max(SIGSTKSZ,
/// AT_MINSIGSTKSZ)` plus a guard page, 12 KiB on x86-64), glibc's guard page and static TLS,
/// and the first heap of the thread's own malloc arena (`M_TOP_PAD` 128 KiB plus the first
/// request, made writable by the thread's first `malloc`, which is glibc registering a TLS
/// destructor: when that fails glibc aborts, "failed to register TLS destructor"; T541's gate,
/// `-m 6`, instrumented build). 1 MiB leaves room for the worker's setup as well; a start under
/// a tiny `-m` is refused a little sooner, cleanly.
pub const THREAD_EXTRA: usize = 1024 * 1024;

/// Ok when a thread with a `stack`-byte stack fits under `RLIMIT_DATA` now: `stack` plus
/// [`THREAD_EXTRA`] is mapped (private, writable, never touched) and unmapped again.
///
/// # Errors
/// `ENOMEM` when the mapping does not fit.
pub fn thread_fits(stack: usize) -> std::io::Result<()> {
    use rustix::mm::{mmap_anonymous, munmap, MapFlags, ProtFlags};
    let len = stack.saturating_add(THREAD_EXTRA);
    // SAFETY: a fresh anonymous mapping at an address the kernel picks; nothing else refers to
    // it, it is never read or written, and it is unmapped with the length it was mapped with.
    unsafe {
        let p = mmap_anonymous(std::ptr::null_mut(), len, ProtFlags::READ | ProtFlags::WRITE, MapFlags::PRIVATE)?;
        munmap(p, len)?;
    }
    Ok(())
}
