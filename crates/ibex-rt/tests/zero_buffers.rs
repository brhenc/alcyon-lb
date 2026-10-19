// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (AGENTS.md rule 6): sets the process-wide `tune.ibex.zero-buffers` and reads the
// thread's buffer pool back, which any other test's buffers in a shared binary would disturb.

//! T437 part 5b: a buffer that goes back to its pool is zeroed up to its high-water mark, so
//! the next owner reads zeros where the plaintext of the last one was. With the setting off the
//! old bytes stay (which is what the setting is for).

use ibex_rt::buf::Buf;
use std::sync::Mutex;

/// The setting is process-wide: the two tests take turns.
static SETTING: Mutex<()> = Mutex::new(());

const SECRET: &[u8] = b"GET /secret-token-0123456789 HTTP/1.1\r\nAuthorization: Bearer hunter2\r\n\r\n";

fn leave_secret_and_reacquire(make: fn() -> Buf) -> Vec<u8> {
    let mut b = make();
    assert!(b.put(SECRET));
    b.consume(10);
    drop(b);
    // The pool is LIFO per thread: the next buffer is the one just given back.
    let b = make();
    assert!(b.is_empty());
    b.raw_slice().to_vec()
}

#[test]
fn released_buffers_read_back_zeros_when_the_setting_is_on_and_old_bytes_when_off() {
    let _turn = SETTING.lock().unwrap();
    ibex_rt::buf::init_buffer_sizes(16_384, 1_024, Some(65_536));
    for make in [Buf::standard as fn() -> Buf, Buf::small, Buf::large] {
        ibex_alloc::set_zero_buffers(true);
        let raw = leave_secret_and_reacquire(make);
        assert!(raw.iter().all(|&x| x == 0), "setting on: the secret is still in the pooled buffer");

        ibex_alloc::set_zero_buffers(false);
        let raw = leave_secret_and_reacquire(make);
        assert_eq!(&raw[..SECRET.len()], SECRET, "setting off: the old bytes are expected to remain");
    }
    ibex_alloc::set_zero_buffers(true);
}

#[test]
fn a_release_after_a_compaction_and_a_grow_leaves_nothing_behind() {
    let _turn = SETTING.lock().unwrap();
    ibex_rt::buf::init_buffer_sizes(16_384, 1_024, Some(65_536));
    ibex_alloc::set_zero_buffers(true);
    let mut b = Buf::standard();
    assert!(b.put(SECRET));
    b.consume(SECRET.len() - 4);
    b.compact(); // the stale tail of SECRET is past len now
    b.release();
    let b = Buf::standard();
    assert!(b.raw_slice().iter().all(|&x| x == 0));
    drop(b);

    // Zeroed through the raw slice too.
    let mut b = Buf::standard();
    b.raw_slice_mut()[8000..8004].copy_from_slice(b"KEEP");
    drop(b);
    let b = Buf::standard();
    assert!(b.raw_slice().iter().all(|&x| x == 0));
}

/// AGENTS.md 5: the keyword reaches the release path. `Engine::new` applies the global
/// setting (`engine.rs`, next to `set_trim_disabled`), and `Buf`'s `Drop` reads it through
/// `ibex_alloc::wipe`.
#[test]
fn the_configured_setting_reaches_the_buffer_release_path() {
    use ibex_config::ast::{Config, GlobalSection};
    use ibex_rt::engine::Engine;
    let _turn = SETTING.lock().unwrap();
    for (zero_buffers, expect_zeros) in [(Some(false), false), (None, true), (Some(true), true)] {
        let config = Config {
            global: Some(GlobalSection { zero_buffers, ..Default::default() }),
            ..Default::default()
        };
        let _engine = Engine::new(&config, 1024).expect("Engine::new");
        let raw = leave_secret_and_reacquire(Buf::standard);
        assert_eq!(raw.iter().all(|&x| x == 0), expect_zeros, "zero_buffers {zero_buffers:?}");
    }
    ibex_alloc::set_zero_buffers(true);
}

/// An HTX keeps its data at the front and its descriptors at the end of the memory: both
/// ends are zeroed on release, the untouched middle is not walked (the release of a 16 KB
/// buffer that wrote 300 bytes costs 300 bytes of stores, not 16 KB).
#[test]
fn an_htx_buffer_is_zeroed_at_both_ends_when_released() {
    let _turn = SETTING.lock().unwrap();
    ibex_alloc::set_zero_buffers(true);
    let mut b = Buf::standard();
    let cap = b.capacity();
    let raw = b.htx_slice_mut();
    raw[..6].copy_from_slice(b"secret");
    raw[cap - 5..].copy_from_slice(b"desc!");
    b.note_htx(6, 5);
    drop(b);
    let b = Buf::standard();
    assert!(b.raw_slice().iter().all(|&x| x == 0));
    drop(b);

    // Bytes written and never noted are not tracked: that is the contract of `note_htx`.
    let mut b = Buf::standard();
    b.htx_slice_mut()[100..104].copy_from_slice(b"lost");
    drop(b);
    let b = Buf::standard();
    assert_eq!(&b.raw_slice()[100..104], b"lost");
    ibex_alloc::set_zero_buffers(true);
}
