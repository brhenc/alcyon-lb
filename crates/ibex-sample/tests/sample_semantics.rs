// SPDX-License-Identifier: GPL-2.0-or-later

//! Properties of the sample lattice that the tcp-request work changed without a test.
//!
//! Each test here describes behaviour `HAProxy` guarantees and Ibex currently does not.
//! They are expected to fail until the corresponding defect is fixed. Making one pass by
//! weakening its assertion removes the only record that the defect existed -- fix the
//! code, not the test.

use std::collections::HashSet;

use ibex_sample::{Matcher, Registry, Sample, SampleContext};

/// A NUL inside a string sample must not turn one match into several.
///
/// `Matcher::Str` was changed to `s.split('\0').any(...)` so that `fc_pp_tlv`, which
/// joins repeated PROXY-protocol TLVs with a NUL byte, could be matched with `-m str`.
/// That delimiter is now honoured for *every* string sample, including ones built from
/// client-controlled bytes: a header, path or query value carrying a NUL matches if any
/// NUL-separated piece of it matches. An ACL written to allow exactly `admin` also
/// allows `notadmin\0admin`, and one written to deny exactly `admin` is evaded by
/// `admin\0`.
///
/// Multiple values are a property of the sample, not of the bytes in it. A fetch that
/// can return several values needs a representation that says so; the matcher must not
/// have to guess from a delimiter that appears in untrusted input.
#[test]
fn a_nul_byte_does_not_split_a_string_match() {
    let m = Matcher::compile("str", "admin").expect("compile -m str");

    assert!(m.matches(&Sample::Str("admin".into())), "the plain value must match");
    assert!(
        !m.matches(&Sample::Str("notadmin".into())),
        "a different value must not match"
    );

    // Smuggling the wanted value in behind a NUL.
    assert!(
        !m.matches(&Sample::Str("notadmin\u{0}admin".into())),
        "a NUL-embedded value matched `-m str admin`: any ACL over a client-controlled \
         string is bypassable by embedding a NUL"
    );
    // Hiding the unwanted value behind one.
    assert!(
        !m.matches(&Sample::Str("admin\u{0}x".into())),
        "`admin\\0x` matched `-m str admin`, so a deny rule is evaded by appending a NUL"
    );

    let ci = Matcher::compile_with_flags("str", "admin", true).expect("compile -m str -i");
    assert!(ci.matches(&Sample::Str("ADMIN".into())), "-i must still fold case");
    assert!(
        !ci.matches(&Sample::Str("x\u{0}ADMIN".into())),
        "the case-insensitive path splits on NUL too"
    );
}

/// `uuid` must be unpredictable, not a clock reading wearing version-4 bits.
///
/// The current implementation is `SystemTime::now()` nanoseconds in the low half and the
/// bitwise complement of the same number in the high half. For any present-day timestamp
/// the top eight bytes of a `u128` are zero, so their complement is a constant `0xFF`
/// run: bytes 8..16 never vary except where the variant nibble is stamped in. Two calls
/// inside one clock tick return the same value. `HAProxy` draws these from
/// `ha_random64()`; a request identifier that can be predicted or replayed is worse than
/// none, because downstream systems trust it to be unique.
#[test]
fn uuid_is_not_a_predictable_counter() {
    let reg = Registry::new();
    let ctx = SampleContext::default();
    let f = reg.get_fetch("uuid").expect("uuid fetch is registered");

    let mut seen = HashSet::new();
    let mut samples = Vec::new();
    for _ in 0..256 {
        let Some(Sample::Str(s)) = (f.func)(&ctx, &[]) else {
            panic!("uuid returned a non-string sample");
        };
        seen.insert(s.clone());
        samples.push(s);
    }

    // The decisive one. Characters 19.. are the clock-sequence and node fields, which
    // come from `(!now).to_be_bytes()[..8]` -- the *high* eight bytes of a `u128` holding
    // a nanosecond count, which are zero, so their complement never changes. Half the
    // identifier is a literal constant, and no amount of clock resolution fixes that.
    let tail = |s: &String| s[19..].to_string();
    let tails: HashSet<String> = samples.iter().map(tail).collect();
    assert!(
        tails.len() > 1,
        "the last 17 characters of every uuid are identical ({:?}); bytes 8..15 are the \
         complement of the high half of a nanosecond timestamp, which is always zero, so \
         64 bits of the identifier carry no entropy at all",
        tail(&samples[0])
    );

    // Every hex position that is not fixed by the UUID grammar must actually vary.
    // Positions 8, 13, 18 and 23 are the hyphens and 14 is the version nibble.
    let fixed_by_grammar = |i: usize| matches!(i, 8 | 13 | 14 | 18 | 23);
    let first = samples[0].as_bytes();
    for (i, b) in first.iter().enumerate() {
        if fixed_by_grammar(i) {
            continue;
        }
        let varies = samples.iter().any(|s| s.as_bytes()[i] != *b);
        assert!(
            varies,
            "character {i} is the same in all {} draws ({:?}): the value is a clock \
             reading, not a random number, so its bytes move only as fast as the clock",
            samples.len(),
            samples[0]
        );
    }

    // Uniqueness is the weakest of the three properties -- a fine-grained clock can carry
    // it on a fast machine -- but a collision here is unambiguous.
    assert_eq!(
        seen.len(),
        samples.len(),
        "uuid repeated a value within {} calls: any two calls inside one clock tick \
         collide",
        samples.len()
    );
}

/// The `proc.` scope is process-wide, so it must survive crossing a thread.
///
/// `GLOBAL_PROC_VARS` is declared `thread_local!`. `init_global_vars` fills it on the
/// startup thread and the runtime socket's `set var` fills it on whichever thread serves
/// the CLI, so no worker ever observes either. Nothing fails loudly: `get var` on the
/// writing thread reports success, and a single-threaded test suite cannot tell the
/// difference. This is the same defect as the two `CURRENT_VARS` thread-locals, in the
/// shape that hides best.
#[test]
fn proc_scope_variables_are_visible_from_another_thread() {
    ibex_sample::set_proc_var("proc.crossthread", "set-on-the-main-thread".to_string());
    assert_eq!(
        ibex_sample::get_proc_var("proc.crossthread").as_deref(),
        Some("set-on-the-main-thread"),
        "the writing thread cannot read its own write"
    );

    let seen = std::thread::spawn(|| ibex_sample::get_proc_var("proc.crossthread"))
        .join()
        .expect("reader thread");

    assert_eq!(
        seen.as_deref(),
        Some("set-on-the-main-thread"),
        "a `proc.` variable set on one thread is invisible on another: the scope is \
         backed by a thread-local, so `set var` over the runtime socket and `set-var` in \
         the global section never reach the workers"
    );

    // And a write from a worker must be visible back on the main thread, which is what
    // `tcp-request ... set-var(proc.x)` depends on.
    std::thread::spawn(|| {
        ibex_sample::set_proc_var("proc.fromworker", "set-on-a-worker".to_string());
    })
    .join()
    .expect("writer thread");

    assert_eq!(
        ibex_sample::get_proc_var("proc.fromworker").as_deref(),
        Some("set-on-a-worker"),
        "a `proc.` variable set on a worker thread is invisible elsewhere"
    );
}
