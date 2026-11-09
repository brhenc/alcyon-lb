// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.alcyon.quic-ack-frequency off|on`, `-threshold <n>` and `-max-delay <time>` (Q0,
//! Alcyon-only): whether the server asks a QUIC peer to acknowledge less often. `HAProxy` refuses
//! them as unknown.

use alcyon_config::parse_str;

fn global(text: &str) -> alcyon_config::GlobalSection {
    parse_str(&format!("global\n{text}")).expect("accepted").global.expect("global")
}

#[test]
fn unset_is_off_with_no_overrides() {
    let g = global("  nbthread 1\n");
    assert_eq!(g.quic_ack_frequency, None);
    assert_eq!(g.quic_ack_frequency_threshold, None);
    assert_eq!(g.quic_ack_frequency_max_delay_ms, None);
}

#[test]
fn the_three_keywords_are_kept() {
    let g = global("  tune.alcyon.quic-ack-frequency on\n  tune.alcyon.quic-ack-frequency-threshold 4\n  tune.alcyon.quic-ack-frequency-max-delay 40ms\n");
    assert_eq!(g.quic_ack_frequency, Some(true));
    assert_eq!(g.quic_ack_frequency_threshold, Some(4));
    assert_eq!(g.quic_ack_frequency_max_delay_ms, Some(40));
    assert_eq!(global("  tune.alcyon.quic-ack-frequency off\n").quic_ack_frequency, Some(false));
    assert_eq!(global("  tune.alcyon.quic-ack-frequency-threshold 0\n").quic_ack_frequency_threshold, Some(0));
    assert_eq!(global("  tune.alcyon.quic-ack-frequency-max-delay 1s\n").quic_ack_frequency_max_delay_ms, Some(1000));
}

#[test]
fn bad_values_are_refused_with_a_message() {
    for (text, want) in [
        ("tune.alcyon.quic-ack-frequency\n", "expects 'on' or 'off'"),
        ("tune.alcyon.quic-ack-frequency auto\n", "expects 'on' or 'off', got 'auto'"),
        ("tune.alcyon.quic-ack-frequency on now\n", "cannot handle unexpected argument 'now'"),
        ("tune.alcyon.quic-ack-frequency-threshold\n", "expects an integer from 0 to 255"),
        ("tune.alcyon.quic-ack-frequency-threshold 2 3\n", "cannot handle unexpected argument '3'"),
        ("tune.alcyon.quic-ack-frequency-max-delay 25ms 30ms\n", "cannot handle unexpected argument '30ms'"),
        ("tune.alcyon.quic-ack-frequency-threshold -1\n", "expects an integer from 0 to 255"),
        ("tune.alcyon.quic-ack-frequency-threshold 256\n", "expects an integer from 0 to 255"),
        ("tune.alcyon.quic-ack-frequency-threshold two\n", "expects an integer from 0 to 255"),
        ("tune.alcyon.quic-ack-frequency-max-delay 0\n", "expects a time from 1ms to 16383ms"),
        ("tune.alcyon.quic-ack-frequency-max-delay 20s\n", "expects a time from 1ms to 16383ms"),
        ("tune.alcyon.quic-ack-frequency-max-delay fast\n", "expects a time from 1ms to 16383ms"),
        ("tune.alcyon.quic-ack-frequency-max-delay\n", "expects a time from 1ms to 16383ms"),
    ] {
        let e = parse_str(&format!("global\n  {text}")).expect_err(text).to_string();
        assert!(e.contains(want), "{text:?}: {e}");
    }
}
