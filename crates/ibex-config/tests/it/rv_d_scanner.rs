// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Config input that used to panic or be stored wrong (scanner candidates 34 and 39), with
//! `haproxy -c` (3.5-dev8-885761-29) as the oracle:
//!
//! * `tune.h2.fe.rxbuf` is a `parse_size_err` size held in 32 bits: `4g`, `4194304k`,
//!   `4096m`, `4294967296` and `99999999999` are refused naming the character where it
//!   overflows (`g`, `k`, `m`, `6`, `9`... the one that overflowed); `4294967295`, `3g` and
//!   `4095m` are accepted. Ibex saturated to `usize::MAX`, and `rx_budget` overflowed.
//! * `tcp-check send-binary "aéb"` / `"+f"`: "an hex digit is expected (found ...)". Ibex
//!   sliced a `str` inside a UTF-8 character (panic) and accepted `+f`.

use ibex_config::parse_str;

fn rxbuf(v: &str) -> Result<Option<usize>, String> {
    parse_str(&format!("global\n\ttune.h2.fe.rxbuf {v}\n")).map(|c| c.global.expect("global").h2_fe_rxbuf).map_err(|e| e.message)
}

#[test]
fn rxbuf_past_32_bits_is_refused() {
    assert_eq!(rxbuf("4294967295"), Ok(Some(4_294_967_295)));
    assert_eq!(rxbuf("3g"), Ok(Some(3 << 30)));
    assert_eq!(rxbuf("4095m"), Ok(Some(4095 << 20)));
    for (v, c) in [("4g", 'g'), ("4194304k", 'k'), ("4096m", 'm'), ("17179869184g", '4'), ("4294967296", '6'), ("100000000000", '0')] {
        let e = rxbuf(v).expect_err(v);
        assert_eq!(e, format!("'tune.h2.fe.rxbuf': unexpected character '{c}' in size argument '{v}'."), "{v}");
    }
}

fn send_binary(v: &str) -> Result<(), String> {
    let cfg = format!("listen l\n\tmode tcp\n\tbind 127.0.0.1:8080\n\toption tcp-check\n\ttcp-check send-binary \"{v}\"\n\tserver s 127.0.0.1:1\n");
    parse_str(&cfg).map(|_| ()).map_err(|e| e.message)
}

#[test]
fn send_binary_refuses_non_hex_without_panicking() {
    assert_eq!(send_binary("0aff"), Ok(()));
    for v in ["aéb", "éé", "+f", "-1", "zz"] {
        let e = send_binary(v).expect_err(v);
        assert!(e.contains("invalid binary string") || e.contains("hex"), "{v}: {e}");
    }
}

#[test]
fn rise_and_fall_past_i32_max_are_refused() {
    let cfg = |kw: &str, v: &str| format!("listen l\n\tmode tcp\n\tbind 127.0.0.1:8080\n\tserver s 127.0.0.1:1 check {kw} {v}\n");
    for kw in ["rise", "fall"] {
        assert!(parse_str(&cfg(kw, "2147483647")).is_ok(), "{kw}");
        let e = parse_str(&cfg(kw, "2147483648")).expect_err(kw).message;
        assert!(e.contains(&format!("'{kw}' has to be > 0")), "{e}");
    }
}

/// VV-33: `rise 0` / `fall 0` are refused, on a server and on `default-server`, as HAProxy
/// 3.5-dev8 refuses them ("'rise' has to be > 0.").
#[test]
fn rise_and_fall_zero_are_refused() {
    for line in ["server s 127.0.0.1:1 check", "default-server"] {
        for kw in ["rise", "fall"] {
            let cfg = format!("listen l\n\tmode tcp\n\tbind 127.0.0.1:8080\n\t{line} {kw} 0\n\tserver t 127.0.0.1:2\n");
            let e = parse_str(&cfg).expect_err(kw).message;
            assert!(e.contains(&format!("'{kw}' has to be > 0")), "{line} {kw}: {e}");
            assert!(parse_str(&cfg.replace(&format!("{kw} 0"), &format!("{kw} 1"))).is_ok(), "{line} {kw} 1");
        }
    }
}
