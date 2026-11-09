// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.quic.fe.max-idle-timeout`, `tune.quic.fe.stream.max-concurrent`,
//! `tune.quic.fe.stream.max-total` and `tune.quic.listen` (T525), and the `tune.quic.*`
//! keywords that stay refused.
//!
//! Measured with `haproxy -c` on the QUIC oracle (3.5-dev7-e6f616-55, src/cfgparse-quic.c):
//! - `max-idle-timeout`: `parse_time_err` in ms; `5s`, `1500`, `0`, `0s`, `1h`, `1us`,
//!   `2147483647` load; `abc` is "unexpected character 'a' in 'tune.quic.fe.max-idle-timeout'",
//!   `1x` the same with 'x', `-1` with '-', no argument with an empty quote; `2147483648` is
//!   "timer overflow in argument '2147483648' to 'tune.quic.fe.max-idle-timeout' (maximum value
//!   is 2147483647 ms or ~24.8 days)"; `5s 6s` is "cannot handle unexpected argument '6s'.".
//! - `stream.max-concurrent` and `stream.max-total`: `atoi` into an `unsigned int`, at least 1
//!   ("expects a positive integer."): `5`, `7x` (7), `-1` (4294967295), `4294967297` (1) load;
//!   `0`, `abc`, no argument fail; `5 6` is "cannot handle unexpected argument '6'.".
//! - `tune.quic.listen`: `on`/`off`; `maybe` and no argument are "'tune.quic.listen' expects
//!   'on' or 'off'."; `on off` is "cannot handle unexpected argument 'off'.".

use alcyon_config::parse_str;

fn global(line: &str) -> Result<alcyon_config::ast::GlobalSection, String> {
    parse_str(&format!("global\n  {line}\ndefaults\n  mode http\n"))
        .map(|c| c.global.expect("global"))
        .map_err(|e| e.to_string())
}

#[test]
fn max_idle_timeout_is_read_in_milliseconds() {
    for (v, ms) in [("5s", 5000), ("1500", 1500), ("0", 0), ("0s", 0), ("1h", 3_600_000), ("1us", 1), ("2147483647", 2_147_483_647)] {
        assert_eq!(global(&format!("tune.quic.fe.max-idle-timeout {v}")).map(|g| g.quic_max_idle_timeout), Ok(Some(ms)), "{v}");
    }
}

#[test]
fn max_idle_timeout_refusals_are_the_oracles() {
    for (v, msg) in [
        ("abc", "unexpected character 'a' in 'tune.quic.fe.max-idle-timeout'"),
        ("1x", "unexpected character 'x' in 'tune.quic.fe.max-idle-timeout'"),
        ("-1", "unexpected character '-' in 'tune.quic.fe.max-idle-timeout'"),
        (
            "2147483648",
            "timer overflow in argument '2147483648' to 'tune.quic.fe.max-idle-timeout' (maximum value is 2147483647 ms or ~24.8 days)",
        ),
        ("5s 6s", "'tune.quic.fe.max-idle-timeout' cannot handle unexpected argument '6s'."),
    ] {
        let e = global(&format!("tune.quic.fe.max-idle-timeout {v}")).unwrap_err();
        assert!(e.contains(msg), "{v}: {e}");
    }
    let e = global("tune.quic.fe.max-idle-timeout").unwrap_err();
    assert!(e.contains("unexpected character '") && e.contains("in 'tune.quic.fe.max-idle-timeout'"), "{e}");
}

#[test]
fn stream_limits_read_as_atoi_into_an_unsigned_int() {
    for (v, n) in [("5", 5), ("7x", 7), ("-1", 4_294_967_295), ("4294967297", 1)] {
        let g = global(&format!("tune.quic.fe.stream.max-concurrent {v}")).expect("max-concurrent");
        assert_eq!(g.quic_stream_max_concurrent, Some(n), "{v}");
        let g = global(&format!("tune.quic.fe.stream.max-total {v}")).expect("max-total");
        assert_eq!(g.quic_stream_max_total, Some(n), "{v}");
    }
}

#[test]
fn stream_limit_refusals_are_the_oracles() {
    for k in ["tune.quic.fe.stream.max-concurrent", "tune.quic.fe.stream.max-total"] {
        for v in ["", "0", "abc"] {
            let e = global(&format!("{k} {v}")).unwrap_err();
            assert!(e.contains(&format!("'{k}' expects a positive integer.")), "{k} {v:?}: {e}");
        }
        let e = global(&format!("{k} 5 6")).unwrap_err();
        assert!(e.contains(&format!("'{k}' cannot handle unexpected argument '6'.")), "{e}");
    }
}

#[test]
fn listen_is_on_or_off() {
    assert_eq!(global("tune.quic.listen off").map(|g| g.quic_listen), Ok(Some(false)));
    assert_eq!(global("tune.quic.listen on").map(|g| g.quic_listen), Ok(Some(true)));
    for v in ["maybe", ""] {
        let e = global(&format!("tune.quic.listen {v}")).unwrap_err();
        assert!(e.contains("'tune.quic.listen' expects 'on' or 'off'."), "{v:?}: {e}");
    }
    let e = global("tune.quic.listen on off").unwrap_err();
    assert!(e.contains("'tune.quic.listen' cannot handle unexpected argument 'off'."), "{e}");
}

#[test]
fn the_knobs_are_unset_by_default() {
    let g = global("maxconn 10").expect("parse");
    assert_eq!((g.quic_max_idle_timeout, g.quic_stream_max_concurrent, g.quic_stream_max_total, g.quic_listen), (None, None, None, None));
}

/// Every other `tune.quic.*` keyword of the oracle (src/cfgparse-quic.c) is refused, the
/// message naming it: Alcyon has no congestion-control, pacing, GSO, per-connection socket or
/// backend QUIC to give them. Listed in `docs/differences.md`.
#[test]
fn the_other_tune_quic_keywords_are_refused_by_name() {
    let kws = [
        "tune.quic.mem.tx-max 1m",
        "tune.quic.sec.stateless-reset-rate 5",
        "tune.quic.zero-copy-fwd-send on",
        "tune.quic.fe.cc.cubic-min-losses 2",
        "tune.quic.fe.cc.hystart on",
        "tune.quic.fe.cc.max-frame-loss 3",
        "tune.quic.fe.cc.max-win-size 1m",
        "tune.quic.fe.cc.reorder-ratio 50",
        "tune.quic.fe.sec.glitches-threshold 10",
        "tune.quic.fe.sock-per-conn default-on",
        "tune.quic.fe.stream.data-ratio 90",
        "tune.quic.fe.stream.rxbuf 1m",
        "tune.quic.fe.tx.pacing on",
        "tune.quic.fe.tx.udp-gso on",
        "tune.quic.be.cc.cubic-min-losses 2",
        "tune.quic.be.cc.hystart on",
        "tune.quic.be.cc.max-frame-loss 3",
        "tune.quic.be.cc.max-win-size 1m",
        "tune.quic.be.cc.reorder-ratio 50",
        "tune.quic.be.max-idle-timeout 5s",
        "tune.quic.be.sec.glitches-threshold 10",
        "tune.quic.be.stream.data-ratio 90",
        "tune.quic.be.stream.max-concurrent 10",
        "tune.quic.be.stream.rxbuf 1m",
        "tune.quic.be.tx.pacing on",
        "tune.quic.be.tx.udp-gso on",
    ];
    for line in kws {
        let name = line.split(' ').next().expect("name");
        let e = global(line).unwrap_err();
        assert!(e.contains(&format!("'{name}' is not supported by Alcyon")), "{line}: {e}");
    }
}

#[test]
fn the_quic_bind_keywords_that_do_nothing_stay_refused() {
    for kw in ["allow-0rtt", "quic-cc-algo cubic", "quic-socket connection"] {
        let cfg = format!("frontend f\n  mode http\n  bind quic4@127.0.0.1:4433 ssl crt /x.pem alpn h3 {kw}\n");
        let e = parse_str(&cfg).unwrap_err().to_string();
        assert!(e.contains(kw.split(' ').next().expect("kw")), "{kw}: {e}");
    }
}
