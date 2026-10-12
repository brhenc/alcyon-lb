// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.h2.{,fe.,be.}max-concurrent-streams` as `h2_parse_max_concurrent_streams`
//! (`mux_h2.c`) reads them, measured with `haproxy -c` on 3.5-dev8-885761-29 (T299): the
//! value is `atoi`'d (text is 0, 99999999999 wraps to 1215752191), a negative one (as an
//! `int`) is refused, 0 means "use the other level", and the global and `be.` keywords take
//! no further argument. The values reach the data path in `ibex-rt`
//! (`tests/it/h2_concurrent_streams.rs` drives them).

use ibex_config::parse_str;

fn global(line: &str) -> Result<(Option<u32>, Option<u32>), String> {
    let cfg = parse_str(&format!("global\n\t{line}\n")).map_err(|e| e.message)?;
    let g = cfg.global.expect("global");
    Ok((g.h2_max_concurrent_streams, g.h2_fe_max_concurrent_streams))
}

#[test]
fn the_global_and_frontend_values_are_kept() {
    assert_eq!(global("tune.h2.max-concurrent-streams 2"), Ok((Some(2), None)));
    assert_eq!(global("tune.h2.fe.max-concurrent-streams 7"), Ok((None, Some(7))));
    assert_eq!(global("tune.h2.max-concurrent-streams 0"), Ok((Some(0), None)));
}

#[test]
fn the_value_is_read_as_atoi_does() {
    assert_eq!(global("tune.h2.max-concurrent-streams abc"), Ok((Some(0), None)));
    assert_eq!(global("tune.h2.max-concurrent-streams"), Ok((Some(0), None)));
    assert_eq!(global("tune.h2.fe.max-concurrent-streams 12x"), Ok((None, Some(12))));
    assert_eq!(global("tune.h2.max-concurrent-streams 99999999999"), Ok((Some(1_215_752_191), None)));
}

/// A leading `+` is part of `atoi`; `haproxy -c` accepts `+5` and `+-5` (the latter is 0).
#[test]
fn a_leading_plus_is_read_as_atoi_does() {
    assert_eq!(global("tune.h2.max-concurrent-streams +5"), Ok((Some(5), None)));
    assert_eq!(global("tune.h2.fe.max-concurrent-streams +5"), Ok((None, Some(5))));
    assert_eq!(global("tune.h2.max-concurrent-streams +-5"), Ok((Some(0), None)));
}

#[test]
fn a_negative_value_is_refused() {
    for v in ["-1", "2147483648", "4294967295"] {
        for kw in ["tune.h2.max-concurrent-streams", "tune.h2.fe.max-concurrent-streams"] {
            let e = global(&format!("{kw} {v}")).unwrap_err();
            assert!(e.contains(&format!("'{kw}' expects a positive numeric value.")), "{kw} {v}: {e}");
        }
    }
}

#[test]
fn the_global_keyword_takes_one_argument() {
    let e = global("tune.h2.max-concurrent-streams 5 6").unwrap_err();
    assert!(e.contains("'tune.h2.max-concurrent-streams' cannot handle unexpected argument '6'."), "{e}");
}

#[test]
fn the_frontend_keyword_takes_rq_load_ignore_only() {
    assert_eq!(global("tune.h2.fe.max-concurrent-streams 5 rq-load ignore"), Ok((None, Some(5))));
    for (args, want) in [
        ("rq-load", "expects a strictly positive run-queue length, or 'auto' or 'ignore'."),
        ("rq-load 0", "expects a strictly positive run-queue length, or 'auto' or 'ignore'."),
        ("bogus", "only supports 'rq-load' or 'min' after the numeric value, but found 'bogus'."),
        ("min 0", "expects a strictly positive minimum number of streams'."),
        ("min 9", "minimum number of streams (9) cannot be higher than the maximum (5)'."),
        // Parsed by HAProxy, but a load-dependent limit Ibex does not compute (AGENTS.md 5).
        ("rq-load auto", "not supported"),
        ("rq-load 100", "not supported"),
        ("min 2", "not supported"),
    ] {
        let e = global(&format!("tune.h2.fe.max-concurrent-streams 5 {args}")).unwrap_err();
        assert!(e.contains(want), "{args}: {e}");
    }
}

#[test]
fn the_backend_keyword_is_refused_with_its_reason() {
    let e = global("tune.h2.be.max-concurrent-streams 3").unwrap_err();
    assert!(e.contains("'tune.h2.be.max-concurrent-streams' is not supported") && e.contains("HTTP/1.1"), "{e}");
}

/// `tune.h2.fe.rxbuf` as `h2_parse_rxbuf` reads it (`haproxy -c` 3.5-dev8-885761-29): a size
/// with an optional k, m or g, one argument; `abc` is "unexpected character 'a' in size
/// argument 'abc'". It reaches the data path as the connection's receive budget
/// (`H2MuxContext::rx_budget`, `ibex-proto`).
#[test]
fn the_frontend_rxbuf_is_a_size() {
    let rxbuf = |line: &str| parse_str(&format!("global\n\t{line}\n")).map(|c| c.global.expect("global").h2_fe_rxbuf).map_err(|e| e.message);
    assert_eq!(rxbuf("tune.h2.fe.rxbuf 8m"), Ok(Some(8 << 20)));
    assert_eq!(rxbuf("tune.h2.fe.rxbuf 1048576"), Ok(Some(1 << 20)));
    assert_eq!(rxbuf("tune.h2.fe.rxbuf 2k"), Ok(Some(2048)));
    assert_eq!(rxbuf("tune.h2.fe.rxbuf abc"), Err("'tune.h2.fe.rxbuf': unexpected character 'a' in size argument 'abc'.".to_string()));
    assert_eq!(rxbuf("tune.h2.fe.rxbuf 5 6"), Err("'tune.h2.fe.rxbuf' cannot handle unexpected argument '6'.".to_string()));
}
