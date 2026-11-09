// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `log-tag` and `log ... sample <ranges>:<size>`, as the reference `HAProxy`
//! (3.5-dev7-e6f616-55) accepts and refuses them with `haproxy -c`, measured 2026-10-02.
//! The parsing it mirrors is `get_logger_smp_range` and the `sample` arm of
//! `parse_logger` in `src/log.c`.

use alcyon_config::parse_str;

fn with_sample(spec: &str) -> Result<alcyon_config::Config, alcyon_config::ConfigError> {
    parse_str(&format!(
        "frontend f\n  mode http\n  bind 127.0.0.1:8080\n  log 127.0.0.1:514 sample {spec} local0\n"
    ))
}

#[test]
fn haproxy_accepts_these_samples() {
    for spec in ["1,3:5", "3,1:5", "1-2,4:5", "1:1", "1,:5"] {
        let cfg = with_sample(spec).unwrap_or_else(|e| panic!("HAProxy accepts {spec}: {e}"));
        let sample = cfg.frontends[0].logs[0].sample.as_ref().expect("sample kept");
        assert!(sample.size >= 1, "{spec}");
    }
    let cfg = with_sample("3,1-2:7").expect("parse");
    let s = cfg.frontends[0].logs[0].sample.as_ref().expect("sample");
    assert_eq!(s.size, 7);
    // Sorted, as HAProxy qsorts them: the selection walks the ranges in order.
    assert_eq!(s.ranges, vec![1..=2, 3..=3]);
}

#[test]
fn haproxy_refuses_these_samples() {
    for (spec, why) in [
        ("1-3,2:5", "ranges are overlapping"),
        ("1,3:2", "size below the highest range bound"),
        ("1,3:0", "a size of 0"),
        ("1,3", "missing sample size"),
        ("0:5", "a range starting at 0"),
        ("3-1:5", "a reversed range"),
        ("2-2:5", "a range whose high equals its low"),
        ("1,3:5x", "a size with trailing garbage"),
        (":5", "no ranges"),
        (",1:5", "an empty range before the first"),
        ("1,,3:5", "an empty range between two"),
    ] {
        assert!(with_sample(spec).is_err(), "HAProxy refuses {spec} ({why}); Alcyon accepted it");
    }
}

#[test]
fn log_profile_is_refused_until_it_is_implemented() {
    let err = parse_str("frontend f\n  log 127.0.0.1:514 profile p local0\n")
        .expect_err("profile is not implemented, so it must not parse");
    assert!(err.message.contains("profile"), "{}", err.message);
}

#[test]
fn log_tag_is_read_in_every_section_and_inherited_from_defaults() {
    let cfg = parse_str(
        "global\n  log-tag g\n\
         defaults\n  log-tag d\n\
         frontend f\n  bind 127.0.0.1:8080\n\
         backend b\n  log-tag own\n\
         listen l\n  bind 127.0.0.1:8081\n  log-tag lst\n",
    )
    .expect("parse");
    assert_eq!(cfg.global.as_ref().and_then(|g| g.log_tag.as_deref()), Some("g"));
    assert_eq!(cfg.frontends[0].log_tag.as_deref(), Some("d"));
    assert_eq!(cfg.backends[0].log_tag.as_deref(), Some("own"));
    assert_eq!(cfg.listens[0].log_tag.as_deref(), Some("lst"));
}

#[test]
fn log_tag_without_a_value_is_refused() {
    assert!(parse_str("global\n  log-tag\n").is_err());
    assert!(parse_str("frontend f\n  log-tag\n").is_err());
    assert!(parse_str("global\n  log-tag \"\"\n").is_err());
    assert!(parse_str("frontend f\n  log-tag \"\"\n").is_err());
    // `alertif_too_many_args(1, ...)` in the global section only.
    assert!(parse_str("global\n  log-tag a b\n").is_err());
}

#[test]
fn a_udp_prefixed_log_target_is_the_plain_address() {
    let cfg = parse_str("frontend f\n  log udp@127.0.0.1:1514 local0\n").expect("HAProxy accepts udp@");
    assert_eq!(
        cfg.frontends[0].logs[0].target,
        alcyon_config::LogTarget::Udp("127.0.0.1:1514".parse().expect("addr"))
    );
}
