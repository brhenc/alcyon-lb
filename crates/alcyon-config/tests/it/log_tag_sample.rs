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
fn log_profile_on_a_log_line_parses_and_requires_a_name() {
    let cfg = parse_str(
        "log-profile p\n  on accept drop\nfrontend f\n  log 127.0.0.1:514 profile p local0\n",
    )
    .expect("log profile should parse");
    assert_eq!(cfg.frontends[0].logs[0].profile.as_deref(), Some("p"));

    let err = parse_str("frontend f\n  log 127.0.0.1:514 profile\n")
        .expect_err("profile without a name must not parse");
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

#[test]
fn log_profile_and_log_steps_errors_and_overrides_are_handled() {
    let ok = parse_str(
        "log-profile p\n\
           log-tag pt\n\
           on accept drop\n\
           on accept format %o\n\
         frontend f\n\
           log-steps accept,,connect\n\
           log 127.0.0.1:514 profile p local0\n",
    )
    .expect("valid log-profile redefinition and trailing/empty log-steps");
    assert_eq!(ok.log_profiles[0].log_tag.as_deref(), Some("pt"));
    assert_eq!(ok.log_profiles[0].steps.len(), 1);
    assert!(!ok.log_profiles[0].steps[0].drop);
    assert_eq!(ok.log_profiles[0].steps[0].format.as_deref(), Some("%o"));

    for bad in [
        "log-profile\n",
        "log-profile bad$name\n",
        "log-profile p\n  log-tag\n",
        "log-profile p\n  bogus\n",
        "log-profile p\n  on\n",
        "log-profile p\n  on accept\n",
        "log-profile p\n  on accept bogus\n",
        "log-profile p\n  on accept format %o drop\n",
        "log-profile p\n  on accept format\n",
        "log-profile p\n  on accept sd\n",
        "frontend f\n  log-steps\n",
        "frontend f\n  log-steps bogus\n",
        "frontend f\n  log 127.0.0.1:514\n",
        "frontend f\n  log 127.0.0.1:514 profile p\n",
    ] {
        assert!(parse_str(bad).is_err(), "expected error for:\n{bad}");
    }
}

/// Every `log-steps` name the reference (3.5-dev11-ce79f339c, 2026-11-21) accepts on a
/// frontend: the five that select a step set their bit, the rule-set names are accepted and
/// select nothing, `all` is every step. On a backend `HAProxy` accepts the keyword and warns
/// that it is ignored (no frontend capability).
#[test]
fn log_steps_names_and_backend_keyword() {
    use alcyon_config::ast::{LOG_STEP_ACCEPT, LOG_STEP_ALL, LOG_STEP_CLOSE, LOG_STEP_CONNECT, LOG_STEP_REQUEST, LOG_STEP_RESPONSE};
    let fe = |steps: &str| {
        parse_str(&format!("frontend f\n  log-steps {steps}\n")).expect(steps).frontends[0].log_steps
    };
    assert_eq!(fe("accept,request,connect,response,close"),
               Some(LOG_STEP_ACCEPT | LOG_STEP_REQUEST | LOG_STEP_CONNECT | LOG_STEP_RESPONSE | LOG_STEP_CLOSE));
    assert_eq!(fe("request"), Some(LOG_STEP_REQUEST));
    assert_eq!(fe("response"), Some(LOG_STEP_RESPONSE));
    assert_eq!(fe("http-req,http-res,http-after-res,tcp-req-conn,tcp-req-sess,tcp-req-cont,tcp-res-cont"), Some(0));
    assert_eq!(fe("all"), Some(LOG_STEP_ALL));
    let be = parse_str("backend b\n  log-steps request,response\n").expect("log-steps on a backend");
    assert_eq!(be.backends[0].log_steps, Some(LOG_STEP_REQUEST | LOG_STEP_RESPONSE));
}
