// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `cookie` line as `cfg_parse_listen` (`src/cfgparse-listen.c`) reads it. Its
//! refusals and warnings are measured on `HAProxy 3.5-dev8-885761-29` in
//! `crates/ibex-rt/tests/cookie_persistence.rs`; what is read is here.

use ibex_config::{parse_str, CookieConfig};

fn backend_cookie(line: &str) -> CookieConfig {
    let cfg = parse_str(&format!("backend b\n  {line}\n  server s 127.0.0.1:8001\n")).expect("parse");
    cfg.backends[0].cookie.clone().expect("a cookie")
}

/// `maxidle` and `maxlife` are `parse_time_err(.., TIME_UNIT_S)`: a unit, rounded up to
/// a whole second (`src/tools.c`).
#[test]
fn maxidle_and_maxlife_are_seconds_rounded_up() {
    for (text, secs) in [("90", 90), ("90s", 90), ("2m", 120), ("1h", 3600), ("1d", 86400), ("1500ms", 2), ("1us", 1), ("2000ms", 2)] {
        let c = backend_cookie(&format!("cookie S insert maxidle {text} maxlife {text}"));
        assert_eq!((c.maxidle, c.maxlife), (secs, secs), "{text}");
    }
}

#[test]
fn every_option_is_read_and_the_last_line_replaces_the_one_before() {
    let c = backend_cookie("cookie SRV insert indirect nocache postonly httponly secure domain .a.com domain .b.org attr SameSite=Lax attr Foo");
    assert_eq!(c.name, "SRV");
    assert!(c.insert && c.indirect && c.nocache && c.postonly && c.httponly && c.secure);
    assert!(!c.rewrite && !c.prefix && !c.preserve);
    assert_eq!(c.domain.as_deref(), Some(".a.com; domain=.b.org"));
    assert_eq!(c.attrs.as_deref(), Some("SameSite=Lax; Foo"));

    let c = backend_cookie("cookie A insert\n  cookie B rewrite");
    assert_eq!((c.name.as_str(), c.insert, c.rewrite), ("B", false, true));
    let c = backend_cookie("cookie B prefix");
    assert!(c.prefix);
    let c = backend_cookie("cookie B insert preserve");
    assert!(c.preserve);
}

#[test]
fn a_backend_inherits_the_defaults_cookie_and_a_frontend_has_none() {
    let cfg = parse_str(
        "defaults\n  cookie D insert\n\
         backend b1\n  server s 127.0.0.1:8001\n\
         backend b2\n  cookie O rewrite\n  server s 127.0.0.1:8001\n\
         frontend f\n  bind 127.0.0.1:8080\n  cookie F insert\n  default_backend b1\n",
    )
    .expect("parse");
    assert_eq!(cfg.backends[0].cookie.as_ref().map(|c| c.name.as_str()), Some("D"));
    assert_eq!(cfg.backends[1].cookie.as_ref().map(|c| (c.name.as_str(), c.rewrite)), Some(("O", true)));
    assert!(cfg.frontends[0].default_backend.is_some());
}
