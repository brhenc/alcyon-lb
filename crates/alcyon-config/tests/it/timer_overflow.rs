// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A timer over 2^31-1 ms is refused at load (T240 item 1). HAProxy keeps timers in a
//! signed 32-bit tick, so `parse_time_err` reports `PARSE_TIME_OVER` and every keyword
//! refuses the line. Alcyon used to accept `25d`, and the tick wrapped: `timeout client 25d`
//! answered 408 at once, `inter 25d` marked every server DOWN. The texts are those of
//! `haproxy -c` (3.5-dev8), less the `parsing [file:line] :` prefix.

use alcyon_config::parse_str;

const LIMIT: &str = "(maximum value is 2147483647 ms or ~24.8 days)";

fn refusal(cfg: &str) -> String {
    match parse_str(cfg) {
        Ok(_) => panic!("accepted:\n{cfg}"),
        Err(e) => e.message,
    }
}

#[test]
fn the_largest_tick_is_accepted_and_one_more_is_refused() {
    assert!(parse_str("defaults\n timeout client 2147483647\n").is_ok());
    assert_eq!(
        refusal("defaults\n timeout client 2147483648\n"),
        format!("timer overflow in argument '2147483648' to 'timeout client' {LIMIT}")
    );
}

#[test]
fn proxy_timeouts_refuse_an_overflow() {
    for (kw, arg) in [("client", "25d"), ("server", "25d"), ("connect", "597h"), ("client-fin", "25d"),
                      ("http-request", "99999999999999999999"), ("tunnel", "35792m")] {
        assert_eq!(
            refusal(&format!("defaults\n timeout {kw} {arg}\n")),
            format!("timer overflow in argument '{arg}' to 'timeout {kw}' {LIMIT}"),
        );
    }
}

#[test]
fn global_timers_refuse_an_overflow() {
    for kw in ["stats timeout", "hard-stop-after"] {
        assert_eq!(
            refusal(&format!("global\n {kw} 25d\n")),
            format!("timer overflow in argument '25d' to '{kw}' {LIMIT}"),
        );
    }
}

#[test]
fn server_delays_refuse_an_overflow() {
    for (kw, what) in [("inter", "timer overflow"), ("fastinter", "timer overflow"), ("downinter", "timer overflow"),
                       ("idle-ping", "timer overflow"), ("agent-inter", "timer overflow"), ("slowstart", "overflow")] {
        let m = refusal(&format!("listen l\n bind :1\n server s 127.0.0.1:1 check {kw} 25d\n"));
        assert!(
            m.ends_with(&format!(
                "' : {what} in argument <25d> to <{kw}> of server s, maximum value is 2147483647 ms (~24.8 days).."
            )),
            "{m}"
        );
        let m = refusal(&format!("listen l\n bind :1\n default-server {kw} 25d\n"));
        assert_eq!(
            m,
            format!("{what} in argument <25d> to <{kw}> of server (null), maximum value is 2147483647 ms (~24.8 days)..")
        );
    }
    let m = refusal("listen l\n bind :1\n server s 127.0.0.1:1 tcp-ut 25d\n");
    assert!(m.ends_with(&format!("' : timer overflow in argument '25d' to 'tcp-ut' {LIMIT}.")), "{m}");
}

#[test]
fn inspect_delays_refuse_an_overflow() {
    for dir in ["request", "response"] {
        assert_eq!(
            refusal(&format!("listen l\n bind :1\n tcp-{dir} inspect-delay 25d\n")),
            format!(
                "'tcp-{dir} inspect-delay' expects a positive delay in milliseconds, in proxy 'l' \
                 (timer overflow in '25d', maximum value is 2147483647 ms or ~24.8 days)"
            )
        );
    }
}

#[test]
fn other_timers_refuse_an_overflow() {
    assert_eq!(
        refusal("backend b\n stick-table type ip size 1k expire 25d\n"),
        "stick-table: timer overflow in argument <25d> to <expire>, maximum value is 2147483647 ms (~24.8 days)."
    );
    assert_eq!(
        refusal("listen l\n bind 127.0.0.1:18001 tcp-ut 25d\n"),
        format!("timer overflow in argument '25d' to 'tcp-ut' {LIMIT}")
    );
    assert_eq!(
        refusal("ring r\n size 32768\n timeout connect 25d\n server s 127.0.0.1:1\n"),
        "timer overflow in argument <25d> to <timeout connect>, maximum value is 2147483647 ms (~24.8 days)."
    );
    assert_eq!(
        refusal("log-forward lf\n bind 127.0.0.1:18002\n timeout client 25d\n"),
        format!("timeout : timer overflow in argument '25d' to 'timeout client' {LIMIT}")
    );
}

#[test]
fn the_values_just_under_the_limit_are_accepted() {
    // 596h is 2145600000 ms and 35791m 2147460000 ms: both fit.
    assert!(parse_str("defaults\n timeout connect 596h\n timeout tunnel 35791m\n").is_ok());
}
