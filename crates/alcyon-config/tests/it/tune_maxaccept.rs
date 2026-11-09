// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.maxaccept` (T295 item 2): how many connections a listener wakeup accepts in a
//! row before the thread goes back to its other work.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29 (`haproxy -c`) on 2026-10-11
//! (`src/cfgparse-global.c`): `4` and `-1` load; `0` loads and means the default; `-5`
//! loads (`max < -1` is commented out); `abc` loads (`atol`, so it is 0: the default);
//! `99999999999` fails ("expects -1 or an integer from 0 to INT_MAX"); no argument fails;
//! a second `tune.maxaccept` warns "already specified. Continuing." and the first stays.

use alcyon_config::parse_str;

fn with(v: &str) -> Result<Option<i32>, String> {
    parse_str(&format!("global\n  tune.maxaccept {v}\ndefaults\n  mode http\n"))
        .map(|c| c.global.and_then(|g| g.maxaccept))
        .map_err(|e| e.to_string())
}

#[test]
fn an_integer_and_minus_one_load() {
    assert_eq!(with("4"), Ok(Some(4)));
    assert_eq!(with("-1"), Ok(Some(-1)));
    assert_eq!(with("-5"), Ok(Some(-5)), "HAProxy comments the `max < -1` check out");
}

#[test]
fn zero_and_a_non_number_are_the_default() {
    assert_eq!(with("0"), Ok(Some(0)));
    assert_eq!(with("abc"), Ok(Some(0)), "atol");
}

#[test]
fn over_int_max_and_no_argument_are_refused() {
    let e = with("99999999999").unwrap_err();
    assert!(e.contains("'tune.maxaccept' expects -1 or an integer from 0 to INT_MAX"), "{e}");
    let e = parse_str("global\n  tune.maxaccept\ndefaults\n  mode http\n").unwrap_err().to_string();
    assert!(e.contains("'tune.maxaccept' expects an integer argument"), "{e}");
}

#[test]
fn a_second_one_keeps_the_first() {
    let c = parse_str("global\n  tune.maxaccept 4\n  tune.maxaccept 8\ndefaults\n  mode http\n").expect("loads");
    assert_eq!(c.global.and_then(|g| g.maxaccept), Some(4));
}
