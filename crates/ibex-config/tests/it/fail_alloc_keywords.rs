// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.fail-alloc`, `tune.buffers.limit`, `tune.buffers.reserve` (memory slice S5), read as
//! `HAProxy`'s `mem_parse_global_fail_alloc` (src/pool.c) and `cfg_parse_tune_buffers_limit` /
//! `_reserve` (src/dynbuf.c) read them. Measured on 3.5-dev8-885761-29 (`haproxy -c`):
//! `tune.fail-alloc 101` gives "'tune.fail-alloc' expects a numeric value between 0 and 100.",
//! `abc` and a missing value are 0, a second argument "cannot handle unexpected argument";
//! `tune.buffers.limit -1` gives "'tune.buffers.limit' expects a non-negative number but got
//! '-1'.", and a limit of 1 or 2 is 3. `tune.buffers.reserve` is read the same way (S6b).

use ibex_config::parse_str;

fn global(line: &str) -> ibex_config::ast::GlobalSection {
    parse_str(&format!("global\n  {line}\n")).expect("accepted").global.expect("global")
}

fn refused(line: &str) -> String {
    parse_str(&format!("global\n  {line}\n")).expect_err(line).message
}

#[test]
fn fail_alloc_is_a_percentage_read_as_atoi() {
    assert_eq!(global("tune.fail-alloc 5").fail_alloc, Some(5));
    assert_eq!(global("tune.fail-alloc 100").fail_alloc, Some(100));
    assert_eq!(global("tune.fail-alloc abc").fail_alloc, Some(0));
    assert_eq!(global("tune.fail-alloc").fail_alloc, Some(0));
    assert_eq!(global("maxconn 10").fail_alloc, None);
    for v in ["101", "-1"] {
        assert_eq!(refused(&format!("tune.fail-alloc {v}")), "'tune.fail-alloc' expects a numeric value between 0 and 100.");
    }
    assert_eq!(refused("tune.fail-alloc 5 6"), "'tune.fail-alloc' cannot handle unexpected argument '6'.");
}

#[test]
fn buffers_limit_is_at_least_three_and_reserve_is_checked() {
    assert_eq!(global("tune.buffers.limit 10").buffers_limit, Some(10));
    assert_eq!(global("tune.buffers.limit 1").buffers_limit, Some(3));
    assert_eq!(global("tune.buffers.limit 0").buffers_limit, Some(0));
    assert_eq!(global("maxconn 10").buffers_limit, None);
    assert_eq!(refused("tune.buffers.limit -1"), "'tune.buffers.limit' expects a non-negative number but got '-1'.");
    assert_eq!(refused("tune.buffers.limit 1 2"), "'tune.buffers.limit' cannot handle unexpected argument '2'.");
    assert_eq!(refused("tune.buffers.reserve -2"), "'tune.buffers.reserve' expects a non-negative number but got '-2'.");
    assert_eq!(refused("tune.buffers.reserve 1 2"), "'tune.buffers.reserve' cannot handle unexpected argument '2'.");
}

/// S6b: `tune.buffers.reserve` is read (`atoi`, >= 0) since the emergency buffers reach the take
/// path (`ibex_rt::buf::set_buffers_reserve`).
#[test]
fn buffers_reserve_is_read() {
    assert_eq!(global("tune.buffers.reserve 2").buffers_reserve, Some(2));
    assert_eq!(global("tune.buffers.reserve 0").buffers_reserve, Some(0));
    assert_eq!(global("maxconn 10").buffers_reserve, None);
}
