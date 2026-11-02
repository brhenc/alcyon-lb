// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `parse_h1` on input that ends before the start line does (T611 / #2): `h1.c` writes `*slp`
//! only once the start line is parsed, so the safe view of it must not be built from
//! stack leftovers.

use ibex_h1_sys::{parse_h1, SafeSl};
use std::hint::black_box;

#[inline(never)]
fn dirty_the_stack() {
    let a = [0xAAu8; 8192];
    black_box(&a);
}

#[test]
fn an_incomplete_start_line_gives_an_empty_view() {
    for is_response in [false, true] {
        dirty_the_stack();
        let mut input = b"GET /x HT".to_vec();
        let r = parse_h1(&mut input, 8, is_response);
        assert_eq!(r.ret, 0, "incomplete head");
        match r.sl {
            SafeSl::Request(rq) => assert!(rq.m.is_empty() && rq.u.is_empty() && rq.v.is_empty()),
            SafeSl::Response(st) => assert!(st.v.is_empty() && st.c.is_empty() && st.r.is_empty()),
        }
    }
}
