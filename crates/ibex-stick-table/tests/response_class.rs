// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Which statuses `count_response_class` counts: `http-err-codes` (400 to 499) as errors,
//! `http-fail-codes` (500 to 599 but 501 and 505) as failures, and nothing else.

use ibex_stick_table::StickEntryData;

fn counted(status: u16) -> (u64, u64) {
    let mut e = StickEntryData::default();
    e.count_response_class(status);
    (e.http_err_cnt, e.http_fail_cnt)
}

#[test]
fn only_the_error_and_failure_classes_are_counted() {
    for status in [100, 200, 204, 301, 304, 399, 501, 505, 600] {
        assert_eq!(counted(status), (0, 0), "status {status}");
    }
    for status in [400, 404, 429, 499] {
        assert_eq!(counted(status), (1, 0), "status {status}");
    }
    for status in [500, 502, 503, 504, 506, 599] {
        assert_eq!(counted(status), (0, 1), "status {status}");
    }
}
