// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! VV-26: the `master-worker` global keyword was removed in HAProxy 3.5 and is a
//! configuration error there (`haproxy -c`, 3.5-dev8, exit 1). Alcyon used to accept it and
//! ignore it: no master, no worker, and "Configuration file is valid.".

use alcyon_config::parse_str;

fn refusal(cfg: &str) -> (usize, String) {
    match parse_str(cfg) {
        Ok(_) => panic!("accepted:\n{cfg}"),
        Err(e) => (e.line, e.message),
    }
}

#[test]
fn master_worker_keyword_is_refused() {
    let (line, msg) = refusal("global\n  master-worker\n");
    assert_eq!(line, 2);
    assert_eq!(msg, "support for 'master-worker' was removed in version 3.5. Use -W or -Ws in the startup script instead.");
}

#[test]
fn master_worker_no_exit_on_failure_is_refused() {
    let (line, msg) = refusal("global\n  master-worker no-exit-on-failure\n");
    assert_eq!(line, 2);
    assert_eq!(msg, "'master-worker no-exit-on-failure' is only supported in master-worker mode. Use -W or -Ws in the startup script.");
}
