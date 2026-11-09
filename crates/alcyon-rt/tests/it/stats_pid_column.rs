// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `pid` column of `show stat` is the process number (1 with one process), not the
//! operating-system process id (T151 item 8; measured on HAProxy 3.5-dev8: `1`).

use alcyon_config::parse_str;
use alcyon_rt::Engine;

#[test]
fn pid_column_is_the_process_number() {
    let cfg = parse_str(
        "listen l\n  bind 127.0.0.1:0\n  mode http\n  server s 127.0.0.1:1\n",
    )
    .expect("parse");
    let engine = Engine::new(&cfg, 64).expect("engine");
    let csv = engine.stats_csv(4242);
    let mut lines = csv.lines();
    let header: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
    let col = header.iter().position(|h| *h == "pid").expect("pid column");
    let mut rows = 0;
    for l in lines.filter(|l| !l.is_empty()) {
        assert_eq!(l.split(',').nth(col), Some("1"), "{l}");
        rows += 1;
    }
    assert!(rows >= 3, "frontend, server, backend");
}
