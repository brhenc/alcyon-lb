// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The runtime socket must satisfy unmodified `hatop`.
//!
//! These replay exactly what `hatop` 0.8.3 does on connect, derived from its source:
//! `prompt` to enter interactive mode, `set timeout cli`, `show info` parsed against 14
//! mandatory regexes, then `show stat` as positional CSV.
//!
//! Verified end to end by running real `hatop` against a live Alcyon: it renders the
//! banner, the software name from `show info`, and FRONTEND/BACKEND rows, with no
//! traceback.

use alcyon_rt::{stats_csv_header, StatRow, STAT_FIELDS, STAT_FIELD_COUNT};

/// The 14 keys `hatop`'s `HAPROXY_INFO_RE` requires. A missing one makes it show blanks
/// or abort, depending on which.
const HATOP_INFO_KEYS: [&str; 14] = [
    "Name:",
    "Version:",
    "Release_date:",
    "Nbproc:",
    "Process_num:",
    "Pid:",
    "Uptime:",
    "Maxconn:",
    "CurrConns:",
    "Maxpipes:",
    "PipesUsed:",
    "Tasks:",
    "Run_queue:",
    "node:",
];

#[test]
fn show_info_carries_every_key_hatop_requires() {
    let info = alcyon_rt::format_show_info(std::time::Instant::now(), 4242, 3, 1, 0, 2000);
    for key in HATOP_INFO_KEYS {
        assert!(
            info.lines().any(|l| l.starts_with(key)),
            "show info is missing {key:?}, which hatop parses with a required regex.\n\
             Got:\n{info}"
        );
    }
}

#[test]
fn stat_header_matches_the_captured_haproxy_reference() {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    let reference = std::fs::read_to_string(p.join("data").join("stats_csv_header.txt"))
        .expect("data/stats_csv_header.txt");

    let ours = stats_csv_header();
    let a: Vec<&str> = ours.trim().trim_start_matches("# ").split(',').collect();
    let b: Vec<&str> = reference.trim().trim_start_matches("# ").trim_end_matches(',').split(',').collect();

    assert_eq!(
        a.len(),
        b.len(),
        "column count differs from the live HAProxy 3.5 capture. hatop parses this CSV \
         positionally, so a width mismatch misaligns every column past the divergence \
         and presents as corrupt data rather than a missing feature."
    );
    assert_eq!(a, b, "column names or order differ from the reference");
}

#[test]
fn every_stat_row_is_exactly_the_header_width() {
    // The bug this guards: rows were emitted as hand-written format strings padded
    // with literal commas, and drifted to 130 and 119 columns against a 146 header.
    let mut r = StatRow::new();
    r.set("pxname", "fe");
    r.set("svname", "FRONTEND");
    r.set("status", "OPEN");
    let row = r.finish();
    assert_eq!(
        row.trim_end().split(',').count(),
        STAT_FIELD_COUNT,
        "a partially populated row must still be full width"
    );

    let empty = StatRow::new().finish();
    assert_eq!(
        empty.trim_end().split(',').count(),
        STAT_FIELD_COUNT,
        "even an empty row must be full width"
    );
}

#[test]
fn module_separator_sits_at_index_119() {
    let row = StatRow::new().finish();
    let fields: Vec<&str> = row.trim_end().split(',').collect();
    assert_eq!(
        fields[119], "-",
        "HAProxy emits a literal '-' separating the proxy stats from the per-module \
         h2_*/ssl_*/h1_* columns"
    );
    assert_eq!(STAT_FIELDS[119], "-");
}

#[test]
fn unknown_columns_are_left_empty_not_zero() {
    // Empty and 0 mean different things to a stats consumer: empty is "not applicable
    // here", zero is a measurement. Zero-filling would report fabricated data.
    let row = StatRow::new().finish();
    let fields: Vec<&str> = row.trim_end().split(',').collect();
    let zeros = fields.iter().filter(|f| **f == "0").count();
    assert_eq!(zeros, 0, "a fresh row must contain no fabricated zero measurements");
}

#[test]
fn setting_an_unknown_column_is_ignored_not_fatal() {
    // The runtime socket is an attack surface; a typo must not take down a proxy that
    // was only asked for statistics.
    let mut r = StatRow::new();
    r.set("this_column_does_not_exist", 42);
    assert_eq!(r.finish().trim_end().split(',').count(), STAT_FIELD_COUNT);
}
