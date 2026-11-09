// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `show stat` CSV header must match `HAProxy`'s exactly.
//!
//! hatop and every other stats consumer parses this CSV **positionally**. A header of
//! the wrong width silently misaligns every column past the divergence point, which
//! looks like corrupt data rather than a missing feature.
//!
//! `data/stats_csv_header.txt` is the reference, captured from a real `HAProxy` 3.5
//! binary and verified byte-identical to its live `show stat` output. It regressed
//! once from 146 fields to 119 and was committed unnoticed; this test exists so that
//! cannot happen silently again.

fn reference_header() -> Vec<String> {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    let raw = std::fs::read_to_string(p.join("data").join("stats_csv_header.txt"))
        .expect("data/stats_csv_header.txt must exist");
    raw.trim()
        .trim_start_matches("# ")
        .trim_end_matches(',')
        .split(',')
        .map(str::to_string)
        .collect()
}

#[test]
fn reference_header_has_the_full_modern_field_set() {
    let h = reference_header();
    assert_eq!(
        h.len(),
        146,
        "HAProxy 3.5 emits 146 columns: the 119 ST_I_PX_* fields, a '-' separator, and \
         26 per-module h2_*/ssl_*/h1_* columns. A 119-field reference means the \
         per-module stats were dropped again."
    );
    assert_eq!(h[0], "pxname", "field 0 must be pxname, unprefixed");
    assert_eq!(h[1], "svname");
    assert_eq!(h[119], "-", "field 119 is the literal module separator");
    assert!(
        h.iter().any(|f| f.starts_with("h2_")),
        "per-module h2_* columns must be present"
    );
    assert!(
        h.iter().any(|f| f.starts_with("ssl_")),
        "per-module ssl_* columns must be present"
    );
}

#[test]
fn reference_header_field_names_are_well_formed() {
    for (i, f) in reference_header().iter().enumerate() {
        assert!(!f.is_empty(), "field {i} is empty");
        assert!(
            f == "-" || f.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "field {i} ({f:?}) is not a plain identifier"
        );
    }
}
