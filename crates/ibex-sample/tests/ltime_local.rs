// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): sets the process's TZ environment variable, which local-time formatting in every other test reads

//! `ltime`, `ms_ltime` and `us_ltime` format in the process's local time zone (`localtime_r`),
//! with `%z` the numeric offset and `%Z` the zone's abbreviation; `utime` stays in GMT
//! (T147 item 5). Before this they formatted in GMT.
//!
//! Measured against `HAProxy` 3.5-dev8-885761-29, 2026-10-04, `TZ=Europe/Zagreb`, with
//! `http-request return ... hdr x "%[int(<n>),<conv>(<fmt>)]"`:
//!
//! * `int(1791038898),ltime(%Y-%m-%d %H:%M:%S %z %Z)` is `2026-10-03 16:48:18 +0200 CEST`
//! * `int(1768478400),ltime(...)` is `2026-01-15 13:00:00 +0100 CET`
//! * `int(1791038898),utime(%H:%M %z %Z)` is `14:48 +0000 GMT`
//! * `int(1791038898123),ms_ltime(%H:%M:%S.%3N %z)` is `16:48:18.123 +0200`
//! * `int(1791038898),ltime(%H:%M,3600)` is `17:48` (the offset is added before the zone)

use ibex_sample::{Registry, Sample};

fn conv(reg: &Registry, name: &str, input: i64, args: &[&str]) -> Option<String> {
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    match (reg.get_converter(name)?.func)(Sample::Sint(input), &args)? {
        Sample::Str(s) => Some(s),
        other => panic!("not a string: {other:?}"),
    }
}

#[test]
fn ltime_formats_in_the_local_zone() {
    if !std::path::Path::new("/usr/share/zoneinfo/Europe/Zagreb").exists() {
        return;
    }
    // Read once, on first use; this file has no other test.
    std::env::set_var("TZ", "Europe/Zagreb");
    let reg = Registry::new();
    let full = "%Y-%m-%d %H:%M:%S %z %Z";
    assert_eq!(conv(&reg, "ltime", 1_791_038_898, &[full]).as_deref(), Some("2026-10-03 16:48:18 +0200 CEST"));
    assert_eq!(conv(&reg, "ltime", 1_768_478_400, &[full]).as_deref(), Some("2026-01-15 13:00:00 +0100 CET"));
    assert_eq!(conv(&reg, "utime", 1_791_038_898, &["%H:%M %z %Z"]).as_deref(), Some("14:48 +0000 GMT"));
    assert_eq!(conv(&reg, "ms_ltime", 1_791_038_898_123, &["%H:%M:%S.%3N %z"]).as_deref(), Some("16:48:18.123 +0200"));
    assert_eq!(conv(&reg, "us_ltime", 1_791_038_898_123_456, &["%H:%M:%S.%6N"]).as_deref(), Some("16:48:18.123456"));
    assert_eq!(conv(&reg, "ltime", 1_791_038_898, &["%H:%M", "3600"]).as_deref(), Some("17:48"));
}
