// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A pattern `UserRegex` accepts must never panic when it is run (T277): `fancy-regex`
//! 0.19.2 compiled `(?(2))` and then indexed out of bounds at match time. The input is the
//! pattern, then optionally a NUL and the text to match it against.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let (pattern, text) = s.split_once('\0').unwrap_or((s, "/abc?a=b&c"));
    if pattern.len() > 512 || text.len() > 256 {
        return;
    }
    for ci in [false, true] {
        if let Ok(re) = ibex_regex::UserRegex::with_case(pattern, ci) {
            let _ = re.is_match(text);
            if let Some(c) = re.captures(text) {
                let mut out = String::new();
                c.expand("$1${2}x", &mut out);
            }
            let _ = re.replace_all(text, "<$0>");
            let _ = re.is_match("");
        }
    }
});
