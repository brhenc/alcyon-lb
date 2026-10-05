// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // bounded: a huge pattern only measures the compiler, not a bug
        if s.len() <= 4096 {
            let _ = ibex_regex::UserRegex::new(s);
        }
    }
});
