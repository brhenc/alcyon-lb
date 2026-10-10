// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! LDAP and MySQL check replies (T242), apart from `check_reply`: they panic on short
//! replies (production review #7, fixed by T238). First byte: parser, EOF, MySQL user.
#![no_main]
use ibex_rt::check_reply as cr;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    let eof = sel & 0x80 != 0;
    if sel & 1 == 0 {
        let _ = cr::ldap(rest, eof);
    } else {
        let _ = cr::mysql(rest, eof, sel & 2 != 0);
    }
});
