// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![no_main]
use libfuzzer_sys::fuzz_target;
use ibex_sample::Registry;
use std::sync::LazyLock;

static REG: LazyLock<Registry> = LazyLock::new(Registry::new);

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ibex_rt::logfmt::LogFormat::compile(s, &REG);
        let _ = ibex_rt::logfmt::LogFormat::compile_unique_id(s, &REG);
    }
});
