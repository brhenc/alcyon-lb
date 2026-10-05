// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![no_main]
use libfuzzer_sys::fuzz_target;
use ibex_proto::h2::{H2FrameParser, H2Multiplexer, H2Role};

fuzz_target!(|data: &[u8]| {
    let parser = H2FrameParser::new();
    let mut mux = H2Multiplexer::new(H2Role::Server);
    let mut off = 0;
    // decode every frame in the buffer and feed it to a server-side multiplexer
    while off < data.len() {
        match parser.parse(&data[off..]) {
            Ok(Some((frame, n))) => {
                off += n;
                let _ = mux.handle_frame(frame);
            }
            _ => break,
        }
    }
});
