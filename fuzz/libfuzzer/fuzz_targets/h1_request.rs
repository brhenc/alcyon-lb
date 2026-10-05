// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![no_main]
use libfuzzer_sys::fuzz_target;
use ibex_proto::htx::HtxSlice;
use ibex_proto::H1Parser;

fuzz_target!(|data: &[u8]| {
    let _ = ibex_rt::proxy::find_eoh(data);
    let _ = ibex_rt::txn::request_framing(data);
    // whole buffer, then fed in two pieces (the proxy parses what has arrived so far)
    for split in [data.len(), data.len() / 2] {
        let mut p = H1Parser::new(false);
        let mut buf = vec![0u8; 64 * 1024];
        let mut htx = HtxSlice::new(&mut buf);
        let _ = p.parse(&data[..split], &mut htx);
        if split != data.len() {
            let _ = p.parse(data, &mut htx);
        }
        p.finish(&mut htx);
    }
});
