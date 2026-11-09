// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The HTTP/2 connection state machine as a hostile client reaches it (T242): the bytes
//! after the client preface go into a server-side `MuxH2` the way proxy.rs feeds it
//! (`parse`, then `ensure_goaway` on an error), split into reads whose sizes come from
//! the first byte, and the output is written out between reads unless bit 7 says the
//! client does not read. No stream is consumed (a slow backend). Asserted: no panic, and
//! what the connection holds (input, output, CONTINUATION and request blocks) stays under
//! 2 MiB -- the shape of review #1/#3, unbounded growth from a peer.
#![no_main]
use alcyon_proto::conn::ConnId;
use alcyon_proto::h2::H2_CONN_PREFACE;
use alcyon_proto::htx::HtxBlock;
use alcyon_proto::mux_h2::{H2MuxContext, MuxH2};
use alcyon_proto::Mux;
use libfuzzer_sys::fuzz_target;

const BOUND: usize = 2 << 20;

fn held(ctx: &H2MuxContext) -> usize {
    let mut n = ctx.rx_buf.len() + (ctx.tx_buf.len() - ctx.tx_consumed.min(ctx.tx_buf.len())) + ctx.continuation_buf.len();
    for s in ctx.streams.values() {
        for b in s.rx_htx.blocks() {
            n += match b {
                HtxBlock::ReqLine(r) => r.uri.len() + 16,
                HtxBlock::Header(h) | HtxBlock::Trailer(h) => h.name.len() + h.value.len(),
                HtxBlock::Data(d) | HtxBlock::RawData(d) => d.len(),
                _ => 1,
            };
        }
    }
    n
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, frames)) = data.split_first() else { return };
    let chunk = usize::from(sel & 0x3f) * 97 + 1;
    let reads = sel & 0x80 == 0;
    let Ok(mut ctx) = MuxH2.init(ConnId(1), true) else { return };
    let mut input = H2_CONN_PREFACE.to_vec();
    input.extend_from_slice(frames);
    for piece in input.chunks(chunk) {
        if MuxH2.parse(&mut ctx, piece).is_err() {
            ctx.ensure_goaway();
        }
        let h = held(&ctx);
        assert!(h <= BOUND, "h2 connection holds {h} bytes from {} bytes of input", input.len());
        if reads {
            let n = ctx.tx_buf.len() - ctx.tx_consumed.min(ctx.tx_buf.len());
            MuxH2.consume_output(&mut ctx, n);
        }
    }
});
