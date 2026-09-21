// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/mux_pt.c (passthrough mux).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Passthrough Mux (`mux_pt`): Zero-framing multiplexer for `mode tcp`.

use crate::conn::ConnId;
use crate::endpoint::SeDesc;
use crate::mux::{mux_flags, Mux, MuxFlags, MuxOps, ShutMode};
use std::io;

static PT_OPS: MuxOps = MuxOps {
    name: "pt",
    alpn: None,
    flags: MuxFlags(mux_flags::REUSABLE),
};

/// Connection context for the passthrough mux.
pub struct PtMuxContext {
    pub conn: ConnId,
    pub tx_buf: Vec<u8>,
    pub tx_consumed: usize,
    pub is_shut: bool,
}

/// Passthrough multiplexer.
#[derive(Debug, Clone, Copy, Default)]
pub struct MuxPt;

impl Mux for MuxPt {
    type Ctx = PtMuxContext;

    fn ops(&self) -> &'static MuxOps {
        &PT_OPS
    }

    fn init(&self, conn: ConnId, _is_server: bool) -> io::Result<Self::Ctx> {
        Ok(PtMuxContext {
            conn,
            tx_buf: Vec::with_capacity(4096),
            tx_consumed: 0,
            is_shut: false,
        })
    }

    fn parse(&self, _ctx: &mut Self::Ctx, input: &[u8]) -> io::Result<usize> {
        Ok(input.len())
    }

    fn rcv_buf(
        &self,
        _ctx: &mut Self::Ctx,
        _sd: &mut SeDesc,
        _out: &mut [u8],
    ) -> io::Result<usize> {
        Ok(0)
    }

    fn snd_buf(&self, ctx: &mut Self::Ctx, _sd: &mut SeDesc, input: &[u8]) -> io::Result<usize> {
        ctx.tx_buf.extend_from_slice(input);
        Ok(input.len())
    }

    fn pending_output<'a>(&self, ctx: &'a Self::Ctx) -> &'a [u8] {
        if ctx.tx_consumed >= ctx.tx_buf.len() {
            &[]
        } else {
            &ctx.tx_buf[ctx.tx_consumed..]
        }
    }

    fn consume_output(&self, ctx: &mut Self::Ctx, n: usize) {
        ctx.tx_consumed += n;
        if ctx.tx_consumed >= ctx.tx_buf.len() {
            ctx.tx_buf.clear();
            ctx.tx_consumed = 0;
        }
    }

    fn shut(&self, ctx: &mut Self::Ctx, _sd: &mut SeDesc, _mode: ShutMode) {
        ctx.is_shut = true;
    }

    fn avail_streams(&self, ctx: &Self::Ctx) -> u32 {
        u32::from(!ctx.is_shut)
    }

    fn used_streams(&self, _ctx: &Self::Ctx) -> u32 {
        1
    }
}
