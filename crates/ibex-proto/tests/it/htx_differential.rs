// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Differential testing of HtxBuffer against reference Htx (Vec<HtxBlock>).

use ibex_proto::htx::{
    HeaderField, Htx, HtxBlock, HtxBlockType, HtxBuffer, HtxError,
};
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Op {
    PushHeader(String, String),
    PushData(Vec<u8>),
    PushTrailer(String, String),
    PushEoh,
    PushEot,
    PushEom,
    RemoveBlock(usize),
    ReplaceValue(usize, String),
    Defrag,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (any::<String>(), any::<String>()).prop_map(|(k, v)| Op::PushHeader(k, v)),
        2 => prop::collection::vec(any::<u8>(), 0..64).prop_map(Op::PushData),
        1 => (any::<String>(), any::<String>()).prop_map(|(k, v)| Op::PushTrailer(k, v)),
        1 => Just(Op::PushEoh),
        1 => Just(Op::PushEot),
        1 => Just(Op::PushEom),
        2 => (0usize..32).prop_map(Op::RemoveBlock),
        2 => (0usize..32, any::<String>()).prop_map(|(i, v)| Op::ReplaceValue(i, v)),
        1 => Just(Op::Defrag),
    ]
}

/// Finds the physical descriptor index corresponding to the `logical_idx`-th active block.
fn physical_index_of_active(buf: &HtxBuffer, logical_idx: usize) -> Option<usize> {
    let mut active = 0;
    for i in 0..buf.num_blocks() {
        if buf.block_type(i) != Some(HtxBlockType::Unused) {
            if active == logical_idx {
                return Some(i);
            }
            active += 1;
        }
    }
    None
}

fn run_ops(ops: &[Op]) -> Result<(), TestCaseError> {
    let mut buf = HtxBuffer::with_capacity(32768);
    let mut htx = Htx::new();

    for (step, op) in ops.iter().enumerate() {
        match op {
            Op::PushHeader(k, v) => {
                let mut k = k.replace(['\r', '\n'], "").replace(':', "");
                if k.is_empty() {
                    k = "X-Header".into();
                }
                let v = v.replace(['\r', '\n'], "");
                let k: String = k.chars().take(64).collect();
                let v: String = v.chars().take(128).collect();

                if buf.push_header(&k, &v).is_ok() {
                    htx.push(HtxBlock::Header(HeaderField { name: k, value: v }));
                }
            }
            Op::PushData(d) => {
                if buf.push_data(d).is_ok() {
                    htx.push(HtxBlock::Data(d.clone()));
                }
            }
            Op::PushTrailer(k, v) => {
                let mut k = k.replace(['\r', '\n'], "").replace(':', "");
                if k.is_empty() {
                    k = "X-Trailer".into();
                }
                let v = v.replace(['\r', '\n'], "");
                let k: String = k.chars().take(64).collect();
                let v: String = v.chars().take(128).collect();

                if buf.push_trailer(&k, &v).is_ok() {
                    htx.push(HtxBlock::Trailer(HeaderField { name: k, value: v }));
                }
            }
            Op::PushEoh => {
                if buf.push_eoh().is_ok() {
                    htx.push(HtxBlock::Eoh);
                }
            }
            Op::PushEot => {
                if buf.push_eot().is_ok() {
                    htx.push(HtxBlock::Eot);
                }
            }
            Op::PushEom => {
                if buf.push_eom().is_ok() {
                    htx.push(HtxBlock::Eom);
                }
            }
            Op::RemoveBlock(nth) => {
                let active_count = htx.blocks().len();
                if active_count > 0 {
                    let logical_idx = nth % active_count;
                    if let Some(phys_idx) = physical_index_of_active(&buf, logical_idx) {
                        buf.remove_block(phys_idx);
                        htx.remove_block(logical_idx);
                    }
                }
            }
            Op::ReplaceValue(nth, v) => {
                let active_count = htx.blocks().len();
                if active_count > 0 {
                    let logical_idx = nth % active_count;
                    if let Some(phys_idx) = physical_index_of_active(&buf, logical_idx) {
                        let v = v.replace(['\r', '\n'], "");
                        let v: String = v.chars().take(128).collect();

                        match &mut htx.blocks_mut()[logical_idx] {
                            HtxBlock::Header(h)
                                if buf.replace_block_value(phys_idx, v.as_bytes()).is_ok() =>
                            {
                                h.value = v;
                            }
                            HtxBlock::Trailer(t)
                                if buf.replace_block_value(phys_idx, v.as_bytes()).is_ok() =>
                            {
                                t.value = v;
                            }
                            HtxBlock::Data(d)
                                if buf.replace_block_value(phys_idx, v.as_bytes()).is_ok() =>
                            {
                                *d = v.into_bytes();
                            }
                            _ => {}
                        }
                    }
                }
            }
            Op::Defrag => {
                buf.defrag();
            }
        }

        // Structural invariants check after EVERY operation
        if let Err(e) = buf.check_invariants() {
            return Err(TestCaseError::fail(format!(
                "step {step}: invariant violated after {op:?}: {e}"
            )));
        }

        // Exact, uncompromised equality check between HtxBuffer and Htx oracle
        prop_assert_eq!(
            buf.to_blocks(),
            htx.blocks().to_vec(),
            "step {}: state desync after op {:?}",
            step,
            op
        );
    }

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn prop_differential_htx_buffer_vs_htx(ops in prop::collection::vec(op_strategy(), 0..80)) {
        run_ops(&ops)?;
    }
}

// ---------------------------------------------------------------------------
// Explicit T15 Required Tests
// ---------------------------------------------------------------------------

#[test]
fn test_explicit_replace_growing_forces_tail_append() {
    let mut buf = HtxBuffer::with_capacity(4096);
    let mut htx = Htx::new();

    buf.push_header("X-App", "v1").unwrap();
    htx.push(HtxBlock::Header(HeaderField {
        name: "X-App".into(),
        value: "v1".into(),
    }));
    buf.check_invariants().unwrap();

    // Growing replacement: "v1" (2 bytes) -> 200 bytes string
    let large_val = "A".repeat(200);
    buf.replace_block_value(0, large_val.as_bytes()).unwrap();
    if let HtxBlock::Header(h) = &mut htx.blocks_mut()[0] {
        h.value = large_val;
    }

    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());
}

#[test]
fn test_explicit_heavy_churn_and_defrag() {
    let mut buf = HtxBuffer::with_capacity(16384);
    let mut htx = Htx::new();

    for i in 0..20 {
        let name = format!("Header-{i}");
        let val = format!("val-{i}");
        buf.push_header(&name, &val).unwrap();
        htx.push(HtxBlock::Header(HeaderField {
            name,
            value: val,
        }));
    }
    buf.check_invariants().unwrap();

    // Remove even blocks: 0, 2, 4, ...
    for i in (0..20).step_by(2) {
        buf.remove_block(i);
    }
    let mut keep = Vec::new();
    for (i, b) in htx.blocks().iter().enumerate() {
        if i % 2 != 0 {
            keep.push(b.clone());
        }
    }
    htx = Htx::new();
    for b in keep {
        htx.push(b);
    }

    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());

    // Replace odd blocks with longer values to create fragmented garbage
    for (logical_idx, i) in (1..20).step_by(2).enumerate() {
        let new_val = format!("much_longer_value_for_odd_block_{i}_{}", "X".repeat(50));
        buf.replace_block_value(i, new_val.as_bytes()).unwrap();
        if let HtxBlock::Header(h) = &mut htx.blocks_mut()[logical_idx] {
            h.value = new_val;
        }
    }
    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());

    // Defrag and verify reads before and after
    let before_defrag = buf.to_blocks();
    buf.defrag();
    buf.check_invariants().unwrap();
    let after_defrag = buf.to_blocks();

    assert_eq!(before_defrag, after_defrag);
    assert_eq!(after_defrag, htx.blocks());
}

#[test]
fn test_explicit_removals_boundary() {
    let mut buf = HtxBuffer::with_capacity(2048);
    let mut htx = Htx::new();

    for i in 0..5 {
        let name = format!("H{i}");
        let val = format!("{i}");
        buf.push_header(&name, &val).unwrap();
        htx.push(HtxBlock::Header(HeaderField { name, value: val }));
    }

    // Remove first block (0)
    buf.remove_block(0);
    htx.remove_block(0);
    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());

    // Remove middle block (now index 2 in active list, which was original index 2)
    buf.remove_block(2);
    htx.remove_block(1);
    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());

    // Remove last block (original index 4)
    buf.remove_block(4);
    htx.remove_block(2);
    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());

    // Run defrag and assert clean state
    buf.defrag();
    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());
}

#[test]
fn test_explicit_capacity_exhaustion_no_corruption() {
    let mut buf = HtxBuffer::with_capacity(256);
    let mut pushed_count = 0;

    loop {
        match buf.push_header("X-Hdr", "SomeValue") {
            Ok(()) => pushed_count += 1,
            Err(HtxError::OutOfMemory) => break,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    assert!(pushed_count > 0);
    buf.check_invariants().unwrap();
    let blocks = buf.to_blocks();
    assert_eq!(blocks.len(), pushed_count);
    for b in &blocks {
        if let HtxBlock::Header(h) = b {
            assert_eq!(h.name, "X-Hdr");
            assert_eq!(h.value, "SomeValue");
        } else {
            panic!("unexpected block: {b:?}");
        }
    }
}

#[test]
fn test_measure_htx_block_desc_and_allocations() {
    use ibex_proto::htx::{HttpMethod, HttpVersion, RequestLine};

    let desc_size = std::mem::size_of::<ibex_proto::htx::HtxBlockDesc>();
    let enum_block_size = std::mem::size_of::<HtxBlock>();

    assert_eq!(desc_size, 16, "HtxBlockDesc must be exactly 16 bytes");

    // Build a realistic request in Htx: 1 start line + 10 headers
    let headers_data = [
        ("Host", "api.project-ibex.internal"),
        ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0"),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Connection", "keep-alive"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
    ];

    let mut htx = Htx::new();
    htx.push(HtxBlock::ReqLine(RequestLine {
        method: HttpMethod::Get,
        uri: "/v1/cluster/nodes?active=true&zone=us-east-1".into(),
        version: HttpVersion::Http11,
    }));
    for (name, val) in headers_data {
        htx.push(HtxBlock::Header(HeaderField {
            name: name.into(),
            value: val.into(),
        }));
    }

    // Build the same request in HtxBuffer
    let mut buf = HtxBuffer::with_capacity(4096);
    buf.push_req_line("GET", "/v1/cluster/nodes?active=true&zone=us-east-1", "HTTP/1.1").unwrap();
    for (name, val) in headers_data {
        buf.push_header(name, val).unwrap();
    }

    buf.check_invariants().unwrap();
    assert_eq!(buf.to_blocks(), htx.blocks());

    // Measurement calculations:
    // Htx: 1 allocation for Vec<HtxBlock> (11 items * 56B), 1 allocation for uri string, 10 * 2 allocations for header strings = 22 allocations.
    // HtxBuffer: 1 single contiguous buffer allocation.
    assert!(desc_size <= 16);
    assert!(enum_block_size >= 48);
}

// ---------------------------------------------------------------------------
// X1: the request head indexed where it was received (htx-engine-2026-11-01.md §2.1)
// ---------------------------------------------------------------------------
//
// `H1Parser::index_head_in_place` writes the descriptors of a head that lies in the
// transport buffer into the buffer's reserve, over the received bytes. Every reader must see
// what the copying parse (`H1Parser::parse` into an `HtxSlice::new`) leaves, every edit must
// encode to the same head, and a reserve that runs out is defragmented once and gives the same
// result.

mod in_place {
    use ibex_proto::htx::{HtxBlockType, HtxError, HtxRegion, HtxSlice, HtxSliceRef};
    use ibex_proto::H1Parser;
    use proptest::prelude::*;

    /// Bytes before the head in the transport buffer: the addresses are absolute.
    const LEAD: usize = 7;
    const BUF: usize = 16384;

    /// The parser's outcome: consumed bytes or the error, and what the end of the head read.
    #[derive(Debug, PartialEq)]
    struct Facts {
        res: Result<usize, String>,
        oom: bool,
        phase: String,
        content_length: Option<usize>,
        chunked: bool,
        upgrade: bool,
        close: bool,
        conflict: bool,
        rewritten: bool,
        lines: u16,
        saw_upgrade: bool,
    }

    fn facts(p: &H1Parser, res: std::io::Result<usize>) -> Facts {
        Facts {
            oom: res.as_ref().is_err_and(|e| e.kind() == std::io::ErrorKind::OutOfMemory),
            res: res.map_err(|e| format!("{e}")),
            phase: format!("{:?}", p.phase),
            content_length: p.content_length,
            chunked: p.is_chunked,
            upgrade: p.is_upgrade,
            close: p.connection_close,
            conflict: p.framing_conflict,
            rewritten: p.head_rewritten,
            lines: p.header_lines,
            saw_upgrade: p.saw_upgrade(),
        }
    }

    /// The copying parse: the head into an HTX of its own.
    struct Copied {
        buf: Vec<u8>,
        tail: usize,
        blocks: usize,
        facts: Facts,
    }

    fn copied(head: &[u8], accept_unsafe: bool) -> Copied {
        let mut buf = vec![0u8; 32768];
        let mut p = H1Parser::new(false);
        p.accept_unsafe_request = accept_unsafe;
        let mut s = HtxSlice::new(&mut buf);
        let res = p.parse(head, &mut s);
        let (tail, blocks) = (s.tail_addr(), s.num_blocks());
        Copied { buf, tail, blocks, facts: facts(&p, res) }
    }

    /// The in-place index: `LEAD` bytes, the head, `body`, free space, a reserve of `reserve`.
    struct Placed {
        buf: Vec<u8>,
        region: HtxRegion,
        tail: usize,
        blocks: usize,
        facts: Facts,
    }

    fn placed(head: &[u8], body: &[u8], reserve: usize, accept_unsafe: bool) -> Placed {
        let mut buf = vec![0xAAu8; BUF];
        buf[LEAD..LEAD + head.len()].copy_from_slice(head);
        buf[LEAD + head.len()..LEAD + head.len() + body.len()].copy_from_slice(body);
        let region = HtxRegion { head_start: LEAD, head_end: LEAD + head.len(), reserve_start: BUF - reserve };
        let mut p = H1Parser::new(false);
        p.accept_unsafe_request = accept_unsafe;
        let mut s = HtxSlice::over_received(&mut buf, region).expect("the layout fits");
        let res = p.index_head_in_place(&mut s);
        let (tail, blocks) = (s.tail_addr(), s.num_blocks());
        s.check_invariants().expect("in-place invariants");
        Placed { buf, region, tail, blocks, facts: facts(&p, res) }
    }

    /// Everything a reader of the HTX can see.
    fn readers(v: HtxSliceRef<'_>) -> String {
        let names = ["host", "HOST", "content-length", "transfer-encoding", "connection", "upgrade", "te", "x-a", "X-MiXed", "absent", "cookie"];
        let gets: Vec<_> = names.iter().map(|n| (v.get_header(n), v.get_header_bytes(n.as_bytes()))).collect();
        let line = v.req_line().map(|l| (l.method.to_string(), l.uri.to_string(), l.version.to_string()));
        let line_b = v.req_line_bytes().map(|l| (l.method.to_vec(), l.uri.to_vec(), l.version.to_vec()));
        let headers: Vec<_> = v.headers().collect();
        let blocks: Vec<_> = v.header_blocks().map(|(_, n, val)| (n, val)).collect();
        let types: Vec<HtxBlockType> = v.active_block_types();
        format!(
            "line={line:?}\nline_b={line_b:?}\nheaders={headers:?}\nblocks={blocks:?}\ngets={gets:?}\nbody={}\neoh={} eom={}\ntypes={types:?}\nwire={:?}",
            v.body_len(),
            v.is_eoh(),
            v.is_eom(),
            String::from_utf8_lossy(&v.write_h1_wire_vec()),
        )
    }

    /// The in-place index of `head` reads as the copying parse does.
    fn same(head: &[u8], accept_unsafe: bool) -> Result<(), TestCaseError> {
        let c = copied(head, accept_unsafe);
        let p = placed(head, b"BODYBYTES", 1024, accept_unsafe);
        prop_assert_eq!(&p.facts, &c.facts, "parser facts for {:?}", String::from_utf8_lossy(head));
        if c.facts.res.is_ok() {
            prop_assert_eq!(
                readers(HtxSliceRef::new(&p.buf, p.blocks)),
                readers(HtxSliceRef::new(&c.buf, c.blocks)),
                "readers for {:?}",
                String::from_utf8_lossy(head)
            );
            // Nothing outside the reserve is written but what an edit of the parser changed.
            if !c.facts.rewritten {
                prop_assert_eq!(&p.buf[LEAD..LEAD + head.len()], head, "the received head is untouched");
            }
            prop_assert_eq!(&p.buf[LEAD + head.len()..LEAD + head.len() + 9], b"BODYBYTES");
            prop_assert!(p.tail >= p.region.reserve_start);
        }
        let _ = c.tail;
        Ok(())
    }

    /// The R1 smuggling corpus and the parser's own rewrites, as heads.
    const CORPUS: &[&[u8]] = &[
        b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
        b"GET /x?y=z HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\nAccept: */*\r\nX-MiXed: Case\r\n\r\n",
        b"POST /smuggle HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST /smuggle HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5, 5\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5, 6\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 005\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: -5\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: +5\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: \r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: Chunked\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
        b"POST /x HTTP/1.0\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET /x HTTP/1.0\r\nHost: h\r\nContent-Length: 4\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n",
        b"GET http://example.com/p HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET http://example.com:80/p HTTP/1.1\r\nHost: example.com:80\r\n\r\n",
        b"GET http://example.com/p HTTP/1.1\r\nHost: other.com\r\n\r\n",
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nTE: trailers\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nTE: gzip, trailers\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nTE: deflate\r\n continued\r\nX-A: 1\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nX-Fold: a\r\n  b\r\n\tc\r\n\r\n",
        b"GET / HTTP/1.1\nHost: h\nX-Fold: a\n b\n\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nX-A:no-space\r\nX-B:   lots   \r\nX-C: tab\t\r\nX-D:\r\n\r\n",
        b"GET  /  HTTP/1.1\r\nHost: h\r\n\r\n",
        b"GET\t/\tHTTP/1.1\r\nHost: h\r\n\r\n",
        b"GET / HTTP/1.2\r\nHost: h\r\n\r\n",
        b"GET / HTTP/1.0\r\nHost: h\r\nConnection: keep-alive\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: h2c, websocket\r\nConnection: upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nX-Utf8: caf\xc3\xa9\r\nX-Latin1: \xe9t\xe9\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nX-Latin1: \xe9\r\n \xe8\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nBad Name: x\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nNoColon\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\n: empty\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nX-A: a\rb\r\n\r\n",
        b"GET / HTTP/1.1\r\n Host: h\r\n\r\n",
        b"GET /#frag HTTP/1.1\r\nHost: h\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h@\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nCookie: a=1; b=2\r\nCookie: c=3\r\n\r\n",
        b"G@T / HTTP/1.1\r\nHost: h\r\n\r\n",
        b"GET / HTTP/1.1\r\nhost: lower\r\nCONTENT-LENGTH: 0\r\n\r\n",
    ];

    #[test]
    fn the_corpus_reads_the_same_in_place() {
        for head in CORPUS {
            same(head, false).unwrap();
            same(head, true).unwrap();
        }
    }

    #[test]
    fn a_head_with_a_non_ascii_target_reads_the_same_in_place() {
        same(b"GET /caf\xc3\xa9 HTTP/1.1\r\nHost: h\r\n\r\n", true).unwrap();
        same(b"GET /\xe9 HTTP/1.1\r\nHost: h\r\n\r\n", true).unwrap();
    }

    /// An unmodified head: the descriptors point at the bytes that arrived, names in the case
    /// they arrived in (lowercasing is the encoder's, X5), and nothing past the reserve's
    /// start is written but descriptors.
    #[test]
    fn an_unmodified_head_is_indexed_over_its_own_bytes() {
        let head = b"GET /p HTTP/1.1\r\nHost: h\r\nX-MiXed:  Case \r\n\r\n";
        let p = placed(head, b"", 256, false);
        assert_eq!(p.facts.res, Ok(head.len()));
        assert_eq!(&p.buf[LEAD..LEAD + head.len()], head);
        let v = HtxSliceRef::new(&p.buf, p.blocks);
        assert_eq!(v.headers().collect::<Vec<_>>(), [("Host", "h"), ("X-MiXed", "Case")]);
        // No payload in the reserve: every block addresses the received text.
        assert_eq!(p.tail, p.region.reserve_start);
        for i in 0..v.num_blocks() {
            let d = v.read_desc(i);
            assert!(d.span() == 0 || d.addr as usize + d.span() <= LEAD + head.len(), "block {i} is in the head");
        }
    }

    #[derive(Debug, Clone)]
    enum Edit {
        Set(&'static str, String),
        Add(&'static str, String),
        Del(&'static str),
        Replace(&'static str, &'static str, &'static str),
        Uri(String),
        Method(&'static str),
    }

    fn edit_strategy() -> impl Strategy<Value = Edit> {
        let name = prop::sample::select(vec!["host", "X-A", "x-new", "Cookie", "user-agent", "Content-Length"]);
        let value = "[a-z0-9=;, ]{0,200}";
        prop_oneof![
            3 => (name.clone(), value).prop_map(|(n, v)| Edit::Set(n, v)),
            3 => (name.clone(), value).prop_map(|(n, v)| Edit::Add(n, v)),
            2 => name.clone().prop_map(Edit::Del),
            1 => name.prop_map(|n| Edit::Replace(n, "[a-z]+", "R")),
            1 => "/[a-z0-9/]{0,120}".prop_map(Edit::Uri),
            1 => prop::sample::select(vec!["GET", "POST", "PATCH"]).prop_map(Edit::Method),
        ]
    }

    fn apply(s: &mut HtxSlice<'_>, e: &Edit) -> Result<(), HtxError> {
        match e {
            Edit::Set(n, v) => s.set_header(n, v),
            Edit::Add(n, v) => s.add_header(n, v),
            Edit::Del(n) => {
                s.remove_header(n);
                Ok(())
            }
            Edit::Replace(n, re, repl) => s.replace_header(n, re, repl).map(|_| ()),
            Edit::Uri(u) => s.set_uri(u),
            Edit::Method(m) => s.set_method(m),
        }
    }

    const EDIT_HEADS: &[&[u8]] = &[
        b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
        b"GET /x?y=z HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\nX-A:  1  \r\nCookie: a=1\r\nCookie: b=2\r\n\r\n",
        b"POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nX-A: a\r\n  folded\r\n\r\n",
    ];

    /// Edits on the in-place index encode to what they encode to on the copying HTX; an edit
    /// the reserve has no room for defragments once (`retry_after_defrag`) and goes on, and one
    /// that still does not fit stops the comparison (the encoder's fallback, X2).
    fn edits_encode_the_same(head: &[u8], reserve: usize, edits: &[Edit]) -> Result<usize, TestCaseError> {
        let mut c = copied(head, false);
        let mut p = placed(head, b"", reserve, false);
        prop_assert!(c.facts.res.is_ok());
        if p.facts.oom {
            // A reserve too small for the descriptors: the head is parsed by copying (X2).
            prop_assert!(reserve < 16 * 12, "a reserve of {} has no room for the index", reserve);
            return Ok(0);
        }
        prop_assert!(p.facts.res.is_ok(), "{:?} with a reserve of {}", p.facts, reserve);
        let mut done = 0;
        for e in edits {
            let mut cs = HtxSlice::with_offsets(&mut c.buf, c.tail, c.blocks);
            apply(&mut cs, e).expect("the copying HTX has room");
            (c.tail, c.blocks) = (cs.tail_addr(), cs.num_blocks());
            let mut ps = HtxSlice::over_received_with(&mut p.buf, p.region, p.tail, p.blocks);
            let r = ps.retry_after_defrag(|s| apply(s, e));
            ps.check_invariants().map_err(TestCaseError::fail)?;
            (p.tail, p.blocks) = (ps.tail_addr(), ps.num_blocks());
            if r == Err(HtxError::OutOfMemory) {
                break;
            }
            prop_assert_eq!(r, Ok(()));
            done += 1;
            prop_assert_eq!(
                readers(HtxSliceRef::new(&p.buf, p.blocks)),
                readers(HtxSliceRef::new(&c.buf, c.blocks)),
                "after {:?} with a reserve of {}",
                e,
                reserve
            );
        }
        Ok(done)
    }

    /// The reserve runs out after four growing `set-header`s of one header: the dead copies
    /// are reclaimed by one defrag, the fifth fits, and the head encodes the same.
    #[test]
    fn a_full_reserve_is_defragmented_once_and_the_head_is_the_same() {
        let head = b"GET / HTTP/1.1\r\nHost: h\r\nX-A: 1\r\n\r\n";
        let mut c = copied(head, false);
        let mut p = placed(head, b"", 256, false);
        let mut defrags = 0;
        for len in [20, 30, 40, 50, 60] {
            let v = "v".repeat(len);
            let mut cs = HtxSlice::with_offsets(&mut c.buf, c.tail, c.blocks);
            cs.set_header("x-a", &v).unwrap();
            (c.tail, c.blocks) = (cs.tail_addr(), cs.num_blocks());
            let mut ps = HtxSlice::over_received_with(&mut p.buf, p.region, p.tail, p.blocks);
            if ps.set_header("x-a", &v) == Err(HtxError::OutOfMemory) {
                defrags += 1;
                ps.defrag();
                ps.check_invariants().unwrap();
                ps.set_header("x-a", &v).unwrap();
            }
            ps.check_invariants().unwrap();
            (p.tail, p.blocks) = (ps.tail_addr(), ps.num_blocks());
        }
        assert_eq!(defrags, 1, "one defrag reclaims the dead values");
        assert_eq!(readers(HtxSliceRef::new(&p.buf, p.blocks)), readers(HtxSliceRef::new(&c.buf, c.blocks)));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        /// 200 generated heads read the same in place.
        #[test]
        fn generated_heads_read_the_same_in_place(
            method in prop::sample::select(vec!["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]),
            uri in prop::sample::select(vec!["/", "/a/b?c=d", "*", "http://h.example/x", "http://h.example:80/x", "/%41"]),
            version in prop::sample::select(vec!["HTTP/1.1", "HTTP/1.0", "HTTP/1.2"]),
            sep in prop::sample::select(vec![" ", " ", " ", "  ", "\t"]),
            eol in prop::sample::select(vec!["\r\n", "\r\n", "\r\n", "\n"]),
            lines in prop::collection::vec((
                prop::sample::select(vec!["Host", "host", "HOST", "Content-Length", "Transfer-Encoding", "Connection",
                    "Upgrade", "TE", "X-A", "X-MiXed", "Cookie", "Accept", "Sec-WebSocket-Key", "User-Agent"]),
                prop::sample::select(vec![": ", ":", ":  ", ": \t"]),
                prop::sample::select(vec![&b""[..], b"a", b"h.example", b"5", b"05", b"5, 5", b"0", b"chunked",
                    b"gzip, chunked", b"Chunked", b"close", b"keep-alive", b"upgrade", b"websocket", b"h2c",
                    b"trailers", b"trailers, deflate", b"dGhlIHNhbXBsZSBub25jZQ==", b"caf\xc3\xa9", b"\xe9t\xe9",
                    b"a\tb", b"x y z"]),
                prop::sample::select(vec!["", "", "", " ", "\t "]),
                prop::sample::select(vec![None, None, None, None, None, Some("  more"), Some("\tmore")]),
            ), 0..12),
        ) {
            let mut head = format!("{method}{sep}{uri}{sep}{version}{eol}").into_bytes();
            for (name, colon, value, trail, fold) in lines {
                head.extend_from_slice(name.as_bytes());
                head.extend_from_slice(colon.as_bytes());
                head.extend_from_slice(value);
                head.extend_from_slice(trail.as_bytes());
                head.extend_from_slice(eol.as_bytes());
                if let Some(f) = fold {
                    head.extend_from_slice(f.as_bytes());
                    head.extend_from_slice(eol.as_bytes());
                }
            }
            head.extend_from_slice(eol.as_bytes());
            same(&head, false)?;
        }

        /// Edit sequences over reserves of 64 to 1024 bytes encode the same.
        #[test]
        fn edits_in_place_encode_the_same(
            head in prop::sample::select(EDIT_HEADS.to_vec()),
            reserve in 64usize..=1024,
            edits in prop::collection::vec(edit_strategy(), 1..12),
        ) {
            edits_encode_the_same(head, reserve, &edits)?;
        }
    }

    /// The sweep is not vacuous: with a reserve of 1024 every edit of a short sequence runs.
    #[test]
    fn edits_run_with_a_large_reserve() {
        let edits = [
            Edit::Set("x-a", "1".repeat(100)),
            Edit::Add("x-new", "n".repeat(150)),
            Edit::Del("cookie"),
            Edit::Replace("host", "[a-z]+", "R"),
            Edit::Uri("/new/path".into()),
            Edit::Method("POST"),
            Edit::Set("host", "short".into()),
        ];
        for head in EDIT_HEADS {
            assert_eq!(edits_encode_the_same(head, 1024, &edits).unwrap(), edits.len());
        }
    }
}
