// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Differential testing of HtxBuffer against reference Htx (Vec<HtxBlock>).

use alcyon_proto::htx::{
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
    use alcyon_proto::htx::{HttpMethod, HttpVersion, RequestLine};

    let desc_size = std::mem::size_of::<alcyon_proto::htx::HtxBlockDesc>();
    let enum_block_size = std::mem::size_of::<HtxBlock>();

    assert_eq!(desc_size, 16, "HtxBlockDesc must be exactly 16 bytes");

    // Build a realistic request in Htx: 1 start line + 10 headers
    let headers_data = [
        ("Host", "api.alcyon-lb.internal"),
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
    use alcyon_proto::htx::{HtxBlockType, HtxError, HtxRegion, HtxSlice, HtxSliceRef};
    use alcyon_proto::H1Parser;
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
        // Heads that are not whole, and refusals before the end of the head.
        b"GET / HTT",
        b"GET / HTTP/1.1\r",
        b"GET / HTTP/1.1\r\nHost",
        b"GET / HTTP/1.1\r\nHost: h\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nX-Fold: a\r\n b\x00c\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\rX-A: 1\r\n\r\n",
    ];

    #[test]
    fn the_corpus_reads_the_same_in_place() {
        for head in CORPUS {
            same(head, false).unwrap();
            same(head, true).unwrap();
        }
    }

    /// More header lines than `MAX_REQUEST_HEADERS` are refused in place as by copying.
    #[test]
    fn too_many_header_lines_are_refused_the_same_in_place() {
        let mut head = b"GET / HTTP/1.1\r\nHost: h\r\n".to_vec();
        for i in 0..120 {
            head.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        head.extend_from_slice(b"\r\n");
        let c = copied(&head, false);
        assert!(c.facts.res.is_err());
        let mut buf = vec![0u8; 8192];
        buf[..head.len()].copy_from_slice(&head);
        let region = HtxRegion { head_start: 0, head_end: head.len(), reserve_start: head.len() };
        let mut s = HtxSlice::over_received(&mut buf, region).unwrap();
        let mut p = H1Parser::new(false);
        let r = p.index_head_in_place(&mut s);
        assert_eq!(facts(&p, r), c.facts);
    }

    /// What the in-place index and the layout refuse.
    #[test]
    fn the_in_place_layout_refuses_what_it_cannot_hold() {
        let head = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut buf = vec![0u8; 256];
        buf[..head.len()].copy_from_slice(head);
        let ok = HtxRegion { head_start: 0, head_end: head.len(), reserve_start: 128 };
        for bad in [
            HtxRegion { head_start: 5, head_end: 4, reserve_start: 128 },
            HtxRegion { head_start: 0, head_end: 200, reserve_start: 128 },
            HtxRegion { head_start: 0, head_end: 4, reserve_start: 300 },
        ] {
            assert_eq!(HtxSlice::over_received(&mut buf, bad).err(), Some(HtxError::InvalidData));
        }
        let mut s = HtxSlice::over_received(&mut buf, ok).unwrap();
        assert_eq!(s.region(), ok);
        // Ranges outside the head, a value before its name's end, a name too long.
        assert_eq!(s.push_req_line_in_place(100..110, 3, 1), Err(HtxError::InvalidData));
        assert_eq!(s.push_header_in_place(0..4, 2..3), Err(HtxError::InvalidData));
        assert_eq!(s.push_header_in_place(0..4, 6..120), Err(HtxError::InvalidData));
        // A response is not indexed in place, nor a parser past a request's start.
        assert_eq!(H1Parser::new(true).index_head_in_place(&mut s).unwrap_err().kind(), std::io::ErrorKind::Unsupported);
        let mut p = H1Parser::new(false);
        assert_eq!(p.index_head_in_place(&mut s).unwrap(), head.len());
        assert_eq!(p.index_head_in_place(&mut s).unwrap_err().kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(s.payload_bytes(), 0);
        assert_eq!(s.fragmented_bytes(), 0);
        // An edit that fails for another reason than room is not retried.
        assert_eq!(s.retry_after_defrag(|s| s.replace_block_value(0, b"x").and(Err::<(), _>(HtxError::InvalidData))), Err(HtxError::InvalidData));
        s.clear();
        assert_eq!((s.num_blocks(), s.tail_addr()), (0, 128));
        s.defrag();
        assert_eq!(s.tail_addr(), 128);
        // A reserve with no room for a descriptor.
        let full = HtxRegion { head_start: 0, head_end: head.len(), reserve_start: 256 };
        let mut s = HtxSlice::over_received(&mut buf, full).unwrap();
        assert_eq!(s.push_header_in_place(16..20, 22..23), Err(HtxError::OutOfMemory));
        let mut long = vec![b'n'; 300];
        long.extend_from_slice(b": v\r\n");
        let mut big = vec![0u8; 1024];
        big[..long.len()].copy_from_slice(&long);
        let region = HtxRegion { head_start: 0, head_end: long.len(), reserve_start: 512 };
        let mut s = HtxSlice::over_received(&mut big, region).unwrap();
        assert_eq!(s.push_header_in_place(0..300, 302..303), Err(HtxError::LimitExceeded));
    }

    /// The invariants check names a region out of order and a block outside it; slices that
    /// differ by a header name are not equal; the debug form shows in-place fields.
    #[test]
    fn invariants_equality_and_debug_know_the_gap() {
        let head = b"GET / HTTP/1.1\r\nHost: h\r\nX-A: 1\r\n\r\n";
        let p = placed(head, b"", 256, false);
        let v = HtxSliceRef::new(&p.buf, p.blocks);
        assert!(v.check_invariants_in(p.tail, p.region).is_ok());
        let late = HtxRegion { reserve_start: p.tail + 1, ..p.region };
        assert!(v.check_invariants_in(p.tail, late).unwrap_err().contains("out of order"));
        // A head shorter than the one indexed leaves its blocks outside.
        let short = HtxRegion { head_end: p.region.head_start + 5, ..p.region };
        assert!(v.check_invariants_in(p.tail, short).unwrap_err().contains("outside"));
        let other = placed(b"GET / HTTP/1.1\r\nHost: h\r\nX-B: 1\r\n\r\n", b"", 256, false);
        assert!(v != HtxSliceRef::new(&other.buf, other.blocks));
        assert!(v == HtxSliceRef::new(&p.buf, p.blocks));
        let c = copied(head, false);
        assert!(v == HtxSliceRef::new(&c.buf, c.blocks), "in place and copied hold the same blocks");
        assert!(format!("{v:?}").contains("(\"X-A\", \"1\")"));
        let mut t = vec![0u8; 512];
        let mut s = HtxSlice::new(&mut t);
        s.push_trailer("x-t", "tv").unwrap();
        assert!(format!("{:?}", s.as_ref()).contains("(\"Trailer\", \"x-t\", \"tv\")"));
    }

    /// A trailer continued after another block moves to the tail whole (name, then value),
    /// and a trailer at the tail gives its trimmed blanks back.
    #[test]
    fn trailers_move_and_trim_as_fields() {
        let mut t = vec![0u8; 512];
        let mut s = HtxSlice::new(&mut t);
        s.push_trailer("x-t", " a ").unwrap();
        s.finalize_last_trailer();
        let tail = s.tail_addr();
        assert_eq!(tail, 4, "the blanks at the tail are given back");
        s.push_data(b"zz").unwrap();
        s.append_to_last_trailer("bc").unwrap();
        assert_eq!(s.trailers().collect::<Vec<_>>(), [("x-t", "abc")]);
        s.check_invariants().unwrap();
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

/// CP1 (`docs/design/copies-2026-11-02.md` section 6, row S1): `write_request_htx` over the
/// decoded fields writes the blocks, and refuses the heads, that the h2 mux's former
/// `H2ReqHead::write` followed by `HtxSlice::put_request_head` did. The reference is the golden
/// files (CP2b-2: the live code is gone), dumped from it; the expected values behind it are
/// pinned by T437/T449/T451/E1 (`h2_field_validity.rs`) and were measured on ``HAProxy``
/// 3.5-dev8 then, so no row here doubts them.
mod request_head_writer {
    use alcyon_proto::h2::{write_request_htx, HeadError};
    use alcyon_proto::hpack::{DecodedFields, HpackDecoder, HpackEncoder};
    use alcyon_proto::htx::{HtxSlice, RxHead};
    use proptest::prelude::*;

    type Fields = Vec<(Vec<u8>, Vec<u8>)>;

    fn row(f: &[(&[u8], &[u8])]) -> Fields {
        f.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect()
    }

    /// The pseudo-headers of a plain GET, then `more`.
    fn get(more: &[(&[u8], &[u8])]) -> Fields {
        let mut f = row(&[(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/p?q=1"), (b":authority", b"example.com")]);
        f.extend(row(more));
        f
    }

    fn block(fields: &Fields) -> Vec<u8> {
        let mut enc = HpackEncoder::new();
        let mut b = Vec::new();
        for (n, v) in fields {
            enc.encode_field_bytes(n, v, &mut b);
        }
        b
    }

    fn decoded(fields: &Fields) -> DecodedFields {
        let mut d = DecodedFields::default();
        HpackDecoder::new().decode_into(&block(fields), &mut d).expect("decodes");
        d
    }

    /// The golden file: for every row of the corpus, on every memory, under both settings of
    /// `accept-unsafe-violations-in-http-request`, what `H2ReqHead::write` + `put_request_head`
    /// made of the head (CP2b-1, the reference the writer was built against, dumped before it
    /// went): the verdict, and for a written head its facts and its blocks.
    const GOLDEN: &str = include_str!("../data/htx_request_head_golden.txt");

    /// One line of the golden file: tab-separated `name`, `relaxed`, `cap`, the verdict
    /// (`Ok`, `Refused`, `Invalid`, `NoRoom`) and, for `Ok`, the facts and the blocks.
    fn golden_line(name: &str, relaxed: bool, cap: usize, verdict: &Result<(), HeadError>, facts: &str, blocks: &str) -> String {
        let v = match verdict {
            Ok(()) => "Ok",
            Err(HeadError::Refused(_)) => "Refused",
            Err(HeadError::Invalid) => "Invalid",
            Err(HeadError::NoRoom) => "NoRoom",
        };
        if verdict.is_ok() { format!("{name}\t{relaxed}\t{cap}\t{v}\t{facts}\t{blocks}") } else { format!("{name}\t{relaxed}\t{cap}\t{v}") }
    }

    /// The golden line of what the writer makes.
    fn new_line(name: &str, fields: &Fields, relaxed: bool, cap: usize) -> String {
        let mut mem = vec![0u8; cap];
        let mut slice = HtxSlice::new(&mut mem);
        let r = write_request_htx(&decoded(fields), &mut slice, relaxed);
        match r {
            Ok(f) => {
                let facts = format!(
                    "{} {} {} {:?} {} {} {} {} {} {} {} {}",
                    f.tail, f.blocks, f.bad_request, f.content_length, f.ext_connect, f.method_len, f.uri_len, f.path_raw, f.has_abs, f.fields, f.field_bytes, f.wire_len()
                );
                golden_line(name, relaxed, cap, &Ok(()), &facts, &format!("{:?}", slice.as_ref()))
            }
            Err(e) => golden_line(name, relaxed, cap, &Err(e), "", ""),
        }
    }

    /// The memories a row runs on:
    /// The memories a row runs on: a normal buffer and several too small ones, so that every
    /// write of the head is the one that finds no room in some run.
    const CAPS: [usize; 9] = [64, 96, 128, 160, 200, 256, 400, 1024, 16384];

    fn corpus() -> Vec<(&'static str, Fields)> {
        let long = |c: u8, n: usize| vec![c; n];
        let mut rows: Vec<(&'static str, Fields)> = vec![
            ("plain", get(&[])),
            ("authority first", row(&[(b":authority", b"a.test"), (b":path", b"/"), (b":scheme", b"http"), (b":method", b"POST")])),
            ("no scheme", row(&[(b":method", b"GET"), (b":path", b"/x"), (b":authority", b"a.test")])),
            ("no authority", row(&[(b":method", b"GET"), (b":path", b"/x"), (b":scheme", b"https"), (b"host", b"h.test")])),
            ("no path", row(&[(b":method", b"CONNECT"), (b":authority", b"a.test:443")])),
            ("empty path", row(&[(b":method", b"GET"), (b":path", b""), (b":authority", b"a")])),
            ("no method", row(&[(b":path", b"/"), (b":authority", b"a")])),
            ("dup method", row(&[(b":method", b"GET"), (b":method", b"GET"), (b":path", b"/")])),
            ("dup path", row(&[(b":method", b"GET"), (b":path", b"/"), (b":path", b"/")])),
            ("dup authority", row(&[(b":method", b"GET"), (b":path", b"/"), (b":authority", b"a"), (b":authority", b"a")])),
            ("dup scheme", row(&[(b":method", b"GET"), (b":path", b"/"), (b":scheme", b"http"), (b":scheme", b"http")])),
            ("dup protocol", row(&[(b":method", b"CONNECT"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"a"), (b":protocol", b"websocket"), (b":protocol", b"websocket")])),
            ("pseudo after regular", get(&[(b"x-a", b"1"), (b":method", b"GET")])),
            ("unknown pseudo", get(&[]).into_iter().chain(row(&[(b":foo", b"1")])).collect()),
            ("status pseudo", row(&[(b":method", b"GET"), (b":path", b"/"), (b":status", b"200")])),
            ("authority and equal host", get(&[(b"host", b"example.com")])),
            ("authority and host in another case", get(&[(b"host", b"EXAMPLE.com")])),
            ("authority and other host", get(&[(b"host", b"other.test")])),
            ("two hosts", get(&[(b"host", b"example.com"), (b"x", b"1"), (b"host", b"example.com")])),
            ("two different hosts", row(&[(b":method", b"GET"), (b":path", b"/"), (b"host", b"a"), (b"host", b"b")])),
            ("host in blanks", row(&[(b":method", b"GET"), (b":path", b"/"), (b"host", b"  a.test \t")])),
            ("empty host", row(&[(b":method", b"GET"), (b":path", b"/"), (b"host", b"")])),
            ("empty authority", row(&[(b":method", b"GET"), (b":path", b"/"), (b":authority", b""), (b":scheme", b"https")])),
            ("default port", row(&[(b":method", b"GET"), (b":path", b"/"), (b":authority", b"example.com:443"), (b":scheme", b"https")])),
            ("extended connect", row(&[(b":method", b"CONNECT"), (b":scheme", b"https"), (b":path", b"/chat"), (b":authority", b"a.test"), (b":protocol", b"websocket"), (b"sec-websocket-version", b"13")])),
            ("extended connect no scheme", row(&[(b":method", b"CONNECT"), (b":path", b"/chat"), (b":authority", b"a.test"), (b":protocol", b"websocket")])),
            ("extended connect no path", row(&[(b":method", b"CONNECT"), (b":scheme", b"https"), (b":authority", b"a.test"), (b":protocol", b"websocket")])),
            ("extended connect no authority", row(&[(b":method", b"CONNECT"), (b":scheme", b"https"), (b":path", b"/"), (b":protocol", b"websocket")])),
            ("extended connect to h2c", row(&[(b":method", b"CONNECT"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"a"), (b":protocol", b"h2c")])),
            ("extended connect to H2", row(&[(b":method", b"CONNECT"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"a"), (b":protocol", b"H2")])),
            ("protocol not text", row(&[(b":method", b"CONNECT"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"a"), (b":protocol", b"\xff")])),
            ("connect", row(&[(b":method", b"CONNECT"), (b":authority", b"a.test:443")])),
            ("lower case method", row(&[(b":method", b"get"), (b":path", b"/")])),
            ("method with a blank", row(&[(b":method", b"GE T"), (b":path", b"/")])),
            ("empty method", row(&[(b":method", b""), (b":path", b"/")])),
            ("method not text", row(&[(b":method", b"G\xe9T"), (b":path", b"/")])),
            ("scheme not a scheme", row(&[(b":method", b"GET"), (b":path", b"/"), (b":scheme", b"1http"), (b":authority", b"a")])),
            ("scheme not text, no authority", row(&[(b":method", b"GET"), (b":path", b"/"), (b":scheme", b"ht\xfftp")])),
            ("scheme not text", row(&[(b":method", b"GET"), (b":path", b"/"), (b":scheme", b"ht\xfftp"), (b":authority", b"a")])),
            ("authority not text", row(&[(b":method", b"GET"), (b":path", b"/"), (b":authority", b"a\xe9")])),
            ("star with authority", row(&[(b":method", b"GET"), (b":path", b"*"), (b":authority", b"a"), (b":scheme", b"http")])),
            ("options star with authority", row(&[(b":method", b"OPTIONS"), (b":path", b"*"), (b":authority", b"a"), (b":scheme", b"http")])),
            ("star without authority", row(&[(b":method", b"OPTIONS"), (b":path", b"*"), (b"host", b"a")])),
            ("path with a blank", row(&[(b":method", b"GET"), (b":path", b"/a b")])),
            ("path with a hash", row(&[(b":method", b"GET"), (b":path", b"/a#b")])),
            ("path with DEL", row(&[(b":method", b"GET"), (b":path", b"/a\x7fb")])),
            ("path not absolute", row(&[(b":method", b"GET"), (b":path", b"a")])),
            ("latin-1 path", row(&[(b":method", b"GET"), (b":path", b"/caf\xe9"), (b":authority", b"a"), (b":scheme", b"http")])),
            ("escape character in a path", row(&[(b":method", b"GET"), (b":path", "/\u{f780}".as_bytes())])),
            ("two content-length", get(&[(b"content-length", b"5"), (b"content-length", b"5")])),
            ("conflicting content-length", get(&[(b"content-length", b"5"), (b"content-length", b"6")])),
            ("content-length list", get(&[(b"content-length", b"5, 5")])),
            ("content-length list conflict", get(&[(b"content-length", b"5, 6")])),
            ("content-length letters", get(&[(b"content-length", b"abc")])),
            ("content-length not text", get(&[(b"content-length", b"5\xe9")])),
            ("content-length padded", get(&[(b"content-length", b"005")])),
            ("content-length zero", get(&[(b"content-length", b"0")])),
            ("content-length empty", get(&[(b"content-length", b"")])),
            ("content-length u64 max", get(&[(b"content-length", b"18446744073709551615")])),
            ("content-length past u64", get(&[(b"content-length", b"18446744073709551616")])),
            ("content-length in blanks", get(&[(b"content-length", b" 7 ")])),
            ("value not text", get(&[(b"x-a", b"caf\xe9")])),
            ("value with an escape character", get(&[(b"x-a", "a\u{f781}b".as_bytes())])),
            ("value in blanks", get(&[(b"x-a", b" \t v \t ")])),
            ("value all blanks", get(&[(b"x-a", b" \t ")])),
            ("empty value", get(&[(b"x-a", b"")])),
            ("one cookie", get(&[(b"cookie", b"a=1")])),
            ("cookies", get(&[(b"cookie", b"a=1"), (b"x-a", b"1"), (b"cookie", b" b=2 "), (b"cookie", b"")])),
            ("cookie not text", get(&[(b"cookie", b"a=1"), (b"cookie", b"b=\xff")])),
            ("cookie with an escape character", get(&[(b"cookie", "a=\u{f782}".as_bytes()), (b"cookie", b"b=2")])),
            ("cookie before host", row(&[(b":method", b"GET"), (b":path", b"/"), (b"cookie", b"a=1"), (b"host", b"h"), (b"cookie", b"b=2")])),
            ("upper case name", get(&[(b"X-A", b"1")])),
            ("empty name", get(&[(b"", b"1")])),
            ("name not text", get(&[(b"x-\xe9", b"1")])),
            ("CR in a value", get(&[(b"x-a", b"1\r\nx: 2")])),
            ("NUL in a value", get(&[(b"x-a", b"1\0")])),
            ("tab and controls in a value", get(&[(b"x-a", b"a\t\x01\x7fb")])),
            ("connection", get(&[(b"connection", b"close")])),
            ("keep-alive", get(&[(b"keep-alive", b"1")])),
            ("transfer-encoding", get(&[(b"transfer-encoding", b"chunked")])),
            ("upgrade", get(&[(b"upgrade", b"websocket")])),
            ("te trailers", get(&[(b"te", b"trailers")])),
            ("te gzip", get(&[(b"te", b"gzip")])),
            ("authority with a forbidden character", row(&[(b":method", b"GET"), (b":path", b"/"), (b":authority", b"u@x")])),
            ("many fields", get(&[(b"x-a", b"1"), (b"user-agent", b"ua"), (b"accept", b"*/*"), (b"accept-encoding", b"gzip"), (b"accept-language", b"en"), (b"referer", b"https://r/"), (b"x-b", b"2"), (b"x-c", b"3")])),
        ];
        // The protocol pseudo-header outside an extended CONNECT.
        let mut with_protocol = get(&[]);
        with_protocol.insert(1, (b":protocol".to_vec(), b"websocket".to_vec()));
        rows.push(("protocol on a GET", with_protocol));
        // The limits: 100 fields pass (the host the authority makes counted), 101 do not.
        let many = |n: usize, extra: &[(&[u8], &[u8])]| -> Fields {
            let mut f = row(&[(b":method", b"GET"), (b":path", b"/")]);
            f.extend(extra.iter().map(|(a, b)| (a.to_vec(), b.to_vec())));
            f.extend((0..n).map(|i| (format!("x-{i}").into_bytes(), b"v".to_vec())));
            f
        };
        rows.push(("99 fields", many(99, &[])));
        rows.push(("100 fields", many(100, &[])));
        rows.push(("101 fields", many(101, &[])));
        rows.push(("100 fields and a made host", many(99, &[(b":authority", b"a")])));
        rows.push(("101 with a made host", many(100, &[(b":authority", b"a")])));
        rows.push(("100 fields and a host", many(99, &[(b":authority", b"a"), (b"host", b"a")])));
        rows.push(("100 fields, extended connect", {
            let mut f = many(98, &[(b":authority", b"a"), (b":scheme", b"https"), (b":protocol", b"websocket")]);
            f[0].1 = b"CONNECT".to_vec();
            f
        }));
        rows.push(("100 fields, extended connect, 2 more lines", {
            let mut f = many(100, &[(b":authority", b"a"), (b":scheme", b"https"), (b":protocol", b"websocket")]);
            f[0].1 = b"CONNECT".to_vec();
            f
        }));
        // The size: 15,360 bytes of names and values pass, one more does not.
        let sized = |total: usize| -> Fields {
            let mut f = row(&[(b":method", b"GET"), (b":path", b"/")]);
            let used: usize = f.iter().map(|(n, v)| n.len() + v.len()).sum();
            f.push((b"x-big".to_vec(), long(b'a', total - used - 5)));
            f
        };
        rows.push(("15360 bytes", sized(15_360)));
        rows.push(("15361 bytes", sized(15_361)));
        rows.push(("15400 bytes", sized(15_400)));
        rows.push(("a long cookie", get(&[(b"cookie", &long(b'c', 3000)), (b"cookie", &long(b'd', 3000))])));
        rows
    }

    /// The writer's blocks, facts and verdicts for the whole corpus are those in the golden
    /// file (CP2b-1: dumped from `H2ReqHead::write` + `put_request_head`, which are gone).
    #[test]
    fn the_written_head_is_the_one_in_the_golden_file() {
        let mut want = GOLDEN.lines();
        let (mut written, mut refused, mut parser_refused, mut no_room, mut bad) = (0, 0, 0, 0, 0);
        for (name, fields) in corpus() {
            for relaxed in [false, true] {
                for cap in CAPS {
                    let line = new_line(name, &fields, relaxed, cap);
                    assert_eq!(Some(line.as_str()), want.next(), "{name} (cap {cap}, relaxed {relaxed})");
                    match line.split('\t').nth(3) {
                        Some("Ok") => written += 1,
                        Some("Refused") => refused += 1,
                        Some("Invalid") => parser_refused += 1,
                        _ => no_room += 1,
                    }
                    bad += usize::from(line.split('\t').nth(4).is_some_and(|f| f.split(' ').nth(2) == Some("true")));
                }
            }
        }
        assert_eq!(want.next(), None, "the golden file has rows the corpus lost");
        // The corpus reaches every verdict, so the comparison above is not vacuous.
        assert!(written > 300 && refused > 400 && parser_refused > 20 && no_room > 100 && bad >= 5, "{written} {refused} {parser_refused} {no_room} {bad}");
    }

    /// The text golden file: for every row the HTTP/1 checks refuse (`Invalid` on the large
    /// memory), the head as the HTTP/1.1 text `H2ReqHead::to_wire` made of it, which is what
    /// the data path forwards (CP2b-2, dumped before the live reference went).
    const TEXT_GOLDEN: &str = include_str!("../data/htx_request_text_golden.txt");

    fn text_line(name: &str, fields: &Fields, relaxed: bool) -> Option<String> {
        let t = alcyon_proto::h2::write_request_text(&decoded(fields), relaxed, None).ok()?;
        Some(format!("{name}\t{relaxed}\t{}\t{}\t{}\t{}", t.wire.escape_ascii(), t.facts.method_len, t.facts.uri_len, t.facts.field_bytes))
    }

    /// The text of a head the HTTP/1 checks refuse is the one in the golden file; every other
    /// row has no text (the writer makes its blocks).
    #[test]
    fn the_text_of_a_refused_head_is_the_one_in_the_text_golden_file() {
        let mut want = TEXT_GOLDEN.lines();
        let mut n = 0;
        for (name, fields) in corpus() {
            for relaxed in [false, true] {
                let mut mem = vec![0u8; 16384];
                let invalid = matches!(write_request_htx(&decoded(&fields), &mut HtxSlice::new(&mut mem), relaxed), Err(HeadError::Invalid));
                if !invalid {
                    continue;
                }
                let line = text_line(name, &fields, relaxed).expect("a head the checks refuse has its text");
                assert_eq!(Some(line.as_str()), want.next(), "{name} (relaxed {relaxed})");
                n += 1;
            }
        }
        assert_eq!(want.next(), None, "the golden file has rows the corpus lost");
        assert!(n >= 20, "{n}");
    }

    /// The blocks writer and the text writer scan the same fields: one refuses what the other
    /// refuses, and where the blocks are written they agree on what the head is made of.
    fn the_two_writers_agree(name: &str, fields: &Fields, relaxed: bool, cap: usize) {
        let d = decoded(fields);
        let mut mem = vec![0u8; cap];
        let blocks = write_request_htx(&d, &mut HtxSlice::new(&mut mem), relaxed);
        let text = alcyon_proto::h2::write_request_text(&d, relaxed, None);
        let ctx = format!("{name} (cap {cap}, relaxed {relaxed}): {fields:?}");
        match (&blocks, &text) {
            (Err(HeadError::Refused(_)), Err(HeadError::Refused(_))) => {}
            (Ok(f), Ok(t)) => {
                let g = &t.facts;
                assert_eq!((f.method_len, f.uri_len, f.path_raw, f.has_abs, f.fields, f.field_bytes, f.cl_bytes), (g.method_len, g.uri_len, g.path_raw, g.has_abs, g.fields, g.field_bytes, g.cl_bytes), "{ctx}");
                assert_eq!((f.bad_request, f.content_length, f.ext_connect), (g.bad_request, g.content_length, g.ext_connect), "{ctx}");
                assert_eq!(f.wire_len(), t.wire.len(), "{ctx}");
            }
            (Err(HeadError::Invalid | HeadError::NoRoom), Ok(_)) => {}
            (a, b) => panic!("{ctx}: blocks {a:?}, text {:?}", b.as_ref().map(|t| t.facts)),
        }
    }

    #[test]
    fn the_writers_agree_on_the_corpus() {
        for (name, fields) in corpus() {
            for relaxed in [false, true] {
                for cap in CAPS {
                    the_two_writers_agree(name, &fields, relaxed, cap);
                }
            }
        }
    }

    /// E1, kept from the bridge's test: the blocks the writer makes of a head are the ones the
    /// HTTP/1 parser makes of the same head as text ([`alcyon_proto::h2::TextHead`]), and so is the
    /// head written from them; a head the parser refuses, the writer finds `Invalid`.
    #[test]
    fn the_blocks_written_are_the_parsers_of_the_text() {
        let mut compared = 0;
        for (name, fields) in corpus() {
            let d = decoded(&fields);
            let (mut a, mut b) = (vec![0u8; 16384], vec![0u8; 16384]);
            let mut put = HtxSlice::new(&mut a);
            let written = write_request_htx(&d, &mut put, false);
            let Ok(text) = alcyon_proto::h2::write_request_text(&d, false, None) else { continue };
            let mut parsed = HtxSlice::new(&mut b);
            let parse_ok = alcyon_proto::H1Parser::new(false).parse(&text.wire, &mut parsed).is_ok();
            let shown = String::from_utf8_lossy(&text.wire);
            assert_eq!(written.is_ok(), parse_ok, "{name}: {shown}");
            if written.is_ok() {
                // `Invalid` is where the parser refuses; a head the parser takes has the same
                // blocks. (The cookie's blanks are kept by the writer, the parser trims them.)
                if !shown.contains("cookie") {
                    assert_eq!(put.to_blocks(), parsed.to_blocks(), "{name}: {shown}");
                    assert_eq!(put.to_h1_wire(), parsed.to_h1_wire(), "{name}: {shown}");
                    compared += 1;
                }
            }
        }
        assert!(compared > 30, "{compared}");
    }

    #[test]
    fn rows_whose_head_is_known() {
        let d = |f: &Fields| {
            let mut mem = vec![0u8; 16384];
            let mut s = HtxSlice::new(&mut mem);
            let facts = write_request_htx(&decoded(f), &mut s, false).expect("written");
            (facts, format!("{:?}", s.as_ref()))
        };
        // The made host leads, the cookies are one line at the end, the ASCII fast path of the joined value.
        let (facts, blocks) = d(&get(&[(b"cookie", b"a=1"), (b"x-a", b" v "), (b"cookie", b"b=2")]));
        assert!(facts.has_abs && !facts.ext_connect && !facts.bad_request && facts.content_length.is_none());
        let at = |s: &str| blocks.find(s).unwrap_or_else(|| panic!("{s} in {blocks}"));
        assert!(at("example.com") < at("x-a") && at("x-a") < at("a=1; b=2"), "{blocks}");
        let (facts, _) = d(&get(&[(b"content-length", b"5, 5")]));
        assert_eq!((facts.content_length, facts.wire_len() > 40), (Some(5), true));
    }

    /// `HeadError` of the heads the mux refuses is `Refused`, and of the ones the parser does
    /// `Invalid`; the messages name the rule.
    #[test]
    fn a_refusal_names_the_rule() {
        let why = |f: &Fields| {
            let mut mem = vec![0u8; 16384];
            write_request_htx(&decoded(f), &mut HtxSlice::new(&mut mem), false).expect_err("refused")
        };
        assert_eq!(why(&get(&[(b"x-a", b"1\0")])), HeadError::Refused("malformed field"));
        assert_eq!(why(&row(&[(b":path", b"/")])), HeadError::Refused("no :method"));
        assert_eq!(why(&row(&[(b":method", b"GE T"), (b":path", b"/")])), HeadError::Invalid);
        let mut mem = vec![0u8; 64];
        assert_eq!(write_request_htx(&decoded(&get(&[])), &mut HtxSlice::new(&mut mem), false), Err(HeadError::NoRoom));
    }

    /// The memory the head is written into is the memory of a buffer: `HtxSlice::over` an
    /// `RxHead` is the HTX of a boxed slice, and the box comes back out as it went in.
    #[test]
    fn a_head_is_written_into_an_rx_head_and_the_box_comes_back() {
        let mut rx = RxHead::from_box(vec![0u8; 2048].into_boxed_slice());
        assert!(!rx.is_empty());
        let facts = {
            let mut s = HtxSlice::over(&mut rx);
            write_request_htx(&decoded(&get(&[(b"x-a", b"1")])), &mut s, false).expect("written")
        };
        assert!(facts.tail > 0 && facts.blocks == 5, "{facts:?}");
        assert_eq!(rx.len(), 2048);
        let mem = rx.into_box();
        assert_eq!(mem.len(), 2048);
        assert!(RxHead::from_box(Box::new([])).is_empty());
    }

    /// The joined header refuses what `push_header_bytes` refuses: a name past 255 bytes (the
    /// writer's own name is `cookie`, so only a direct call reaches it).
    #[test]
    fn a_joined_header_has_the_limits_of_a_header() {
        use alcyon_proto::htx::HtxError;
        let mut mem = vec![0u8; 512];
        let mut s = HtxSlice::new(&mut mem);
        let name = "n".repeat(256);
        assert_eq!(s.push_header_joined(&name, b"a", [&b"b"[..]].into_iter()), Err(HtxError::LimitExceeded));
        assert_eq!(s.num_blocks(), 0);
    }

    fn token() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            Just(b"x-a".to_vec()), Just(b"host".to_vec()), Just(b"cookie".to_vec()), Just(b"content-length".to_vec()),
            Just(b"te".to_vec()), Just(b"X-Up".to_vec()), Just(b":path".to_vec()), Just(b":authority".to_vec()),
            Just(b":scheme".to_vec()), Just(b":method".to_vec()), Just(b":protocol".to_vec()), Just(b":status".to_vec()),
        ]
    }

    fn value() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            Just(b"GET".to_vec()), Just(b"CONNECT".to_vec()), Just(b"/".to_vec()), Just(b"*".to_vec()), Just(b"/a?b".to_vec()),
            Just(b"a.test".to_vec()), Just(b"https".to_vec()), Just(b"websocket".to_vec()), Just(b"5".to_vec()), Just(b"6".to_vec()),
            Just(b" v ".to_vec()), Just(b"a=1".to_vec()), Just(b"\xe9".to_vec()), Just(b"".to_vec()), Just(b"trailers".to_vec()),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(400))]

        /// Random field lists over the names and values the rules look at: whatever the
        /// pseudo-headers' order, duplicates and values, the two writers agree.
        #[test]
        fn random_heads_have_one_scan(fields in prop::collection::vec((token(), value()), 0..9), relaxed in any::<bool>(), cap in prop::sample::select(CAPS.to_vec())) {
            the_two_writers_agree("random", &fields, relaxed, cap);
        }
    }
}
