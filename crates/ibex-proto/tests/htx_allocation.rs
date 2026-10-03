// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Allocation oracle for HTX request parsing (nudge-agy-htx.md Stage 0).

use ibex_alloc::CountingAllocator;
use ibex_proto::h1::H1Parser;
use ibex_proto::htx::HtxSlice;

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

#[test]
fn parsing_a_request_into_htx_allocates_nothing() {
    let mut parser = H1Parser::new(false);
    let req = b"GET /index.html?query=test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\nContent-Length: 11\r\n\r\nhello world";

    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    let before = ibex_alloc::alloc_counters();
    let consumed = parser.parse(req, &mut htx).expect("parse request");
    let after = ibex_alloc::alloc_counters();

    let diff = before.diff(&after);
    assert_eq!(consumed, req.len());
    assert_eq!(
        diff.alloc_count, 0,
        "parsing a request into HTX must not allocate on the heap, got: {diff:?}"
    );
    assert_eq!(
        diff.bytes_allocated, 0,
        "parsing a request into HTX must not allocate bytes, got: {diff:?}"
    );
}
