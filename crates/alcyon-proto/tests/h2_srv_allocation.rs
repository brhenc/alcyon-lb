// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T537): installs a counting #[global_allocator] and asserts on this thread's allocations

//! Allocations of the h2 server codec (`alcyon_proto::h2_srv`) per request (AGENTS.md section 8).

use alcyon_alloc::CountingAllocator;

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

/// T537: a warm h2 server codec (`alcyon_proto::h2_srv`) allocates nothing per request: a
/// GET with headers, a POST with a content-length body, a chunked POST with trailers, and
/// their responses (content-length, chunked with trailers), each a stream of their own on the
/// same connection, once the codec's buffers and HPACK table have grown.
#[test]
fn a_warm_h2_server_codec_allocates_nothing_per_request() {
    use alcyon_proto::h2_srv::H2SrvCodec;
    fn fr(t: u8, f: u8, sid: u32, p: &[u8], out: &mut Vec<u8>) {
        let n = p.len();
        out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8, t, f]);
        out.extend_from_slice(&sid.to_be_bytes());
        out.extend_from_slice(p);
    }
    // :status 200 (indexed), content-length: 5 (incremental, indexed name), x-srv: a
    // (incremental, new name: the second round finds both in the dynamic table).
    let head_cl: &[u8] = b"\x88\x5c\x015\x40\x05x-srv\x01a";
    let head: &[u8] = b"\x88\x40\x05x-srv\x01a";
    let trailer: &[u8] = b"\x40\x05x-trl\x011";
    let reqs: [&[u8]; 3] = [
        b"GET /a/b?c=d HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\nCookie: a=1\r\nX-Forwarded-For: 10.0.0.1\r\n\r\n",
        b"POST /up HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world",
        b"POST /up HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTE: trailers\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nx-rt: 9\r\n\r\n",
    ];
    let mut c = H2SrvCodec::new();
    let mut rx = Vec::with_capacity(4096);
    fr(4, 0, 0, &[], &mut rx);
    c.receive(&rx).unwrap();
    let n = c.output().len();
    c.advance_output(n);
    let mut sid = 1u32;
    let round = |c: &mut H2SrvCodec, rx: &mut Vec<u8>, sid: &mut u32| {
        for (i, req) in reqs.iter().enumerate() {
            assert_eq!(c.send_request(req).unwrap(), req.len());
            let n = c.output().len();
            c.advance_output(n);
            rx.clear();
            if i == 2 {
                fr(1, 4, *sid, head, rx);
                fr(0, 0, *sid, b"hello", rx);
                fr(1, 5, *sid, trailer, rx);
            } else {
                fr(1, 4, *sid, head_cl, rx);
                fr(0, 1, *sid, b"hello", rx);
            }
            c.receive(rx).unwrap();
            let n = c.response().len();
            assert!(n > 0);
            c.advance_response(n);
            let n = c.output().len();
            c.advance_output(n);
            assert!(c.response_complete() && c.reusable());
            *sid += 2;
        }
    };
    // Every response inserts its literals into the decoder's dynamic table (as HAProxy's
    // stateless encoder makes a server do): warm until the 4096-byte table turns over, from
    // when each insert reuses the memory of the entry it evicts.
    for _ in 0..40 {
        round(&mut c, &mut rx, &mut sid);
    }
    let before = alcyon_alloc::thread_alloc_counters();
    for _ in 0..10 {
        round(&mut c, &mut rx, &mut sid);
    }
    let diff = before.diff(&alcyon_alloc::thread_alloc_counters());
    assert_eq!((diff.alloc_count, diff.realloc_count), (0, 0), "30 warm requests and responses: {diff:?}");
}
