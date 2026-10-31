// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T537 (slice B-H1 of T535): the h1↔h2 server-side codec, frame vectors both ways.
//!
//! Every request vector is the wire HAProxy 3.5-dev8 (`~/reference/haproxy/haproxy`) wrote to
//! an h2c server (`server s1 127.0.0.1:64201 proto h2`) for the same HTTP/1.1 request,
//! captured 2026-10-31 by a scripted h2 server that logs each frame it reads
//! (`~/ibex-worktrees/review/t537-2026-10-31/h2srv.py`, rig in `tasks/T537-progress.md`).
//! Every response expectation is the HTTP/1.1 text HAProxy gave an h1 client for the same
//! server frames.

#![allow(clippy::doc_markdown, clippy::many_single_char_names, clippy::type_complexity)]

use ibex_proto::h2::H2_CONN_PREFACE;
use ibex_proto::h2_srv::{H2SrvCodec, SrvH2Error};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn fr(t: u8, f: u8, sid: u32, p: &[u8]) -> Vec<u8> {
    let n = p.len();
    let mut v = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, t, f];
    v.extend_from_slice(&sid.to_be_bytes());
    v.extend_from_slice(p);
    v
}

/// Literal without indexing, new name, no Huffman (what the scripted server sends).
fn lit(n: &str, v: &str) -> Vec<u8> {
    let mut b = vec![0, n.len() as u8];
    b.extend_from_slice(n.as_bytes());
    b.push(v.len() as u8);
    b.extend_from_slice(v.as_bytes());
    b
}

fn hdrs(sid: u32, fields: &[Vec<u8>], es: bool) -> Vec<u8> {
    fr(1, 4 | u8::from(es), sid, &fields.concat())
}

fn data(sid: u32, d: &[u8], es: bool) -> Vec<u8> {
    fr(0, u8::from(es), sid, d)
}

/// HAProxy's preface and SETTINGS (ENABLE_PUSH 0, ENABLE_CONNECT_PROTOCOL 1,
/// INITIAL_WINDOW_SIZE 16384, MAX_CONCURRENT_STREAMS 100, in that order).
const HAPROXY_SETTINGS: &str = "000018040000000000000200000000000800000001000400004000000300000064";

fn take_out(c: &mut H2SrvCodec) -> Vec<u8> {
    let v = c.output().to_vec();
    c.advance_output(v.len());
    v
}

fn take_rsp(c: &mut H2SrvCodec) -> Vec<u8> {
    let v = c.response().to_vec();
    c.advance_response(v.len());
    v
}

/// A codec past the preface, the server's empty SETTINGS read and answered.
fn ready() -> H2SrvCodec {
    let mut c = H2SrvCodec::new();
    let _ = take_out(&mut c);
    c.receive(&fr(4, 0, 0, &[])).unwrap();
    let _ = take_out(&mut c);
    c
}

/// Sends `req` whole, returns the frames written for it.
fn request(c: &mut H2SrvCodec, req: &[u8]) -> Vec<u8> {
    let n = c.send_request(req).unwrap();
    assert_eq!(n, req.len(), "request consumed whole");
    take_out(c)
}

#[test]
fn preface_and_settings_are_haproxys_then_ack_and_window_update_after_the_servers_settings() {
    let mut c = H2SrvCodec::new();
    let mut want = H2_CONN_PREFACE.to_vec();
    want.extend(hex(HAPROXY_SETTINGS));
    assert_eq!(take_out(&mut c), want);
    // The server's SETTINGS: a SETTINGS ACK.
    c.receive(&fr(4, 0, 0, &[])).unwrap();
    assert_eq!(take_out(&mut c), hex("000000040100000000"));
    // A SETTINGS ACK from the server is answered by nothing.
    c.receive(&fr(4, 1, 0, &[])).unwrap();
    assert_eq!(c.output(), b"");
}

#[test]
fn get_origin_form_is_method_scheme_https_path_then_host_as_a_header() {
    let mut c = ready();
    let w = request(&mut c, b"GET /sc/cl HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(w, hex("00000d010500000001828744062f73632f636c660178"));
}

#[test]
fn the_encoding_is_stateless_and_static_paths_are_indexed() {
    let mut c = ready();
    let w = request(&mut c, b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: u\r\n\r\n");
    assert_eq!(w, hex("0000090105000000018287846601787a0175"));
    c.receive(&hdrs(1, &[lit(":status", "200"), lit("content-length", "0")], true)).unwrap();
    let _ = take_rsp(&mut c);
    assert!(c.is_idle() && c.reusable());
    let w = request(&mut c, b"GET /index.html HTTP/1.1\r\nHost: x\r\nUser-Agent: u\r\n\r\n");
    assert_eq!(w, hex("0000090105000000038287856601787a0175"), "stream 3, same literals");
}

#[test]
fn absolute_form_gives_scheme_and_authority_and_drops_host() {
    let mut c = ready();
    let w = request(&mut c, b"GET http://h.example:81/sc/a/?q HTTP/1.1\r\nHost: h.example:81\r\nAccept: */*\r\n\r\n");
    assert_eq!(w, hex("00001f0105000000018286410c682e6578616d706c653a383144082f73632f612f3f7153032a2f2a"));
    let mut c = ready();
    let w = request(&mut c, b"GET https://h.example/x HTTP/1.1\r\nHost: h.example\r\nX-Big: VALUE\r\nUser-Agent: u\r\n\r\n");
    assert_eq!(w, hex("00002101050000000182874109682e6578616d706c6544022f780005782d6269670556414c55457a0175"));
}

#[test]
fn options_asterisk_and_a_method_not_in_the_table() {
    let mut c = ready();
    let w = request(&mut c, b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(w, hex("00001001050000000142074f5054494f4e538744012a660178"));
}

#[test]
fn connect_is_refused_per_request() {
    let mut c = ready();
    assert!(matches!(c.send_request(b"CONNECT h.example:443 HTTP/1.1\r\nHost: h.example:443\r\n\r\n"), Err(SrvH2Error::Unsupported(_))));
}

#[test]
fn hop_by_hop_fields_dropped_te_kept_as_trailers_chunked_body_and_trailers() {
    let mut c = ready();
    let req = b"POST /sc/a/ HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, x-foo\r\nKeep-Alive: 5\r\nX-Foo: 1\r\nUpgrade: h2c\r\nTE: trailers, deflate\r\nProxy-Connection: x\r\nCookie: a=1; b=2\r\nCookie: c=3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\nx-rt: 9\r\ngrpc-x: y\r\n\r\n";
    let w = request(&mut c, req);
    let mut want = hex("000032010400000001838744062f73632f612f6601780005782d666f6f01310002746508747261696c6572736008613d313b20623d326003633d33");
    want.extend(hex("0000050000000000016162636465"));
    want.extend(hex("0000120105000000010004782d727401390006677270632d780179"));
    assert_eq!(w, want);
}

#[test]
fn te_without_trailers_is_dropped() {
    let mut c = ready();
    let w = request(&mut c, b"GET / HTTP/1.1\r\nHost: x\r\nTE: gzip\r\nTE: trailersx\r\n\r\n");
    assert_eq!(w, hex("000006010500000001828784660178"));
}

#[test]
fn chunked_body_without_trailers_ends_on_an_empty_data_frame() {
    let mut c = ready();
    let w = request(&mut c, b"POST /sc/a/ HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
    assert_eq!(w, hex("00000d010400000001838744062f73632f612f660178000003000000000001616263000000000100000001"));
    let mut c = ready();
    let w = request(&mut c, b"POST /sc/a/ HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    assert_eq!(w, hex("00000d010400000001838744062f73632f612f660178000000000100000001"));
}

#[test]
fn chunked_body_split_anywhere_gives_the_same_bytes() {
    let req: &[u8] = b"POST /p HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nx-rt: 9\r\n\r\n";
    for cut in 1..req.len() {
        let mut c = ready();
        let mut sent = 0;
        let mut pending = req[..cut].to_vec();
        let mut body = Vec::new();
        let mut trailers = 0;
        for chunk in [&req[cut..], &[][..]] {
            loop {
                let n = c.send_request(&pending).unwrap();
                sent += n;
                pending.drain(..n);
                if n == 0 {
                    break;
                }
            }
            pending.extend_from_slice(chunk);
        }
        loop {
            let n = c.send_request(&pending).unwrap();
            sent += n;
            pending.drain(..n);
            if n == 0 {
                break;
            }
        }
        assert_eq!(sent, req.len(), "cut {cut}");
        let w = take_out(&mut c);
        let mut i = 0;
        while i < w.len() {
            let len = (usize::from(w[i]) << 16) | (usize::from(w[i + 1]) << 8) | usize::from(w[i + 2]);
            if w[i + 3] == 0 {
                body.extend_from_slice(&w[i + 9..i + 9 + len]);
            }
            if w[i + 3] == 1 && i > 0 {
                trailers += 1;
                assert_eq!(w[i + 4], 5, "trailers end the stream");
            }
            i += 9 + len;
        }
        assert_eq!((body.as_slice(), trailers), (&b"abcde"[..], 1), "cut {cut}");
    }
}

#[test]
fn content_length_body_and_zero_length() {
    let mut c = ready();
    let w = request(&mut c, b"POST /sc/a/ HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(w, hex("000010010500000001838744062f73632f612f6601785c0130"));
    let mut c = ready();
    let w = request(&mut c, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc");
    assert_eq!(w, hex("0000090104000000018387846601785c0133000003000100000001616263"), "last DATA carries END_STREAM");
}

#[test]
fn body_waits_for_the_servers_window() {
    let mut c = H2SrvCodec::new();
    let _ = take_out(&mut c);
    // The server's SETTINGS: INITIAL_WINDOW_SIZE 100.
    c.receive(&fr(4, 0, 0, &[0, 4, 0, 0, 0, 100])).unwrap();
    let _ = take_out(&mut c);
    let mut req = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 250\r\n\r\n".to_vec();
    req.extend(std::iter::repeat_n(b'a', 250));
    let head = req.len() - 250;
    assert_eq!(c.send_request(&req).unwrap(), head + 100);
    assert_eq!(c.send_request(&req[head + 100..]).unwrap(), 0, "window spent");
    let w = take_out(&mut c);
    assert!(w.ends_with(&[&[0, 0, 100, 0, 0, 0, 0, 0, 1][..], &[b'a'; 100][..]].concat()));
    c.receive(&fr(8, 0, 1, &200u32.to_be_bytes())).unwrap();
    assert_eq!(c.send_request(&req[head + 100..]).unwrap(), 150);
    let w = take_out(&mut c);
    assert_eq!(&w[..9], &[0, 0, 150, 0, 1, 0, 0, 0, 1], "the rest, END_STREAM");
}

#[test]
fn data_frames_are_at_most_the_servers_max_frame_size() {
    let mut c = ready();
    let mut req = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 40000\r\n\r\n".to_vec();
    req.extend(std::iter::repeat_n(b'z', 40000));
    assert_eq!(c.send_request(&req).unwrap(), req.len());
    let w = take_out(&mut c);
    let mut i = 0;
    let mut sizes = Vec::new();
    while i < w.len() {
        let len = (usize::from(w[i]) << 16) | (usize::from(w[i + 1]) << 8) | usize::from(w[i + 2]);
        if w[i + 3] == 0 {
            sizes.push((len, w[i + 4]));
        }
        i += 9 + len;
    }
    assert_eq!(sizes, vec![(16384, 0), (16384, 0), (7232, 1)]);
}

/// The HTTP/1.1 text HAProxy gave an h1 client for each response the scripted server sent.
fn answer(req: &[u8], frames: &[Vec<u8>]) -> (Vec<u8>, Result<(), SrvH2Error>) {
    let mut c = ready();
    let _ = request(&mut c, req);
    let mut r = Ok(());
    for f in frames {
        r = c.receive(f);
        if r.is_err() {
            break;
        }
    }
    (take_rsp(&mut c), r)
}

fn get(frames: &[Vec<u8>]) -> (Vec<u8>, Result<(), SrvH2Error>) {
    answer(b"GET /x HTTP/1.1\r\nHost: x\r\nTE: trailers\r\n\r\n", frames)
}

fn st(c: &str) -> Vec<u8> {
    lit(":status", c)
}

#[test]
fn responses_as_haproxy_writes_them_for_an_h1_client() {
    let cl5 = || vec![st("200"), lit("content-length", "5"), lit("x-srv", "a")];
    let cases: Vec<(&str, Vec<Vec<u8>>, &[u8])> = vec![
        ("cl", vec![hdrs(1, &cl5(), false), data(1, b"hello", true)], b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-srv: a\r\n\r\nhello"),
        ("nocl", vec![hdrs(1, &[st("200")], false), data(1, b"hello", false), data(1, b"", true)], b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
        (
            "trlcl",
            vec![hdrs(1, &cl5(), false), data(1, b"hello", false), hdrs(1, &[lit("x-trl", "1"), lit("grpc-status", "0")], true)],
            b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-srv: a\r\n\r\nhello",
        ),
        (
            "trlnocl",
            vec![hdrs(1, &[st("200")], false), data(1, b"hello", false), hdrs(1, &[lit("x-trl", "1")], true)],
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nx-trl: 1\r\n\r\n",
        ),
        (
            "1xx",
            vec![hdrs(1, &[st("103"), lit("link", "</s.css>")], false), hdrs(1, &[st("200"), lit("content-length", "2")], false), data(1, b"ok", true)],
            b"HTTP/1.1 103 Informational\r\nlink: </s.css>\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        ),
        (
            "100",
            vec![hdrs(1, &[st("100")], false), hdrs(1, &[st("200"), lit("content-length", "2")], false), data(1, b"ok", true)],
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        ),
        ("es", vec![hdrs(1, &[st("200"), lit("x-srv", "a")], true)], b"HTTP/1.1 200 OK\r\nx-srv: a\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n"),
        ("204", vec![hdrs(1, &[st("204")], true)], b"HTTP/1.1 204 No Content\r\n\r\n"),
        ("404", vec![hdrs(1, &[st("404"), lit("content-length", "0")], true)], b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n"),
        ("299", vec![hdrs(1, &[st("299"), lit("content-length", "0")], true)], b"HTTP/1.1 299 Success\r\ncontent-length: 0\r\n\r\n"),
        (
            "pad",
            vec![
                fr(1, 4 | 8, 1, &[&[3][..], &st("200"), &lit("content-length", "3"), &[0, 0, 0]].concat()),
                fr(0, 1 | 8, 1, b"\x02abc\0\0"),
            ],
            b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nabc",
        ),
        (
            "cont",
            vec![fr(1, 0, 1, &st("200")), fr(9, 4, 1, &[lit("content-length", "3"), lit("x-c", "y")].concat()), data(1, b"abc", true)],
            b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\nx-c: y\r\n\r\nabc",
        ),
        (
            "cookie",
            vec![hdrs(1, &[st("200"), lit("set-cookie", "a=1"), lit("set-cookie", "b=2"), lit("content-length", "0")], true)],
            b"HTTP/1.1 200 OK\r\nset-cookie: a=1\r\nset-cookie: b=2\r\ncontent-length: 0\r\n\r\n",
        ),
    ];
    for (name, frames, want) in cases {
        let (got, r) = get(&frames);
        assert_eq!(r, Ok(()), "{name}");
        assert_eq!(String::from_utf8_lossy(&got), String::from_utf8_lossy(want), "{name}");
    }
}

#[test]
fn head_response_keeps_its_length_and_has_no_body() {
    let (got, r) = answer(b"HEAD /x HTTP/1.1\r\nHost: x\r\n\r\n", &[hdrs(1, &[st("200"), lit("content-length", "1234")], true)]);
    assert_eq!((got.as_slice(), r), (&b"HTTP/1.1 200 OK\r\ncontent-length: 1234\r\n\r\n"[..], Ok(())));
}

#[test]
fn ping_is_acked_and_the_response_follows() {
    let mut c = ready();
    let _ = request(&mut c, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    c.receive(&fr(6, 0, 0, b"12345678")).unwrap();
    assert_eq!(take_out(&mut c), fr(6, 1, 0, b"12345678"));
    c.receive(&[hdrs(1, &[st("200"), lit("content-length", "1")], false), data(1, b"p", true)].concat()).unwrap();
    assert_eq!(take_rsp(&mut c), b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\np");
}

#[test]
fn a_connection_header_in_the_response_is_a_bad_response() {
    // HAProxy: 502, PH--.
    let (_, r) = get(&[hdrs(1, &[st("200"), lit("connection", "close"), lit("content-length", "0")], true)]);
    assert_eq!(r, Err(SrvH2Error::BadResponse));
    let (_, r) = get(&[hdrs(1, &[lit("x-a", "1")], true)]);
    assert_eq!(r, Err(SrvH2Error::BadResponse), "no :status");
    let (_, r) = get(&[data(1, b"x", true)]);
    assert_eq!(r, Err(SrvH2Error::BadResponse), "DATA before HEADERS");
}

#[test]
fn reset_before_the_head_and_after_it() {
    // HAProxy: 502 SH-- before the head (INTERNAL_ERROR or REFUSED_STREAM), the response
    // truncated (SD--) after it.
    let (got, r) = get(&[fr(3, 0, 1, &2u32.to_be_bytes())]);
    assert_eq!((got.len(), r), (0, Err(SrvH2Error::Reset { code: 2, after_head: false })));
    let (_, r) = get(&[fr(3, 0, 1, &7u32.to_be_bytes())]);
    assert_eq!(r, Err(SrvH2Error::Refused));
    let (got, r) = get(&[hdrs(1, &[st("200")], false), data(1, b"part", false), fr(3, 0, 1, &2u32.to_be_bytes())]);
    assert_eq!(got, b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n4\r\npart\r\n");
    assert_eq!(r, Err(SrvH2Error::Reset { code: 2, after_head: true }));
}

#[test]
fn goaway_below_our_stream_refuses_it_and_at_it_lets_it_finish_without_reuse() {
    let (_, r) = get(&[fr(7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0])]);
    assert_eq!(r, Err(SrvH2Error::Refused));
    let mut c = ready();
    let _ = request(&mut c, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    c.receive(&fr(7, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0])).unwrap();
    c.receive(&hdrs(1, &[st("200"), lit("content-length", "0")], true)).unwrap();
    assert_eq!(take_rsp(&mut c), b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
    assert!(c.response_complete() && c.is_idle());
    assert!(!c.reusable(), "GOAWAY: no new stream on this connection");
}

#[test]
fn response_data_is_granted_back_once_the_session_took_it() {
    let mut c = ready();
    let _ = request(&mut c, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    c.receive(&[hdrs(1, &[st("200")], false), data(1, &[b'a'; 1000], false)].concat()).unwrap();
    assert!(c.output().is_empty(), "nothing granted while the text is not taken");
    let _ = take_rsp(&mut c);
    let mut want = fr(8, 0, 1, &1000u32.to_be_bytes());
    // The first connection WINDOW_UPDATE also opens the window to 2^31-1, as HAProxy's
    // (captured: 0x7fff0002 after a 2-byte body, 0x7fff4000 after 16384 bytes).
    want.extend(fr(8, 0, 0, &(0x7fff_0000u32 + 1000).to_be_bytes()));
    assert_eq!(take_out(&mut c), want, "stream then connection WINDOW_UPDATE");
    c.receive(&data(1, b"bb", true)).unwrap();
    let _ = take_rsp(&mut c);
    assert_eq!(take_out(&mut c), fr(8, 0, 0, &2u32.to_be_bytes()), "stream ended: the connection's only");
}

#[test]
fn the_first_connection_window_update_is_haproxys() {
    let mut c = ready();
    let _ = request(&mut c, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    c.receive(&[hdrs(1, &[st("200"), lit("content-length", "2")], false), data(1, b"ok", true)].concat()).unwrap();
    let _ = take_rsp(&mut c);
    assert_eq!(take_out(&mut c), hex("0000040800000000007fff0002"));
}

#[test]
fn protocol_errors_close_the_connection_with_goaway() {
    let mut c = ready();
    let _ = request(&mut c, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    let r = c.receive(&fr(5, 4, 1, &[0, 0, 0, 2, 0x88]));
    assert_eq!(r, Err(SrvH2Error::Connection(1)), "PUSH_PROMISE with push disabled");
    assert_eq!(take_out(&mut c), fr(7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 1]));
    assert!(!c.reusable());
    let mut c = ready();
    let _ = request(&mut c, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    let mut big = vec![0u8, 0x40, 1, 0, 0, 0, 0, 0, 1];
    big.extend(std::iter::repeat_n(0, 0x4001));
    assert_eq!(c.receive(&big), Err(SrvH2Error::Connection(6)), "frame over 16384: FRAME_SIZE_ERROR");
}

#[test]
fn after_a_reset_the_next_request_is_the_next_stream_on_the_same_connection() {
    let mut c = ready();
    let _ = request(&mut c, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(c.receive(&fr(3, 0, 1, &2u32.to_be_bytes())), Err(SrvH2Error::Reset { code: 2, after_head: false }));
    assert!(c.is_idle() && c.reusable() && !c.response_complete());
    let w = request(&mut c, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(w, hex("000006010500000003828784660178"), "stream 3, the error given once");
}

#[test]
fn a_head_not_whole_yet_uses_nothing() {
    let mut c = ready();
    assert_eq!(c.send_request(b"GET / HTTP/1.1\r\nHost: x\r\n").unwrap(), 0);
    assert!(c.output().is_empty() && c.is_idle());
}

#[test]
fn a_head_larger_than_a_frame_goes_on_in_continuation() {
    let mut c = ready();
    let big = "v".repeat(20_000);
    let req = format!("GET / HTTP/1.1\r\nHost: x\r\nX-Big: {big}\r\n\r\n");
    let w = request(&mut c, req.as_bytes());
    // HEADERS of 16384 bytes without END_HEADERS, then a CONTINUATION with it.
    assert_eq!(&w[..9], &[0x00, 0x40, 0x00, 1, 0x01, 0, 0, 0, 1]);
    let rest = &w[9 + 16384..];
    assert_eq!(&rest[3..9], &[9, 0x04, 0, 0, 0, 1]);
    let len = (usize::from(rest[0]) << 16) | (usize::from(rest[1]) << 8) | usize::from(rest[2]);
    assert_eq!(9 + 16384 + 9 + len, w.len());
}

#[test]
fn a_response_before_the_whole_request_cancels_the_stream_and_the_rest_is_dropped() {
    let mut c = ready();
    let head = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc";
    assert_eq!(c.send_request(head).unwrap(), head.len());
    let _ = take_out(&mut c);
    c.receive(&hdrs(1, &[st("413"), lit("content-length", "0")], true)).unwrap();
    assert_eq!(take_rsp(&mut c), b"HTTP/1.1 413 Request Entity Too Large\r\ncontent-length: 0\r\n\r\n");
    assert_eq!(take_out(&mut c), fr(3, 0, 1, &8u32.to_be_bytes()), "RST_STREAM CANCEL");
    assert_eq!(c.send_request(b"defghij").unwrap(), 7, "the rest of the body is read and dropped");
    assert_eq!(c.output(), b"");
    assert!(!c.reusable());
}

#[test]
fn a_body_longer_or_shorter_than_its_content_length_is_a_bad_response() {
    let (_, r) = get(&[hdrs(1, &[st("200"), lit("content-length", "2")], false), data(1, b"abc", true)]);
    assert_eq!(r, Err(SrvH2Error::BadResponse));
    let (_, r) = get(&[hdrs(1, &[st("200"), lit("content-length", "4")], false), data(1, b"abc", true)]);
    assert_eq!(r, Err(SrvH2Error::BadResponse));
}

#[test]
fn a_codec_from_the_pool_is_a_new_connections_whatever_it_was_before() {
    let mut c = H2SrvCodec::take().expect("h2c_srv pool");
    let mut want = H2_CONN_PREFACE.to_vec();
    want.extend(hex(HAPROXY_SETTINGS));
    assert_eq!(c.output(), want.as_slice());
    let n = c.output().len();
    c.advance_output(n);
    c.receive(&fr(4, 0, 0, &[])).unwrap();
    let _ = c.send_request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    c.receive(&fr(7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0])).unwrap_err();
    drop(c);
    let c = H2SrvCodec::take().expect("h2c_srv pool");
    assert_eq!(c.output(), want.as_slice());
    assert!(c.is_idle() && c.reusable() && c.streams() == 0);
}

/// A codec with `GET /x` sent on stream 1, then `frames` read: the result.
fn after(frames: &[Vec<u8>]) -> (H2SrvCodec, Result<(), SrvH2Error>) {
    let mut c = ready();
    let _ = request(&mut c, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    let r = c.receive(&frames.concat());
    (c, r)
}

#[test]
fn malformed_frames_are_connection_errors_with_their_codes() {
    use SrvH2Error::Connection as C;
    let h200 = || hdrs(1, &[st("200")], false);
    let cases: Vec<(&str, Vec<Vec<u8>>, SrvH2Error)> = vec![
        ("DATA on stream 0", vec![data(0, b"x", false)], C(1)),
        ("HEADERS on stream 0", vec![hdrs(0, &[st("200")], true)], C(1)),
        ("CONTINUATION alone", vec![fr(9, 4, 1, &st("200"))], C(1)),
        ("HEADERS without END_HEADERS, then DATA", vec![fr(1, 0, 1, &st("200")), data(1, b"x", true)], C(1)),
        ("RST_STREAM of 3 bytes", vec![fr(3, 0, 1, &[0, 0, 2])], C(6)),
        ("RST_STREAM on stream 0", vec![fr(3, 0, 0, &[0, 0, 0, 2])], C(1)),
        ("PING of 7 bytes", vec![fr(6, 0, 0, b"1234567")], C(6)),
        ("PING on stream 1", vec![fr(6, 0, 1, b"12345678")], C(1)),
        ("GOAWAY on stream 1", vec![fr(7, 0, 1, &[0; 8])], C(1)),
        ("GOAWAY of 4 bytes", vec![fr(7, 0, 0, &[0; 4])], C(1)),
        ("WINDOW_UPDATE of 3 bytes", vec![fr(8, 0, 0, &[0, 0, 1])], C(6)),
        ("connection WINDOW_UPDATE of 0", vec![fr(8, 0, 0, &[0; 4])], C(1)),
        ("connection window past 2^31-1", vec![fr(8, 0, 0, &0x7fff_ffffu32.to_be_bytes())], C(3)),
        ("SETTINGS on stream 1", vec![fr(4, 0, 1, &[])], C(1)),
        ("SETTINGS ACK with a payload", vec![fr(4, 1, 0, &[0, 3, 0, 0, 0, 1])], C(6)),
        ("SETTINGS of 5 bytes", vec![fr(4, 0, 0, &[0, 3, 0, 0, 0])], C(6)),
        ("INITIAL_WINDOW_SIZE past 2^31-1", vec![fr(4, 0, 0, &[0, 4, 0x80, 0, 0, 0])], C(3)),
        ("MAX_FRAME_SIZE below 16384", vec![fr(4, 0, 0, &[0, 5, 0, 0, 0, 100])], C(1)),
        ("ENABLE_PUSH 2", vec![fr(4, 0, 0, &[0, 2, 0, 0, 0, 2])], C(1)),
        ("HPACK index 0", vec![hdrs(1, &[vec![0x80]], true)], C(9)),
        ("HEADERS on a stream never opened", vec![hdrs(3, &[st("200")], true)], C(1)),
        ("DATA on an even stream", vec![data(2, b"x", true)], C(1)),
        ("HEADERS whose padding is longer than it", vec![fr(1, 4 | 8, 1, &[9, 0x88])], C(1)),
        ("DATA PADDED without a pad length", vec![h200(), fr(0, 8, 1, &[])], C(6)),
        ("DATA whose padding is longer than it", vec![h200(), fr(0, 8, 1, &[5, b'a'])], C(1)),
        ("more DATA than the connection window", (0..5).map(|_| data(1, &[0; 16384], false)).collect(), C(3)),
    ];
    for (name, frames, want) in cases {
        let (mut c, r) = after(&frames);
        assert_eq!(r, Err(want), "{name}");
        assert!(!c.reusable(), "{name}");
        let out = take_out(&mut c);
        let SrvH2Error::Connection(code) = want else { unreachable!() };
        assert!(out.ends_with(&fr(7, 0, 0, &[&[0, 0, 0, 0][..], &code.to_be_bytes()].concat())), "{name}: GOAWAY last");
        assert_eq!(c.receive(b"anything"), Err(want), "{name}: given again");
        assert_eq!(c.send_request(b"GET / HTTP/1.1\r\n\r\n"), Err(want), "{name}");
        c.advance_response(c.response().len());
        assert_eq!(c.output(), b"", "{name}: nothing after the GOAWAY");
    }
}

#[test]
fn malformed_responses_reset_the_stream_and_the_connection_goes_on() {
    use SrvH2Error::BadResponse as B;
    let h200 = || hdrs(1, &[st("200")], false);
    let cases: Vec<(&str, Vec<Vec<u8>>, u32)> = vec![
        ("stream WINDOW_UPDATE of 0", vec![fr(8, 0, 1, &[0; 4])], 1),
        ("stream window past 2^31-1", vec![fr(8, 0, 1, &0x7fff_ffffu32.to_be_bytes())], 3),
        ("trailers without END_STREAM", vec![h200(), hdrs(1, &[lit("x-t", "1")], false)], 1),
        ("a pseudo-header in the trailers", vec![h200(), hdrs(1, &[st("200")], true)], 1),
        ("two content-lengths that differ", vec![hdrs(1, &[st("200"), lit("content-length", "1"), lit("content-length", "2")], false)], 1),
        ("a status of two digits", vec![hdrs(1, &[st("20")], true)], 1),
        ("101", vec![hdrs(1, &[st("101")], true)], 1),
        ("an interim response that ends the stream", vec![hdrs(1, &[st("103")], true)], 1),
        ("a pseudo-header after a field", vec![hdrs(1, &[lit("x-a", "1"), st("200")], true)], 1),
        ("a request pseudo-header", vec![hdrs(1, &[st("200"), lit(":path", "/")], true)], 1),
        ("an uppercase name", vec![hdrs(1, &[st("200"), lit("X-A", "1")], true)], 1),
        ("content-length and END_STREAM without the body", vec![hdrs(1, &[st("200"), lit("content-length", "3")], true)], 1),
        ("more DATA than the stream window", vec![h200(), data(1, &[0; 16384], false), data(1, b"x", false)], 3),
    ];
    for (name, frames, rst) in cases {
        let (mut c, r) = after(&frames);
        assert_eq!(r, Err(B), "{name}");
        assert!(take_out(&mut c).ends_with(&fr(3, 0, 1, &rst.to_be_bytes())), "{name}: RST_STREAM {rst}");
        assert!(c.is_idle() && c.reusable(), "{name}");
        // Frames still in flight for the closed stream are dropped.
        assert_eq!(c.receive(&data(1, b"late", true)), Ok(()), "{name}");
        assert_eq!(c.receive(&fr(3, 0, 1, &[0, 0, 0, 8])), Ok(()), "{name}");
        let _ = take_out(&mut c);
        let w = request(&mut c, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(&w[5..9], &[0, 0, 0, 3], "{name}: next stream");
    }
}

#[test]
fn ignored_frames() {
    let (mut c, r) = after(&[
        fr(2, 0, 1, &[0, 0, 0, 0, 16]),
        fr(0xfa, 0, 0, b"unknown"),
        fr(6, 1, 0, b"12345678"),
        fr(4, 0, 0, &[0, 5, 0, 0, 0x50, 0, 0, 0x3, 0, 0, 0, 1]),
        fr(1, 1, 1, &st("200")),
        fr(9, 0, 1, &lit("x-a", "1")),
        fr(9, 4, 1, &lit("content-length", "0")),
    ]);
    assert_eq!(r, Ok(()));
    assert_eq!(take_rsp(&mut c), b"HTTP/1.1 200 OK\r\nx-a: 1\r\ncontent-length: 0\r\n\r\n");
    // The server's MAX_FRAME_SIZE 20480 is used for our frames.
    let mut req = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 20000\r\n\r\n".to_vec();
    req.extend(std::iter::repeat_n(b'q', 20000));
    let _ = take_out(&mut c);
    assert_eq!(c.send_request(&req).unwrap(), req.len());
    let w = take_out(&mut c);
    assert_eq!(w[w.len() - 20009..][..9], [0x00, 0x4e, 0x20, 0, 1, 0, 0, 0, 3], "one DATA frame of 20000 bytes");
}

#[test]
fn request_heads_it_cannot_write() {
    for (req, what) in [
        (&b"GET /\r\n\r\n"[..], "no version"),
        (b"GET / HTTP/2.0\r\nHost: x\r\n\r\n", "not HTTP/1.x"),
        (b" / HTTP/1.1\r\nHost: x\r\n\r\n", "no method"),
        (b"GET / HTTP/1.1\r\nHost x\r\n\r\n", "a line without a colon"),
        (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1a\r\n\r\n", "content-length"),
    ] {
        let mut c = ready();
        assert!(matches!(c.send_request(req), Err(SrvH2Error::Unsupported(_))), "{what}");
        assert_eq!(c.output(), b"", "{what}: nothing written");
        assert!(c.is_idle() && c.reusable(), "{what}");
    }
}

#[test]
fn absolute_targets_userinfo_empty_paths_and_other_schemes() {
    let mut c = ready();
    let w = request(&mut c, b"GET http://u:p@h/x HTTP/1.1\r\nHost: h\r\n\r\n");
    assert_eq!(&w[9..], &[0x82, 0x86, 0x41, 1, b'h', 0x44, 2, b'/', b'x'], "userinfo dropped");
    let mut c = ready();
    let w = request(&mut c, b"GET http://h HTTP/1.1\r\nHost: h\r\n\r\n");
    assert_eq!(&w[9..], &[0x82, 0x86, 0x41, 1, b'h', 0x84], "empty path: /");
    let mut c = ready();
    let w = request(&mut c, b"OPTIONS http://h HTTP/1.1\r\nHost: h\r\n\r\n");
    assert_eq!(&w[9..], &[&[0x42, 7][..], b"OPTIONS", &[0x86, 0x41, 1, b'h', 0x44, 1, b'*']].concat()[..], "OPTIONS: *");
    let mut c = ready();
    let w = request(&mut c, b"GET ftp://h/ HTTP/1.1\r\n\r\n");
    assert_eq!(&w[9..], &[&[0x82, 0x46, 3][..], b"ftp", &[0x41, 1, b'h', 0x84]].concat()[..], "another scheme: a literal");
}

#[test]
fn no_request_after_goaway_or_on_a_connection_that_failed() {
    let mut c = ready();
    assert_eq!(c.send_request(b"").unwrap(), 0);
    c.receive(&fr(7, 0, 0, &[0; 8])).unwrap();
    assert_eq!(c.send_request(b"GET / HTTP/1.1\r\n\r\n"), Err(SrvH2Error::Refused), "GOAWAY read while idle");
}

#[test]
fn a_reset_while_the_request_body_is_sent_ends_reuse() {
    let mut c = ready();
    let head = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc";
    assert_eq!(c.send_request(head).unwrap(), head.len());
    assert_eq!(c.receive(&fr(3, 0, 1, &[0, 0, 0, 2])), Err(SrvH2Error::Reset { code: 2, after_head: false }));
    assert!(!c.reusable(), "the session still has body bytes for it");
}

#[test]
fn a_response_larger_than_the_room_waits_for_the_session_and_its_errors_come_after() {
    let mut c = ready();
    let _ = request(&mut c, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    let big = "v".repeat(16_000);
    let head = [st("200"), lit_long("x-a", &big), lit_long("x-b", &big), lit_long("x-c", &big)].concat();
    let mut frames = fr(1, 0, 1, &head[..16_000]);
    frames.extend(fr(9, 0, 1, &head[16_000..32_000]));
    frames.extend(fr(9, 4, 1, &head[32_000..]));
    frames.extend(fr(3, 0, 1, &[0, 0, 0, 2]));
    c.receive(&frames).unwrap();
    assert!(c.response().len() > 32 * 1024);
    // Half taken: nothing more is read yet.
    c.advance_response(100);
    assert!(c.response().len() > 32 * 1024 - 100);
    let n = c.response().len();
    c.advance_response(n);
    // The RST read once the text was taken comes back on the next call.
    assert_eq!(c.receive(&[]), Err(SrvH2Error::Reset { code: 2, after_head: true }));
    assert_eq!(c.receive(&[]), Ok(()));
}

/// Literal without indexing with a two-byte-or-more length.
fn lit_long(n: &str, v: &str) -> Vec<u8> {
    let mut b = vec![0, n.len() as u8];
    b.extend_from_slice(n.as_bytes());
    let mut len = v.len() - 127;
    b.push(0x7f);
    while len >= 128 {
        b.push((len % 128) as u8 | 0x80);
        len /= 128;
    }
    b.push(len as u8);
    b.extend_from_slice(v.as_bytes());
    b
}

#[test]
fn default_and_wiped_reset() {
    use ibex_alloc::Poolable;
    let mut c = H2SrvCodec::default();
    c.receive(&fr(4, 0, 0, &[])).unwrap();
    let _ = c.send_request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    c.reset(true);
    let mut want = H2_CONN_PREFACE.to_vec();
    want.extend(hex(HAPROXY_SETTINGS));
    assert_eq!(c.output(), want.as_slice());
    assert!(c.footprint() > 0);
}

#[test]
fn a_response_taken_in_parts_is_granted_once_all_is_taken() {
    let mut c = ready();
    let _ = request(&mut c, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    c.receive(&[hdrs(1, &[st("200"), lit("content-length", "100")], false), data(1, &[b'a'; 50], false)].concat()).unwrap();
    let n = c.response().len();
    c.advance_response(n - 10);
    assert_eq!(c.output(), b"", "not all taken");
    c.advance_response(10);
    assert_eq!(take_out(&mut c)[..9], [0, 0, 4, 8, 0, 0, 0, 0, 1], "stream WINDOW_UPDATE");
}

#[test]
fn a_chunk_larger_than_the_window_waits_for_it() {
    let mut c = H2SrvCodec::new();
    let _ = take_out(&mut c);
    c.receive(&fr(4, 0, 0, &[0, 4, 0, 0, 0, 100])).unwrap();
    let _ = take_out(&mut c);
    let mut req = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nFA\r\n".to_vec();
    req.extend(std::iter::repeat_n(b'c', 250));
    req.extend_from_slice(b"\r\n0\r\n\r\n");
    let first = c.send_request(&req).unwrap();
    assert_eq!(first, req.len() - 250 - 7 + 100, "100 bytes of the chunk: the window");
    assert_eq!(c.send_request(&req[first..]).unwrap(), 0);
    c.receive(&fr(8, 0, 1, &1000u32.to_be_bytes())).unwrap();
    assert_eq!(c.send_request(&req[first..]).unwrap(), req.len() - first);
    let w = take_out(&mut c);
    assert!(w.ends_with(&[&[0, 0, 150, 0, 0, 0, 0, 0, 1][..], &[b'c'; 150][..], &[0, 0, 0, 0, 1, 0, 0, 0, 1][..]].concat()));
}

#[test]
fn an_error_read_while_the_session_took_the_text_comes_with_the_next_request_too() {
    let mut c = ready();
    let _ = request(&mut c, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    let big = "v".repeat(16_000);
    let head = [st("200"), lit_long("x-a", &big), lit_long("x-b", &big), lit_long("x-c", &big)].concat();
    let mut frames = fr(1, 0, 1, &head[..16_000]);
    frames.extend(fr(9, 0, 1, &head[16_000..32_000]));
    frames.extend(fr(9, 4, 1, &head[32_000..]));
    frames.extend(fr(3, 0, 1, &[0, 0, 0, 2]));
    c.receive(&frames).unwrap();
    let n = c.response().len();
    c.advance_response(n);
    assert_eq!(c.send_request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), Err(SrvH2Error::Reset { code: 2, after_head: true }));
    assert_eq!(c.send_request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").map(|n| n > 0), Ok(true), "then the request goes");
}

#[test]
fn a_target_with_a_colon_but_no_authority_is_a_path_and_other_streams_windows_are_ignored() {
    let mut c = ready();
    let w = request(&mut c, b"GET urn:x HTTP/1.1\r\nHost: h\r\n\r\n");
    assert_eq!(&w[9..], &[0x82, 0x87, 0x44, 5, b'u', b'r', b'n', b':', b'x', 0x66, 1, b'h']);
    assert_eq!(c.receive(&fr(8, 0, 7, &[0, 0, 0, 1])), Ok(()));
}
