// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! What a malformed server response head becomes (T275): `HAProxy` parses it
//! (`h1_headers_to_hdr_list`, `h1_process_res_vsn`, `h1_process_headers`) and answers 502,
//! logged `PH--`, unless `option accept-unsafe-violations-in-http-response` (or its
//! deprecated alias `accept-invalid-http-response`) relaxes the rule. A head it accepts goes
//! to the client as `HAProxy` writes it again: CRLF line ends, `name: value`, folded lines
//! joined, a duplicate or zero-padded `Content-Length` cleaned, `Content-Length` dropped
//! next to `Transfer-Encoding`.
//!
//! Every expected value below was measured on `HAProxy` 3.5-dev8-885761-29 with an
//! HTTP/1.1 client sending `Connection: close`, the server closing after its response.
//! What the option relaxes, and nothing else: a header name with a character that is not
//! a token (the header is dropped), a NUL in a value, an empty or repeated `chunked`
//! coding, a version that is not `HTTP/<d>.<d>` (made of `A-Z`, digits, `.` and `/`), a
//! status of more than three digits. Always refused: a bare CR, a line without a colon, an
//! empty name, any `Content-Length` that is not digits or disagrees with another, any
//! transfer coding other than `chunked`, no status.
//!
//! Set `T275_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};

#[derive(Clone, Copy, Debug)]
enum Expect {
    /// A 502 from the proxy, logged `PH--`.
    Bad,
    /// What the client receives, all of it.
    Pass(&'static [u8]),
}
use Expect::{Bad, Pass};

struct Case {
    name: &'static str,
    sent: &'static [u8],
    strict: Expect,
    unsafe_ok: Expect,
}

const CASES: &[Case] = &[
    Case {
        name: "ok",
        sent: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "badname_space",
        sent: b"HTTP/1.1 200 OK\r\nBad Name: x\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "badname_at",
        sent: b"HTTP/1.1 200 OK\r\nBad@Name: x\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "nul_value",
        sent: b"HTTP/1.1 200 OK\r\nX-A: a\x00b\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\nx-a: a\x00b\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "bare_cr_value",
        sent: b"HTTP/1.1 200 OK\r\nX-A: a\rb\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "no_colon",
        sent: b"HTTP/1.1 200 OK\r\nNoColon\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "empty_name",
        sent: b"HTTP/1.1 200 OK\r\n: v\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "space_before_colon",
        sent: b"HTTP/1.1 200 OK\r\nX-A : v\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "cl_conflict",
        sent: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "cl_dup_same",
        sent: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "cl_list_conflict",
        sent: b"HTTP/1.1 200 OK\r\nContent-Length: 2, 3\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "cl_nondigit",
        sent: b"HTTP/1.1 200 OK\r\nContent-Length: 2x\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "cl_empty",
        sent: b"HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "cl_neg",
        sent: b"HTTP/1.1 200 OK\r\nContent-Length: -2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "te_gzip",
        sent: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "te_gzip_chunked",
        sent: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "te_chunked_gzip",
        sent: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "te_chunked_twice",
        sent: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        strict: Bad,
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
    },
    Case {
        name: "te_empty",
        sent: b"HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "te_chunked_cl",
        sent: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        strict: Pass(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
    },
    Case {
        name: "te_http10",
        sent: b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        strict: Pass(b"HTTP/1.0 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
        unsafe_ok: Pass(b"HTTP/1.0 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
    },
    Case {
        name: "ver_bad",
        sent: b"HTTP/1.x 200 OK\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "ver_long",
        sent: b"HTTP/1.10 200 OK\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Pass(b"HTTP/1.10 200 OK\r\ncontent-length: 2\r\n\r\nok"),
    },
    Case {
        name: "ver_foo",
        sent: b"FOO/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Pass(b"FOO/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"),
    },
    Case {
        name: "status_4digit",
        sent: b"HTTP/1.1 2000 OK\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Pass(b"HTTP/1.1 2000 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "status_2digit",
        sent: b"HTTP/1.1 20 OK\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 20 OK\r\ncontent-length: 2\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 20 OK\r\ncontent-length: 2\r\n\r\nok"),
    },
    Case {
        name: "status_alpha",
        sent: b"HTTP/1.1 2x0 OK\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "status_099",
        sent: b"HTTP/1.1 099 OK\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 099 OK\r\ncontent-length: 2\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 099 OK\r\ncontent-length: 2\r\n\r\nok"),
    },
    Case {
        name: "status_600",
        sent: b"HTTP/1.1 600 OK\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 600 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 600 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "status_missing",
        sent: b"HTTP/1.1\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "reason_ctl",
        sent: b"HTTP/1.1 200 O\x01K\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 O\x01K\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 O\x01K\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "lf_only",
        sent: b"HTTP/1.1 200 OK\nContent-Length: 2\n\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "obs_fold",
        sent: b"HTTP/1.1 200 OK\r\nX-A: a\r\n b\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\nx-a: a   b\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\nx-a: a   b\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "leading_crlf",
        sent: b"\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "no_reason",
        sent: b"HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "dbl_space",
        sent: b"HTTP/1.1  200  OK\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "tab_sep",
        sent: b"HTTP/1.1\t200\tOK\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "crlf_cr_only",
        sent: b"HTTP/1.1 200 OK\rContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "hdr_trailing_ws",
        sent: b"HTTP/1.1 200 OK\r\nX-A:   v  \t\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\nx-a: v\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\nx-a: v\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "hdr_nospace",
        sent: b"HTTP/1.1 200 OK\r\nX-A:v\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\nx-a: v\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\nx-a: v\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "te_CHUNKED",
        sent: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        strict: Pass(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
    },
    Case {
        name: "te_two_hdrs",
        sent: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        strict: Bad,
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
    },
    Case {
        name: "te_204",
        sent: b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: gzip\r\n\r\n",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "cl_leading0",
        sent: b"HTTP/1.1 200 OK\r\nContent-Length: 002\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "cl_list_same",
        sent: b"HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "r204_cl0",
        sent: b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nX-A: 1\r\n\r\n",
        strict: Pass(b"HTTP/1.1 204 No Content\r\nx-a: 1\r\nconnection: close\r\n\r\n"),
        unsafe_ok: Pass(b"HTTP/1.1 204 No Content\r\nx-a: 1\r\nconnection: close\r\n\r\n"),
    },
    Case {
        name: "r204_te",
        sent: b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\n",
        strict: Pass(b"HTTP/1.1 204 No Content\r\nx-a: 1\r\nconnection: close\r\n\r\n"),
        unsafe_ok: Pass(b"HTTP/1.1 204 No Content\r\nx-a: 1\r\nconnection: close\r\n\r\n"),
    },
    Case {
        name: "r304_cl",
        sent: b"HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\nX-A: 1\r\n\r\n",
        strict: Pass(b"HTTP/1.1 304 Not Modified\r\ncontent-length: 10\r\nx-a: 1\r\nconnection: close\r\n\r\n"),
        unsafe_ok: Pass(b"HTTP/1.1 304 Not Modified\r\ncontent-length: 10\r\nx-a: 1\r\nconnection: close\r\n\r\n"),
    },
    Case {
        name: "r103_cl",
        sent: b"HTTP/1.1 103 Early Hints\r\nContent-Length: 0\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 103 Early Hints\r\nlink: </a>\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 103 Early Hints\r\nlink: </a>\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "te_ws",
        sent: b"HTTP/1.1 200 OK\r\nTransfer-Encoding:  chunked \r\n\r\n2\r\nok\r\n0\r\n\r\n",
        strict: Pass(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
    },
    Case {
        name: "te_trailing_comma",
        sent: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        strict: Bad,
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
    },
    Case {
        name: "cl_trailing_comma",
        sent: b"HTTP/1.1 200 OK\r\nContent-Length: 2,\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Bad,
    },
    Case {
        name: "x_after_te",
        sent: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\nContent-Length: 2\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        strict: Pass(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nx-a: 1\r\nconnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nx-a: 1\r\nconnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
    },
    Case {
        name: "value_ctl",
        sent: b"HTTP/1.1 200 OK\r\nX-A: a\x01b\x7f\r\nContent-Length: 2\r\n\r\nok",
        strict: Pass(b"HTTP/1.1 200 OK\r\nx-a: a\x01b\x7f\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\nx-a: a\x01b\x7f\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
    Case {
        name: "name_8bit",
        sent: b"HTTP/1.1 200 OK\r\nX-\xe9: v\r\nContent-Length: 2\r\n\r\nok",
        strict: Bad,
        unsafe_ok: Pass(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"),
    },
];

struct Proxy {
    child: Child,
    logs: mpsc::Receiver<String>,
    stats: std::path::PathBuf,
    fe: SocketAddr,
    h2: SocketAddr,
    _cfg: NamedTempFile,
    _dir: TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server that answers `GET /<n>` with `responses[n]` and closes.
fn server(responses: Arc<Vec<&'static [u8]>>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let responses = Arc::clone(&responses);
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let mut req = Vec::new();
                let mut b = [0u8; 4096];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&b[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&req);
                let n: usize = line.split(' ').nth(1).and_then(|p| p.trim_start_matches('/').parse().ok()).unwrap_or(0);
                let _ = s.write_all(responses[n]);
                thread::sleep(Duration::from_millis(100));
            });
        }
    });
    addr
}

fn start(defaults: &str, backend: &str, responses: Arc<Vec<&'static [u8]>>) -> Proxy {
    let dir = TempDir::new().expect("dir");
    let stats = dir.path().join("stats.sock");
    let (fe, h2, sentinel) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let be = server(responses);
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  log stdout format raw local0\n  stats socket {}\n\
         defaults\n  mode http\n  log global\n  option httplog\n  {defaults}\n  timeout connect 2s\n  \
         timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  bind {h2} proto h2\n  default_backend b\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend b\n  {backend}\n  server s {be}\n",
        stats.display()
    )
    .expect("write");
    let bin = std::env::var("T275_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let mut child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    assert!(common::wait_listening(sentinel), "never listened");
    Proxy { child, logs, stats, fe, h2, _cfg: cfg, _dir: dir }
}

fn get(p: &Proxy, n: usize) -> Vec<u8> {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(format!("GET /{n} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    got
}

/// The log line of `GET /<n>` (HTTP/2: `GET http://<authority>/<n>`).
fn log_of(p: &Proxy, n: usize) -> String {
    let want = format!("/{n} HTTP/");
    while let Ok(l) = p.logs.recv_timeout(Duration::from_secs(3)) {
        if l.contains(&want) {
            return l;
        }
    }
    String::new()
}

fn show_stat(p: &Proxy) -> String {
    let mut s = UnixStream::connect(&p.stats).expect("stats");
    s.write_all(b"show stat\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// The `show stat` field `field` of the row `pxname,svname`.
fn stat(csv: &str, row: &str, field: &str) -> String {
    let mut lines = csv.lines();
    let header: Vec<&str> = lines.next().unwrap_or("").trim_start_matches("# ").split(',').collect();
    let col = header.iter().position(|h| *h == field).expect("field");
    lines.find(|l| l.starts_with(row)).and_then(|l| l.split(',').nth(col)).unwrap_or("").to_string()
}

fn esc(b: &[u8]) -> String {
    b.escape_ascii().to_string()
}

fn run_cases(defaults: &str, backend: &str, pick: fn(&Case) -> Expect) {
    let responses = Arc::new(CASES.iter().map(|c| c.sent).collect::<Vec<_>>());
    let p = start(defaults, backend, responses);
    let mut wrong = Vec::new();
    for (n, case) in CASES.iter().enumerate() {
        let got = get(&p, n);
        let log = log_of(&p, n);
        match pick(case) {
            Bad => {
                if !got.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n") || !log.contains(" 502 0 - - PH-- ") {
                    wrong.push(format!("{}: want a 502 PH--, got {} / log {log}", case.name, esc(&got)));
                }
            }
            Pass(want) => {
                if got != want || !log.contains(" - - ---- ") {
                    wrong.push(format!("{}: want {}, got {} / log {log}", case.name, esc(want), esc(&got)));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{} of {} cases differ:\n{}", wrong.len(), CASES.len(), wrong.join("\n"));
}

#[test]
fn malformed_response_heads_are_refused_with_502() {
    run_cases("", "", |c| c.strict);
}

#[test]
fn accept_unsafe_violations_in_http_response_relaxes_what_haproxy_relaxes() {
    run_cases("", "option accept-unsafe-violations-in-http-response", |c| c.unsafe_ok);
}

#[test]
fn accept_invalid_http_response_is_the_same_option() {
    run_cases("", "option accept-invalid-http-response", |c| c.unsafe_ok);
}

#[test]
fn the_option_comes_from_defaults_and_no_option_turns_it_off() {
    run_cases("option accept-unsafe-violations-in-http-response", "", |c| c.unsafe_ok);
    run_cases("option accept-unsafe-violations-in-http-response", "no option accept-unsafe-violations-in-http-response", |c| c.strict);
}

/// A refused head counts as `HAProxy` counts it: `eresp` twice on the server and on the
/// backend (`h1` and the stream each count it), and a 5xx on the backend only.
#[test]
fn a_refused_head_counts_a_response_error() {
    let bad: &'static [u8] = b"HTTP/1.1 200 OK\r\nBad Name: x\r\nContent-Length: 2\r\n\r\nok";
    let p = start("", "", Arc::new(vec![bad]));
    let got = get(&p, 0);
    assert!(got.starts_with(b"HTTP/1.1 502 "), "got {}", esc(&got));
    let _ = log_of(&p, 0);
    let csv = show_stat(&p);
    assert_eq!(stat(&csv, "b,s,", "eresp"), "2", "server eresp\n{csv}");
    assert_eq!(stat(&csv, "b,BACKEND,", "eresp"), "2", "backend eresp\n{csv}");
    assert_eq!(stat(&csv, "b,BACKEND,", "hrsp_5xx"), "1", "backend 5xx\n{csv}");
    assert_eq!(stat(&csv, "b,s,", "hrsp_5xx"), "0", "server 5xx\n{csv}");
}

/// An HTTP/2 client gets the same answer: a 502 for a bad name, the response under the
/// option (without the header it drops).
#[test]
fn an_h2_client_gets_the_502_too() {
    let bad: &'static [u8] = b"HTTP/1.1 200 OK\r\nBad Name: x\r\nX-Good: y\r\nContent-Length: 2\r\n\r\nok";
    for (backend, want) in [("", "502"), ("option accept-unsafe-violations-in-http-response", "200")] {
        let p = start("", backend, Arc::new(vec![bad]));
        let out = Command::new("curl")
            .args(["-s", "-i", "--http2-prior-knowledge", "--max-time", "5"])
            .arg(format!("http://{}/0", p.h2))
            .output()
            .expect("curl");
        let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
        assert!(text.starts_with(&format!("http/2 {want}")), "{backend:?}: {text}");
        if want == "200" {
            assert!(text.contains("x-good: y") && !text.contains("bad name"), "{text}");
        }
        assert!(log_of(&p, 0).contains(&format!(" {want} ")), "{backend:?}");
    }
}

/// A `101` that switches to websocket without `Sec-WebSocket-Accept` is refused
/// (`h1_search_websocket_key`), unless under the option. (`HAProxy` then writes the accept
/// key it computes from the request's `Sec-WebSocket-Key`; Ibex forwards the 101 as it is,
/// and only the status is checked here.)
#[test]
fn a_websocket_101_without_its_accept_key_is_refused() {
    let ws: &'static [u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n";
    for (backend, want, term) in
        [("", "HTTP/1.1 502 ", " 502 0 - - PH-- "), ("option accept-unsafe-violations-in-http-response", "HTTP/1.1 101 ", " 101 ")]
    {
        let p = start("", backend, Arc::new(vec![ws]));
        let mut c = TcpStream::connect(p.fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(
            b"GET /0 HTTP/1.1\r\nHost: x\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .unwrap();
        // The head only: a 101 leaves a tunnel open.
        let mut got = Vec::new();
        let mut b = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            match c.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&b[..n]),
            }
        }
        drop(c);
        assert!(got.starts_with(want.as_bytes()), "{backend:?}: {}", esc(&got));
        let log = log_of(&p, 0);
        assert!(log.contains(term), "{backend:?}: {log}");
    }
}
