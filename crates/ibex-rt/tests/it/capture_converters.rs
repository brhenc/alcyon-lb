// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T331: the `capture-req(<id>)` and `capture-res(<id>)` converters store their input in the
//! stream's capture slot (cut at the slot's length) and pass it on; the `capture.req.hdr` and
//! `capture.res.hdr` fetches read it back. Every expected value was measured on `HAProxy`
//! 3.5-dev8 with the same configuration.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-B: hello\r\n\r\nok";

/// A server that answers every request with `RESP` and closes.
fn backend() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let (mut head, mut b) = (Vec::new(), [0u8; 4096]);
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&b[..n]),
                }
            }
            let _ = c.write_all(RESP);
        }
    });
    addr
}

/// Starts ibex on `cfg` (`{A}` the frontend address, `{BE}` the server's) and waits for it.
fn start(tag: &str, cfg: &str) -> (Ibex, SocketAddr) {
    let a = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("t331-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    let text = format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{cfg}");
    std::fs::write(&path, text.replace("{A}", &a.to_string()).replace("{BE}", &backend().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, dir);
    assert!(common::wait_listening(a), "ibex did not listen on {a} ({tag})");
    (ibex, a)
}

/// `ibex -c` on `cfg`: whether it was accepted, and what it said.
fn check(cfg: &str) -> (bool, String) {
    let path = std::env::temp_dir().join(format!("t331-check-{}.cfg", std::process::id()));
    std::fs::write(&path, format!("defaults\n  mode http\n{cfg}")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// The value of the `x-out` header in the answer to `req`.
fn xout(addr: SocketAddr, req: &[u8]) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let s = String::from_utf8_lossy(&out).into_owned();
    let head = s.split("\r\n\r\n").next().unwrap_or("");
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("x-out")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("no x-out header in the answer: {s:?}"))
}

fn req(extra: &str) -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: a\r\n{extra}Connection: close\r\n\r\n").into_bytes()
}

const DECL: &str = "  declare capture request len 4\n  declare capture response len 8\n";
const FE: &str = "frontend fe\n  bind {A}\n";
const BE: &str = "  default_backend b\nbackend b\n  server s {BE}\n";

fn cfg(body: &str, out: &str) -> String {
    format!("{FE}{DECL}{body}  http-response set-header x-out \"{out}\"\n{BE}")
}

/// The task's table: the converter's own output, then what the fetches read back.
#[test]
fn rows_of_the_oracle_table() {
    let c = cfg(
        "  http-request set-var(txn.c) req.fhdr(x-a),capture-req(0)\n  http-response set-var(txn.d) res.fhdr(x-b),capture-res(0)\n",
        "[%[var(txn.c)]][%[capture.req.hdr(0)]][%[var(txn.d)]][%[capture.res.hdr(0)]]",
    );
    let (_i, a) = start("rows", &c);
    assert_eq!(xout(a, &req("X-A: abcdefgh\r\n")), "[abcdefgh][abcd][hello][hello]");
    assert_eq!(xout(a, &req("X-A: ab\r\n")), "[ab][ab][hello][hello]");
    assert_eq!(xout(a, &req("")), "[][][hello][hello]");
}

/// A later rule sees the slot; so does a later item of the same log-format string; a second
/// write replaces the first; a converter and `http-request capture` write the same slot.
#[test]
fn the_slot_is_written_when_the_converter_runs() {
    let c = cfg(
        "  http-request set-var(txn.c) req.fhdr(x-a),capture-req(0)\n  http-request set-var(txn.e) capture.req.hdr(0)\n",
        "[%[var(txn.e)]][%[capture.req.hdr(0)]]",
    );
    let (_i, a) = start("later", &c);
    assert_eq!(xout(a, &req("X-A: abcdefgh\r\n")), "[abcd][abcd]");

    let c = cfg("", "[%[str(abcdefgh),capture-req(0)]][%[capture.req.hdr(0)]][%[capture.req.hdr(0)]]");
    let (_i, a) = start("same", &c);
    assert_eq!(xout(a, &req("")), "[abcdefgh][abcd][abcd]");

    let c = cfg("  http-request set-var(txn.c) str(aa),capture-req(0)\n  http-request set-var(txn.c) str(bb),capture-req(0)\n", "[%[capture.req.hdr(0)]]");
    let (_i, a) = start("twice", &c);
    assert_eq!(xout(a, &req("")), "[bb]");

    let c = cfg(
        "  http-request capture str(first) id 0\n  http-request set-var(txn.c) str(second),capture-req(0)\n",
        "[%[capture.req.hdr(0)]]",
    );
    let (_i, a) = start("then-capture", &c);
    assert_eq!(xout(a, &req("")), "[seco]");

    let c = cfg(
        "  http-request set-var(txn.c) str(second),capture-req(0)\n  http-request capture str(first) id 0\n",
        "[%[capture.req.hdr(0)]]",
    );
    let (_i, a) = start("capture-then", &c);
    assert_eq!(xout(a, &req("")), "[firs]");
}

/// A slot that does not exist: the capture fails silently and the converter returns its input.
#[test]
fn a_missing_slot_fails_silently() {
    let c = cfg("  http-request set-var(txn.c) str(abcdefgh),capture-req(5)\n", "[%[var(txn.c)]][%[capture.req.hdr(5)]][%[capture.req.hdr(0)]]");
    let (_i, a) = start("missing", &c);
    assert_eq!(xout(a, &req("")), "[abcdefgh][][]");

    let c = format!(
        "{FE}  http-request set-var(txn.c) str(abcdefgh),capture-req(0)\n  http-response set-header x-out \"[%[var(txn.c)]][%[capture.req.hdr(0)]]\"\n{BE}"
    );
    let (_i, a) = start("nodecl", &c);
    assert_eq!(xout(a, &req("")), "[abcdefgh][]");

    let c = cfg("  http-request set-var(txn.c) str(zz),capture-req(-1)\n", "[%[var(txn.c)]][%[capture.req.hdr(0)]]");
    let (_i, a) = start("neg", &c);
    assert_eq!(xout(a, &req("")), "[zz][]");
}

/// Either converter works in either direction's rules; a backend's rule writes the frontend's slots.
#[test]
fn both_converters_in_both_rule_sets() {
    let c = cfg("  http-response set-var(txn.c) str(abcdefgh),capture-req(0)\n", "[%[var(txn.c)]][%[capture.req.hdr(0)]]");
    let (_i, a) = start("req-in-res", &c);
    assert_eq!(xout(a, &req("")), "[abcdefgh][abcd]");

    let c = cfg("  http-request set-var(txn.c) str(abcdefgh),capture-res(0)\n", "[%[var(txn.c)]][%[capture.res.hdr(0)]]");
    let (_i, a) = start("res-in-req", &c);
    assert_eq!(xout(a, &req("")), "[abcdefgh][abcdefgh]");

    let c = format!(
        "{FE}{DECL}  use_backend b2 if TRUE\n  http-response set-header x-out \"[%[capture.req.hdr(0)]]\"\nbackend b2\n  http-request set-var(txn.c) str(inbe),capture-req(0)\n  server s {{BE}}\n"
    );
    let (_i, a) = start("backend", &c);
    assert_eq!(xout(a, &req("")), "[inbe]");
}

/// A named response slot: the header, when the response has it, replaces what a request rule
/// wrote; when it does not, the written value stays.
#[test]
fn a_header_slot_is_overwritten_only_by_its_header() {
    for (hdr, want) in [("x-b", "[hello]"), ("x-nope", "[zz]")] {
        let c = format!(
            "{FE}  capture response header {hdr} len 8\n  http-request set-var(txn.c) str(zz),capture-res(0)\n  http-response set-header x-out \"[%[capture.res.hdr(0)]]\"\n{BE}"
        );
        let (_i, a) = start("named", &c);
        assert_eq!(xout(a, &req("")), want, "header {hdr}");
    }
}

/// Every input type is converted to a string first.
#[test]
fn non_string_input() {
    for (smp, want) in [("int(1234567)", "[1234567][1234]"), ("src", "[127.0.0.1][127.]"), ("bool(1)", "[1][1]"), ("bin(616263646566)", "[abcdef][abcd]"), ("str()", "[][]")] {
        let c = cfg(&format!("  http-request set-var(txn.c) {smp},capture-req(0)\n"), "[%[var(txn.c)]][%[capture.req.hdr(0)]]");
        let (_i, a) = start("types", &c);
        assert_eq!(xout(a, &req("")), want, "{smp}");
    }
}

/// The argument is one integer (`ARG1(1,SINT)`): the others are refused at load.
#[test]
fn the_argument_is_checked_at_load() {
    for (arg, msg) in [
        ("", "invalid arg 1 in converter 'capture-req' : expected type 'integer' at position 1, but got nothing."),
        ("(x)", "invalid arg 1 in converter 'capture-req' : failed to parse 'x' as type 'integer' at position 1."),
        ("(1.5)", "invalid arg 1 in converter 'capture-req' : failed to parse '1.5' as type 'integer' at position 1."),
        ("(1,2)", "invalid arg 2 in converter 'capture-req' : expected ')' before ',2)'."),
    ] {
        let (ok, out) = check(&format!("frontend fe\n  bind 127.0.0.1:0\n  declare capture request len 4\n  http-request set-var(txn.c) str(a),capture-req{arg}\n"));
        assert!(!ok && out.contains(msg), "capture-req{arg}: {out}");
    }
    let (ok, out) = check("frontend fe\n  bind 127.0.0.1:0\n  declare capture response len 4\n  http-request set-var(txn.c) str(a),capture-res(0)\n");
    assert!(ok, "{out}");
}
