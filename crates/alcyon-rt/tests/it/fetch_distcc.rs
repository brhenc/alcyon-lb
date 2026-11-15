// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `distcc_param(<token>[,<occ>])` and `distcc_body(<token>[,<occ>])` (`src/payload.c`): a
//! DISTCC stream in a TCP proxy's request buffer, a sequence of 12-byte headers (a 4-character
//! token, an 8-digit hexadecimal parameter), most followed by a body of that many bytes.
//!
//! Every expected line of [`CASES`] was measured on `HAProxy` 3.5-dev8-885761-29, 2026-11-15
//! (the payload sent in one write and the write side then shut, the stream's log line read
//! back), except the three rows marked otherwise: there `HAProxy` reads past the data it
//! received, and Alcyon returns only the bytes that arrived.

use alcyon_rt::engine::Engine;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use crate::common;

const FORMAT: &str = "p=%[var(txn.p)] a1=%[var(txn.a1)] a2=%[var(txn.a2)] a3=%[var(txn.a3)] a0=%[var(txn.a0)] b1=%[var(txn.b1)] b2=%[var(txn.b2)] bd=%[var(txn.bd)] bdist=%[var(txn.bdist)] pdist=%[var(txn.pdist)] pargc=%[var(txn.pargc)] pdone=%[var(txn.pdone)] pstat=%[var(txn.pstat)] pnfil=%[var(txn.pnfil)] bnfil=%[var(txn.bnfil)] n=%[var(txn.n)]";

const SETS: &str = "tcp-request content set-var(txn.p) distcc_param(DOTI)\n  tcp-request content set-var(txn.a1) distcc_param(ARGV)\n  tcp-request content set-var(txn.a2) distcc_param(ARGV,2)\n  tcp-request content set-var(txn.a3) distcc_param(ARGV,3)\n  tcp-request content set-var(txn.a0) distcc_param(ARGV,0)\n  tcp-request content set-var(txn.b1) distcc_body(ARGV),hex\n  tcp-request content set-var(txn.b2) distcc_body(ARGV,2),hex\n  tcp-request content set-var(txn.bd) distcc_body(DOTI),hex\n  tcp-request content set-var(txn.bdist) distcc_body(DIST),hex\n  tcp-request content set-var(txn.pdist) distcc_param(DIST)\n  tcp-request content set-var(txn.pargc) distcc_param(ARGC)\n  tcp-request content set-var(txn.pdone) distcc_param(DONE)\n  tcp-request content set-var(txn.pstat) distcc_param(STAT)\n  tcp-request content set-var(txn.pnfil) distcc_param(NFIL)\n  tcp-request content set-var(txn.bnfil) distcc_body(NFIL),hex\n  tcp-request content set-var(txn.n) distcc_param(NOPE)\n  tcp-request content reject";

fn start(mode: &str, rules: &str) -> (Engine, UdpSocket, SocketAddr) {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode {mode}\n  timeout client 2s\n  timeout connect 1s\n  timeout server 1s\n\
         frontend fe\n  bind {fe}\n  log {} local0\n  log-format \"{FORMAT}\"\n  tcp-request inspect-delay 300ms\n  {rules}\n",
        collector.local_addr().expect("addr")
    );
    let engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    (engine, collector, fe)
}

/// Sends `payload` in one write, shuts the write side and returns the stream's log line.
fn log_of(engine: &mut Engine, collector: &UdpSocket, fe: SocketAddr, payload: Vec<u8>) -> String {
    let c = thread::spawn(move || {
        let mut s = TcpStream::connect(fe).expect("connect");
        let _ = s.write_all(&payload);
        thread::sleep(Duration::from_millis(40));
        let _ = s.shutdown(std::net::Shutdown::Write);
        s.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let mut sink = [0u8; 16];
        let _ = s.read(&mut sink);
    });
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut line = String::from("NOLOG");
    while Instant::now() < deadline {
        let _ = engine.run_once();
        if let Ok(n) = collector.recv(&mut buf) {
            line = String::from_utf8_lossy(&buf[..n]).split_once("]: ").map_or(String::new(), |(_, b)| b.trim_end().to_string());
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    let _ = c.join();
    line
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex")).collect()
}

/// (name, payload in hex, the log line).
const CASES: &[(&str, &str, &str)] = &[
        ("basic", "4449535430303030303030314152474330303030303030324152475630303030303030336763634152475630303030303030322d63444f5449303030303030303568656c6c6f", "p=5 a1=3 a2=2 a3=- a0=3 b1=676363 b2=2D63 bd=68656C6C6F bdist=- pdist=1 pargc=2 pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("lowerhex", "444953543030303030303031415247563030303030306162787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878444f544930303030303030327a7a", "p=2 a1=171 a2=- a3=- a0=171 b1=787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878 b2=- bd=7A7A bdist=- pdist=1 pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("empty", "", "p=- a1=- a2=- a3=- a0=- b1=- b2=- bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("short_hdr", "4449535430303030", "p=- a1=- a2=- a3=- a0=- b1=- b2=- bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("exact12", "444953543030303030303031", "p=- a1=- a2=- a3=- a0=- b1=- b2=- bd=- bdist=- pdist=1 pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("badhex_first", "444953543030303030303047444f5449303030303030303171", "p=- a1=- a2=- a3=- a0=- b1=- b2=- bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("badhex_later", "4449535430303030303030314152475630303030305a3033676363444f5449303030303030303171", "p=- a1=- a2=- a3=- a0=- b1=- b2=- bd=- bdist=- pdist=1 pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        // Not HAProxy's: HAProxy returns the declared 10 bytes, 7 of them past the data (stale pool memory, findings-db 639): only the 3 received.
        ("body_truncated", "444953543030303030303031415247563030303030303041616263", "p=- a1=10 a2=- a3=- a0=10 b1=616263 b2=- bd=- bdist=- pdist=1 pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        // Not HAProxy's: as above: HAProxy pads to the declared 4 bytes from past the data; only the 2 received.
        ("body_trunc_then", "4152475630303030303030346162", "p=- a1=4 a2=- a3=- a0=4 b1=6162 b2=- bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("zero_body", "4152475630303030303030304152475630303030303030315a444f54493030303030303030", "p=0 a1=0 a2=1 a3=- a0=0 b1=- b2=5A bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("bodiless_big", "444953544646464646464646415247433746464646464646535441543030303030303033444f4e4530303030303030394e46494c303030303030303241524756303030303030303121", "p=- a1=1 a2=- a3=- a0=1 b1=21 b2=- bd=- bdist=- pdist=4294967295 pargc=2147483647 pdone=9 pstat=3 pnfil=2 bnfil=- n=-"),
        // Not HAProxy's: HAProxy yields nothing (ofs + body wraps, chunk_initlen refuses a negative length, findings-db 288): the 6 bytes received, as for any body longer than the data.
        ("huge_body", "415247564646464646464646616263646566", "p=- a1=4294967295 a2=- a3=- a0=4294967295 b1=616263646566 b2=- bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("occ_many", "4152475630303030303030314141524756303030303030303142415247563030303030303031434152475630303030303030314441524756303030303030303145", "p=- a1=1 a2=1 a3=1 a0=1 b1=41 b2=42 bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("lowercase_tok", "6172677630303030303030316141524756303030303030303162", "p=- a1=1 a2=- a3=- a0=1 b1=62 b2=- bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("garbage", "474554202f20485454502f312e300d0a0d0a", "p=- a1=- a2=- a3=- a0=- b1=- b2=- bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("trailing_partial", "41524756303030303030303178444f5449303030", "p=- a1=1 a2=- a3=- a0=1 b1=78 b2=- bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("only_doti", "444f54493030303030303033616263", "p=3 a1=- a2=- a3=- a0=- b1=- b2=- bd=616263 bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("nul_tok", "0000000030303030303030317841524756303030303030303179", "p=- a1=1 a2=- a3=- a0=1 b1=79 b2=- bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("space_hex", "41524756203030303030303178444f5449303030303030303171", "p=- a1=- a2=- a3=- a0=- b1=- b2=- bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
        ("plus_hex", "415247562b3030303030303178444f5449303030303030303171", "p=- a1=- a2=- a3=- a0=- b1=- b2=- bd=- bdist=- pdist=- pargc=- pdone=- pstat=- pnfil=- bnfil=- n=-"),
];

#[test]
fn distcc_fetches_agree_with_haproxy() {
    let (mut engine, collector, fe) = start("tcp", SETS);
    for (name, hex, want) in CASES {
        assert_eq!(log_of(&mut engine, &collector, fe, unhex(hex)), *want, "{name}");
    }
}

/// The buffer of an HTTP stream is HTX, where these fetches have no value (`IS_HTX_STRM`):
/// a request whose body is a DISTCC stream gives no sample, as on `HAProxy`.
#[test]
fn distcc_fetches_give_nothing_in_an_http_proxy() {
    let (mut engine, collector, fe) = start("http", &SETS.replace("tcp-request content reject", "http-request return status 200"));
    let req = b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 27\r\nconnection: close\r\n\r\nDIST00000001ARGV00000003gcc";
    let line = log_of(&mut engine, &collector, fe, req.to_vec());
    assert!(line.starts_with("p=- a1=- a2=- "), "{line}");
    assert!(line.contains(" b1=- ") && line.contains(" pdist=- "), "{line}");
}

fn check(i: usize, rule: &str) -> Option<String> {
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout client 1s\n  timeout server 1s\n  timeout connect 1s\n\
         frontend fe\n  bind 127.0.0.1:1\n  {rule}\n  default_backend be\nbackend be\n  server s 127.0.0.1:2\n"
    );
    let p = std::env::temp_dir().join(format!("alcyon_distcc_{}_{i}.cfg", std::process::id()));
    std::fs::write(&p, cfg).expect("write config");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&p).output().expect("run alcyon -c");
    let _ = std::fs::remove_file(&p);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    text.lines().find(|l| l.contains("rror")).map(str::to_string)
}

/// `val_distcc`: the token is exactly 4 characters, as `haproxy -c` (3.5-dev8-885761-29)
/// says; an occurrence is not checked.
#[test]
fn distcc_token_is_four_characters() {
    for (i, (rule, fetch)) in [
        ("tcp-request content set-var(txn.x) distcc_param(DOT)", "distcc_param"),
        ("tcp-request content set-var(txn.x) distcc_param(DOTIX)", "distcc_param"),
        ("tcp-request content set-var(txn.x) distcc_body()", "distcc_body"),
    ]
    .iter()
    .enumerate()
    {
        let want = format!("invalid args in fetch method '{fetch}' : token name must be exactly 4 characters");
        let got = check(i, rule);
        assert!(got.as_deref().is_some_and(|g| g.contains(&want)), "{rule}: wanted {want:?}, got {got:?}");
    }
    assert_eq!(check(10, "tcp-request content set-var(txn.x) distcc_param(DOTI,-1)"), None);
}
