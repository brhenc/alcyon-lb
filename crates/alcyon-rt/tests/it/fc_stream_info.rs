// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T331 / G3 CONNVIEW: `fc_nb_streams` (HTTP/1, HTTP/2, HTTP/3), `fc_settings_streams_limit`
//! (HTTP/1 and HTTP/2) and `fc_glitches` (HTTP/2 only; HTTP/1 stays refused at load because
//! Alcyon counts no HTTP/1 glitches) read the connection through `ConnView`. `HAProxy` 3.5-dev8,
//! three HEADERS frames in one write on a `proto h2` bind:
//! `fc_nb_streams|fc_settings_streams_limit|fc_glitches` gives `3|100|0`, `2|100|0`, `1|100|0`,
//! and `3|7|0`, `2|7|0`, `1|7|0` with `tune.h2.fe.max-concurrent-streams 7`.
//! Set `T281_ORACLE=/path/to/haproxy` to run the wire tests against `HAProxy`.

use crate::common;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

/// `{X}` is the place of the expression under test.
const CFG: &str = "global
  nbthread 1
defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend fe
  bind 127.0.0.1:0
  {X}
";

/// `alcyon -c` on `CFG` with `line` in the frontend: the exit code and what it printed.
fn check(tag: &str, line: &str) -> (Option<i32>, String) {
    let dir = std::env::temp_dir().join(format!("fc-stream-info-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(&path, CFG.replace("{X}", line)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn fc_stream_fetches_are_refused_with_a_reason() {
    for (i, f) in ["fc_glitches"].into_iter().enumerate() {
        for (j, line) in [
            format!("http-request return status 200 content-type text/plain lf-string \"%[{f}]\""),
            format!("http-request deny if {{ {f} gt 0 }}"),
            format!("http-request set-var(txn.v) {f}"),
        ]
        .iter()
        .enumerate()
        {
            let (code, out) = check(&format!("{i}-{j}"), line);
            assert_ne!(code, Some(0), "{line:?} loaded: {out}");
            assert!(out.contains(&format!("'{f}' : not implemented in Alcyon")), "{line:?}: {out}");
        }
    }
    // `listen` section with an HTTP/1 bind also refuses `fc_glitches`.
    let dir = std::env::temp_dir().join(format!("fc-stream-info-listen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nlisten li\n  bind 127.0.0.1:0\n  http-request deny if { fc_glitches gt 0 }\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_ne!(out.status.code(), Some(0));
    let txt = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(txt.contains("'fc_glitches' : not implemented in Alcyon"), "{txt}");

    // `backend` section with `fc_glitches` loads (checked against frontend at runtime/bind).
    let dir = std::env::temp_dir().join(format!("fc-stream-info-be-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind 127.0.0.1:0 proto h2\n  default_backend be\nbackend be\n  http-request return status 200 content-type text/plain lf-string \"%[fc_glitches]\"\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(0), "backend fc_glitches failed -c: {:?}", out);
}

fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut f = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, kind, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

#[test]
fn fc_settings_streams_limit_h1_answers_one() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  nbthread 1\n\
         defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n  \
         http-request return status 200 content-type text/plain lf-string \"%[fc_settings_streams_limit]\"\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let _child = Command::new(bin())
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn");
    assert!(common::wait_listening(fe), "never listened");

    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(2))).ok();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let mut resp = String::new();
    let _ = c.read_to_string(&mut resp);
    assert!(resp.starts_with("HTTP/1.1 200"), "unexpected response: {resp:?}");
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    assert_eq!(body, "1", "expected 1 on HTTP/1, got {resp:?}");
}

fn run_h2_three_streams(max_concurrent_streams: Option<u32>, lf_string: &str) -> Vec<String> {
    let fe = common::reserve_addr();
    let tune = max_concurrent_streams.map_or_else(String::new, |n| format!("  tune.h2.fe.max-concurrent-streams {n}\n"));
    let cfg = format!(
        "global\n  nbthread 1\n{tune}\
         defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe} proto h2\n  \
         http-request return status 200 content-type text/plain lf-string \"{lf_string}\"\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let _child = Command::new(bin())
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn");
    assert!(common::wait_listening(fe), "never listened");

    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(50))).ok();
    let req = [0x82, 0x86, 0x84, 0x01, 0x01, b'x'];
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    hello.extend_from_slice(&h2_frame(1, 5, 1, &req));
    hello.extend_from_slice(&h2_frame(1, 5, 3, &req));
    hello.extend_from_slice(&h2_frame(1, 5, 5, &req));
    c.write_all(&hello).expect("send");

    let mut bodies: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut ended: BTreeMap<u32, bool> = BTreeMap::new();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let t0 = Instant::now();
    while ended.values().filter(|&&done| done).count() < 3 && t0.elapsed() < Duration::from_secs(5) {
        match c.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let kind = buf[3];
            let flags = buf[4];
            let stream = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            let payload = &buf[9..9 + len];
            if kind == 0 && stream != 0 {
                let data = if flags & 0x08 != 0 && !payload.is_empty() {
                    let pad = usize::from(payload[0]);
                    &payload[1..payload.len().saturating_sub(pad)]
                } else {
                    payload
                };
                bodies.entry(stream).or_default().extend_from_slice(data);
            }
            if (kind == 0 || kind == 1) && stream != 0 && (flags & 0x01 != 0) {
                ended.insert(stream, true);
            }
            buf.drain(..9 + len);
        }
    }
    [1u32, 3, 5]
        .into_iter()
        .map(|s| String::from_utf8_lossy(bodies.get(&s).map_or(&[], Vec::as_slice)).into_owned())
        .collect()
}

#[test]
fn fc_settings_streams_limit_and_glitches_h2_three_streams() {
    let lf = "%[fc_settings_streams_limit]|%[fc_glitches]";
    assert_eq!(run_h2_three_streams(None, lf), vec!["100|0", "100|0", "100|0"]);
    assert_eq!(run_h2_three_streams(Some(7), lf), vec!["7|0", "7|0", "7|0"]);
}

#[test]
fn fc_nb_streams_h2_three_streams() {
    let lf = "%[fc_nb_streams]|%[fc_settings_streams_limit]|%[fc_glitches]";
    assert_eq!(run_h2_three_streams(None, lf), vec!["3|100|0", "2|100|0", "1|100|0"]);
    assert_eq!(run_h2_three_streams(Some(7), lf), vec!["3|7|0", "2|7|0", "1|7|0"]);
}
