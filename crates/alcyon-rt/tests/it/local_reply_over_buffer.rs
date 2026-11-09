// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A local reply larger than one buffer (T589, found by T580).
//!
//! `TcpSession::write_reply_with` keeps what does not fit in `rep` as `PendingOut::Raw`;
//! only `process_cli_io` drained it, and that returns at once for an HTTP/2 stream, so the
//! first buffer went out as DATA and the rest never did (curl: 16315 bytes, exit 92).
//!
//! `HAProxy` 3.5-dev8-885761-29 refuses at parse what cannot be a reply: `return`, `deny`
//! and `http-error` with a `file`/`lf-file` larger than `tune.bufsize`
//! (`file '<f>' exceeds the buffer size (<size> > <bufsize>)`, the rules with a final `.`),
//! one that cannot be opened (`error opening file '<f>'`), and an errorfile whose parsed
//! message does not fit the buffer's HTX (`'<f>': unable to add payload into the HTX
//! message`; a file over the buffer is cut at it, and a warning says so). The size check
//! comes before the `content-type` one. Measured: a 16384-byte file is accepted, 16385
//! refused; with `tune.bufsize 2048` a 3000-byte one is refused; an errorfile of
//! `HTTP/1.0 400 Bad` + a body is refused from 16306 bytes in all (1970 at 2048).

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("alcyon-t589-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("dir");
    d
}

/// `alcyon -c` on `cfg`: whether it was accepted, and what it printed.
fn check(d: &Path, cfg: &str) -> (bool, String) {
    let path = d.join("c.cfg");
    std::fs::write(&path, cfg).expect("cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().expect("alcyon -c");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn cfg(global: &str, rule: &str) -> String {
    format!("{global}defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\nfrontend f\n  bind 127.0.0.1:1\n  {rule}\n")
}

fn file_of(d: &Path, name: &str, len: usize) -> String {
    let p = d.join(name);
    std::fs::write(&p, vec![b'a'; len]).expect("file");
    p.display().to_string()
}

/// An errorfile: `HTTP/1.0 400 Bad`, a blank line, and a body so the whole file is `total`.
fn errorfile_of(d: &Path, name: &str, total: usize) -> String {
    let p = d.join(name);
    let head = b"HTTP/1.0 400 Bad\r\n\r\n";
    let mut v = head.to_vec();
    v.resize(total, b'a');
    std::fs::write(&p, v).expect("file");
    p.display().to_string()
}

#[test]
fn a_reply_file_over_the_buffer_is_refused_at_parse() {
    let d = dir("file");
    let big = file_of(&d, "big.txt", 100_000);
    for (what, rule) in [
        ("return file", format!("http-request return status 200 content-type text/plain file {big}")),
        ("return lf-file", format!("http-request return status 200 content-type text/plain lf-file {big}")),
        ("response return file", format!("http-response return status 200 content-type text/plain file {big}")),
        ("deny file", format!("http-request deny deny_status 403 content-type text/plain file {big}")),
        // The size is checked before the content type: none is given here.
        ("return file, no content-type", format!("http-request return status 200 file {big}")),
    ] {
        let (ok, err) = check(&d, &cfg("", &rule));
        assert!(!ok, "{what}: accepted");
        let want = format!("file '{big}' exceeds the buffer size (100000 > 16384).");
        assert!(err.contains(&want), "{what}: {err}");
    }
    let (ok, err) = check(&d, &cfg("", &format!("http-error status 400 file {big}")));
    assert!(!ok && err.contains(&format!("file '{big}' exceeds the buffer size (100000 > 16384)")), "http-error: {err}");
    assert!(!err.contains("(100000 > 16384)."), "http-error has no final dot: {err}");
}

#[test]
fn the_limit_is_the_buffer_size() {
    let d = dir("limit");
    let at = file_of(&d, "at.txt", 16384);
    let over = file_of(&d, "over.txt", 16385);
    let (ok, err) = check(&d, &cfg("", &format!("http-request return status 200 content-type text/plain file {at}")));
    assert!(ok, "16384 bytes refused: {err}");
    let (ok, err) = check(&d, &cfg("", &format!("http-request return status 200 content-type text/plain file {over}")));
    assert!(!ok && err.contains(&format!("file '{over}' exceeds the buffer size (16385 > 16384).")), "{err}");
    let small = file_of(&d, "small.txt", 3000);
    let rule = format!("http-request return status 200 content-type text/plain file {small}");
    let (ok, err) = check(&d, &cfg("global\n  tune.bufsize 2048\n", &rule));
    assert!(!ok && err.contains(&format!("file '{small}' exceeds the buffer size (3000 > 2048).")), "{err}");
}

#[test]
fn a_reply_file_that_cannot_be_opened_is_refused() {
    let d = dir("open");
    let gone = d.join("gone.txt").display().to_string();
    for kw in ["file", "lf-file"] {
        let rule = format!("http-request return status 200 content-type text/plain {kw} {gone}");
        let (ok, err) = check(&d, &cfg("", &rule));
        assert!(!ok && err.contains(&format!("error opening file '{gone}'.")), "{kw}: {err}");
    }
    let (ok, err) = check(&d, &cfg("", &format!("http-error status 400 file {gone}")));
    assert!(!ok && err.contains(&format!("error opening file '{gone}'")), "http-error: {err}");
}

#[test]
fn an_errorfile_that_does_not_fit_the_buffer_is_refused() {
    let d = dir("ef");
    let big = errorfile_of(&d, "big.http", 100_000);
    let edge = errorfile_of(&d, "edge.http", 16306);
    let fits = errorfile_of(&d, "fits.http", 16305);
    for (what, rule) in [
        ("errorfile", format!("errorfile 400 {big}")),
        ("errorfile at the edge", format!("errorfile 400 {edge}")),
        ("return errorfile", format!("http-request return status 400 errorfile {big}")),
        ("http-error errorfile", format!("http-error status 400 errorfile {big}")),
    ] {
        let file = if what.contains("edge") { &edge } else { &big };
        let (ok, err) = check(&d, &cfg("", &rule));
        assert!(!ok, "{what}: accepted");
        assert!(err.contains(&format!("'{file}': unable to add payload into the HTX message")), "{what}: {err}");
    }
    let (ok, err) = check(&d, &cfg("", &format!("errorfile 400 {fits}")));
    assert!(ok, "16305 bytes refused: {err}");
    // Smaller buffer, same rule: 2048 - 78 = 1970.
    let small = errorfile_of(&d, "s.http", 1970);
    let (ok, err) = check(&d, &cfg("global\n  tune.bufsize 2048\n", &format!("errorfile 400 {small}")));
    assert!(!ok && err.contains("unable to add payload into the HTX message"), "{err}");
    let small = errorfile_of(&d, "s2.http", 1969);
    let (ok, err) = check(&d, &cfg("global\n  tune.bufsize 2048\n", &format!("errorfile 400 {small}")));
    assert!(ok, "{err}");
}

// ---- what is accepted and still larger than a buffer: it must arrive whole ----------------

// The longest `string` is the one that fits the HTX buffer with its head (T597: HAProxy answers 500
// for a longer one, which `local_reply_string_fit` checks); the reply is then nearly a whole buffer.
const BODY: usize = 16_000;

struct Run {
    child: common::Alcyon,
    d: PathBuf,
    plain: std::net::SocketAddr,
    tls: std::net::SocketAddr,
}

impl Drop for Run {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.d);
    }
}

fn start(tag: &str) -> Run {
    start_with(tag, "", BODY)
}

fn start_with(tag: &str, global: &str, body_len: usize) -> Run {
    let d = dir(tag);
    let (plain, tls) = (common::reserve_addr(), common::reserve_addr());
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    // `string` is the one body HAProxy accepts at any length at parse (and answers 500 for at
    // run time when it does not fit, T597); a reply that fits goes whole over HTTP/1.1 and HTTP/2.
    let body = "b".repeat(body_len);
    let c = format!(
        "global\n  nbthread 1\n{global}defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend f\n  bind {plain} proto h2\n  bind {tls} ssl crt {crt} alpn h2,http/1.1\n  http-request return status 200 content-type text/plain string \"{body}\"\n"
    );
    let cfg = d.join("run.cfg");
    std::fs::write(&cfg, c).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Alcyon).expect("spawn");
    assert!(common::wait_listening(plain) && common::wait_listening(tls), "alcyon never listened");
    Run { child, d, plain, tls }
}

/// curl's "<status> <bytes> <http version>" for `url` with `args`, and its exit code.
fn curl(args: &[&str], url: &str) -> (String, Option<i32>, Duration) {
    let t = Instant::now();
    let out = Command::new("curl")
        .args(["-s", "-k", "-m", "10", "-o", "/dev/null", "-w", "%{http_code} %{size_download} %{http_version}"])
        .args(args)
        .arg(url)
        .output()
        .expect("curl");
    (String::from_utf8_lossy(&out.stdout).into_owned(), out.status.code(), t.elapsed())
}

#[test]
fn a_buffer_sized_local_reply_arrives_whole_over_h2c() {
    let r = start("h2c");
    let (got, code, took) = curl(&["--http2-prior-knowledge"], &format!("http://{}/", r.plain));
    assert_eq!((got.as_str(), code), (&*format!("200 {BODY} 2"), Some(0)), "after {took:?}");
}

#[test]
fn a_buffer_sized_local_reply_arrives_whole_over_tls_h2() {
    let r = start("tls");
    let (got, code, took) = curl(&["--http2"], &format!("https://{}/", r.tls));
    assert_eq!((got.as_str(), code), (&*format!("200 {BODY} 2"), Some(0)), "after {took:?}");
}

#[test]
fn the_same_reply_over_http11_stays_whole() {
    let r = start("h1");
    let (got, code, _) = curl(&["--http1.1"], &format!("https://{}/", r.tls));
    assert_eq!((got.as_str(), code), (&*format!("200 {BODY} 1.1"), Some(0)));
}

/// A slow reader: the reply is longer than the stream's buffer and the connection's window
/// several times over, so the buffer is consumed in pieces, and what is left of the reply
/// is moved into the room that appears.
#[test]
fn a_slow_h2_reader_gets_a_long_local_reply_whole() {
    const LONG: usize = 16_000;
    let r = start_with("slow", "", LONG);
    let (got, code, took) = curl(&["--http2-prior-knowledge", "--limit-rate", "400k"], &format!("http://{}/", r.plain));
    assert_eq!((got.as_str(), code), (&*format!("200 {LONG} 2"), Some(0)), "after {took:?}");
}
