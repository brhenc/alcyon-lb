// SPDX-License-Identifier: GPL-2.0-or-later
//! Byte-count fetches: `bytes_in`, `bytes_out`, `req.bytes_in` and `res.bytes_in` (HAProxy
//! `smp_fetch_bytes`, `src/sample.c`), read from a custom `log-format`.
//!
//! Each counts the stream's bytes as the proxy sees them, in the HTX (parsed
//! message) not the wire framing: `bytes_in`/`req.bytes_in` count the request the
//! client sent, `bytes_out`/`res.bytes_in` the response the server sent. A chunked
//! body is counted decoded, not as its chunk framing, and a request the proxy answers
//! itself receives nothing from a server. `req.bytes_out`/`res.bytes_out` are refused
//! at load (`fetch_edge_cases::bytes_out_fetches_are_refused_with_a_reason`).
//!
//! Scenarios, one connection each (`Connection: close`, one log line per request):
//! an HTTP/1.1 GET with no body, a POST with a 1000-byte body answered by a 5000-byte
//! response, a chunked response, a request the proxy answers itself (`http-request
//! return`), and one HTTP/2 GET over a `proto h2` bind (bridged to the HTTP/1.1
//! backend). All expected values were measured on the HAProxy 3.5-dev11 oracle; run
//! with `T281_ORACLE=/var/tmp/qwen-next-eval/oracle/haproxy` to re-verify. The
//! oracle is the judge: a row it does not pass is a wrong row, not a pass.

use crate::common;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;



struct Proxy {
    child: Child,
    _cfg: NamedTempFile,
    fe: SocketAddr,
    fe_h2: SocketAddr,
    logs: mpsc::Receiver<String>,
}

impl Proxy {
    fn start(be: SocketAddr) -> Self {
        let fe = common::reserve_addr();
        let fe_h2 = common::reserve_addr();

        let mut cfg = NamedTempFile::new().expect("tmp");
        let _ = write!(
            cfg,
            "global
  log stdout format raw local0
defaults
  mode http
  log global
  timeout client 5s
  timeout server 5s
  timeout connect 2s
  timeout http-request 2s
  timeout http-keep-alive 2s
  log-format \"%[bytes_in] %[bytes_out] %[req.bytes_in] %[res.bytes_in] %r\"
listen l
  bind {fe}
  bind {fe_h2} proto h2
  http-request return status 200 content-type text/plain lf-string \"ok\" if {{ path /local }}
  server s {be}
"
        );

        let bin = std::env::var("T281_ORACLE")
            .unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
        let cfg_path = cfg.path().to_path_buf();
        let mut child = Command::new(&bin)
            .arg("-f")
            .arg(cfg.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn proxy");

        let (tx, rx) = mpsc::channel();
        let out = child.stdout.take().expect("stdout piped");
        thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                match line {
                    Ok(l) => {
                        if tx.send(l).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let p = Proxy {
            child,
            _cfg: cfg,
            fe,
            fe_h2,
            logs: rx,
        };
        if !common::wait_listening(p.fe) {
            // Config rejected at load: show the checker's verdict and the config.
            let check = Command::new(&bin).arg("-c").arg("-f").arg(&cfg_path).output();
            panic!(
                "never listened; `{bin} -c` says:\n{}\nconfig:\n{}",
                check
                    .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
                    .unwrap_or_default(),
                std::fs::read_to_string(&cfg_path).unwrap_or_default()
            );
        }
        p
    }

    /// Drive the scenario on a fresh connection, then wait for the log line whose
    /// request URI is `uri`; return the six counts.
    fn line_for(&self, fe: SocketAddr, path: &str, uri: &str) -> (i64, i64, i64, i64) {
        match path {
            "/post" => post(fe),
            "/h2get" => h2_get(fe),
            _ => get(path, fe),
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut recent = Vec::new();
        while Instant::now() < deadline {
            while let Ok(l) = self.logs.try_recv() {
                recent.push(l.clone());
                let toks: Vec<&str> = l.split_whitespace().collect();
                // The custom log-format prints the four counts then the request line
                // (`METHOD SP URI SP VERSION`): match the URI, take the first four fields.
                if toks.len() >= 7
                    && toks[toks.len() - 2] == uri
                    && (0..4).all(|i| toks[i].parse::<i64>().is_ok())
                {
                    let mut v = [0i64; 4];
                    for i in 0..4 {
                        v[i] = toks[i].parse().unwrap();
                    }
                    return (v[0], v[1], v[2], v[3]);
                }
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!(
            "no log line for {uri} ({path}); recent: {:?}",
            recent.iter().take(20).collect::<Vec<_>>()
        );
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// One connection per request; the client closes after the response.
fn get(path: &str, fe: SocketAddr) {
    let mut s = TcpStream::connect(fe).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(8))).unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).unwrap();
    drain(&mut s);
}

/// `POST /post` with a 1000-byte body.
fn post(fe: SocketAddr) {
    let mut s = TcpStream::connect(fe).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut req: Vec<u8> =
        b"POST /post HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 1000\r\n\r\n".to_vec();
    req.extend(std::iter::repeat(b'b').take(1000));
    s.write_all(&req).unwrap();
    drain(&mut s);
}

fn drain(s: &mut TcpStream) {
    let mut buf = [0u8; 65536];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

// --- The backend: HTTP/1.1, one request per connection, closes after each response. ---
// Paths: `/get` and `/h2get` (200, no body), `/post` (200, 5000-byte body; the 1000-byte
// request body is consumed), `/chunked` (200 chunked: `hello`, ` world`, end).

fn backend(port: u16) -> thread::JoinHandle<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let _ = thread::spawn(move || {
                let mut r = BufReader::new(&mut s);
                let mut head = String::new();
                let mut line = String::new();
                loop {
                    line.clear();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut cl: u64 = 0;
                for l in head.lines() {
                    let t = l.trim();
                    if let Some(v) = t.strip_prefix("Content-Length:").or_else(|| t.strip_prefix("content-length:")) {
                        cl = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body_in = vec![0u8; cl.min(1000) as usize];
                let _ = r.read_exact(&mut body_in);
                let low = head.to_ascii_lowercase();
                let resp: Vec<u8> = if low.contains("post /post") {
                    assert_eq!(cl, 1000);
                    let mut b = b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n".to_vec();
                    b.extend(std::iter::repeat(b'a').take(5000));
                    b
                } else if low.contains("get /chunked") {
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec()
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
                };
                let _ = s.write_all(&resp);
            });
        }
    })
}

// --- HTTP/2 client: connection preface, empty SETTINGS, one HEADERS (END_STREAM) on
// stream 1 with four literal (unindexed, un-Huffman) pseudo-headers. ---

fn h2_frame(ftype: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut f = Vec::with_capacity(9 + len);
    let lb = u32::try_from(len).expect("frame < 16MiB").to_be_bytes();
    f.extend([lb[1], lb[2], lb[3], ftype, flags]);
    f.extend((sid & 0x7fff_ffff).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// One `GET /h2get` on stream 1 over a `proto h2` bind, like `conn_addresses.rs`:
/// preface, empty SETTINGS, one literal (unindexed) HEADERS with END_STREAM, then
/// ACK the server SETTINGS and stop once the response head arrives.
fn h2_get(fe: SocketAddr) {
    let mut s = TcpStream::connect(fe).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut init = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    init.extend_from_slice(&h2_frame(4, 0, 0, &[])); // SETTINGS, empty
    s.write_all(&init).unwrap();
    let mut block = Vec::new();
    for (name, value) in [
        (":method", "GET"),
        (":scheme", "http"),
        (":authority", "x"),
        (":path", "/h2get"),
    ] {
        block.push(0u8);
        block.push(name.len() as u8);
        block.extend(name.as_bytes());
        block.push(value.len() as u8);
        block.extend(value.as_bytes());
    }
    s.write_all(&h2_frame(1, 0x05, 1, &block)).unwrap();
    loop {
        let mut hdr = [0u8; 9];
        if s.read_exact(&mut hdr).is_err() {
            break;
        }
        let n = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | (hdr[2] as usize);
        let mut payload = vec![0u8; n];
        if s.read_exact(&mut payload).is_err() {
            break;
        }
        match (hdr[3], hdr[4]) {
            (4, fl) if fl & 1 == 0 => {
                let _ = s.write_all(&h2_frame(4, 1, 0, &[])); // ACK the SETTINGS
            }
            (1, fl) if fl & 1 != 0 => break, // the response HEADERS, end of the stream
            (0, fl) if fl & 1 != 0 => break, // DATA END_STREAM
            _ => {}
        }
    }
}

fn check(name: &str, got: (i64, i64, i64, i64), want: (i64, i64, i64, i64)) {
    assert_eq!(
        got,
        want,
        "{name}: got (bytes_in, bytes_out, req.bytes_in, res.bytes_in) = {got:?}, want {want:?}",
    );
}

#[test]
fn the_four_byte_fetches_match_the_oracle() {
    let be = common::reserve_addr();
    let _be = backend(be.port());
    let p = Proxy::start(be);

    // GET, no body. The request is counted as the HTX the proxy parsed of it,
    // `41` bytes; the response as `49`. In an unedited relay the proxy sends the
    // same logical message on the server hop. (`req.bytes_out`/`res.bytes_out` are refused:
    // `fetch_edge_cases::bytes_out_fetches_are_refused_with_a_reason`.)
    check(
        "h1 get",
        p.line_for(p.fe, "/get", "/get"),
        (41, 49, 41, 49),
    );

    // POST 1000-byte body -> 5000-byte response. Request counted `1061`, response `5052`.
    check(
        "h1 post",
        p.line_for(p.fe, "/post", "/post"),
        (1061, 5052, 1061, 5052),
    );

    // Chunked response: the proxy decodes the chunks, so the response counts as the
    // re-encoded HTX, `70` bytes (not the 97 bytes of chunked framing on the wire).
    check(
        "h1 chunked",
        p.line_for(p.fe, "/chunked", "/chunked"),
        (45, 70, 45, 70),
    );

    // The proxy answers itself: nothing came back from a server (0).
    check(
        "local return",
        p.line_for(p.fe, "/local", "/local"),
        (43, 0, 43, 0),
    );

    // One GET over HTTP/2 (client side); bridged to the HTTP/1.1 backend. The request
    // line in the log is the pseudo-URL, `GET http://x/h2get HTTP/2.0`.
    check(
        "h2 get",
        p.line_for(p.fe_h2, "/h2get", "http://x/h2get"),
        (51, 49, 51, 49),
    );
}
