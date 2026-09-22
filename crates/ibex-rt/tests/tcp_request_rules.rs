// SPDX-License-Identifier: GPL-2.0-or-later

//! End-to-end behaviour of the `tcp-request` rulesets, against the real daemon.
//!
//! The rules added for connection, session and content scope landed with no tests. These
//! describe what `HAProxy` guarantees for the same configuration; several of them fail
//! today, and each failure is the point. Do not relax an assertion to get a green run --
//! the assertion is the specification, and the code is what has to move.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// The daemon binary, as cargo built it for this test.
fn ibex_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_ibex"))
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn write_cfg(name: &str, body: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("ibex_tcpreq_{}_{}", std::process::id(), name));
    std::fs::write(&p, body).expect("write config");
    p
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(cfg: &std::path::Path) -> Daemon {
    Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    )
}

fn wait_for_port(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

/// A backend that records every byte it is handed.
///
/// What reaches this is the whole question: a rule that should have rejected a connection
/// is observable exactly as bytes arriving here that should not have.
struct Backend {
    port: u16,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Backend {
    fn spawn(conns: usize, reply: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
        let port = listener.local_addr().expect("addr").port();
        let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        thread::spawn(move || {
            for _ in 0..conns {
                let Ok((mut c, _)) = listener.accept() else {
                    return;
                };
                c.set_read_timeout(Some(Duration::from_millis(500))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    match c.read(&mut tmp) {
                        Ok(n) if n > 0 => {
                            buf.extend_from_slice(&tmp[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        // End of stream, or the read timeout: either way nothing more is
                        // coming on this connection.
                        Ok(_) | Err(_) => break,
                    }
                }
                let _ = c.write_all(reply);
                let _ = c.flush();
                sink.lock().expect("backend lock").push(buf);
            }
        });
        Self { port, seen }
    }

    /// A backend that answers the instant any byte arrives, so a client can time the
    /// round trip. `spawn` waits for a full HTTP head first, which would hide the
    /// latency this is meant to measure behind its own read timeout.
    fn spawn_echo(conns: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
        let port = listener.local_addr().expect("addr").port();
        let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        thread::spawn(move || {
            for _ in 0..conns {
                let Ok((mut c, _)) = listener.accept() else {
                    return;
                };
                c.set_read_timeout(Some(Duration::from_secs(10))).ok();
                let mut tmp = [0u8; 4096];
                if let Ok(n) = c.read(&mut tmp) {
                    sink.lock().expect("backend lock").push(tmp[..n].to_vec());
                    let _ = c.write_all(b"ok");
                    let _ = c.flush();
                }
            }
        });
        Self { port, seen }
    }

    fn requests(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("backend lock")
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect()
    }

    /// Waits until `n` connections have been recorded, or gives up.
    fn wait_for(&self, n: usize, within: Duration) {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if self.seen.lock().expect("backend lock").len() >= n {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

const HTTP_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

fn tcp_inspect_cfg(port: u16, backend_port: u16) -> String {
    format!(
        "defaults\n\tmode tcp\n\ttimeout connect 3s\n\ttimeout client 5s\n\t\
         timeout server 5s\n\n\
         frontend fe\n\tbind 127.0.0.1:{port}\n\t\
         tcp-request inspect-delay 1s\n\t\
         tcp-request content reject if {{ req.payload(0,0) -m sub FORBIDDEN }}\n\t\
         default_backend be\n\n\
         backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
    )
}

/// Control: the rule works when the payload arrives in a single write.
///
/// This exists so that the failure of the test below cannot be blamed on the rule, the
/// fetch or the matcher. If this one fails, content inspection is broken outright; if it
/// passes and the next fails, the defect is specifically that inspection is decided
/// before the data it inspects has arrived.
#[test]
fn content_inspection_rejects_a_payload_written_in_one_go() {
    let be = Backend::spawn(1, HTTP_OK);
    let port = free_port();
    let cfg = write_cfg("inspect_onego.cfg", &tcp_inspect_cfg(port, be.port));
    let _d = start(&cfg);
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"XFORBIDDEN-PAYLOAD").expect("write");
    s.flush().ok();
    thread::sleep(Duration::from_millis(600));

    assert!(
        be.requests().is_empty(),
        "a payload matching a `tcp-request content reject` rule reached the backend: {:?}",
        be.requests()
    );
    let _ = std::fs::remove_file(&cfg);
}

/// Inspection must wait for the payload, not decide on the first byte to arrive.
///
/// `eval_tcp_req_content_rules` treats a non-empty request buffer as enough to evaluate:
/// one byte runs every rule and returns `Done`, ending inspection for the connection.
/// `HAProxy` does the opposite -- a fetch that cannot yet decide reports that the sample
/// may still change, the ruleset returns "missing data", and the session is retried
/// until the data arrives or `inspect-delay` expires. That is the entire reason
/// `inspect-delay` exists.
///
/// So a client that writes one byte, pauses, and then sends the real payload walks past
/// every content rule. This is the ordinary shape of a TLS or SSH client -- and of
/// anything deliberately trying not to be inspected.
#[test]
fn content_inspection_waits_for_the_payload_not_the_first_byte() {
    let be = Backend::spawn(1, HTTP_OK);
    let port = free_port();
    let cfg = write_cfg("inspect_split.cfg", &tcp_inspect_cfg(port, be.port));
    let _d = start(&cfg);
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    // One byte, well inside the 1s inspect-delay, then the payload the rule looks for.
    s.write_all(b"X").expect("write first byte");
    s.flush().ok();
    thread::sleep(Duration::from_millis(250));
    s.write_all(b"FORBIDDEN-PAYLOAD").expect("write payload");
    s.flush().ok();
    thread::sleep(Duration::from_millis(600));

    assert!(
        be.requests().is_empty(),
        "splitting the payload across two writes bypassed `tcp-request content reject`; \
         the backend received {:?}. Inspection ran against the first byte and finished \
         before the data it was inspecting arrived.",
        be.requests()
    );
    let _ = std::fs::remove_file(&cfg);
}

/// `fc_src` is the real TCP peer and `set-src` must not touch it.
///
/// The two fetches exist precisely so that one can be rewritten and the other cannot:
/// `src` is what the configuration decided the client is, `fc_src` is who actually
/// connected. `eval_tcp_req_conn_rules` assigns both from `set-src`, which removes the
/// only fetch that still reports the truth. An operator writing
/// `tcp-request connection reject if { fc_src -f /etc/blocklist }` after a `set-src`
/// derived from a client-supplied header is then matching the attacker's own value.
#[test]
fn fc_src_is_the_real_peer_after_set_src() {
    let be = Backend::spawn(1, HTTP_OK);
    let port = free_port();
    let cfg = write_cfg(
        "fc_src.cfg",
        &format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 5s\n\t\
             timeout server 5s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\t\
             tcp-request connection set-src ipv4(10.11.12.13)\n\t\
             http-request set-header X-Ibex-Src %[src]\n\t\
             http-request set-header X-Ibex-Fc-Src %[fc_src]\n\t\
             default_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{}\n",
            be.port
        ),
    );
    let _d = start(&cfg);
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .expect("write");
    s.flush().ok();
    let mut sink = Vec::new();
    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let _ = s.read_to_end(&mut sink);
    be.wait_for(1, Duration::from_secs(3));

    let reqs = be.requests();
    let req = reqs.first().expect("the backend saw no request at all");

    // First: `set-src` has to have done something, or the second assertion is vacuous.
    assert!(
        req.contains("X-Ibex-Src: 10.11.12.13"),
        "`set-src` did not rewrite `src`; the request carried: {req:?}"
    );
    // Then: the real peer must still be reachable.
    assert!(
        req.contains("X-Ibex-Fc-Src: 127.0.0.1"),
        "`set-src` also overwrote `fc_src`, so nothing reports the real TCP peer any \
         more. The request carried: {req:?}"
    );
    let _ = std::fs::remove_file(&cfg);
}

/// A `txn.` variable must not survive into the next request.
///
/// `CURRENT_VARS` is a thread-local that `connect_http_backend` inserts into and never
/// clears -- the `CURRENT_TIMEOUTS` block directly below it does call `clear()`, so the
/// pattern was there to follow. Anything a request writes stays visible to every later
/// request served by the same worker thread, including requests from other clients.
///
/// The leak is not only informational. An authorization rule of the shape
/// `http-request deny unless { var(txn.authed) -m found }` passes for an unauthenticated
/// request that happens to land on a thread which previously served an authenticated one.
#[test]
fn a_transaction_variable_does_not_leak_into_the_next_request() {
    let be = Backend::spawn(2, HTTP_OK);
    let port = free_port();
    let cfg = write_cfg(
        "txn_leak.cfg",
        &format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 5s\n\t\
             timeout server 5s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\t\
             http-request set-var(txn.leak) str(tainted) if {{ path -m beg /taint }}\n\t\
             http-request set-header X-Ibex-Leak %[var(txn.leak)]\n\t\
             default_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{}\n",
            be.port
        ),
    );
    let _d = start(&cfg);
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    for path in ["/taint", "/clean"] {
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .expect("write");
        s.flush().ok();
        let mut sink = Vec::new();
        s.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let _ = s.read_to_end(&mut sink);
    }
    be.wait_for(2, Duration::from_secs(4));

    let reqs = be.requests();
    assert_eq!(reqs.len(), 2, "expected both requests to reach the backend: {reqs:?}");
    assert!(
        reqs[0].contains("X-Ibex-Leak: tainted"),
        "the first request should have set the variable: {:?}",
        reqs[0]
    );
    assert!(
        !reqs[1].contains("tainted"),
        "a `txn.` variable set by an earlier request was still readable by a later one \
         on a separate connection. The second request carried: {:?}",
        reqs[1]
    );
    let _ = std::fs::remove_file(&cfg);
}

/// A rule that names a stick table which does not exist must be refused.
///
/// `tcp-request content track-sc0 ... table <name>` parses, is stored, and then falls
/// into the `_ => {}` arm of the content evaluator, so it tracks nothing. Nothing in the
/// configuration path notices either, because an action nobody executes has no references
/// to resolve. `HAProxy` fails to start here ("unable to find table"), which is what
/// makes the silent no-op impossible to ship.
///
/// This is the cheapest possible check on the whole class: if the reference is validated,
/// the action is not being ignored.
#[test]
fn a_track_sc_rule_naming_an_undefined_table_is_refused() {
    let port = free_port();
    let cfg = write_cfg(
        "track_undef.cfg",
        &format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 5s\n\t\
             timeout server 5s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\t\
             tcp-request content track-sc0 src table no_such_table\n\t\
             default_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:1\n"
        ),
    );
    let out = Command::new(ibex_bin())
        .arg("-c")
        .arg(&cfg)
        .output()
        .expect("run ibex -c");
    assert!(
        !out.status.success(),
        "a `track-sc0` rule pointing at an undefined stick table was accepted. Either the \
         action is enforced, in which case the table reference has to resolve, or it is \
         being silently ignored -- and a rate-limiting rule that silently does nothing is \
         the worst of the three outcomes."
    );
    let _ = std::fs::remove_file(&cfg);
}

/// `tcp-request content` in a `backend` must be evaluated.
///
/// The rules are parsed, stored on the backend's `Proxy` (`init_proxy_from_backend`), and
/// never read: evaluation only ever runs against the frontend's proxy index. A rule
/// placed in a backend therefore has no effect at all, with no diagnostic.
#[test]
fn backend_tcp_request_content_rules_are_evaluated() {
    let be = Backend::spawn(1, HTTP_OK);
    let port = free_port();
    let cfg = write_cfg(
        "be_content.cfg",
        &format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 5s\n\t\
             timeout server 5s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\t\
             tcp-request content reject if {{ req.payload(0,0) -m sub FORBIDDEN }}\n\t\
             server s1 127.0.0.1:{}\n",
            be.port
        ),
    );
    let _d = start(&cfg);
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"GET /FORBIDDEN HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .expect("write");
    s.flush().ok();
    let mut sink = Vec::new();
    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let _ = s.read_to_end(&mut sink);
    thread::sleep(Duration::from_millis(400));

    assert!(
        be.requests().is_empty(),
        "a `tcp-request content reject` rule in a backend section had no effect; the \
         backend received {:?}",
        be.requests()
    );
    let _ = std::fs::remove_file(&cfg);
}

/// `inspect-delay` is the longest inspection may take, not how long it always takes.
///
/// `eval_tcp_req_content_rules` now ends with
/// `if inspect_exp.is_some() && !expired { Waiting }`, so once a delay is configured the
/// session is held until the whole of it elapses -- whether or not the rules reached a
/// decision on the first pass. That closes the split-write bypass, which was the urgent
/// part, but it pays for it with the delay on every connection.
///
/// `HAProxy` releases the session as soon as the ruleset reaches a final answer; the delay
/// only bounds how long it will wait for data it still needs. `tcp-request inspect-delay
/// 5s` is an ordinary line in an ordinary configuration, and under the current behaviour
/// it adds five seconds to every connection through that frontend.
///
/// Measured before this test was written, with a rule that never matches:
/// `inspect-delay 5s` -> backend saw the payload after 4.91s; no `inspect-delay` -> 0.00s.
#[test]
fn inspect_delay_is_a_maximum_not_a_fixed_wait() {
    let be = Backend::spawn_echo(1);
    let port = free_port();
    let cfg = write_cfg(
        "inspect_latency.cfg",
        &format!(
            "defaults\n\tmode tcp\n\ttimeout connect 3s\n\ttimeout client 20s\n\t\
             timeout server 20s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\t\
             tcp-request inspect-delay 5s\n\t\
             tcp-request content reject if {{ req.payload(0,0) -m sub NEVERMATCHES }}\n\t\
             default_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{}\n",
            be.port
        ),
    );
    let _d = start(&cfg);
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let started = Instant::now();
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(15))).ok();
    // The whole payload in one write: the rules can decide immediately and they do not
    // match, so there is nothing left for the delay to wait for.
    s.write_all(b"entirely benign traffic, decided on the first pass\n")
        .expect("write");
    s.flush().ok();
    let mut sink = [0u8; 64];
    let _ = s.read(&mut sink);
    let elapsed = started.elapsed();

    assert!(
        !be.requests().is_empty(),
        "the benign payload never reached the backend at all"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "a connection whose rules were decided on the first pass still waited {:.2}s of \
         a 5s `inspect-delay`. The delay is a ceiling on how long inspection may wait for \
         data it still needs, not a toll paid by every connection -- at this rate any \
         frontend carrying an inspect-delay is unusable.",
        elapsed.as_secs_f64()
    );
    let _ = std::fs::remove_file(&cfg);
}

/// A substring match that has not matched yet is never final until the data is.
///
/// `eval_acl_term_extended` decides a payload fetch has enough data by computing
/// `min_needed` -- the offset plus the length of the pattern when no explicit length was
/// given -- and evaluating once that many bytes have arrived. For an anchored match that
/// is right: `-m str` with an explicit length, or `-m beg`, is decided by the bytes at a
/// known position, and once they are present a non-match is final.
///
/// For `-m sub` it is not. A substring may appear at any offset, so "the pattern did not
/// appear in the first `pat_len` bytes" says nothing about whether it appears at all. The
/// same holds for `-m end`, which cannot be decided until the stream is.
///
/// Measured against the current build, with `inspect-delay 3s` and `-m sub FORBIDDEN`:
///
/// ```text
///  1 byte of padding, then the payload -> correctly rejected
///  9 bytes ( == len("FORBIDDEN"))      -> forwarded to the backend
/// 40 bytes                             -> forwarded to the backend
/// ```
///
/// So the bypass this file already tests for survives; it just costs the client nine
/// bytes of padding instead of one. The sibling test above passes only because it happens
/// to send a single byte first.
///
/// The rule: a non-match on an unanchored matcher is not a final answer while the client
/// is open and the delay has not expired. Only a match is final early.
#[test]
fn an_unanchored_payload_match_is_not_decided_by_pattern_length_alone() {
    let be = Backend::spawn(1, HTTP_OK);
    let port = free_port();
    let cfg = write_cfg("inspect_padded.cfg", &tcp_inspect_cfg(port, be.port));
    let _d = start(&cfg);
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    // Longer than the pattern, so a byte-count heuristic believes it can decide.
    s.write_all(&[b'X'; 40]).expect("write padding");
    s.flush().ok();
    thread::sleep(Duration::from_millis(250));
    s.write_all(b"FORBIDDEN-PAYLOAD").expect("write payload");
    s.flush().ok();
    thread::sleep(Duration::from_millis(600));

    assert!(
        be.requests().is_empty(),
        "40 bytes of padding ahead of the payload bypassed `tcp-request content reject`; \
         the backend received {:?}. A `-m sub` non-match was treated as final once \
         pattern-length bytes had arrived, but a substring can appear at any offset.",
        be.requests()
    );
    let _ = std::fs::remove_file(&cfg);
}
