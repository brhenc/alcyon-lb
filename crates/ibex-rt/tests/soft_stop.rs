// SPDX-License-Identifier: GPL-2.0-or-later
//! Soft stop, as `HAProxy` does it on `SIGUSR1` (`src/haproxy.c:2609`, `sig_soft_stop`):
//! stop accepting, let what is in flight finish, then exit.
//!
//! These drive the real binary rather than an in-process `Engine`, because what is under
//! test is the process: its signal disposition, when it closes its listeners, and whether
//! it exits. `-sf <pid>` sends exactly this signal to the old process on every reload, so
//! until this works a reload is an abrupt kill of everything the old process was serving.

mod common;

use rustix::process::{kill_process, Pid, Signal};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;


/// A backend that answers each request after `delay`, or never if `delay` is `None`.
fn slow_backend(delay: Option<Duration>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                match delay {
                    Some(d) => {
                        thread::sleep(d);
                        let _ = s.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow",
                        );
                    }
                    None => thread::sleep(Duration::from_secs(30)),
                }
            });
        }
    });
    addr
}

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Ibex {
    fn start(cfg: &str, fe: SocketAddr) -> Self {
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write cfg");
        let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(f.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ibex");
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(fe).is_err() {
            assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
            thread::sleep(Duration::from_millis(20));
        }
        Self { child, _cfg: f }
    }

    fn signal(&self, sig: Signal) {
        let pid = Pid::from_raw(i32::try_from(self.child.id()).expect("pid")).expect("pid");
        kill_process(pid, sig).expect("kill");
    }

    fn wait_exit(&mut self, within: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Some(st) = self.child.try_wait().expect("try_wait") {
                return Some(st);
            }
            thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn http_config(fe: SocketAddr, be: SocketAddr, global: &str) -> String {
    format!(
        "global\n{global}\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {fe}\n  default_backend be\n\
         backend be\n  server s1 {be}\n"
    )
}

fn read_until_close(s: &mut TcpStream, within: Duration) -> String {
    s.set_read_timeout(Some(within)).expect("timeout");
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The request the old process is serving when `-sf` signals it must be completed, not
/// cut off. Today `SIGUSR1` has no handler, so it takes the default action and the
/// process dies with the request half-served.
#[test]
fn sigusr1_finishes_the_request_in_flight_then_exits() {
    let be = slow_backend(Some(Duration::from_millis(1200)));
    let fe = common::reserve_addr();
    let mut ibex = Ibex::start(&http_config(fe, be, ""), fe);

    let mut client = TcpStream::connect(fe).expect("connect");
    client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    thread::sleep(Duration::from_millis(200));

    ibex.signal(Signal::Usr1);
    thread::sleep(Duration::from_millis(300));

    assert!(
        TcpStream::connect(fe).is_err(),
        "a soft-stopping process must stop accepting new connections"
    );

    let resp = read_until_close(&mut client, Duration::from_secs(4));
    assert!(
        resp.starts_with("HTTP/1.1 200") && resp.ends_with("slow"),
        "the in-flight request must complete through a soft stop, got {resp:?}"
    );

    let st = ibex.wait_exit(Duration::from_secs(3));
    assert!(
        st.is_some_and(|s| s.success()),
        "after draining, the process must exit cleanly; got {st:?}"
    );
}

/// `hard-stop-after` is the bound on a soft stop. It was parsed into
/// `GlobalSection::hard_stop_after` and read by nothing, so a session that never finishes
/// kept a stopping process alive indefinitely.
#[test]
fn hard_stop_after_bounds_a_soft_stop() {
    let be = slow_backend(None);
    let fe = common::reserve_addr();
    let mut ibex = Ibex::start(&http_config(fe, be, "  hard-stop-after 500ms\n"), fe);

    let mut client = TcpStream::connect(fe).expect("connect");
    client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    thread::sleep(Duration::from_millis(200));

    let started = Instant::now();
    ibex.signal(Signal::Usr1);
    let st = ibex.wait_exit(Duration::from_secs(3));
    let took = started.elapsed();
    assert!(
        st.is_some_and(|s| s.success()),
        "hard-stop-after 500ms must end a soft stop whose only session never finishes, \
         cleanly; got {st:?}"
    );
    // Both bounds matter. Exiting at once would pass the upper one for the wrong reason --
    // before this change SIGUSR1 killed the process in milliseconds, which looked exactly
    // like a working hard-stop-after to a test that only checked it had exited.
    assert!(
        took >= Duration::from_millis(400) && took < Duration::from_millis(2000),
        "hard-stop-after 500ms: the process exited after {took:?}"
    );
}

/// A backend that keeps each connection open and answers every request on it. The idle
/// test needs this: a backend that closes after responding makes Ibex close the client
/// connection too -- a keep-alive defect of its own, measured against `HAProxy` (3 of 3
/// requests answered) and Ibex (1 of 3) -- and then there is no idle session to test.
fn keepalive_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0
                        || s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A keep-alive client that is idle between requests is not work in flight. `HAProxy` closes
/// it on soft stop; if it did not, every idle browser tab would hold the old process open
/// until `timeout client`.
#[test]
fn an_idle_keepalive_connection_does_not_hold_a_soft_stop_open() {
    let be = keepalive_backend();
    let fe = common::reserve_addr();
    let mut ibex = Ibex::start(&http_config(fe, be, ""), fe);

    let mut client = TcpStream::connect(fe).expect("connect");
    client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    client.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    let mut buf = [0u8; 4096];
    let n = client.read(&mut buf).expect("first response");
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));

    // The connection must really be idle -- open, and waiting for a second request -- or
    // this test proves nothing: a proxy that closed it after the first response would let
    // the process exit at once, and the test would pass without ever reaching the code that
    // closes idle sessions. It did exactly that once.
    client.set_nonblocking(true).expect("nonblocking");
    thread::sleep(Duration::from_millis(300));
    match client.read(&mut buf) {
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("setup: the connection is not idle-and-open before the signal: {other:?}"),
    }
    client.set_nonblocking(false).expect("blocking");

    let started = Instant::now();
    ibex.signal(Signal::Usr1);
    let st = ibex.wait_exit(Duration::from_secs(3));
    assert!(
        st.is_some_and(|s| s.success()),
        "an idle keep-alive connection held the soft stop open; got {st:?} after {:?}",
        started.elapsed()
    );
}
