// SPDX-License-Identifier: GPL-2.0-or-later
//! Reloads, driven through the real binary the way an operator or systemd drives them.
//!
//! A reload is two processes overlapping: the new one starts on the same config, then tells
//! the old one to soft-stop with `-sf <pid>`. Everything that can go wrong is in the
//! overlap, so these tests start two processes and look at what survives.

use rustix::process::{kill_process, Pid, Signal};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn free_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr")
}

/// A short socket path: `HAProxy` rejects anything over 97 bytes, and a tempdir path is
/// easily longer than that.
fn short_sock(tag: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/ibex-rl-{}-{tag}.sock", std::process::id()))
}

fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn config(fe: SocketAddr, be: SocketAddr, sock: &Path, extra_global: &str) -> String {
    format!(
        "global\n  stats socket {} mode 600 level admin{extra_global}\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {fe}\n  default_backend be\n\
         backend be\n  server s1 {be}\n",
        sock.display()
    )
}

struct Proc {
    child: Child,
}

impl Proc {
    fn start(cfg: &Path, extra: &[String]) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(cfg)
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ibex");
        Self { child }
    }

    fn pid(&self) -> u32 {
        self.child.id()
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

    fn signal(&self, sig: Signal) {
        let pid = Pid::from_raw(i32::try_from(self.pid()).expect("pid")).expect("pid");
        let _ = kill_process(pid, sig);
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_listening(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).is_err() {
        assert!(Instant::now() < deadline, "nothing listening on {addr}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn cli(sock: &Path, cmd: &str) -> Option<String> {
    let mut s = UnixStream::connect(sock).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    s.write_all(format!("{cmd}\n").as_bytes()).ok()?;
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    Some(out)
}

fn write_cfg(text: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write");
    f
}

/// `new -sf <old>`, the reload `HAProxy` has always supported, done once.
///
/// Two things have to survive it. The port, obviously. And the stats socket: both
/// processes are configured with the same path, the new one binds it first, and the old
/// one then exits. The old engine's `Drop` unlinked that path unconditionally, which
/// removed the *new* process's socket file -- after any reload the CLI was simply gone.
#[test]
fn a_graceful_reload_keeps_the_port_and_the_stats_socket() {
    let be = backend();
    let fe = free_addr();
    let sock = short_sock("graceful");
    let cfg = write_cfg(&config(fe, be, &sock, ""));

    let mut old = Proc::start(cfg.path(), &[]);
    wait_listening(fe);
    let old_info = cli(&sock, "show info").expect("old CLI answers");
    assert!(old_info.contains(&format!("Pid: {}", old.pid())), "{old_info}");

    let new = Proc::start(cfg.path(), &["-sf".into(), old.pid().to_string()]);
    let st = old.wait_exit(Duration::from_secs(5));
    assert!(
        st.is_some_and(|s| s.success()),
        "the old process must soft-stop and exit cleanly on -sf; got {st:?}"
    );

    wait_listening(fe);
    let info = cli(&sock, "show info");
    assert!(
        info.as_deref().is_some_and(|i| i.contains(&format!("Pid: {}", new.pid()))),
        "after the old process exits, the stats socket must still be the new process's; \
         got {info:?}"
    );
    let _ = std::fs::remove_file(&sock);
    new.signal(Signal::Kill);
}

/// A backend that holds `/hold` for `hold`, and answers everything else at once.
fn holding_backend(hold: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).unwrap_or(0);
                if String::from_utf8_lossy(&buf[..n]).contains("GET /hold") {
                    thread::sleep(hold);
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            });
        }
    });
    addr
}

fn read_all(s: &mut TcpStream, within: Duration) -> String {
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

/// What makes a reload *hitless* rather than graceful.
///
/// Connections the kernel has completed but the old process has not yet accepted sit in
/// the accept queue of the old process's socket. Every worker binds its own
/// `SO_REUSEPORT` socket, so a new process that binds fresh gets a queue of its own, and
/// the old queue is reset when the old process closes its socket -- however gracefully.
/// Only taking over the same socket (`-x`, served by `expose-fd listeners`) keeps it.
///
/// The scenario is made deterministic with `maxconn 1`: one held request fills the old
/// process, so it stops accepting, and the next connections are left queued on its socket.
#[test]
fn a_reload_with_x_keeps_the_connections_queued_on_the_old_socket() {
    const QUEUED: usize = 5;
    let be = holding_backend(Duration::from_millis(1500));
    let fe = free_addr();
    let sock = short_sock("hitless");
    let text = format!(
        "global\n  stats socket {} mode 600 level admin expose-fd listeners\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {fe}\n  maxconn 1\n  default_backend be\n\
         backend be\n  server s1 {be}\n",
        sock.display()
    );
    let cfg = write_cfg(&text);

    let mut old = Proc::start(cfg.path(), &[]);
    wait_listening(fe);
    // The probe `wait_listening` made counts against maxconn until the old process sees
    // it close; give that a moment so the held request below is the one filling it.
    thread::sleep(Duration::from_millis(200));

    let mut held = TcpStream::connect(fe).expect("connect held");
    held.write_all(b"GET /hold HTTP/1.1\r\nHost: x\r\n\r\n").expect("send held");
    thread::sleep(Duration::from_millis(300));

    let mut queued: Vec<TcpStream> = (0..QUEUED)
        .map(|i| {
            let mut c = TcpStream::connect(fe).expect("connect queued");
            c.write_all(format!("GET /q{i} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
                .expect("send queued");
            c
        })
        .collect();

    // Sanity: they really are queued, not being served.
    let mut probe = [0u8; 1];
    queued[0].set_read_timeout(Some(Duration::from_millis(300))).expect("timeout");
    assert!(
        matches!(queued[0].read(&mut probe), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
            || e.kind() == std::io::ErrorKind::TimedOut),
        "the setup is wrong: the old process is serving connections it should be too full to accept"
    );

    let new = Proc::start(
        cfg.path(),
        &["-x".into(), sock.display().to_string(), "-sf".into(), old.pid().to_string()],
    );

    for (i, c) in queued.iter_mut().enumerate() {
        let resp = read_all(c, Duration::from_secs(5));
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "queued connection {i} was lost across the reload -- the old socket and its \
             accept queue did not survive; got {resp:?}"
        );
    }

    let held_resp = read_all(&mut held, Duration::from_secs(5));
    assert!(held_resp.starts_with("HTTP/1.1 200"), "held request: {held_resp:?}");
    let st = old.wait_exit(Duration::from_secs(5));
    assert!(st.is_some_and(|s| s.success()), "old process: {st:?}");

    let _ = std::fs::remove_file(&sock);
    new.signal(Signal::Kill);
}

/// When the sockets cannot be taken over, the new process must refuse to start rather
/// than fall back to binding fresh ones -- `HAProxy`'s behaviour (`src/haproxy.c:2069`). It
/// is the safe failure: `-sf` is only sent once the new process is listening, so the old
/// one is never told to stop and keeps serving as if no reload had been attempted.
#[test]
fn x_against_a_process_that_does_not_expose_its_sockets_leaves_it_serving() {
    let be = backend();
    let fe = free_addr();
    let sock = short_sock("noexpose");
    let cfg = write_cfg(&config(fe, be, &sock, ""));

    let mut old = Proc::start(cfg.path(), &[]);
    wait_listening(fe);

    let mut new = Proc::start(
        cfg.path(),
        &["-x".into(), sock.display().to_string(), "-sf".into(), old.pid().to_string()],
    );
    let st = new.wait_exit(Duration::from_secs(5));
    assert!(
        st.is_some_and(|s| !s.success()),
        "without `expose-fd listeners` on the old socket, -x must fail and the new process \
         must not start; got {st:?}"
    );

    assert!(old.wait_exit(Duration::from_millis(500)).is_none(), "the old process was stopped");
    let mut c = TcpStream::connect(fe).expect("old still accepting");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let resp = read_all(&mut c, Duration::from_secs(3));
    assert!(resp.starts_with("HTTP/1.1 200"), "old process must still serve: {resp:?}");
    let _ = std::fs::remove_file(&sock);
}
