// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `server ... track [<proxy>/]<server>` (T141).
//!
//! Every expectation was measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-04:
//!
//! * load (`haproxy -c`): a missing proxy or server is "unable to find required proxy|server
//!   '<x>' for tracking."; a target with no `check` and no `track` of its own is "unable to use
//!   <be>/<srv> for tracking as it does not have any check nor agent enabled."; `check` and
//!   `track` on one server is "unable to enable checks and tracking at the same time!"
//!   (`default-server check` counts); a chain that comes back to the server is "unable to track
//!   <x> as it belongs to a tracking chain looping back to <y>." (reported on the server
//!   declared last); `track` alone is "'track' expects [<proxy>/]<server> as argument.";
//!   the proxy is what precedes the last `/`; the last `track` of a line wins; a target
//!   declared later, a target in another proxy, and a chain are accepted, and so is
//!   `default-server track`;
//! * a tracking server takes the state of its target: UP, DOWN, DRAIN, and MAINT, shown by
//!   `show stat` as `MAINT (via <be>/<srv of the direct target>)` when the maintenance is
//!   inherited and as `MAINT` when it is the server's own; the `tracked` column is
//!   `<be>/<srv>`; `show servers state` reports admin state 2 (inherited maintenance) and 16
//!   (inherited drain) against 1 and 8 for the server's own; a tracker's own `disabled` or
//!   `set server state maint` keeps it in MAINT whatever its target does.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn check(servers: &str) -> (Option<i32>, String) {
    let cfg = format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{servers}");
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("ibex_t141_{}_{n}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&path);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn track_is_checked_when_the_configuration_loads() {
    let refused: &[(&str, &str)] = &[
        ("backend a\n  server s1 127.0.0.1:1 track nosuch\n", "'server a/s1' : unable to find required server 'nosuch' for tracking."),
        ("backend a\n  server s1 127.0.0.1:1 track nobe/s1\n", "'server a/s1' : unable to find required proxy 'nobe' for tracking."),
        ("backend a\n  server s1 127.0.0.1:1 check\nbackend b\n  server s1 127.0.0.1:1 track a/s1/x\n", "'server b/s1' : unable to find required proxy 'a/s1' for tracking."),
        (
            "backend a\n  server s1 127.0.0.1:1\n  server s2 127.0.0.1:1 track s1\n",
            "'server a/s2' : unable to use a/s1 for tracking as it does not have any check nor agent enabled.",
        ),
        (
            "backend a\n  server s1 127.0.0.1:1 track s2\n  server s2 127.0.0.1:1 track s3\n  server s3 127.0.0.1:1\n",
            "'server a/s2' : unable to use a/s3 for tracking as it does not have any check nor agent enabled.",
        ),
        ("backend a\n  server s1 127.0.0.1:1 check track s1\n", "'server a/s1' : unable to enable checks and tracking at the same time!"),
        (
            "backend a\n  default-server check\n  server s1 127.0.0.1:1 track s2\n  server s2 127.0.0.1:1\n",
            "'server a/s1' : unable to enable checks and tracking at the same time!",
        ),
        (
            "backend a\n  server s1 127.0.0.1:1 track s2\n  server s2 127.0.0.1:1 track s1\n",
            "'server a/s2' : unable to track a/s1 as it belongs to a tracking chain looping back to a/s2.",
        ),
        (
            "backend a\n  server s1 127.0.0.1:1 track s2\n  server s2 127.0.0.1:1 track s3\n  server s3 127.0.0.1:1 track s1\n",
            "'server a/s3' : unable to track a/s1 as it belongs to a tracking chain looping back to a/s3.",
        ),
        ("backend a\n  server s1 127.0.0.1:1 track s1\n", "'server a/s1' : unable to track a/s1 as it belongs to a tracking chain looping back to a/s1."),
        ("backend a\n  server s1 127.0.0.1:1 track\n", "'track' expects [<proxy>/]<server> as argument."),
        (
            "backend a\n  server s1 127.0.0.1:1 check\nbackend b\n  server s1 127.0.0.1:1 track a/s1 track a/nosuch\n",
            "'server b/s1' : unable to find required server 'nosuch' for tracking.",
        ),
    ];
    for (cfg, msg) in refused {
        let (code, out) = check(cfg);
        assert_eq!(code, Some(1), "{cfg:?} loaded:\n{out}");
        assert!(out.contains(msg), "{cfg:?}: wanted {msg:?} in:\n{out}");
    }
    let accepted = [
        "backend a\n  server s1 127.0.0.1:1 check\n  server s2 127.0.0.1:1 track a/s1\n  server s3 127.0.0.1:1 track s1\n  server s4 127.0.0.1:1 track s2\nbackend b\n  server t1 127.0.0.1:1 track a/s3\n",
        "backend a\n  server s1 127.0.0.1:1 track s2\n  server s2 127.0.0.1:1 check\n",
        "backend a\n  server s1 127.0.0.1:1 check\n  default-server track s1\n  server s2 127.0.0.1:1\n",
        "backend a\n  server s1 127.0.0.1:1 check\n  server s2 127.0.0.1:1 track s1 weight 5 disabled\n",
    ];
    for cfg in accepted {
        let (code, out) = check(cfg);
        assert_eq!(code, Some(0), "{cfg:?} was refused:\n{out}");
    }
}

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
    sock: PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// A server answering every request with `X-Server: <name>`.
fn serve(listener: TcpListener, name: &'static str) {
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        buf.drain(..end + 4);
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Server: {name}\r\n\r\nok");
                        if c.write_all(resp.as_bytes()).is_err() {
                            return;
                        }
                    }
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
            });
        }
    });
}

/// A server on a fixed port that listens while the flag is set and is closed while it is not.
fn switchable_server() -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let port = common::reserve_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let on = std::sync::Arc::new(AtomicBool::new(true));
    let flag = on.clone();
    thread::spawn(move || {
        let mut l: Option<TcpListener> = None;
        loop {
            if flag.load(Ordering::Relaxed) {
                if l.is_none() {
                    if let Ok(x) = TcpListener::bind(addr) {
                        x.set_nonblocking(true).expect("nonblocking");
                        l = Some(x);
                    }
                }
            } else {
                l = None;
            }
            if let Some(x) = &l {
                while let Ok((c, _)) = x.accept() {
                    drop(c);
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    });
    (addr, on)
}

fn plain_server(name: &'static str) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    serve(l, name);
    addr
}

fn start(cfg: &str, checked: SocketAddr) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let sock = std::env::temp_dir().join(format!("ibex_t141_{}_{n}.sock", std::process::id()));
    let mut text = cfg
        .replace("{fe}", &fe.to_string())
        .replace("{sock}", &sock.display().to_string())
        .replace("{chk}", &checked.to_string());
    for name in ["s2", "s3"] {
        text = text.replace(&format!("{{{name}}}"), &plain_server(name).to_string());
    }
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f, sock };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    (ibex, fe)
}

fn cli(ibex: &Ibex, cmd: &str) -> String {
    let mut s = UnixStream::connect(&ibex.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// A column of `show stat` for `<px>,<sv>`.
fn stat(ibex: &Ibex, px: &str, sv: &str, column: &str) -> String {
    let all = cli(ibex, "show stat");
    let mut lines = all.lines();
    let header = lines.next().expect("a header").trim_start_matches("# ");
    let col = header.split(',').position(|c| c == column).expect("the column");
    lines
        .find(|l| l.starts_with(&format!("{px},{sv},")))
        .map_or_else(|| format!("<no {px}/{sv}>"), |l| l.split(',').nth(col).unwrap_or("").to_string())
}

/// `(op_state, admin_state)` of `show servers state <px>` for `sv`.
fn state(ibex: &Ibex, px: &str, sv: &str) -> (String, String) {
    let out = cli(ibex, &format!("show servers state {px}"));
    let f: Vec<&str> = out.lines().find(|l| l.split(' ').nth(3) == Some(sv)).unwrap_or_else(|| panic!("no {sv} in {out:?}")).split(' ').collect();
    (f[5].to_string(), f[6].to_string())
}

fn wait_status(ibex: &Ibex, px: &str, sv: &str, want: &str) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let got = stat(ibex, px, sv, "status");
        if got == want {
            return;
        }
        assert!(Instant::now() < deadline, "{px}/{sv} is {got:?}, wanted {want:?}");
        thread::sleep(Duration::from_millis(50));
    }
}

fn get(fe: SocketAddr) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let text = String::from_utf8_lossy(&got).into_owned();
    text.split("\r\n")
        .find_map(|l| l.strip_prefix("X-Server: "))
        .map_or_else(|| text.lines().next().unwrap_or("<nothing>").to_string(), str::to_string)
}

const CFG: &str = "global\n  stats socket {sock} mode 600 level admin\n\
defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
frontend f\n  bind {fe}\n  default_backend b\n\
backend a\n  server s1 {chk} check inter 100ms fall 1 rise 1\n\
backend b\n  server t {s2} track a/s1\n\
backend c\n  server u {s3} track b/t\n\
backend d\n  server v {s3} track a/s1 disabled\n";

#[test]
fn a_tracking_server_takes_the_state_of_its_target() {
    let (chk, switch) = switchable_server();
    let (ibex, fe) = start(CFG, chk);

    wait_status(&ibex, "b", "t", "UP");
    assert_eq!(get(fe), "s2", "a tracker of an UP server takes traffic");
    assert_eq!(stat(&ibex, "b", "t", "tracked"), "a/s1");
    assert_eq!(stat(&ibex, "c", "u", "tracked"), "b/t");
    assert_eq!(stat(&ibex, "a", "s1", "tracked"), "");
    assert_eq!(stat(&ibex, "c", "u", "status"), "UP", "a chain follows");
    assert_eq!(stat(&ibex, "d", "v", "status"), "MAINT", "`disabled` is the tracker's own maintenance");
    assert_eq!(state(&ibex, "b", "t"), ("2".into(), "0".into()));

    // The target goes DOWN (nothing listens on its port any more), and so does the tracker,
    // which has no check of its own: with it, the frontend answers 503.
    switch.store(false, std::sync::atomic::Ordering::Relaxed);
    wait_status(&ibex, "a", "s1", "DOWN");
    wait_status(&ibex, "b", "t", "DOWN");
    wait_status(&ibex, "c", "u", "DOWN");
    assert_eq!(get(fe), "HTTP/1.1 503 Service Unavailable");
    assert_eq!(state(&ibex, "b", "t"), ("0".into(), "0".into()));
    assert_eq!(stat(&ibex, "d", "v", "status"), "MAINT");

    switch.store(true, std::sync::atomic::Ordering::Relaxed);
    wait_status(&ibex, "a", "s1", "UP");
    wait_status(&ibex, "b", "t", "UP");
    assert_eq!(get(fe), "s2");

    // Maintenance of the target is inherited, and says where from: the direct target.
    assert_eq!(cli(&ibex, "set server a/s1 state maint"), "\n");
    assert_eq!(stat(&ibex, "a", "s1", "status"), "MAINT");
    assert_eq!(stat(&ibex, "b", "t", "status"), "MAINT (via a/s1)");
    assert_eq!(stat(&ibex, "c", "u", "status"), "MAINT (via b/t)");
    assert_eq!(state(&ibex, "a", "s1"), ("0".into(), "1".into()));
    assert_eq!(state(&ibex, "b", "t"), ("0".into(), "2".into()));
    assert_eq!(state(&ibex, "c", "u"), ("0".into(), "2".into()));
    assert_eq!(get(fe), "HTTP/1.1 503 Service Unavailable");

    assert_eq!(cli(&ibex, "set server a/s1 state drain"), "\n");
    assert_eq!(stat(&ibex, "b", "t", "status"), "DRAIN");
    assert_eq!(state(&ibex, "b", "t"), ("2".into(), "16".into()));
    assert_eq!(get(fe), "HTTP/1.1 503 Service Unavailable");

    assert_eq!(cli(&ibex, "set server a/s1 state ready"), "\n");
    assert_eq!(stat(&ibex, "b", "t", "status"), "UP");
    assert_eq!(get(fe), "s2");

    // The tracker's own maintenance holds while the target is UP, and ends on `ready`.
    assert_eq!(cli(&ibex, "set server b/t state maint"), "\n");
    assert_eq!(stat(&ibex, "b", "t", "status"), "MAINT");
    assert_eq!(stat(&ibex, "c", "u", "status"), "MAINT (via b/t)");
    assert_eq!(state(&ibex, "b", "t"), ("0".into(), "1".into()));
    assert_eq!(get(fe), "HTTP/1.1 503 Service Unavailable");
    assert_eq!(cli(&ibex, "set server b/t state ready"), "\n");
    assert_eq!(stat(&ibex, "b", "t", "status"), "UP");
    assert_eq!(get(fe), "s2");

    // `enable server` ends the `disabled` maintenance of a tracker.
    cli(&ibex, "enable server d/v");
    assert_eq!(stat(&ibex, "d", "v", "status"), "UP");
}
