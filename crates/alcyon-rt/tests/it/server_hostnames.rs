// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A name on a `server` line (T483). Measured on `HAProxy 3.5-dev8-885761-29` on
//! 2026-10-25 (`docs/design/dns-2026-10-25.md`, A.t1e, A.t1f, t483-run1):
//!
//! * `server s2 localhost:80` gets the first address libc gives (`::1` on this host) and
//!   `show servers state` prints the name as `srv_fqdn`;
//! * `server s1 nosuch.invalid:80 init-addr none` starts with no address: `srv_addr -`,
//!   `srv_op_state 0`, `srv_admin_state 32` (`SRV_ADMF_RMAINT`), `show stat` status
//!   `MAINT (resolution)` and an empty `addr`. It takes no traffic; `enable server` and
//!   `set server state ready` leave it as it is; `set server addr` is refused with
//!   "Update for the current server address family is only supported through
//!   configuration file.".

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Alcyon {
    child: Child,
    _cfg: NamedTempFile,
    sock: PathBuf,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// A server answering every request with `X-Server: <name>`, one request per connection.
fn server(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Server: {name}\r\nConnection: close\r\n\r\n").as_bytes());
        }
    });
    addr
}

fn start(cfg: &str) -> (Alcyon, SocketAddr) {
    let fe = common::reserve_addr();
    let sock = std::env::temp_dir().join(format!("alcyon_t483_{}_{}.sock", std::process::id(), fe.port()));
    let text = cfg.replace("{fe}", &fe.to_string()).replace("{sock}", &sock.display().to_string());
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let alcyon = Alcyon { child, _cfg: f, sock };
    assert!(common::wait_listening(fe), "alcyon never listened on {fe} with:\n{text}");
    (alcyon, fe)
}

fn cli(alcyon: &Alcyon, cmd: &str) -> String {
    let mut s = UnixStream::connect(&alcyon.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// The `show servers state` line of `sv`, split.
fn state_of(alcyon: &Alcyon, sv: &str) -> Vec<String> {
    let out = cli(alcyon, "show servers state l");
    out.lines()
        .map(|l| l.split(' ').map(str::to_string).collect::<Vec<_>>())
        .find(|f| f.get(3).is_some_and(|n| n == sv))
        .unwrap_or_else(|| panic!("no {sv} in {out:?}"))
}

/// The `status` and `addr` columns of `show stat` for `l,<sv>`.
fn stat_of(alcyon: &Alcyon, sv: &str) -> (String, String) {
    let stat = cli(alcyon, "show stat");
    let mut lines = stat.lines();
    let header: Vec<&str> = lines.next().expect("a header").trim_start_matches("# ").split(',').collect();
    let col = |name: &str| header.iter().position(|c| *c == name).expect("a column");
    let row: Vec<&str> = lines.find(|l| l.starts_with(&format!("l,{sv},"))).expect("a row").split(',').collect();
    (row[col("status")].to_string(), row[col("addr")].to_string())
}

/// The `X-Server` of the answer to `GET /`, or its status line.
fn get(fe: SocketAddr) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let mut got = String::new();
    let _ = c.read_to_string(&mut got);
    got.lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("x-server: ").map(str::to_string))
        .unwrap_or_else(|| got.lines().next().unwrap_or("").to_string())
}

const CFG: &str = "global\n  stats socket {sock} level admin\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
frontend f\n  bind {fe}\n  default_backend l\nbackend l\n  balance roundrobin\n";

#[test]
fn a_name_gets_libcs_first_address_and_shows_as_srv_fqdn() {
    let first = ("localhost", 0).to_socket_addrs().expect("localhost resolves").next().expect("an address").ip();
    let (alcyon, _) = start(&format!("{CFG}  server s2 localhost:80\n  server s4 127.0.0.1:80\n"));
    let s2 = state_of(&alcyon, "s2");
    // srv_addr, srv_op_state, srv_admin_state ... srv_fqdn, srv_port.
    assert_eq!((s2[4].as_str(), s2[5].as_str(), s2[6].as_str()), (first.to_string().as_str(), "2", "0"), "{s2:?}");
    assert_eq!((s2[17].as_str(), s2[18].as_str()), ("localhost", "80"), "{s2:?}");
    let s4 = state_of(&alcyon, "s4");
    assert_eq!(s4[17], "-", "{s4:?}");
}

#[test]
fn init_addr_none_starts_the_server_in_maintenance_with_no_address() {
    // If Alcyon ever sent to the unspecified address, `0.0.0.0:<port>` would reach `bad`.
    let bad = server("bad");
    let good = server("good");
    let (alcyon, fe) = start(&format!(
        "{CFG}  server s1 nosuch.invalid:{} init-addr none\n  server s2 {good}\n",
        bad.port()
    ));
    let s1 = state_of(&alcyon, "s1");
    assert_eq!((s1[4].as_str(), s1[5].as_str(), s1[6].as_str()), ("-", "0", "32"), "{s1:?}");
    assert_eq!(s1[17], "nosuch.invalid", "{s1:?}");
    assert_eq!(stat_of(&alcyon, "s1"), ("MAINT (resolution)".to_string(), String::new()));
    for _ in 0..4 {
        assert_eq!(get(fe), "good");
    }
    // Nothing the operator does gives it an address.
    cli(&alcyon, "enable server l/s1");
    cli(&alcyon, "set server l/s1 state ready");
    assert_eq!(state_of(&alcyon, "s1")[6], "32");
    assert_eq!(stat_of(&alcyon, "s1").0, "MAINT (resolution)");
    assert_eq!(
        cli(&alcyon, "set server l/s1 addr 127.0.0.1").trim(),
        "Update for the current server address family is only supported through configuration file."
    );
    for _ in 0..4 {
        assert_eq!(get(fe), "good");
    }
}
