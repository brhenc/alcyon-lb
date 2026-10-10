// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): lowers the test process's RLIMIT_NOFILE (other tests would get EMFILE)

//! A `log-forward` `bind` (TCP and unix) whose client arrives while the process is out of
//! descriptors: the listener thread retries after a pause (`accept_failed`) and takes the
//! client once a descriptor is free, as `HAProxy`'s listener does (`listener_accept`
//! pauses on `EMFILE` and resumes).
//!
//! The test lowers this process's `RLIMIT_NOFILE`, so it is the only test in its binary.

use rustix::net::{connect_unix, connect_v4, socket, AddressFamily, SocketAddrUnix, SocketType};
use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

#[test]
fn out_of_fds_a_log_forward_bind_takes_its_client_once_one_is_free() {
    let dir = tempfile::TempDir::new().expect("dir");
    let path = dir.path().join("lf.sock");
    let collect = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collect.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("port");
    let port = tcp.local_addr().expect("addr").port();
    drop(tcp);
    let cfg = ibex_config::parse_str(&format!(
        "log-forward lf_emfile\n  bind 127.0.0.1:{port}\n  bind unix@{}\n  log 127.0.0.1:{} format raw local0\n",
        path.display(),
        collect.local_addr().expect("collector addr").port()
    ))
    .expect("parses");
    ibex_rt::logfwd::start(&cfg).expect("starts");

    // The client sockets exist before the descriptors run out; connecting takes none.
    let t = socket(AddressFamily::INET, SocketType::STREAM, None).expect("tcp socket");
    let u = socket(AddressFamily::UNIX, SocketType::STREAM, None).expect("unix socket");

    let saved = getrlimit(Resource::Nofile);
    let max_fd = std::fs::read_dir("/proc/self/fd").expect("fds").filter_map(|d| d.ok()?.file_name().to_str()?.parse::<u64>().ok()).max().unwrap_or(0);
    setrlimit(Resource::Nofile, Rlimit { current: Some(max_fd + 1), maximum: saved.maximum }).expect("setrlimit");
    let mut fillers: Vec<OwnedFd> = Vec::new();
    while let Ok(fd) = rustix::io::fcntl_dupfd_cloexec(&t, 0) {
        fillers.push(fd);
    }
    connect_v4(&t, &std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port)).expect("connect tcp");
    connect_unix(&u, &SocketAddrUnix::new(&path).expect("unix addr")).expect("connect unix");
    let mut t = TcpStream::from(t);
    let mut u = UnixStream::from(u);
    t.write_all(b"<134>Oct 10 12:00:00 h app: over-tcp\n").expect("send tcp");
    u.write_all(b"<134>Oct 10 12:00:00 h app: over-unix\n").expect("send unix");
    // The listener threads find no descriptor for the clients for a while.
    std::thread::sleep(Duration::from_millis(100));
    drop(fillers);
    setrlimit(Resource::Nofile, saved).expect("restore");

    let mut got = Vec::new();
    let mut b = [0u8; 2048];
    while got.len() < 2 {
        let Ok((n, _)) = collect.recv_from(&mut b) else { break };
        got.push(String::from_utf8_lossy(&b[..n]).into_owned());
    }
    got.sort();
    // `format raw`: the message alone.
    assert_eq!(got, ["over-tcp\n", "over-unix\n"]);
}
