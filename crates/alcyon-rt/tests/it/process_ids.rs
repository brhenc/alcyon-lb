// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T331: `tgroup`, `master_id` and `quic_enabled`. Every expected value was measured on
//! `HAProxy` 3.5-dev8-885761-29 with the same configuration and environment.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Alcyon(Child, std::path::PathBuf);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts alcyon on `cfg` with `HAPROXY_MASTER_ID` set to `master_id`, or removed.
fn start(tag: &str, cfg: &str, a: SocketAddr, master_id: Option<&str>) -> Alcyon {
    let dir = std::env::temp_dir().join(format!("process-ids-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_alcyon"));
    cmd.arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null());
    match master_id {
        Some(id) => cmd.env("HAPROXY_MASTER_ID", id),
        None => cmd.env_remove("HAPROXY_MASTER_ID"),
    };
    let alcyon = Alcyon(cmd.spawn().unwrap(), dir);
    assert!(common::wait_listening(a), "alcyon did not listen on {a}");
    alcyon
}

/// The body of the answer to one request on a new connection.
fn body(addr: SocketAddr) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let s = String::from_utf8_lossy(&out).into_owned();
    s.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {s:?}"), |(_, b)| b.to_string())
}

fn cfg(a: SocketAddr) -> String {
    format!(
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"%[tgroup]|[%[master_id]]|%[quic_enabled]\"\n"
    )
}

/// One thread group, numbered from 0; no master; no QUIC.
#[test]
fn t331_process_id_fetches() {
    let a = common::reserve_addr();
    let _alcyon = start("plain", &cfg(a), a, None);
    assert_eq!(body(a), "0|[]|0");
}

/// Without master-worker mode there is no master, so no `master_id`, whatever the
/// environment says: `HAProxy` takes `HAPROXY_MASTER_ID` only in `mworker_prepare_master`.
#[test]
fn master_id_ignores_the_environment_without_a_master() {
    let a = common::reserve_addr();
    let _alcyon = start("env", &cfg(a), a, Some("0190a7d2-1234-7abc-8def-0123456789ab"));
    assert_eq!(body(a), "0|[]|0");
}
