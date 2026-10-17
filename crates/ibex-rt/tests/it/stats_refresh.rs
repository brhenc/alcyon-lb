// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T351: `stats refresh <time>` sends `Refresh: <seconds>` on the stats page. `HAProxy`
//! 3.5-dev8 (`stats-html.c`, `uri->refresh`): `5` and `5s` give 5, `500ms` gives 1 and
//! `1500ms` gives 2 (rounded up), `2m` gives 120, `0` sends none, and `;norefresh` in the
//! URI suppresses it.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};

fn get(addr: std::net::SocketAddr, uri: &str) -> String {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
    write!(c, "GET {uri} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn refresh_of(resp: &str) -> Option<String> {
    let head = resp.split("\r\n\r\n").next().unwrap_or("");
    head.lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("refresh:").map(|v| v.trim().to_string()))
}

#[test]
fn stats_refresh_sends_the_refresh_header_in_seconds() {
    for (arg, want) in [("5", Some("5")), ("5s", Some("5")), ("500ms", Some("1")), ("1500ms", Some("2")), ("2m", Some("120")), ("0", None)] {
        let addr = common::reserve_addr();
        let dir = std::path::PathBuf::from(format!("/tmp/t351-refresh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("c.cfg");
        std::fs::write(
            &cfg,
            format!(
                "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
                 listen s\n  bind {addr}\n  stats enable\n  stats uri /st\n  stats refresh {arg}\n"
            ),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        assert!(common::wait_listening(addr));
        let page = get(addr, "/st");
        let norefresh = get(addr, "/st;norefresh");
        common::stop(&mut child);
        assert!(page.starts_with("HTTP/1.1 200"), "{arg}: {page}");
        assert_eq!(refresh_of(&page).as_deref(), want, "refresh {arg}: {page}");
        assert_eq!(refresh_of(&norefresh), None, "refresh {arg} with ;norefresh");
    }
}
