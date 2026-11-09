// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `show stat` ends with an empty line, like every other answer of the CLI.
//!
//! Measured on `HAProxy 3.5-dev8-885761-29`: one frontend and no backend gives 3 lines, the
//! header, `f,FRONTEND,...` and an empty one; Alcyon gave 2.

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn show_stat_ends_with_an_empty_line() {
    let sock = format!("/tmp/alcyon-showstat-{}.sock", std::process::id());
    let cfg = std::env::temp_dir().join(format!("alcyon-showstat-{}.cfg", std::process::id()));
    let fe = common::reserve_addr();
    std::fs::write(
        &cfg,
        format!("global\n  stats socket {sock} level admin\ndefaults\n  mode http\nfrontend f\n  bind {fe}\n"),
    )
    .expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Alcyon).expect("spawn");
    assert!(common::wait_listening(fe), "alcyon never listened");
    let mut c = UnixStream::connect(&sock).expect("connect cli");
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"show stat\n").unwrap();
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    common::stop(&mut child);
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&cfg);
    let out = String::from_utf8_lossy(&out);
    assert_eq!(out.matches('\n').count(), 3, "{out:?}");
    assert!(out.starts_with("# pxname,"), "{out:?}");
    assert!(out.contains("\nf,FRONTEND,"), "{out:?}");
    assert!(out.ends_with(",\n\n"), "{out:?}");
}
