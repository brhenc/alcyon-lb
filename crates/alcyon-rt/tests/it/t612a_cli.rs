// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T612a: `-N <maxpconn>` is the default per-proxy maxconn (`cfg_maxpconn`, `proxy.c`), and
//! `-e` does not exist on HAProxy 3.5-dev8 (it prints the usage and exits 1; oracle run), so
//! Alcyon must refuse it rather than accept and drop it.

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn cfg(dir: &std::path::Path, addr: std::net::SocketAddr, fe_maxconn: &str) -> std::path::PathBuf {
    let listen = fe_maxconn.starts_with("listen");
    let fe_maxconn = fe_maxconn.trim_start_matches("listen");
    let path = dir.join("c.cfg");
    let proxies = if listen {
        format!("listen f\n    bind {addr}\n{fe_maxconn}    server s 127.0.0.1:1\n")
    } else {
        format!("frontend f\n    bind {addr}\n{fe_maxconn}    default_backend b\nbackend b\n    server s 127.0.0.1:1\n")
    };
    std::fs::write(
        &path,
        format!(
            "global\n    stats socket {}/cli.sock level admin\ndefaults\n    mode http\n    timeout client 5s\n    timeout server 5s\n    timeout connect 5s\n{proxies}",
            dir.display()
        ),
    )
    .unwrap();
    path
}

fn slim_of_frontend(sock: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"show stat\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let mut lines = out.lines();
    let head: Vec<&str> = lines.next().unwrap().trim_start_matches("# ").split(',').collect();
    let col = head.iter().position(|h| *h == "slim").expect("slim column");
    let row = lines.find(|l| l.starts_with("f,FRONTEND,")).expect("frontend row");
    row.split(',').nth(col).unwrap().to_string()
}

fn run_slim(tag: &str, args: &[&str], fe_maxconn: &str) -> String {
    let dir = std::env::temp_dir().join(format!("t612a-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let addr = common::reserve_addr();
    let path = cfg(&dir, addr, fe_maxconn);
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .args(args)
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(common::wait_listening(addr));
    let sock = dir.join("cli.sock").display().to_string();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    let slim = slim_of_frontend(&sock);
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    slim
}

/// HAProxy gives every proxy with no `maxconn` the `-N` value; one with its own keeps it.
#[test]
fn minus_n_is_the_default_proxy_maxconn() {
    assert_eq!(run_slim("n-default", &["-N", "7"], ""), "7");
    assert_eq!(run_slim("n-attached", &["-N7"], ""), "7");
    assert_eq!(run_slim("n-own", &["-N", "7"], "    maxconn 3\n"), "3");
    // A `listen` section is a proxy like the others.
    assert_eq!(run_slim("n-listen", &["-N", "7"], "listen"), "7");
    assert_eq!(run_slim("n-listen-own", &["-N", "7"], "listen    maxconn 3\n"), "3");
}

#[test]
fn minus_e_is_refused_like_haproxy() {
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).args(["-e", "foo=1", "-c"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Unknown option: -e"));
    let help = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-h").output().unwrap();
    assert!(!String::from_utf8_lossy(&help.stdout).contains(" -e <setting>"));
}
