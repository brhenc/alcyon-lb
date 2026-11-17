//! Stats-socket CLI privilege levels (HAProxy reg-test `cli/levels.vtc`).
//!
//! A worker socket opened at `level admin` must: start as `admin`; `operator` and `user`
//! lower the level of the *session* (one `\n` each, no "Permission denied"); run further
//! `;`-chained commands on the same line at the lowered level; refuse admin-only commands
//! with the exact `Permission denied` answer; and allow `clear counters` to `operator`
//! but not to `user`. All expected bytes below were measured on the oracle.
//!
//! `T281_ORACLE` runs the same expectations against HAProxy.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::common;

/// One non-interactive CLI command on a fresh worker-socket connection, whole answer.
fn cli(sock: &Path, cmd: &str) -> String {
    let mut stream = UnixStream::connect(sock).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(cmd.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).unwrap();
    String::from_utf8(out).expect("cli answer is ascii")
}

struct Daemon {
    child: Child,
    sock: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

static TMP_GEN: AtomicUsize = AtomicUsize::new(0);

fn start() -> Daemon {
    let tmp = std::env::temp_dir().join(format!(
        "alcyon-cli-levels-{}-{}",
        std::process::id(),
        TMP_GEN.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    let sock = tmp.join("cli.sock");
    let bind = common::reserve_addr();
    let cfg = tmp.join("cfg");
    let conf = format!(
        "global\n    chroot /\n    stats socket {} level admin\n\
         defaults\n    mode http\n    timeout connect 5s\n    timeout client  5s\n    timeout server  5s\n\
         frontend fe\n    bind {bind}\n    http-request return status 200\n\
         backend be\n    server s1 127.0.0.1:1 disabled\n",
        sock.display(),
    );
    std::fs::write(&cfg, conf).unwrap();
    let bin = std::env::var("T281_ORACLE")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = common::alcyon_command(&bin)
        .args(["-f", &cfg.to_string_lossy(), "-db"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if UnixStream::connect(&sock).is_ok() {
            return Daemon { child, sock };
        }
        std::thread::sleep(Duration::from_millis(10));
        if child.try_wait().unwrap().is_some() {
            panic!("proxy exited before the stats socket appeared");
        }
    }
    panic!("stats socket never appeared");
}

#[test]
fn levels() {
    let d = start();
    let sock = d.sock.as_path();

    // The session starts at the socket's level.
    assert_eq!(cli(sock, "show cli level"), "admin\n\n");
    // `operator` / `user` lower the level: one empty line each, no refusal.
    assert_eq!(cli(sock, "operator"), "\n");
    assert_eq!(cli(sock, "user"), "\n");
    // The level change applies to the rest of the same `;` line (reg-test T146 items 4-8).
    assert_eq!(cli(sock, "operator; show cli level"), "\noperator\n\n");
    assert_eq!(cli(sock, "user; show cli level"), "\nuser\n\n");
    assert_eq!(cli(sock, "operator; user; show cli level"), "\n\nuser\n\n");
    // And commands the level still allows keep running after the change (the case the
    // reg-test failed on: `operator; show stat` answered one empty line, no CSV).
    for cmd in ["operator; show stat", "user; show stat"] {
        let out = cli(sock, cmd);
        assert!(
            out.contains("\n# pxname,svname,qcur"),
            "{cmd:?} answered no CSV:\n{out:?}"
        );
    }
    // `show info` is a User command: fine after the drop, and reports the proxy state.
    let out = cli(sock, "user; show info");
    assert!(out.starts_with("\nName: "), "{out:?}");
    // The socket-level `set maxconn` below has not run yet.
    assert!(!out.contains("Maxconn: 1234"), "{out:?}");

    // `set maxconn` is Admin: allowed at the socket level, refused afterwards.
    let out = cli(sock, "set maxconn global 1234; show info");
    assert!(out.contains("Maxconn: 1234"), "{out:?}");
    assert_eq!(cli(sock, "operator; set maxconn global 4321"), "\nPermission denied\n\n");
    assert_eq!(cli(sock, "user; set maxconn global 4321"), "\nPermission denied\n\n");
    let out = cli(sock, "show info");
    assert!(out.contains("Maxconn: 1234"), "{out:?}");

    // Expert / experimental / ACL editing stay refused at the lowered levels.
    assert_eq!(cli(sock, "user; expert-mode on"), "\nPermission denied\n\n");
    assert_eq!(cli(sock, "operator; experimental-mode on"), "\nPermission denied\n\n");
    assert_eq!(
        cli(sock, "operator; add acl virt@nosuchacl foo"),
        "\nPermission denied\n\n"
    );

    // `clear counters` is Operator: allowed to `operator`, refused to `user` (T146 item 14).
    assert_eq!(cli(sock, "operator; clear counters"), "\n\n");
    assert_eq!(cli(sock, "user; clear counters"), "\nPermission denied\n\n");
    // `set server <srv> state` is Admin-only (T146 item 20).
    assert_eq!(
        cli(sock, "operator; set server be/s1 state ready"),
        "\nPermission denied\n\n"
    );

    // The admin-level success answers are one empty line (non-interactive mode emits no
    // prompt; the connection closes after the line).
    assert_eq!(cli(sock, "experimental-mode on"), "\n");
    assert_eq!(cli(sock, "experimental-mode off"), "\n");

    // In `prompt` mode the same commands end with the prompt instead, and the session
    // keeps running after them (measured on the oracle).
    let mut stream = UnixStream::connect(sock).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = String::new();
    prompt_step(&mut stream, &mut buf, "prompt", "\n> ");
    prompt_step(&mut stream, &mut buf, "operator", "\n> ");
    prompt_step(&mut stream, &mut buf, "show cli level", "operator\n\n> ");
    prompt_step(&mut stream, &mut buf, "user", "\n> ");
    prompt_step(&mut stream, &mut buf, "show cli level", "user\n\n> ");
    prompt_step(&mut stream, &mut buf, "quit", "");
}

/// One line of a `prompt`-mode session: send it, read until `want` arrived, drop it.
fn prompt_step(stream: &mut UnixStream, buf: &mut String, send: &str, want: &str) {
    stream.write_all(send.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut guard = 0;
    loop {
        if want.is_empty() || buf.find(want).is_some() {
            if let Some(i) = buf.find(want) {
                buf.drain(..i + want.len());
            }
            return;
        }
        let mut tmp = [0u8; 4096];
        let n = stream.read(&mut tmp).expect("read in prompt mode");
        guard += 1;
        if guard > 100 {
            panic!("wanted {want:?}, buffer so far: {buf:?}");
        }
        buf.push_str(&String::from_utf8_lossy(&tmp[..n]));
    }
}
