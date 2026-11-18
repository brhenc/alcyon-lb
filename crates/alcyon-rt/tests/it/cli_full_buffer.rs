// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 The Alcyon authors
//
// A stats-socket command line that fills the whole buffer (`tune.bufsize`), final LF included,
// must be run in full: every `;`-separated command on it is answered and the connection is
// closed with nothing else. A line one byte longer is refused with the "too big" message.
// HAProxy had a bug where the last command of a buffer-filling line was re-parsed and answered
// `Unknown command` until the client closed (reg-tests/cli/cmdline_full_buffer.vtc, fixed in
// 3.5-dev11, T617); Alcyon had the same defect plus no `set rate-limit` at all.
//
// Every expectation below was measured on the oracle (HAProxy 3.5-dev11) with
// `tune.bufsize 1024`:
// - a 1023-byte line: reply `b"\n"`, then close; the command ran.
// - a 1024-byte line (exact, LF included): reply `b"\n"`, then close; the command ran.
// - a 1025-byte line: the exact "too big" message, then close; the command did not run.
// - a 1024-byte line of two `;`-separated commands: reply `b"\n\n"`, then close.
// - a 1024-byte line of three `;`-separated commands (last one `show cli level`):
//   reply `b"\n\nadmin\n\n"`, then close.
// - `set rate-limit` argument errors, measured: missing value, negative, unknown target,
//   and the C `atoi` wrap of `2147483648` (leaves the previous value).
//
// Run against the oracle with `T281_ORACLE=/path/to/haproxy cargo test -p alcyon-rt --test it`.

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// The refusal of a line of more than `tune.bufsize` bytes (feed included), byte-exact.
const TOO_BIG: &[u8] = b"The command line is too big for the buffer size. Please change 'tune.bufsize' in the configuration to use a bigger command.\n";

/// The support list answered for a `set rate-limit` with an unknown setting/target pair,
/// byte-exact (HAProxy `cli_parse_set_ratelimit`, src/cli.c).
const ONLY_SUPPORTS: &[u8] = b"'set rate-limit' only supports :\n   - 'connections global' to set the per-process maximum connection rate\n   - 'sessions global' to set the per-process maximum session rate\n   - 'ssl-sessions global' to set the per-process maximum SSL session rate\n   - 'http-compression global' to set the per-process maximum compression speed in kB/s\n\n";

struct CliEnv {
    child: Child,
    sock: PathBuf,
    op_sock: PathBuf,
    cfg: PathBuf,
}

impl Drop for CliEnv {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
        let _ = std::fs::remove_file(&self.op_sock);
        let _ = std::fs::remove_file(&self.cfg);
    }
}

fn start() -> CliEnv {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let sock = PathBuf::from(format!("/tmp/alcyon-cli-fullbuf-{pid}-{n}.sock"));
    let op_sock = PathBuf::from(format!("/tmp/alcyon-cli-fullbuf-{pid}-{n}-op.sock"));
    let cfg = std::env::temp_dir().join(format!("alcyon-cli-fullbuf-{pid}-{n}.cfg"));
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  tune.bufsize 1024\n  stats socket {sock} level admin\n  stats socket {op} level operator\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  http-request return status 200\n",
        sock = sock.display(),
        op = op_sock.display()
    );
    std::fs::write(&cfg, text).expect("write cfg");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = common::alcyon_command(&bin).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn proxy");
    assert!(common::wait_listening(fe), "proxy never listened");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !sock.exists() || !op_sock.exists() {
        assert!(std::time::Instant::now() < deadline, "stats sockets never appeared");
        std::thread::sleep(Duration::from_millis(10));
    }
    CliEnv { child, sock, op_sock, cfg }
}

/// Sends `line` (already ending in `\n`) on the admin socket and reads everything the CLI
/// sends until the connection is closed. Returns the bytes and whether the server closed.
fn drive(env: &CliEnv, line: &str) -> (Vec<u8>, bool) {
    drive_sock(&env.sock, line)
}

/// Same as `drive`, but on an explicit stats-socket path (used for the operator-level socket).
fn drive_sock(sock: &PathBuf, line: &str) -> (Vec<u8>, bool) {
    let mut c = UnixStream::connect(sock).expect("connect stats socket");
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(line.as_bytes()).expect("send line");
    let mut data = Vec::new();
    let mut b = [0u8; 4096];
    let mut closed = false;
    loop {
        match c.read(&mut b) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => data.extend_from_slice(&b[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                closed = true;
                break;
            }
            Err(_) => break,
        }
    }
    (data, closed)
}

fn info_value(env: &CliEnv, key: &str) -> String {
    let (data, closed) = drive(env, "show info\n");
    assert!(closed, "show info: the connection must close");
    let text = String::from_utf8_lossy(&data).into_owned();
    let line = text
        .lines()
        .find(|l| l.starts_with(key))
        .unwrap_or_else(|| panic!("show info has no {key:?} line"));
    line[key.len()..].trim_start().strip_prefix(':').unwrap_or_default().trim().to_string()
}

/// A command line one byte shorter than the buffer (1023 bytes, LF included) is run.
#[test]
fn a_line_one_byte_shorter_than_the_buffer_is_run() {
    let env = start();
    // "set rate-limit connections global 1234" is 38 bytes: 38 + 984 spaces + LF = 1023.
    let line = format!("set rate-limit connections global 1234{}\n", " ".repeat(984));
    assert_eq!(line.len(), 1023);
    let (data, closed) = drive(&env, &line);
    assert!(closed, "the connection must close after the answer");
    assert_eq!(data, b"\n", "an empty command answer, nothing else");
    assert_eq!(info_value(&env, "ConnRateLimit"), "1234");
}

/// A command line of exactly `tune.bufsize` bytes (1024, LF included) is run. This is the
/// buffer-filling case where the last command used to be re-parsed and answered `Unknown
/// command` (reg-tests/cli/cmdline_full_buffer.vtc).
#[test]
fn a_line_of_exactly_the_buffer_size_is_run() {
    let env = start();
    let line = format!("set rate-limit connections global 1234{}\n", " ".repeat(985));
    assert_eq!(line.len(), 1024);
    let (data, closed) = drive(&env, &line);
    assert!(closed, "the connection must close after the answer");
    assert_eq!(data, b"\n", "an empty command answer, nothing else");
    assert_eq!(info_value(&env, "ConnRateLimit"), "1234");
}

/// A command line one byte longer than the buffer (1025, LF included) is refused as a
/// whole with the exact message, and the command did not run.
#[test]
fn a_line_one_byte_longer_than_the_buffer_is_refused() {
    let env = start();
    let line = format!("set rate-limit connections global 1234{}\n", " ".repeat(986));
    assert_eq!(line.len(), 1025);
    let (data, closed) = drive(&env, &line);
    assert!(closed, "the connection must close after the refusal");
    assert_eq!(data, TOO_BIG);
    assert_eq!(info_value(&env, "ConnRateLimit"), "0");
}

/// A buffer-filling line of `;`-separated commands runs every one of them: the reg-test
/// shape (two commands, 1024 bytes) and a three-command line of the same length whose last
/// command is the one HAProxy used to not see as finished.
#[test]
fn a_full_buffer_line_with_semicolon_commands_runs_them_all() {
    let env = start();
    // 39 + 35 + 949 spaces + LF = 1024.
    let two = format!(
        "set rate-limit connections global 3333;set rate-limit sessions global 4444{}\n",
        " ".repeat(949)
    );
    assert_eq!(two.len(), 1024);
    let (data, closed) = drive(&env, &two);
    assert!(closed);
    assert_eq!(data, b"\n\n", "one empty answer per command, no `Unknown command`");
    assert_eq!(info_value(&env, "ConnRateLimit"), "3333");
    assert_eq!(info_value(&env, "SessRateLimit"), "4444");

    // 39 + 36 + 14 + 934 spaces + LF = 1024.
    let three = format!(
        "set rate-limit connections global 1111;set rate-limit sessions global 2222;show cli level{}\n",
        " ".repeat(934)
    );
    assert_eq!(three.len(), 1024);
    let (data, closed) = drive(&env, &three);
    assert!(closed);
    assert_eq!(data, b"\n\nadmin\n\n");
    assert_eq!(info_value(&env, "ConnRateLimit"), "1111");
    assert_eq!(info_value(&env, "SessRateLimit"), "2222");
}

/// `set rate-limit` argument handling, byte-exact against the oracle: unknown setting or
/// target, missing value, negative value, non-numeric (C `atoi` gives 0), and the 32-bit
/// wrap of `2147483648` refusing without changing the value.
#[test]
fn set_rate_limit_argu_errors_answer_like_haproxy() {
    let env = start();
    let (data, closed) = drive(&env, "set rate-limit\n");
    assert!(closed);
    assert_eq!(data, ONLY_SUPPORTS);

    let (data, closed) = drive(&env, "set rate-limit connections frontend 5\n");
    assert!(closed);
    assert_eq!(data, ONLY_SUPPORTS);

    let (data, closed) = drive(&env, "set rate-limit connections global\n");
    assert!(closed);
    assert_eq!(data, b"Expects an integer value.\n\n");

    let (data, closed) = drive(&env, "set rate-limit connections global -5\n");
    assert!(closed);
    assert_eq!(data, b"Value out of range.\n\n");

    let (data, closed) = drive(&env, "set rate-limit connections global abc\n");
    assert!(closed);
    assert_eq!(data, b"\n");
    assert_eq!(info_value(&env, "ConnRateLimit"), "0");

    let (data, closed) = drive(&env, "set rate-limit ssl-sessions global 9\n");
    assert!(closed);
    assert_eq!(data, b"\n");
    assert_eq!(info_value(&env, "SslRateLimit"), "9");

    // Alcyon has no HTTP compression, so the setting is refused and nothing is stored
    // (docs/differences.md); the oracle stores it and answers an empty line.
    let (data, closed) = drive(&env, "set rate-limit http-compression global 9\n");
    assert!(closed);
    assert_eq!(
        data,
        b"Alcyon does not implement HTTP compression; 'http-compression' cannot be rate-limited.\n\n"
    );
    assert_eq!(info_value(&env, "CompressBpsRateLim"), "0");

    let (data, closed) = drive(&env, "set rate-limit connections global 2147483647\n");
    assert!(closed);
    assert_eq!(data, b"\n");
    // C `atoi` of `2147483648` is negative in a 32-bit `int`: refused, value kept.
    let (data, closed) = drive(&env, "set rate-limit connections global 2147483648\n");
    assert!(closed);
    assert_eq!(data, b"Value out of range.\n\n");
    assert_eq!(info_value(&env, "ConnRateLimit"), "2147483647");
}

/// `set rate-limit` is admin-only: the level gate is the dispatch's, and the oracle
/// (3.5-dev11) answers `Permission denied` from a below-admin socket without changing the
/// value (measured: `b'Permission denied\n\n'` on an `level operator` socket).
#[test]
fn set_rate_limit_from_below_admin_is_denied_like_haproxy() {
    let env = start();
    let (data, closed) = drive_sock(&env.op_sock, "set rate-limit connections global 5555\n");
    assert!(closed);
    assert_eq!(data, b"Permission denied\n\n", "the dispatch level gate, byte-exact");
    assert_eq!(info_value(&env, "ConnRateLimit"), "0", "the value must not change");
}
