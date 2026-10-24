// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `stats socket` on TCP (`ipv4@`, `ipv6@`, `tcp@`, `host:port`) and on Linux abstract
//! sockets (`abns@`, `abnsz@`) (T246). T222 refused them because the CLI was built on unix
//! socket files only. Every expected text and behaviour was measured on 3.5-dev8-885761-29:
//!
//! ```text
//! '::1'                 'stats socket' : invalid address: ':' in '::1'
//! 'ipv6@127.0.0.1:80'   'stats socket' : invalid address: '127.0.0.1' in 'ipv6@127.0.0.1:80'
//! '127.0.0.1:0'         'stats socket' : invalid port '0'          (before the address)
//! '127.0.0.1:99999'     'stats socket' : invalid port '99999'
//! show cli sockets      ipv4@127.0.0.1:P admin all / ipv6@[::1]:P / abns@name / unix@path
//! abns@name             the name zero-padded to the whole sun_path; abnsz@ is not padded
//! ```

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn cfg(lines: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tmp");
    write!(f, "global\n{lines}\n").expect("write");
    f
}

fn check(arg: &str) -> (bool, String) {
    let f = cfg(&format!("\tstats socket {arg}"));
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn haproxy_texts_for_bad_tcp_addresses() {
    for (a, text) in [
        ("::1", "'stats socket' : invalid address: ':' in '::1'"),
        ("ipv6@127.0.0.1:80", "'stats socket' : invalid address: '127.0.0.1' in 'ipv6@127.0.0.1:80'"),
        ("ipv4@[::1]:80", "'stats socket' : invalid address: '[::1]' in 'ipv4@[::1]:80'"),
        ("1.2.3.4.5:80", "'stats socket' : invalid address: '1.2.3.4.5' in '1.2.3.4.5:80'"),
        ("nosuchhost.invalid:80", "'stats socket' : invalid address: 'nosuchhost.invalid' in 'nosuchhost.invalid:80'"),
        ("127.0.0.1:0", "'stats socket' : invalid port '0'"),
        ("nosuchhost.invalid:0", "'stats socket' : invalid port '0'"),
        ("127.0.0.1:99999", "'stats socket' : invalid port '99999'"),
        ("127.0.0.1:65536", "'stats socket' : invalid port '65536'"),
        ("127.0.0.1:0-5", "'stats socket' : invalid port '0'"),
        ("127.0.0.1:5-1", "'stats socket' : invalid port range '5-1'"),
        ("127.0.0.1:80x", "'stats socket' : invalid character 'x' in port number '80x' in '127.0.0.1:80x'"),
        ("127.0.0.1:-1", "'stats socket' : port offset not permitted here in '127.0.0.1:-1'"),
        ("127.0.0.1:+5", "'stats socket' : port offset not permitted here in '127.0.0.1:+5'"),
        ("127.0.0.1:", "'stats socket' : missing port specification in '127.0.0.1:'"),
        ("udp@127.0.0.1:80", "'stats socket' : dgram-type address not acceptable in 'udp@127.0.0.1:80'"),
        ("uxdg@/tmp/x", "'stats socket' : dgram-type address not acceptable in 'uxdg@/tmp/x'"),
    ] {
        let (ok, err) = check(a);
        assert!(!ok, "`stats socket {a}` must be refused");
        assert!(err.contains(text), "`stats socket {a}`: expected {text:?} in: {err}");
    }
}

#[test]
fn tcp_and_abstract_forms_haproxy_accepts_are_accepted() {
    for a in [
        "127.0.0.1:19999",
        "ipv4@127.0.0.1:19999",
        "ipv6@[::1]:19999",
        "ipv6@::1:19999",
        "::1:19999",
        "[::1]:19999",
        "*:19999",
        ":19999",
        "tcp@127.0.0.1:19999",
        "tcp4@127.0.0.1:19999",
        "tcp6@[::1]:19999",
        "ip@127.0.0.1:19999",
        "localhost:19999",
        "127.0.0.1:19999 mode 600 level admin expose-fd listeners",
        "abns@foo",
        "abnsz@foo",
    ] {
        let (ok, err) = check(a);
        assert!(ok, "`stats socket {a}` must be accepted: {err}");
    }
}

/// Ranges and `fd@` are accepted by `HAProxy`; Ibex refuses them rather than dropping them.
#[test]
fn forms_ibex_does_not_implement_say_so() {
    for a in ["127.0.0.1:19990-19995", "fd@3", "sockpair@3", "mptcp@127.0.0.1:19999"] {
        let (ok, err) = check(a);
        assert!(!ok, "`stats socket {a}` must be refused");
        assert!(err.contains("not supported by Ibex"), "`stats socket {a}`: {err}");
    }
}

fn start(lines: &str, extra: &[String]) -> (Child, NamedTempFile) {
    let f = cfg(lines);
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    (child, f)
}

fn ask<S: Read + Write>(mut s: S, cmd: &str) -> String {
    s.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn wait<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < end, "{what} never accepted");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn tcp(addr: SocketAddr) -> TcpStream {
    wait(&addr.to_string(), || TcpStream::connect(addr).ok())
}

fn abstract_stream(name: &str, padded: bool) -> Option<UnixStream> {
    use std::os::linux::net::SocketAddrExt;
    let mut bytes = name.as_bytes().to_vec();
    if padded {
        bytes.resize(107, 0);
    }
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(&bytes).ok()?;
    UnixStream::connect_addr(&addr).ok()
}

#[test]
fn the_cli_answers_on_tcp_and_abstract_sockets_with_each_level() {
    let p4 = common::reserve_port();
    let p6 = common::reserve_port();
    let abns = format!("ibex-t246-{}", std::process::id());
    let lines = format!(
        "\tstats socket 127.0.0.1:{p4} level admin mode 600\n\
         \tstats socket ipv6@[::1]:{p6}\n\
         \tstats socket abns@{abns} level user\n\
         \tstats socket abnsz@{abns}z"
    );
    let (mut child, _f) = start(&lines, &[]);
    let v4: SocketAddr = format!("127.0.0.1:{p4}").parse().expect("addr");
    let v6: SocketAddr = format!("[::1]:{p6}").parse().expect("addr");

    assert_eq!(ask(tcp(v4), "show cli level"), "admin\n\n");
    let socks = ask(tcp(v4), "show cli sockets");
    assert!(socks.contains(&format!("ipv4@127.0.0.1:{p4} admin all")), "{socks}");

    assert_eq!(ask(tcp(v6), "show cli level"), "operator\n\n");
    let socks = ask(tcp(v6), "show cli sockets");
    assert!(socks.contains(&format!("ipv6@[::1]:{p6} operator all")), "{socks}");

    let s = wait("abns@", || abstract_stream(&abns, true));
    assert_eq!(ask(s, "show cli level"), "user\n\n");
    let s = wait("abns@", || abstract_stream(&abns, true));
    let socks = ask(s, "show cli sockets");
    assert!(socks.contains(&format!("abns@{abns} user all")), "{socks}");
    assert!(abstract_stream(&abns, false).is_none(), "abns@ binds the zero-padded name, not the short one");

    let s = wait("abnsz@", || abstract_stream(&format!("{abns}z"), false));
    assert_eq!(ask(s, "show cli level"), "operator\n\n");
    common::stop(&mut child);
}

/// `_getsocks` cannot carry descriptors over TCP (`SCM_RIGHTS` is unix-only; `HAProxy`'s
/// sendmsg goes out without them). Ibex closes the connection and keeps serving.
#[test]
fn getsocks_over_tcp_sends_no_descriptors_and_the_cli_keeps_serving() {
    let p = common::reserve_port();
    let (mut child, _f) = start(&format!("\tstats socket 127.0.0.1:{p} level admin expose-fd listeners"), &[]);
    let a: SocketAddr = format!("127.0.0.1:{p}").parse().expect("addr");
    let _ = ask(tcp(a), "_getsocks");
    assert_eq!(ask(tcp(a), "show cli level"), "admin\n\n");
    common::stop(&mut child);
}

/// The new process of a `-sf` reload binds the same TCP address while the old one still
/// holds it (`HAProxy`: `SO_REUSEPORT`), then the old one exits and the CLI is the new one's.
#[test]
fn a_tcp_stats_socket_survives_an_sf_reload() {
    let p = common::reserve_port();
    let lines = format!("\tstats socket 127.0.0.1:{p} level admin");
    let a: SocketAddr = format!("127.0.0.1:{p}").parse().expect("addr");
    let (mut old, f) = start(&lines, &[]);
    let info = ask(tcp(a), "show info");
    assert!(info.contains(&format!("Pid: {}", old.id())), "{info}");

    let mut new = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .args(["-sf".to_string(), old.id().to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let end = Instant::now() + Duration::from_secs(10);
    let st = loop {
        if let Some(st) = old.try_wait().expect("wait") {
            break st;
        }
        assert!(Instant::now() < end, "the old process never exited on -sf");
        assert!(new.try_wait().expect("wait").is_none(), "the new process failed to start (could not bind the TCP CLI?)");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(st.success(), "old exit: {st:?}");
    let info = ask(tcp(a), "show info");
    assert!(info.contains(&format!("Pid: {}", new.id())), "{info}");
    common::stop(&mut new);
}

/// The rest of `str2sa_range`'s branches that a stats socket can reach.
#[test]
fn prefixes_and_host_forms() {
    for (a, ok, text) in [
        ("stream+127.0.0.1:19999", true, ""),
        ("stream+/tmp/x.sock", true, ""),
        ("ipv6@*:19999", true, ""),
        ("dgram+127.0.0.1:19999", false, "'stats socket' : dgram-type address not acceptable in 'dgram+127.0.0.1:19999'"),
        ("dgram+abns@x", false, "'stats socket' : dgram-type address not acceptable in 'dgram+abns@x'"),
        ("ipv6@localhost:19999", true, ""),
        ("ipv4@localhost:19999", true, ""),
        ("ipv4@ip6-localhost:19999", false, "'stats socket' : invalid address: 'ip6-localhost' in 'ipv4@ip6-localhost:19999'"),
        ("[::1:19999", false, "'stats socket' : invalid address: '[::1' in '[::1:19999'"),
        ("[]:19999", false, "'stats socket' : invalid address: '[]' in '[]:19999'"),
        ("dgram@127.0.0.1:80", false, "'stats socket' : invalid address: 'dgram@127.0.0.1' in 'dgram@127.0.0.1:80'"),
        ("127.0.0.1:x80", false, "'stats socket' : invalid character 'x' in port number 'x80' in '127.0.0.1:x80'"),
        ("127.0.0.1:1-99999", false, "'stats socket' : invalid port '99999'"),
        ("127.0.0.1:1-5x", false, "'stats socket' : invalid character 'x' in port number '5x' in '127.0.0.1:1-5x'"),
        ("[::1]", false, "'stats socket' : missing port specification in '[::1]'"),
        ("quic+127.0.0.1:19999", false, "not supported by Ibex"),
        ("quic4@127.0.0.1:19999", false, "not supported by Ibex"),
        ("rhttp@x", false, "not supported by Ibex"),
        ("mptcp4@127.0.0.1:19999", false, "not supported by Ibex"),
    ] {
        let (got, err) = check(a);
        assert_eq!(got, ok, "`stats socket {a}`: {err}");
        assert!(err.contains(text), "`stats socket {a}`: expected {text:?} in: {err}");
    }
}

/// A TCP or abstract address that cannot be bound stops the start, as a unix path does.
#[test]
fn an_unbindable_tcp_or_abstract_address_stops_the_start() {
    let abns = format!("ibex-t246-busy-{}", std::process::id());
    for (lines, text) in [
        ("\tstats socket 192.0.2.1:19999".to_string(), "protocol tcpv4: cannot bind socket"),
        ("\tstats socket ipv6@[2001:db8::1]:19999".to_string(), "protocol tcpv6: cannot bind socket"),
        (format!("\tstats socket abns@{abns}\n\tstats socket abns@{abns}"), "protocol abns: cannot bind UNIX socket"),
    ] {
        let f = cfg(&lines);
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).output().expect("run");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{lines}: started");
        assert!(err.contains(text), "{lines}: expected {text:?} in {err}");
    }
}

/// `-x`: the new process takes the TCP CLI listener over from the old one with the others
/// (`_getsocks`), so connections queued on it are not reset when the old one exits.
#[test]
fn x_hands_the_tcp_stats_socket_over() {
    let p = common::reserve_port();
    let dir = tempfile::TempDir::new().expect("dir");
    let sock = dir.path().join("s.sock");
    let lines = format!(
        "\tstats socket {} level admin expose-fd listeners\n\tstats socket 127.0.0.1:{p} level admin",
        sock.display()
    );
    let a: SocketAddr = format!("127.0.0.1:{p}").parse().expect("addr");
    let (mut old, f) = start(&lines, &[]);
    let _ = tcp(a);
    let _ = wait("unix CLI", || UnixStream::connect(&sock).ok());
    let mut new = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .args(["-x".to_string(), sock.display().to_string(), "-sf".to_string(), old.id().to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let end = Instant::now() + Duration::from_secs(10);
    while old.try_wait().expect("wait").is_none() {
        assert!(Instant::now() < end, "the old process never exited");
        assert!(new.try_wait().expect("wait").is_none(), "the new process failed to start");
        std::thread::sleep(Duration::from_millis(50));
    }
    let info = ask(tcp(a), "show info");
    assert!(info.contains(&format!("Pid: {}", new.id())), "{info}");
    common::stop(&mut new);
    let mut err = String::new();
    let _ = new.stderr.take().expect("stderr").read_to_string(&mut err);
    assert!(err.contains("took over 1 listening socket(s)"), "the TCP CLI was not handed over: {err}");
}

/// T354. `HAProxy` 3.5-dev8-885761-29 (`stats socket` on a unix path at admin, another at
/// operator, a TCP one at user, abnsz@ prints as abns@; asked on each, and after `user;`): every socket is listed,
/// in configuration order, each with the level it was bound at -- not the level the
/// asking session has dropped to, and not only the socket asked on.
#[test]
fn show_cli_sockets_lists_every_socket_with_its_own_level() {
    let p4 = common::reserve_port();
    let p6 = common::reserve_port();
    let abns = format!("ibex-t354-{}", std::process::id());
    let lines = format!(
        "\tstats socket 127.0.0.1:{p4} level admin mode 600\n\
         \tstats socket ipv6@[::1]:{p6}\n\
         \tstats socket abns@{abns} level user\n\
         \tstats socket abnsz@{abns}z"
    );
    let (mut child, _f) = start(&lines, &[]);
    let v4: SocketAddr = format!("127.0.0.1:{p4}").parse().expect("addr");
    let want = format!(
        "# socket lvl processes\nipv4@127.0.0.1:{p4} admin all\nipv6@[::1]:{p6} operator all\n\
         abns@{abns} user all\nabns@{abns}z operator all\n\n"
    );
    assert_eq!(ask(tcp(v4), "show cli sockets"), want, "asked on the first socket");
    let s = wait("abns@", || abstract_stream(&abns, true));
    assert_eq!(ask(s, "show cli sockets"), want, "asked on another one");
    assert_eq!(ask(tcp(v4), "operator;show cli sockets"), format!("\n{want}"), "after the session dropped its level");
    common::stop(&mut child);
}

/// T354. An `abns@` stats socket across a plain `-sf` reload. `HAProxy` 3.5-dev8-885761-29
/// (`haproxy -f c.cfg`, then `haproxy -f c.cfg -sf <pid>`): the new process takes the name
/// (the old one is told to pause with SIGTTOU when the bind finds it in use), answers on it,
/// and the old process exits. Ibex had no pause: the new process died with `Address already
/// in use` and the old one went on serving.
#[test]
fn an_abns_stats_socket_survives_a_sf_reload() {
    let abns = format!("ibex-t354-sf-{}", std::process::id());
    let port = common::reserve_port();
    let lines = format!("\tstats socket abns@{abns} level admin\ndefaults\n\tmode http\n\ttimeout client 5s\n\ttimeout connect 1s\n\ttimeout server 5s\nfrontend fe\n\tbind 127.0.0.1:{port}\n\thttp-request return status 200 content-type text/plain string ok");
    let (mut old, f) = start(&lines, &[]);
    let pid_of = |s: UnixStream| -> String {
        ask(s, "show info").lines().find(|l| l.starts_with("Pid: ")).unwrap_or("").to_string()
    };
    let first = pid_of(wait("abns@", || abstract_stream(&abns, true)));
    assert_eq!(first, format!("Pid: {}", old.id()));

    let mut new = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .arg("-sf")
        .arg(old.id().to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut old_gone = false;
    while Instant::now() < deadline && !old_gone {
        old_gone = old.try_wait().expect("wait").is_some();
        std::thread::sleep(Duration::from_millis(50));
    }
    let answer = abstract_stream(&abns, true).map(pid_of);
    let new_alive = new.try_wait().expect("wait").is_none();
    let _ = Command::new("kill").arg("-USR1").arg(new.id().to_string()).status();
    let _ = new.wait();
    let _ = Command::new("kill").arg("-USR1").arg(old.id().to_string()).status();
    let _ = old.wait();
    assert!(new_alive, "the new process must start");
    assert!(old_gone, "the old process exits after the reload");
    assert_eq!(answer, Some(format!("Pid: {}", new.id())), "the CLI is now the new process's");
}

/// T354. When the successor then fails to start, the old process takes its abstract name
/// back (HAProxy: SIGTTIN) and keeps serving the CLI.
#[test]
fn a_failed_sf_successor_gives_the_abns_name_back() {
    let abns = format!("ibex-t354-ttin-{}", std::process::id());
    let port = common::reserve_port();
    let good = format!("\tstats socket abns@{abns} level admin\ndefaults\n\tmode http\n\ttimeout client 5s\n\ttimeout connect 1s\n\ttimeout server 5s\nfrontend fe\n\tbind 127.0.0.1:{port}\n\thttp-request return status 200 content-type text/plain string ok");
    let (mut old, _f) = start(&good, &[]);
    let pid_of = |s: UnixStream| -> String {
        ask(s, "show info").lines().find(|l| l.starts_with("Pid: ")).unwrap_or("").to_string()
    };
    assert_eq!(pid_of(wait("abns@", || abstract_stream(&abns, true))), format!("Pid: {}", old.id()));

    // The same stats socket, and a frontend that cannot start: a port in use without
    // SO_REUSEPORT (bound by the test), after the stats socket has been bound.
    let hog = std::net::TcpListener::bind("127.0.0.1:0").expect("hog");
    let hog_port = hog.local_addr().expect("addr").port();
    let bad = good.replace(&format!("bind 127.0.0.1:{port}"), &format!("bind 127.0.0.1:{hog_port}"));
    let (mut new, _g) = start(&bad, &["-sf".to_string(), old.id().to_string()]);
    let st = new.wait().expect("wait");
    assert!(!st.success(), "the successor must fail: {st:?}");
    std::thread::sleep(Duration::from_millis(300));
    let now = wait("abns@ again", || abstract_stream(&abns, true));
    assert_eq!(pid_of(now), format!("Pid: {}", old.id()), "the old process serves its CLI again");
    let _ = Command::new("kill").arg("-USR1").arg(old.id().to_string()).status();
    let _ = old.wait();
}

/// A stand-in for the process being replaced, so the handover can be observed from its
/// side: it holds `name` (zero-padded, as `abns@`), lets go of it on SIGTTOU, and on SIGTTIN
/// tries to bind it back exactly once, at once, as HAProxy's `protocol_resume_all` does, and
/// prints `bound` or `busy`. It needs no retry if the successor has closed its socket before
/// it signals.
fn old_process_stand_in(name: &str) -> Child {
    const SCRIPT: &str = r#"
import os, signal, socket, sys
addr = b"\0" + sys.argv[1].encode().ljust(107, b"\0")
held = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
held.bind(addr); held.listen(1)
def ttou(sig, frame):
    held.close()
def ttin(sig, frame):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.bind(addr); print("bound", flush=True)
    except OSError as e:
        print("busy", e.errno, flush=True)
    os._exit(0)
signal.signal(signal.SIGTTOU, ttou)
signal.signal(signal.SIGTTIN, ttin)
print("ready", flush=True)
while True:
    signal.pause()
"#;
    Command::new("python3")
        .args(["-I", "-c", SCRIPT, name])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("python3")
}

/// T370. A `-sf` successor that fails to start closes its abstract stats socket before it
/// sends SIGTTIN, so the old process takes the name back at its first try. `HAProxy` sends
/// SIGTTIN first and unbinds after (src/haproxy.c:2115-2116) and still took the name back
/// 30 times in 30 on an idle host, because its resume runs from the event loop a wake-up
/// later; under the gate's load Ibex lost it 1 run in 3 (gate 48). Here the old side is a
/// stand-in that binds once, at once, when SIGTTIN arrives.
#[test]
fn a_failed_sf_successor_frees_its_abns_name_before_it_signals() {
    let abns = format!("ibex-t370-order-{}", std::process::id());
    let mut stand_in = old_process_stand_in(&abns);
    let mut out = std::io::BufReader::new(stand_in.stdout.take().expect("stdout"));
    let mut line = String::new();
    std::io::BufRead::read_line(&mut out, &mut line).expect("ready");
    assert_eq!(line.trim(), "ready");
    assert!(abstract_stream(&abns, true).is_some(), "the stand-in holds the name");

    let hog = std::net::TcpListener::bind("127.0.0.1:0").expect("hog");
    let hog_port = hog.local_addr().expect("addr").port();
    let lines = format!("\tstats socket abns@{abns} level admin\ndefaults\n\tmode http\n\ttimeout client 5s\n\ttimeout connect 1s\n\ttimeout server 5s\nfrontend fe\n\tbind 127.0.0.1:{hog_port}\n\thttp-request return status 200 content-type text/plain string ok");
    let (mut new, _g) = start(&lines, &["-sf".to_string(), stand_in.id().to_string()]);
    let st = new.wait().expect("wait");
    assert!(!st.success(), "the successor must fail: {st:?}");
    line.clear();
    std::io::BufRead::read_line(&mut out, &mut line).expect("verdict");
    let _ = stand_in.wait();
    assert_eq!(line.trim(), "bound", "the name must be free when SIGTTIN arrives");
}

/// T370. The name is held by something else when SIGTTIN arrives: as `HAProxy`
/// 3.5-dev8-885761-29 (measured: `kill -TTOU`, bind the name from outside, `kill -TTIN`),
/// the one bind fails and is reported, the name is not polled for, and the next SIGTTIN
/// takes it back once it is free.
///
/// ```text
/// [ALERT]    (pid) : Resuming listener: protocol abns_stream: cannot bind UNIX socket (already in use) [abns@NAME].
/// [WARNING]  (pid) : Some proxies refused to resume, probably due to a conflict on a listening port. You may want to try again after the conflicting application is stopped, otherwise a restart might be needed to resume safe operations.
/// ```
#[test]
fn an_abns_name_still_held_when_sigttin_arrives_is_reported_and_taken_back_on_the_next_sigttin() {
    use std::os::linux::net::SocketAddrExt;
    let abns = format!("ibex-t370-held-{}", std::process::id());
    let f = cfg(&format!("\tstats socket abns@{abns} level admin"));
    let err = tempfile::NamedTempFile::new().expect("stderr file");
    let mut p = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(err.reopen().expect("reopen"))
        .spawn()
        .expect("spawn");
    drop(wait("abns@", || abstract_stream(&abns, true)));
    let sig = |s: &str| {
        let _ = Command::new("kill").arg(format!("-{s}")).arg(p.id().to_string()).status();
    };
    sig("TTOU");
    wait("name released", || abstract_stream(&abns, true).is_none().then_some(()));
    let mut bytes = abns.as_bytes().to_vec();
    bytes.resize(107, 0);
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(&bytes).expect("addr");
    let hold = std::os::unix::net::UnixListener::bind_addr(&addr).expect("the test takes the name");
    sig("TTIN");
    let text = wait("the refusal is reported", || {
        let t = std::fs::read_to_string(err.path()).unwrap_or_default();
        t.contains("refused to resume").then_some(t)
    });
    assert!(
        text.contains(&format!("[ALERT]    ({}) : Resuming listener: protocol abns_stream: cannot bind UNIX socket (already in use) [abns@{abns}].", p.id())),
        "{text}"
    );
    assert!(
        text.contains(&format!("[WARNING]  ({}) : Some proxies refused to resume, probably due to a conflict on a listening port. You may want to try again after the conflicting application is stopped, otherwise a restart might be needed to resume safe operations.", p.id())),
        "{text}"
    );
    drop(hold);
    std::thread::sleep(Duration::from_millis(300));
    assert!(abstract_stream(&abns, true).is_none(), "the name is not polled for once it is free");
    sig("TTIN");
    let s = wait("abns@ after the next SIGTTIN", || abstract_stream(&abns, true));
    assert!(ask(s, "show cli level").contains("admin"));
    common::stop(&mut p);
}

/// T354. SIGTTOU and SIGTTIN sent straight to a process with several stats sockets: every
/// abns@ one (the first and an extra) lets go of its name and takes it back, as HAProxy
/// 3.5-dev8-885761-29 does (measured: `kill -TTOU` frees both abstract names, `kill -TTIN`
/// binds them again, `show cli sockets` lists all three afterwards). The TCP stats socket is
/// paused too: a connect is refused until SIGTTIN (T456, measured the same).
#[test]
fn sigttou_and_sigttin_release_and_rebind_every_abns_stats_socket() {
    let abns = format!("ibex-t354-sig-{}", std::process::id());
    let tcp_addr = common::reserve_addr();
    let port = common::reserve_port();
    let lines = format!("\tstats socket abns@{abns}x level admin\n\tstats socket {tcp_addr} level admin\n\tstats socket abns@{abns}y level user\ndefaults\n\tmode http\n\ttimeout client 5s\n\ttimeout connect 1s\n\ttimeout server 5s\nfrontend fe\n\tbind 127.0.0.1:{port}\n\thttp-request return status 200 content-type text/plain string ok");
    let (mut p, _f) = start(&lines, &[]);
    let sig = |s: &str| {
        let _ = Command::new("kill").arg(format!("-{s}")).arg(p.id().to_string()).status();
    };
    let (x, y) = (format!("{abns}x"), format!("{abns}y"));
    drop(wait("abns@x", || abstract_stream(&x, true)));
    drop(wait("abns@y", || abstract_stream(&y, true)));
    sig("TTOU");
    wait("both names released", || (abstract_stream(&x, true).is_none() && abstract_stream(&y, true).is_none()).then_some(()));
    wait("tcp cli refused", || {
        matches!(TcpStream::connect(tcp_addr), Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused).then_some(())
    });
    sig("TTIN");
    // the TCP socket answers again and lists all three sockets
    let listing = wait("tcp cli", || {
        let s = TcpStream::connect(tcp_addr).ok()?;
        Some(ask(s, "show cli sockets"))
    });
    assert!(listing.contains(&format!("abns@{x} admin all")) && listing.contains(&format!("abns@{y} user all")), "{listing}");
    let sy = wait("abns@y again", || abstract_stream(&y, true));
    assert!(ask(sy, "show cli level").contains("user"));
    let sx = wait("abns@x again", || abstract_stream(&x, true));
    assert!(ask(sx, "show cli level").contains("admin"));
    sig("USR1");
    let _ = p.wait();
}
