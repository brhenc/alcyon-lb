// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tcp-response content` in TCP mode, as `HAProxy` (3.5-dev8-885761-29) ran the same
//! configuration and backend, measured 2026-10-03 (`tcp_inspect_response`,
//! `src/tcp_rules.c`):
//!
//! * the response is held from the client until the rules decide;
//! * a `res.payload(0,0)` that does not match yet waits for more data
//!   (`SMP_F_MAY_CHANGE`), until the inspect-delay expires or the server closes;
//! * a reject closes the client connection cleanly (EOF) with nothing forwarded;
//! * `set-var` on the response feeds later rules.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use alcyon_rt::Engine;

/// A backend reading one line naming a script, then sending its parts 200 ms apart, then
/// closing (or holding the connection open for three seconds first).
fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 100];
                let n = c.read(&mut buf).unwrap_or(0);
                let (parts, hold): (&[&[u8]], bool) = match String::from_utf8_lossy(&buf[..n]).trim() {
                    "good" => (&[b"good"], false),
                    "bad" => (&[b"bad!"], false),
                    "split" => (&[b"go", b"od"], false),
                    "partial" => (&[b"go"], true),
                    "empty" => (&[], false),
                    "var" => (&[b"v=42"], false),
                    _ => (&[b"?"], false),
                };
                for (i, p) in parts.iter().enumerate() {
                    if i > 0 {
                        thread::sleep(Duration::from_millis(200));
                    }
                    let _ = c.write_all(p);
                }
                if hold {
                    thread::sleep(Duration::from_secs(3));
                }
            });
        }
    });
    addr
}

#[test]
fn the_response_is_held_until_the_rules_decide() {
    let srv = backend();
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         listen l\n  bind {fe}\n  tcp-response inspect-delay 1s\n  \
         tcp-response content set-var(res.p) res.payload(0,0)\n  \
         tcp-response content reject if {{ res.payload(0,0) -m str bad! }}\n  \
         tcp-response content accept if {{ res.payload(0,0) -m str good }}\n  \
         tcp-response content accept if {{ var(res.p) -m beg v= }}\n  \
         tcp-response content reject\n  \
         server s {srv}\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let keys = ["good", "bad", "split", "partial", "empty", "var"];
    let client = thread::spawn(move || {
        keys.iter()
            .map(|k| {
                let mut c = TcpStream::connect(fe).expect("connect");
                c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                let t = Instant::now();
                c.write_all(format!("{k}\n").as_bytes()).expect("send");
                let mut got = Vec::new();
                let how = match c.read_to_end(&mut got) {
                    Ok(_) => "eof",
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => "rst",
                    Err(_) => "timeout",
                };
                (format!("{k}: {} {how}", String::from_utf8_lossy(&got)), t.elapsed())
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let got = client.join().expect("client");
    let lines: Vec<&str> = got.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(lines, ["good: good eof", "bad:  eof", "split: good eof", "partial:  eof", "empty:  eof", "var: v=42 eof"]);
    // `split` waited for its second part; `partial` for the inspect-delay.
    assert!(got[2].1 >= Duration::from_millis(180), "split answered after {:?}", got[2].1);
    assert!(got[3].1 >= Duration::from_millis(900) && got[3].1 < Duration::from_millis(2500), "partial after {:?}", got[3].1);
}

/// In HTTP mode the rules run before the response is analysed (`AN_RES_INSPECT` ahead of
/// `AN_RES_WAIT_HTTP`): its headers are not there to fetch, so a condition on them does
/// not hold and a variable taken from them is empty. A reject that does fire closes the
/// client connection with no response at all (curl: exit 52), not a 502.
#[test]
fn in_http_mode_the_rules_cannot_see_the_response() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Bad: 1\r\n\r\nok");
        }
    });
    let (hdr, var, src, vars) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         listen hdr\n  bind {hdr}\n  tcp-response content reject if {{ res.hdr(x-bad) -m found }}\n  server s {srv}\n\
         listen var\n  bind {var}\n  tcp-response content set-var(txn.x) res.hdr(x-bad)\n  \
         http-response set-header y \"%[var(txn.x)]\"\n  server s {srv}\n\
         listen src\n  bind {src}\n  tcp-response content reject if {{ src 127.0.0.1 }}\n  server s {srv}\n\
         listen vars\n  bind {vars}\n  http-request set-var(txn.gone) str(g)\n  \
         tcp-response content set-var-fmt(txn.f) \"f-%[str(1)]\"\n  tcp-response content set-var(sess.s) str(s1)\n  \
         tcp-response content unset-var(txn.gone)\n  \
         tcp-response content set-var(txn.none) res.payload(0,0)\n  tcp-response content accept\n  tcp-response content reject\n  \
         http-response set-header y \"%[var(txn.f)]|%[var(sess.s)]|%[var(txn.gone)]\"\n  \
         http-response set-header z found if {{ var(txn.none) -m found }}\n  server s {srv}\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let client = thread::spawn(move || {
        [hdr, var, src, vars]
            .iter()
            .map(|&a| {
                let mut c = TcpStream::connect(a).expect("connect");
                c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
                let mut out = Vec::new();
                let _ = c.read_to_end(&mut out);
                String::from_utf8_lossy(&out).into_owned()
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let got = client.join().expect("client");
    assert!(got[0].starts_with("HTTP/1.1 200") && got[0].ends_with("ok"), "{:?}", got[0]);
    assert!(got[1].to_ascii_lowercase().contains("\r\ny: \r\n"), "{:?}", got[1]);
    assert_eq!(got[2], "");
    // `HAProxy`: 200 with `y: f-1|s1|` -- the variables set and unset, then `accept` --
    // and no `z`: a `set-var` whose sample cannot be fetched sets nothing (`action_store`).
    assert!(!got[3].to_ascii_lowercase().contains("\r\nz:"), "{:?}", got[3]);
    assert!(got[3].starts_with("HTTP/1.1 200") && got[3].to_ascii_lowercase().contains("\r\ny: f-1|s1|\r\n"), "{:?}", got[3]);
}

/// The FIX converters on the response, as `HAProxy` ran this configuration with a
/// two-second inspect-delay: a valid logon goes through (a split one once its second part
/// is in); an invalid one is rejected at once -- `fix_is_valid` knows it will not become
/// valid, so the rules do not wait (`sample_conv_fix_is_valid` clears
/// `SMP_F_MAY_CHANGE`); one cut short waits out the delay, then is rejected.
#[test]
fn fix_responses_are_judged_as_haproxy_judges_them() {
    fn m(s: &str) -> Vec<u8> {
        s.bytes().map(|b| if b == b'|' { 1 } else { b }).collect()
    }
    let valid = m("8=FIX.4.4|9=79|35=A|34=1|49=EXECUTOR|52=20201029-13:02:44.535360|56=CLIENT1|98=0|108=30|141=Y|10=038|");
    let badsum = m("8=FIX.4.4|9=79|35=A|34=1|49=EXECUTOR|52=20201029-13:02:44.535360|56=CLIENT1|98=0|108=30|141=Y|10=039|");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv = listener.local_addr().expect("addr");
    let scripts: Vec<(&'static str, Vec<Vec<u8>>)> = vec![
        ("valid", vec![valid.clone()]),
        ("split", vec![valid[..40].to_vec(), valid[40..].to_vec()]),
        ("badsum", vec![badsum]),
        ("partial", vec![valid[..40].to_vec()]),
    ];
    let served = scripts.clone();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let served = served.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 100];
                let n = c.read(&mut buf).unwrap_or(0);
                let key = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                let parts = served.iter().find(|(k, _)| *k == key).map(|(_, p)| p.clone()).unwrap_or_default();
                for (i, p) in parts.iter().enumerate() {
                    if i > 0 {
                        thread::sleep(Duration::from_millis(300));
                    }
                    let _ = c.write_all(p);
                }
                thread::sleep(Duration::from_secs(3));
            });
        }
    });
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 6s\n  timeout server 6s\n\
         listen l\n  bind {fe}\n  tcp-response inspect-delay 2s\n  \
         tcp-response content reject unless {{ res.payload(0,0),fix_is_valid }}\n  \
         tcp-response content set-var(res.sender) res.payload(0,0),fix_tag_value(SenderCompID)\n  \
         tcp-response content reject unless {{ var(res.sender) -m str EXECUTOR }}\n  \
         server s {srv}\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let want = valid.clone();
    let client = thread::spawn(move || {
        scripts
            .iter()
            .map(|(k, _)| {
                let mut c = TcpStream::connect(fe).expect("connect");
                c.set_read_timeout(Some(Duration::from_secs(6))).expect("timeout");
                let t = Instant::now();
                c.write_all(format!("{k}\n").as_bytes()).expect("send");
                let mut got = Vec::new();
                let mut buf = [0u8; 200];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                    if got == want {
                        break;
                    }
                }
                (format!("{k}: {}", if got == want { "the logon" } else if got.is_empty() { "nothing" } else { "garbage" }), t.elapsed())
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let got = client.join().expect("client");
    let lines: Vec<&str> = got.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(lines, ["valid: the logon", "split: the logon", "badsum: nothing", "partial: nothing"]);
    assert!(got[1].1 >= Duration::from_millis(280), "split after {:?}", got[1].1);
    assert!(got[2].1 < Duration::from_millis(1000), "an invalid message is rejected at once, not after {:?}", got[2].1);
    assert!(got[3].1 >= Duration::from_millis(1900), "partial waits the delay, answered after {:?}", got[3].1);
}

/// What `HAProxy` did with each of these, measured with the same configuration
/// (inspect-delay 1s), from the client's side: what arrived, when the first byte did,
/// and how the connection ended.
///
/// * `trunc`: `res.payload(0,60)` cannot be fetched from the first 30 bytes, so the rule
///   waits for the rest (0.3s later) even though tag 35 is already there.
/// * `drop`: the rule ahead of `silent-drop` waits for a fifth byte that never comes; at
///   the delay it drops the client, which sees a reset.
/// * `fmt`: `set-var-fmt` stores the length, a named ACL and `proc.` variable pass.
/// * `unset`: `unset-var` removes it, so the response is refused at once.
/// * `short`: `res.len`, `res.payload(0,5)` wait for the second part.
#[test]
fn response_actions_variables_and_partial_fetches() {
    fn m(s: &str) -> Vec<u8> {
        s.bytes().map(|b| if b == b'|' { 1 } else { b }).collect()
    }
    let logon = m("8=FIX.4.4|9=79|35=A|34=1|49=EXECUTOR|52=20201029-13:02:44.535360|56=CLIENT1|98=0|108=30|141=Y|10=038|");
    let scripts: Vec<(&'static str, Vec<Vec<u8>>)> = vec![
        ("trunc", vec![logon[..30].to_vec(), logon[30..].to_vec()]),
        ("drop", vec![b"drop".to_vec()]),
        ("fmt", vec![b"fmtfmt".to_vec()]),
        ("unset", vec![b"unset".to_vec()]),
        ("short", vec![b"ab".to_vec(), b"cdef".to_vec()]),
    ];
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv = listener.local_addr().expect("addr");
    let served = scripts.clone();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let served = served.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 100];
                let n = c.read(&mut buf).unwrap_or(0);
                let key = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                let parts = served.iter().find(|(k, _)| *k == key).map(|(_, p)| p.clone()).unwrap_or_default();
                for (i, p) in parts.iter().enumerate() {
                    if i > 0 {
                        thread::sleep(Duration::from_millis(300));
                    }
                    let _ = c.write_all(p);
                }
                thread::sleep(Duration::from_secs(2));
            });
        }
    });
    let (fixl, acts) = (common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 4s\n  timeout server 4s\n\
         listen fixl\n  bind {fixl}\n  tcp-response inspect-delay 1s\n  \
         tcp-response content reject if {{ res.payload(0,60),fix_tag_value(35) -m str Z }}\n  \
         tcp-response content accept\n  server s {srv}\n\
         listen acts\n  bind {acts}\n  acl is_drop res.payload(0,4) -m str drop\n  tcp-response inspect-delay 1s\n  \
         tcp-response content set-var(proc.seen) str(yes)\n  \
         tcp-response content set-var-fmt(txn.f) \"%[res.len]\"\n  \
         tcp-response content unset-var(txn.f) if {{ res.payload(0,5) -m str unset }}\n  \
         tcp-response content silent-drop if is_drop\n  \
         tcp-response content accept if {{ var(txn.f) -m str 6 }} {{ var(proc.seen) -m str yes }}\n  \
         tcp-response content reject if {{ res.len ge 5 }}\n  \
         tcp-response content reject\n  server s {srv}\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let targets = [(fixl, "trunc"), (acts, "drop"), (acts, "fmt"), (acts, "unset"), (acts, "short")];
    let client = thread::spawn(move || {
        targets
            .iter()
            .map(|&(addr, k)| {
                let mut c = TcpStream::connect(addr).expect("connect");
                c.set_read_timeout(Some(Duration::from_secs(4))).expect("timeout");
                let t = Instant::now();
                c.write_all(format!("{k}\n").as_bytes()).expect("send");
                let (mut got, mut first, mut buf) = (0usize, None, [0u8; 200]);
                let how = loop {
                    match c.read(&mut buf) {
                        Ok(0) => break "eof",
                        Ok(n) => {
                            first.get_or_insert(t.elapsed());
                            got += n;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break "rst",
                        Err(_) => break "timeout",
                    }
                };
                (format!("{k}: {got}B {how}"), first, t.elapsed())
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let got = client.join().expect("client");
    let lines: Vec<&str> = got.iter().map(|(l, _, _)| l.as_str()).collect();
    assert_eq!(lines, ["trunc: 101B eof", "drop: 0B rst", "fmt: 6B eof", "unset: 0B eof", "short: 6B eof"]);
    let ms = |d: Option<Duration>| d.map_or(u128::MAX, |d| d.as_millis());
    assert!((280..900).contains(&ms(got[0].1)), "trunc's first byte waited for the rest: {:?}", got[0].1);
    assert!(got[1].2 >= Duration::from_millis(900), "drop at the delay, not {:?}", got[1].2);
    assert!(ms(got[2].1) < 250, "fmt forwarded at once: {:?}", got[2].1);
    assert!(got[3].2 < Duration::from_millis(250), "unset refused at once, not {:?}", got[3].2);
    assert!((280..900).contains(&ms(got[4].1)), "short waited for its second part: {:?}", got[4].1);
}

/// The rules run as soon as the server connection is up, before any of the response:
/// `res.len lt 4` matches the empty buffer, so `HAProxy` (same configuration, measured)
/// refused at once although the server was about to send six bytes. A condition that
/// does not hold yet waits; one that holds decides.
#[test]
fn the_rules_run_before_the_response_arrives() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 100];
                let _ = c.read(&mut buf);
                thread::sleep(Duration::from_millis(300));
                let _ = c.write_all(b"fmtfmt");
                thread::sleep(Duration::from_secs(2));
            });
        }
    });
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 4s\n  timeout server 4s\n\
         listen l\n  bind {fe}\n  tcp-response inspect-delay 1s\n  \
         tcp-response content reject if {{ res.len lt 4 }}\n  server s {srv}\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let client = thread::spawn(move || {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(4))).expect("timeout");
        let t = Instant::now();
        c.write_all(b"x\n").expect("send");
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
        (got.len(), t.elapsed())
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let (n, took) = client.join().expect("client");
    assert_eq!(n, 0, "refused with nothing forwarded");
    assert!(took < Duration::from_millis(250), "refused before the server's bytes, not after {took:?}");
}

/// `res.len` may still grow: `accept if { res.len ge 4 }` does not hold on "ab" but waits
/// for "cdef" (0.3s later) rather than falling through to `reject` -- `HAProxy` forwarded
/// the six bytes after 0.3s. `unset-var(sess.x)` undoes the `set-var` before it.
#[test]
fn res_len_waits_for_more_of_the_response() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 100];
                let _ = c.read(&mut buf);
                let _ = c.write_all(b"ab");
                thread::sleep(Duration::from_millis(300));
                let _ = c.write_all(b"cdef");
                thread::sleep(Duration::from_secs(1));
            });
        }
    });
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 4s\n  timeout server 4s\n\
         listen l\n  bind {fe}\n  tcp-response inspect-delay 1s\n  \
         tcp-response content set-var(sess.x) str(1)\n  tcp-response content unset-var(sess.x)\n  \
         tcp-response content accept if {{ res.len ge 4 }} !{{ var(sess.x) -m found }}\n  \
         tcp-response content reject\n  server s {srv}\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let client = thread::spawn(move || {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(4))).expect("timeout");
        let t = Instant::now();
        c.write_all(b"x\n").expect("send");
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
        (got, t.elapsed())
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let (got, took) = client.join().expect("client");
    assert_eq!(got, b"abcdef");
    assert!(took >= Duration::from_millis(280), "{took:?}");
}
