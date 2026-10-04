// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Sample fetch edge cases against the real binary (T137). Every expected value was measured
//! on `HAProxy` 3.5-dev8-885761-29 with the same configuration.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0
                        || s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    addr
}

struct Ibex(Child, NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, fe: SocketAddr) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    Ibex(child, f)
}

/// One request on its own connection; the whole response.
fn get(fe: SocketAddr, extra: &str) -> String {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}\r\n").expect("send");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn header(resp: &str, name: &str) -> Option<String> {
    resp.split("\r\n").find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n";

#[test]
fn acl_fetch_evaluates_named_acls_with_negation_and_the_predefined_ones() {
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {fe}\n  acl ACL1 always_true\n  acl ACL2 acl(ACL1)\n  \
             acl ACL3 acl(!ACL2)\n  acl ACL4 acl(ACL2,!ACL3)\n  \
             http-request return status 200 hdr x-acl \"ACL1=%[acl(ACL1)] ACL2=%[acl(ACL2)] \
             ACL3=%[acl(ACL3)] ACL4=%[acl(ACL4)] TRUE=%[acl(TRUE)] FALSE=%[acl(FALSE)] \
             both=%[acl(ACL1,ACL3)] mix=%[acl(ACL1,!ACL3)]\"\n"
        ),
        fe,
    );
    let r = get(fe, "");
    assert_eq!(
        header(&r, "x-acl").as_deref(),
        Some("ACL1=1 ACL2=1 ACL3=0 ACL4=1 TRUE=1 FALSE=0 both=0 mix=1"),
        "{r}"
    );
}

#[test]
fn set_var_conditions_are_honoured_on_every_rule_set() {
    let be = backend();
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!(
            r####"global
  set-var proc.int12 int(12)
defaults
  mode http
  timeout connect 2s
  timeout client 5s
  timeout server 5s
frontend fe
  bind {fe}
  tcp-request content set-var(txn.t,ifnotexists) str(t1)
  tcp-request content set-var(txn.t,ifnotexists) str(t2)
  tcp-request session set-var(sess.q,ifnotexists) str(q1)
  tcp-request session set-var(sess.q,ifnotexists) str(q2)
  http-request set-var(txn.a) str(a)
  http-request set-var(txn.a,ifexists) str(b)
  http-request set-var(txn.n,ifexists) str(never)
  http-request set-var(txn.e,ifnotexists) str(first)
  http-request set-var(txn.e,ifnotexists) str(second)
  http-request set-var(txn.s,ifset) str(never)
  http-request set-var(txn.s,ifnotset) str(one)
  http-request set-var(txn.s,ifnotset) str(two)
  http-request set-var(txn.s,ifset) str(three)
  http-request set-var(txn.m) str(full)
  http-request set-var(txn.m,ifempty) str(x)
  http-request set-var(txn.m,ifnotempty) str(y)
  http-request set-var(txn.m,ifempty) str()
  http-request set-var(txn.m,ifnotempty) str(z)
  http-request set-var(txn.i,ifempty) int(7)
  http-request set-var(txn.i2,ifnotempty) int(8)
  http-request set-var(txn.c,ifnotset,ifnotempty) str(both)
  http-request set-var(txn.c2,ifnotset,ifempty) str(c2)
  http-request set-var-fmt(txn.f,ifnotexists) "fmt-%[str(1)]"
  http-request set-var-fmt(txn.f,ifnotexists) "fmt2"
  http-request set-var(proc.pe,ifexists) int(5)
  http-request set-var(proc.pn,ifnotexists) int(5)
  http-request set-var(proc.ps,ifnotset) int(6)
  http-request set-var(proc.ps,ifnotset) int(7)
  http-request unset-var(proc.ps)
  http-request set-var(proc.pu) int(9)
  http-request unset-var(proc.pu)
  http-response set-var(res.r,ifnotexists) str(r1)
  http-response set-var(res.r,ifnotexists) str(r2)
  http-response set-header x-a "a=%[var(txn.a)] n=%[var(txn.n)] e=%[var(txn.e)] s=%[var(txn.s)] m=%[var(txn.m)] i=%[var(txn.i)] i2=%[var(txn.i2)] c=%[var(txn.c)] c2=%[var(txn.c2)] f=%[var(txn.f)] t=%[var(txn.t)] q=%[var(sess.q)]"
  http-response set-header x-b "pe=%[var(proc.pe)] pn=%[var(proc.pn)] ps=%[var(proc.ps)] pu=%[var(proc.pu)] r=%[var(res.r)] i12=%[var(proc.int12)]"
  default_backend be
backend be
  server s {be}
"####
        ),
        fe,
    );
    let r = get(fe, "");
    assert_eq!(
        header(&r, "x-a").as_deref(),
        Some("a=b n= e=first s=three m=z i= i2=8 c=both c2= f=fmt-1 t=t1 q=q1"),
        "{r}"
    );
    assert_eq!(header(&r, "x-b").as_deref(), Some("pe=5 pn= ps= pu= r=r1 i12=12"), "{r}");
}

#[test]
fn set_var_converter_honours_its_conditions() {
    let be = backend();
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!(
            r####"defaults
  mode http
  timeout connect 2s
  timeout client 5s
  timeout server 5s
frontend fe
  bind {fe}
  http-request set-var(txn.pre) str(x)
  http-request set-header x-t1 "%[str(first),set-var(txn.cv,ifnotexists)]"
  http-request set-header x-t2 "%[str(second),set-var(txn.cv,ifnotexists)]"
  http-request set-header x-t3 "%[str(third),set-var(txn.pre,ifexists)]"
  http-request set-header x-t4 "%[str(),set-var(txn.cv2,ifnotempty)]"
  http-request set-header x-t5 "%[str(five),set-var(proc.pc,ifexists)]"
  http-request set-header x-t6 "%[str(six),set-var(sess.sc,ifnotset)]"
  http-request set-header x-t7 "%[str(seven),set-var(sess.sc,ifnotset)]"
  http-response set-header x-var "cv=%[var(txn.cv)] pre=%[var(txn.pre)] cv2=%[var(txn.cv2)] pc=%[var(proc.pc)] sc=%[var(sess.sc)]"
  default_backend be
backend be
  server s {be}
"####
        ),
        fe,
    );
    let r = get(fe, "");
    assert_eq!(
        header(&r, "x-var").as_deref(),
        Some("cv=first pre=third cv2= pc=five sc=six"),
        "{r}"
    );
}

/// `haproxy -c` on one rule; the exit code and what it printed.
fn load(rule: &str) -> (Option<i32>, String) {
    let cfg = format!("{DEFAULTS}frontend fe\n  bind 127.0.0.1:18081\n  {rule}\n  default_backend be\nbackend be\n  server s1 127.0.0.1:1\n");
    let path = std::env::temp_dir().join(format!("ibex_t137_{}_{}.cfg", std::process::id(), {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }));
    std::fs::write(&path, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&path);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// HAProxy: `unknown condition "ifbad".` on the action and `invalid args in converter 'set-var'
/// : unknown condition "ifbad".` on the converter. `ifgt` and `iflt` are valid there, but need
/// typed variables, so Ibex refuses them rather than ignore them.
#[test]
fn set_var_unknown_and_untyped_conditions_are_refused_at_load() {
    for rule in [
        "http-request set-var(txn.x,ifbad) str(a)",
        "http-request set-var(txn.x,IFEXISTS) str(a)",
        "http-response set-var-fmt(txn.x,ifbad) a",
        "http-after-response set-var(txn.x,ifbad) str(a)",
        "tcp-request content set-var(txn.x,ifbad) str(a)",
        "tcp-request session set-var(sess.x,ifbad) str(a)",
        "http-request set-header x \"%[str(a),set-var(txn.x,ifbad)]\"",
        "http-request set-var(txn.x,ifgt) int(1)",
        "http-request set-var(txn.x,iflt) int(1)",
        "http-request set-header x \"%[int(1),set-var(txn.x,iflt)]\"",
    ] {
        let (code, out) = load(rule);
        assert_ne!(code, Some(0), "{rule} loaded: {out}");
        assert!(out.contains("condition"), "{rule}: {out}");
    }
    for rule in [
        "http-request set-var(txn.x,ifexists,ifnotexists) str(a)",
        "http-request set-var(txn.x,) str(a)",
        "http-request set-var-fmt(txn.x,ifnotset) a",
        "http-request set-header x \"%[str(a),set-var(txn.x,ifempty,ifset)]\"",
    ] {
        let (code, out) = load(rule);
        assert_eq!(code, Some(0), "{rule} refused: {out}");
    }
}

/// `length` and the string converters cast a binary with `c_bin2str`, which stops at the first
/// NUL byte (HAProxy 3.5-dev8: `bin(41420043),length` is 2, `bin(00),length` 0,
/// `bin(ff41),length` 2, `str(AAEC),b64dec,length` 0, `bin(41004243),upper` "A").
#[test]
fn binary_cast_to_string_stops_at_the_first_nul() {
    let be = backend();
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {fe}\n  default_backend be\n\
             backend be\n  server s {be}\n  \
             http-response set-header x-l \"%[bin(41420043),length] %[bin(414243),length] %[bin(ff41),length] %[bin(00),length] %[str(AAEC),b64dec,length] %[int(12345),length] %[ipv4(1.2.3.4),length]\"\n  \
             http-response set-header x-u \"%[bin(41004243),upper]\"\n"
        ),
        fe,
    );
    let r = get(fe, "");
    assert_eq!(header(&r, "x-l").as_deref(), Some("2 3 2 0 0 5 7"), "{r}");
    assert_eq!(header(&r, "x-u").as_deref(), Some("A"), "{r}");
}

/// `http_auth_bearer(<header>)` on a custom header and on `Authorization` (HAProxy 3.5-dev8,
/// the same rules as reg-tests/sample_fetches/http_auth_bearer.vtc plus a token with a space).
#[test]
fn http_auth_bearer_reads_the_named_header() {
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {fe}\n  \
             http-request return status 200 hdr tok \"%[http_auth_bearer(x-tok)]\" if {{ http_auth_bearer(x-tok) -m found }}\n  \
             http-request return status 201 hdr tok \"%[http_auth_bearer]\" if {{ http_auth_bearer -m found }}\n  \
             http-request return status 404\n"
        ),
        fe,
    );
    let cases: &[(&str, &str, &str)] = &[
        ("x-tok: Bearer a", "200", "a"),
        ("x-tok: Bearer abcdef", "200", "abcdef"),
        ("x-tok: Bearer abcdefg", "200", "abcdefg"),
        ("x-tok: bearer   xyz123", "200", "xyz123"),
        ("x-tok: BEARER abc def", "200", "abc def"),
        ("x-tok: Bearer", "404", ""),
        ("x-tok: Bearerabc", "404", ""),
        ("x-tok: Basic abcdef", "404", ""),
        ("authorization: Bearer abcdef", "201", "abcdef"),
        ("authorization: Basic YTpi", "404", ""),
    ];
    for (hdr, status, tok) in cases {
        let r = get(fe, &format!("{hdr}\r\n"));
        assert!(r.starts_with(&format!("HTTP/1.1 {status}")), "{hdr}: {r}");
        assert_eq!(header(&r, "tok").unwrap_or_default(), *tok, "{hdr}: {r}");
    }
}

/// `meth(<name>)` is the constant method (HAProxy 3.5-dev8): the name as written, known or not.
#[test]
fn meth_with_an_argument_is_a_constant_method() {
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {fe}\n  \
             http-request return status 200 hdr x-m \"a=[%[meth(GET)]] b=[%[meth(POST)]] c=[%[meth(HEAD)]] d=[%[meth(OPTIONS)]] e=[%[meth(CONNECT)]] f=[%[meth(PURGE)]] g=[%[meth(get)]] h=[%[meth(GET),length]]\" \
             hdr x-n \"%[meth(GET)]-%[meth(TRACE)]-%[meth(PUT)]-%[meth(DELETE)]-%[meth(PATCH)]\"\n"
        ),
        fe,
    );
    let r = get(fe, "");
    assert_eq!(
        header(&r, "x-m").as_deref(),
        Some("a=[GET] b=[POST] c=[HEAD] d=[OPTIONS] e=[CONNECT] f=[PURGE] g=[get] h=[3]"),
        "{r}"
    );
    assert_eq!(header(&r, "x-n").as_deref(), Some("GET-TRACE-PUT-DELETE-PATCH"), "{r}");
}

/// `srv_id` and `srv_name` in `http-response` name the server that answered (HAProxy 3.5-dev8:
/// round robin over `srv1`, `srv2` gives `1 srv1` then `2 srv2`).
#[test]
fn srv_id_and_srv_name_in_http_response() {
    let b1 = backend();
    let b2 = backend();
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {fe}\n  \
             http-response set-header srv-id \"%[srv_id]\"\n  http-response set-header srv-name \"%[srv_name]\"\n  \
             default_backend be\nbackend be\n  balance roundrobin\n  server srv1 {b1}\n  server srv2 {b2}\n"
        ),
        fe,
    );
    let r1 = get(fe, "");
    let r2 = get(fe, "");
    assert_eq!((header(&r1, "srv-id").as_deref(), header(&r1, "srv-name").as_deref()), (Some("1"), Some("srv1")), "{r1}");
    assert_eq!((header(&r2, "srv-id").as_deref(), header(&r2, "srv-name").as_deref()), (Some("2"), Some("srv2")), "{r2}");
}

/// The TCP_INFO counters need `getsockopt(TCP_INFO)`, which the memory-safe crates cannot call.
/// They are refused with a reason, rather than loaded and left empty on every request.
#[test]
fn tcp_info_counters_are_refused_with_a_reason() {
    for f in ["fc_unacked", "fc_sacked", "fc_lost", "fc_retrans", "fc_fackets", "fc_reordering"] {
        let (code, out) = load(&format!("http-request set-header x \"%[{f}]\""));
        assert_ne!(code, Some(0), "{f} loaded: {out}");
        assert!(out.contains("not implemented in Ibex"), "{f}: {out}");
    }
}
