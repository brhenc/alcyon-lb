// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T343 (V&V VV-14): a fetch or converter argument that does not parse as its declared type is
//! refused at load, in every context, as `HAProxy`'s `make_arg_list` and `val_args` functions
//! refuse it. Before this, `http-request deny if { src,ipmask(255.255.255.O) -m ip 127.0.0.0/8 }`
//! (letter O) loaded, the converter gave no sample on every request, and the deny never fired.
//!
//! Every row was measured on `HAProxy` 3.5-dev8-885761-29 on 2026-10-17 with `haproxy -c -f`,
//! the row's expression placed in the configuration [`config`] writes for its context:
//! `set-header` is `http-request set-header X "%[<expr>]"`, `set-var` is
//! `http-request set-var(txn.v) <expr>`, `acl` is `acl a <expr> -m found` used by a deny,
//! `anon-acl` is `http-request deny if { <expr> -m found }`, `stick-on` is `stick on <expr>` in a
//! backend with a string table, and the log-format family is `<directive> "%[<expr>]"` in the
//! frontend; `set-header-uq` is the `set-header` without quotes. A row gives the exit code and the core of the first ALERT: the message
//! `sample_parse_expr` builds, without the context's prefix ("failed to parse sample
//! expression <...> : ", "error detected while parsing ACL 'a' : ", "'stick': ", ...), its
//! suffix (" in ACL expression '...'", " in http-request expression in proxy 'f'", the regex
//! library's own explanation) and the closing `]` of a `%[...]` (`HAProxy` quotes the rest of
//! the format string there; Ibex quotes the expression). Ibex must give the same exit code and,
//! when it refuses, a message containing that core.
//!
//! The SWEEP rows are the V&V's `tools/battery/repro/vv-1017c/cases_sweep.py`; the CONTEXTS
//! rows its `cases_ctx.py`; the FORMS rows add accepted forms and the edges of each argument
//! type and `val_args` function, so that nothing `HAProxy` accepts is refused.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

type Row = (&'static str, &'static str, i32, &'static str);

fn ibex_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_ibex"))
}

/// The configuration `HAProxy` was measured with, `expr` placed for `ctx`.
fn config(ctx: &str, expr: &str) -> String {
    let (fe, be) = match ctx {
        "set-header" => (format!("http-request set-header X \"%[{expr}]\""), String::new()),
        // Unquoted: a blank ends the word, and the `%[` is left without its `]`.
        "set-header-uq" => (format!("http-request set-header X %[{expr}]"), String::new()),
        "set-var" => (format!("http-request set-var(txn.v) {expr}"), String::new()),
        "acl" => (format!("acl a {expr} -m found\n    http-request deny if a"), String::new()),
        "anon-acl" => (format!("http-request deny if {{ {expr} -m found }}"), String::new()),
        "stick-on" => (String::new(), format!("stick-table type string size 10\n    stick on {expr}")),
        "log-format" | "unique-id-format" | "error-log-format" | "log-format-sd" => (format!("{ctx} \"%[{expr}]\""), String::new()),
        _ => panic!("no context {ctx}"),
    };
    let ind = |s: &str| {
        use std::fmt::Write;
        s.lines().filter(|l| !l.is_empty()).fold(String::new(), |mut o, l| {
            let _ = writeln!(o, "    {l}");
            o
        })
    };
    format!(
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 1s\n    timeout server 1s\n    timeout connect 1s\n\
         frontend f\n    bind 127.0.0.1:46199\n{}    default_backend b\nbackend b\n{}    server s 127.0.0.1:46198\n\
         backend t\n    stick-table type ip size 10\n",
        ind(&fe),
        ind(&be)
    )
}

/// `ibex -c -f <cfg>`: exit code and output.
fn check(tag: &str, cfg: &str) -> (i32, String) {
    let p = std::env::temp_dir().join(format!("ibex_t343_{}_{tag}.cfg", std::process::id()));
    std::fs::write(&p, cfg).expect("write config");
    let out = Command::new(ibex_bin()).arg("-c").arg("-f").arg(&p).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&p);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

/// Every row of `rows` on `ibex -c`; panics listing those that differ from `HAProxy`.
fn run(group: &str, rows: &[Row]) {
    let mut bad = Vec::new();
    for (i, &(ctx, expr, rc, core)) in rows.iter().enumerate() {
        let (got, text) = check(&format!("{group}{i}"), &config(ctx, expr));
        let alert = text.lines().find(|l| l.contains("ALERT")).unwrap_or("").to_string();
        if got != rc {
            bad.push(format!("{ctx} {expr}: exit {got}, HAProxy {rc} ({core}) | {alert}"));
        } else if rc != 0 && !text.contains(core) {
            bad.push(format!("{ctx} {expr}: refused, but not with \"{core}\" | {alert}"));
        }
    }
    assert!(bad.is_empty(), "{group}: {} of {} rows differ from HAProxy:\n{}", bad.len(), rows.len(), bad.join("\n"));
}

#[test]
fn the_vv_sweep_of_argument_errors_is_refused_as_haproxy_refuses_it() {
    run("sweep", SWEEP);
}

#[test]
fn argument_errors_are_refused_in_set_var_acls_and_stick_rules() {
    run("ctx", CONTEXTS);
    run("aclconv", ACL_CONVERTERS);
}

#[test]
fn argument_errors_are_refused_in_the_log_format_family() {
    run("lf", LOG_FORMATS);
}

#[test]
fn the_forms_haproxy_accepts_load_and_the_edges_it_refuses_do_not() {
    run("forms", FORMS);
}

/// What the arguments the load now accepts give at run time, measured on `HAProxy` with curl
/// (same date): `read_int64` makes `-`, `+` and nothing 0 (`and(-)`, `add`, `sub(+)`), and
/// `digest` takes `OpenSSL`'s aliases (`sha-1`, `SHA2-256`) -- Ibex hashed every name it did not
/// know with sha256.
#[test]
fn operator_and_digest_arguments_give_haproxys_values() {
    let bind = free_addr(46150..46198);
    let cfg = format!(
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 1s\n    timeout server 1s\n    timeout connect 1s\n\
         frontend f\n    bind {bind}\n    http-request return status 200 content-type text/plain lf-string \
         \"and=%[int(5),and(-)] add=%[int(5),add] sub=%[int(5),sub(+)] sha1=%[str(a),digest(sha-1),hex] s256=%[str(a),digest(SHA2-256),hex]\"\n"
    );
    let body = get(bind, &cfg, "rt");
    assert!(
        body.ends_with(
            "and=0 add=5 sub=5 sha1=86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8 \
             s256=CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB"
        ),
        "{body}"
    );
}

/// `ipmask` gives an address (`SMP_T_ADDR`), so an ACL on it matches networks by default:
/// `str(10.1.2.3),ipmask(8) 10.0.0.0/8` holds, and the deny answers 403 on `HAProxy` (curl, same
/// date). Ibex declared it `Same`, took the string input's string match, and compared
/// "10.0.0.0" with "10.0.0.0/8".
#[test]
fn an_acl_after_ipmask_matches_addresses() {
    let bind = free_addr(46050..46100);
    let cfg = format!(
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 1s\n    timeout server 1s\n    timeout connect 1s\n\
         frontend f\n    bind {bind}\n    http-request deny if {{ str(10.1.2.3),ipmask(8) 10.0.0.0/8 }}\n\
         \x20   http-request return status 200 content-type text/plain string allowed\n"
    );
    let resp = get(bind, &cfg, "ipm");
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
}

/// `digest(sha3-256)` loads on `HAProxy` (an `OpenSSL` digest); Ibex does not compute it and
/// refuses the configuration rather than give no sample on every request, as it does for
/// `hmac` (a documented gap, not parity).
#[test]
fn a_digest_ibex_does_not_compute_is_refused() {
    let (rc, text) = check("sha3", &config("set-header", "str(a),digest(sha3-256)"));
    assert_eq!(rc, 1, "{text}");
    assert!(text.contains("converter 'digest' with digest 'sha3-256' is not implemented by Ibex"), "{text}");
}

/// Starts ibex on `cfg`, sends one GET to `bind`, stops it; the whole response.
fn get(bind: SocketAddr, cfg: &str, tag: &str) -> String {
    let p = std::env::temp_dir().join(format!("ibex_t343_{}_{tag}.cfg", std::process::id()));
    std::fs::write(&p, cfg).expect("write config");
    let mut child = Command::new(ibex_bin()).arg("-f").arg(&p).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Ibex).expect("spawn ibex");
    assert!(common::wait_listening(bind), "ibex did not listen on {bind}");
    let mut s = TcpStream::connect(bind).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    common::stop(&mut child);
    let _ = std::fs::remove_file(&p);
    resp.trim_end().to_string()
}

/// The V&V reproducer, `vv14-deny-typo.cfg`, with the letter O in the mask.
fn vv14(mask: &str, bind: SocketAddr) -> String {
    format!(
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 1s\n    timeout server 1s\n    timeout connect 1s\n\
         frontend f\n    bind {bind}\n    http-request deny if {{ src,ipmask({mask}) -m ip 127.0.0.0/8 }}\n\
         \x20   http-request return status 200 content-type text/plain string allowed\n"
    )
}

#[test]
fn the_vv14_deny_with_a_mistyped_mask_is_refused() {
    let (rc, text) = check("vv14", &vv14("255.255.255.O", "127.0.0.1:46199".parse().expect("addr")));
    assert_eq!(rc, 1, "{text}");
    assert!(
        text.contains("invalid arg 1 in converter 'ipmask' : failed to parse '255.255.255.O' as type 'IPv4 mask' at position 1"),
        "{text}"
    );
}

/// A free port in `ports`, of the range this task may listen on; each test has its own, as
/// they run at the same time.
fn free_addr(ports: std::ops::Range<u16>) -> SocketAddr {
    ports.map(|p| SocketAddr::from(([127, 0, 0, 1], p))).find(|a| TcpListener::bind(a).is_ok()).expect("a free port")
}

/// Its fixed form loads, and a GET from 127.0.0.1 is denied: 403 on both (`HAProxy` measured
/// with curl, same date).
#[test]
fn the_vv14_deny_with_the_mask_fixed_denies_with_403() {
    let bind = free_addr(46100..46150);
    let resp = get(bind, &vv14("255.255.255.0", bind), "vv14ok");
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
}

const SWEEP: &[Row] = &[
    ("set-header", "src,ipmask(abc)", 1, "invalid arg 1 in converter 'ipmask' : failed to parse 'abc' as type 'IPv4 mask' at position 1"),
    ("set-header", "src,ipmask(24,abc)", 1, "invalid arg 2 in converter 'ipmask' : failed to parse 'abc' as type 'IPv6 mask' at position 2"),
    ("set-header", "str(a),bytes(x)", 1, "invalid args in converter 'bytes' : expects an integer or a variable name"),
    ("set-header", "str(a),bytes(1,x)", 1, "invalid args in converter 'bytes' : expects an integer or a variable name"),
    ("set-header", "str(a:b),field(x,:)", 1, "invalid arg 1 in converter 'field' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "str(a:b),word(x,:)", 1, "invalid arg 1 in converter 'word' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "str(a:b),field(1)", 1, "invalid arg 2 in converter 'field' : missing arguments (got 1/2), type 'string' expected"),
    ("set-header", "int(x)", 1, "fetch method 'int' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "int( 1)", 1, "fetch method 'int' : failed to parse ' 1' as type 'integer' at position 1"),
    ("set-header", "int(1x)", 1, "fetch method 'int' : failed to parse '1x' as type 'integer' at position 1"),
    ("set-header", "int(1),add(1x)", 1, "invalid args in converter 'add' : expects an integer or a variable name"),
    ("set-header", "int(1),mul(abc)", 1, "invalid args in converter 'mul' : expects an integer or a variable name"),
    ("set-header", "int(1),div(1.5)", 1, "invalid args in converter 'div' : expects an integer or a variable name"),
    ("set-header", "int(1),and(-)", 0, ""),
    ("set-header", "str(a),regsub(a**,b)", 1, "error in regex 'a**' in arg 1 of conversion keyword 'regsub' for sample fetch keyword 'str'"),
    ("set-header", "str(a),regsub(a)", 1, "invalid arg 2 in converter 'regsub' : missing arguments (got 1/2), type 'string' expected"),
    ("set-header", "str(a),map(/nonexistent/m)", 1, "invalid args in converter 'map' : failed to open pattern file </nonexistent/m>"),
    ("set-header", "str(a),map_str_int(/nonexistent/m)", 1, "invalid args in converter 'map_str_int' : failed to open pattern file </nonexistent/m>"),
    ("set-header", "src,table_trackers(nosuchtable)", 1, "unable to find table 'nosuchtable' referenced in arg 1 of conversion keyword 'table_trackers' for sample fetch keyword 'src'"),
    ("set-header", "table_cnt(nosuchtable)", 1, "unable to find table 'nosuchtable' referenced in arg 1 of sample fetch keyword 'table_cnt'"),
    ("set-header", "nbsrv(nosuchbe)", 1, "unable to find backend 'nosuchbe' referenced in arg 1 of sample fetch keyword 'nbsrv'"),
    ("set-header", "srv_conn(nosuchbe/s)", 1, "unable to find proxy 'nosuchbe' referenced in arg 1 of sample fetch keyword 'srv_conn'"),
    ("set-header", "srv_conn(b/nosuchsrv)", 1, "unable to find server 'nosuchsrv'"),
    ("set-header", "str(a),crc32(x)", 1, "invalid arg 1 in converter 'crc32' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "str(a),djb2(x)", 1, "invalid arg 1 in converter 'djb2' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "str(a),xxh32(x)", 1, "invalid arg 1 in converter 'xxh32' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "str(a),json(bogus)", 1, "invalid args in converter 'json' : Unexpected input code type. Allowed value are 'ascii', 'utf8', 'utf8s', 'utf8p' and 'utf8ps'"),
    ("set-header", "int(1),utime(%Y,x)", 1, "invalid arg 2 in converter 'utime' : failed to parse 'x' as type 'integer' at position 2"),
    ("set-header", "int(1),ltime(%Y,nowhere)", 1, "invalid arg 2 in converter 'ltime' : failed to parse 'nowhere' as type 'integer' at position 2"),
    ("set-header", "hdr(x,abc)", 1, "fetch method 'hdr' : failed to parse 'abc' as type 'integer' at position 2"),
    ("set-header", "req.fhdr(x,abc)", 1, "fetch method 'req.fhdr' : failed to parse 'abc' as type 'integer' at position 2"),
    ("set-header", "res.hdr(x,abc)", 1, "fetch method 'res.hdr' : failed to parse 'abc' as type 'integer' at position 2"),
    ("set-header", "str(a),digest(nosuchalgo)", 1, "invalid args in converter 'digest' : algorithm must be a valid OpenSSL message digest name"),
    ("set-header", "str(a),sha2(123)", 1, "invalid args in converter 'sha2' : Unsupported number of bits: '123'"),
    ("set-header", "str(a),be2dec(:,x)", 1, "invalid arg 2 in converter 'be2dec' : failed to parse 'x' as type 'integer' at position 2"),
    ("set-header", "rand(x)", 1, "fetch method 'rand' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "payload(x,1)", 1, "fetch method 'payload' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "str(a),url_dec(x)", 1, "invalid arg 1 in converter 'url_dec' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "str(a),concat(a,nosuchscope.v)", 1, "invalid args in converter 'concat' : failed to register variable name 'nosuchscope.v'"),
    ("set-header", "src,bool", 1, "converter 'bool' cannot be applied"),
    ("set-header", "str(a),ipmask(24)", 0, ""),
    ("set-header", "str(a),ltrim()", 0, ""),
    ("set-header", "str(a),lower(x)", 1, "invalid arg 1 in converter 'lower' : expected ')' before 'x)'"),
    ("set-header", "str(a),upper(1)", 1, "invalid arg 1 in converter 'upper' : expected ')' before '1)'"),
    ("set-header", "str(a),base64(x)", 1, "invalid arg 1 in converter 'base64' : expected ')' before 'x)'"),
    ("set-header", "str(a),hex(1)", 1, "invalid arg 1 in converter 'hex' : expected ')' before '1)'"),
    ("set-header", "str(a),length(1)", 1, "invalid arg 1 in converter 'length' : expected ')' before '1)'"),
    ("set-header", "str(a),htonl", 0, ""),
    ("set-header", "date(x)", 1, "fetch method 'date' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "date(0,ms,x)", 1, "fetch method 'date' : expected ')' before ',x)'"),
    ("set-header", "str(a),in_table(nosuchtable)", 1, "unable to find table 'nosuchtable' referenced in arg 1 of conversion keyword 'in_table' for sample fetch keyword 'str'"),
    ("set-header", "str(a),sub(x)", 1, "invalid args in converter 'sub' : expects an integer or a variable name"),
    ("set-header", "str(a),protobuf(x)", 1, "invalid arg 1 in converter 'protobuf' : failed to parse 'x' as type 'Protocol buffers field number' at position 1"),
    ("set-header", "str(a),ungrpc(x)", 1, "invalid arg 1 in converter 'ungrpc' : failed to parse 'x' as type 'Protocol buffers field number' at position 1"),
];

const CONTEXTS: &[Row] = &[
    ("set-var", "src,ipmask(abc)", 1, "invalid arg 1 in converter 'ipmask' : failed to parse 'abc' as type 'IPv4 mask' at position 1"),
    ("acl", "src,ipmask(abc)", 1, "invalid arg 1 in converter 'ipmask' : failed to parse 'abc' as type 'IPv4 mask' at position 1"),
    ("anon-acl", "src,ipmask(abc)", 1, "invalid arg 1 in converter 'ipmask' : failed to parse 'abc' as type 'IPv4 mask' at position 1"),
    ("stick-on", "src,ipmask(abc)", 1, "invalid arg 1 in converter 'ipmask' : failed to parse 'abc' as type 'IPv4 mask' at position 1"),
    ("set-var", "int(x)", 1, "fetch method 'int' : failed to parse 'x' as type 'integer' at position 1"),
    ("acl", "int(x)", 1, "fetch method 'int' : failed to parse 'x' as type 'integer' at position 1"),
    ("anon-acl", "int(x)", 1, "fetch method 'int' : failed to parse 'x' as type 'integer' at position 1"),
    ("stick-on", "int(x)", 1, "fetch method 'int' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-var", "str(a),bytes(x)", 1, "invalid args in converter 'bytes' : expects an integer or a variable name"),
    ("acl", "str(a),bytes(x)", 1, "invalid args in converter 'bytes' : expects an integer or a variable name"),
    ("anon-acl", "str(a),bytes(x)", 1, "invalid args in converter 'bytes' : expects an integer or a variable name"),
    ("stick-on", "str(a),bytes(x)", 1, "invalid args in converter 'bytes' : expects an integer or a variable name"),
    ("set-var", "str(a),regsub(a**,b)", 1, "error in regex 'a**' in arg 1 of conversion keyword 'regsub' for sample fetch keyword 'str'"),
    ("acl", "str(a),regsub(a**,b)", 1, "error in regex 'a**' in arg 1 of conversion keyword 'regsub' for ACL keyword 'str'"),
    ("anon-acl", "str(a),regsub(a**,b)", 1, "error in regex 'a**' in arg 1 of conversion keyword 'regsub' for ACL keyword 'str'"),
    ("stick-on", "str(a),regsub(a**,b)", 1, "error in regex 'a**' in arg 1 of conversion keyword 'regsub' for sample fetch keyword 'str'"),
    ("set-var", "str(a),map(/nonexistent/m)", 1, "invalid args in converter 'map' : failed to open pattern file </nonexistent/m>"),
    ("acl", "str(a),map(/nonexistent/m)", 1, "invalid args in converter 'map' : failed to open pattern file </nonexistent/m>"),
    ("anon-acl", "str(a),map(/nonexistent/m)", 1, "invalid args in converter 'map' : failed to open pattern file </nonexistent/m>"),
    ("stick-on", "str(a),map(/nonexistent/m)", 1, "invalid args in converter 'map' : failed to open pattern file </nonexistent/m>"),
    ("set-var", "str(a),lower(x)", 1, "invalid arg 1 in converter 'lower' : expected ')' before 'x)'"),
    ("acl", "str(a),lower(x)", 1, "invalid arg 1 in converter 'lower' : expected ')' before 'x)'"),
    ("anon-acl", "str(a),lower(x)", 1, "invalid arg 1 in converter 'lower' : expected ')' before 'x)'"),
    ("stick-on", "str(a),lower(x)", 1, "invalid arg 1 in converter 'lower' : expected ')' before 'x)'"),
    ("set-var", "hdr(x,abc)", 1, "fetch method 'hdr' : failed to parse 'abc' as type 'integer' at position 2"),
    ("acl", "hdr(x,abc)", 1, "ACL keyword 'hdr' : failed to parse 'abc' as type 'integer' at position 2"),
    ("anon-acl", "hdr(x,abc)", 1, "ACL keyword 'hdr' : failed to parse 'abc' as type 'integer' at position 2"),
    ("stick-on", "hdr(x,abc)", 1, "fetch method 'hdr' : failed to parse 'abc' as type 'integer' at position 2"),
    ("set-var", "src,bool", 1, "converter 'bool' cannot be applied"),
    ("acl", "src,bool", 1, "converter 'bool' cannot be applied"),
    ("anon-acl", "src,bool", 1, "converter 'bool' cannot be applied"),
    ("stick-on", "src,bool", 1, "converter 'bool' cannot be applied"),
];

const LOG_FORMATS: &[Row] = &[
    ("log-format", "src,ipmask(abc)", 1, "invalid arg 1 in converter 'ipmask' : failed to parse 'abc' as type 'IPv4 mask' at position 1"),
    ("log-format", "str(a),bytes(x)", 1, "invalid args in converter 'bytes' : expects an integer or a variable name"),
    ("log-format", "int(x)", 1, "fetch method 'int' : failed to parse 'x' as type 'integer' at position 1"),
    ("log-format", "src,bool", 1, "converter 'bool' cannot be applied"),
    ("log-format", "str(a),field(x,:)", 1, "invalid arg 1 in converter 'field' : failed to parse 'x' as type 'integer' at position 1"),
    ("log-format", "str(a),lower(x)", 1, "invalid arg 1 in converter 'lower' : expected ')' before 'x)'"),
    ("unique-id-format", "src,ipmask(abc)", 1, "invalid arg 1 in converter 'ipmask' : failed to parse 'abc' as type 'IPv4 mask' at position 1"),
    ("unique-id-format", "str(a),bytes(x)", 1, "invalid args in converter 'bytes' : expects an integer or a variable name"),
    ("unique-id-format", "int(x)", 1, "fetch method 'int' : failed to parse 'x' as type 'integer' at position 1"),
    ("unique-id-format", "src,bool", 1, "converter 'bool' cannot be applied"),
    ("unique-id-format", "str(a),field(x,:)", 1, "invalid arg 1 in converter 'field' : failed to parse 'x' as type 'integer' at position 1"),
    ("unique-id-format", "str(a),lower(x)", 1, "invalid arg 1 in converter 'lower' : expected ')' before 'x)'"),
    ("error-log-format", "src,ipmask(abc)", 1, "invalid arg 1 in converter 'ipmask' : failed to parse 'abc' as type 'IPv4 mask' at position 1"),
    ("error-log-format", "str(a),bytes(x)", 1, "invalid args in converter 'bytes' : expects an integer or a variable name"),
    ("error-log-format", "int(x)", 1, "fetch method 'int' : failed to parse 'x' as type 'integer' at position 1"),
    ("error-log-format", "src,bool", 1, "converter 'bool' cannot be applied"),
    ("error-log-format", "str(a),field(x,:)", 1, "invalid arg 1 in converter 'field' : failed to parse 'x' as type 'integer' at position 1"),
    ("error-log-format", "str(a),lower(x)", 1, "invalid arg 1 in converter 'lower' : expected ')' before 'x)'"),
    ("log-format-sd", "src,ipmask(abc)", 1, "invalid arg 1 in converter 'ipmask' : failed to parse 'abc' as type 'IPv4 mask' at position 1"),
    ("log-format-sd", "str(a),bytes(x)", 1, "invalid args in converter 'bytes' : expects an integer or a variable name"),
    ("log-format-sd", "int(x)", 1, "fetch method 'int' : failed to parse 'x' as type 'integer' at position 1"),
    ("log-format-sd", "src,bool", 1, "converter 'bool' cannot be applied"),
    ("log-format-sd", "str(a),field(x,:)", 1, "invalid arg 1 in converter 'field' : failed to parse 'x' as type 'integer' at position 1"),
    ("log-format-sd", "str(a),lower(x)", 1, "invalid arg 1 in converter 'lower' : expected ')' before 'x)'"),
];

const ACL_CONVERTERS: &[Row] = &[
    ("acl", "src,nosuchconv", 1, "unknown converter 'nosuchconv'"),
    ("anon-acl", "src,nosuchconv", 1, "unknown converter 'nosuchconv'"),
];

const FORMS: &[Row] = &[
    // T343 covercheck: escapes in an argument (a single-quoted word keeps its backslashes),
    // a missing comma, the TLV type and the other `val_args` edges.
    ("set-var", "'str(a\\tb)'", 0, ""),
    ("set-var", "'str(a\\rb)'", 0, ""),
    ("set-var", "'str(a\\nb)'", 0, ""),
    ("set-var", "'str(a\\\\b)'", 0, ""),
    ("set-var", "'str(a\\ b)'", 0, ""),
    ("set-var", "'str(a\\\"b)'", 0, ""),
    ("set-var", "'str(a\\qb)'", 0, ""),
    ("set-var", "'str(a\\'", 1, "fetch method 'str' : failed to parse '\\' after 'a' as type 'string' at position 1"),
    ("set-var", "str(a)x", 1, "missing comma after fetch keyword"),
    ("set-var", "str(a),lower()x", 1, "missing comma after converter 'lower'"),
    ("set-header", "fc_pp_tlv(-1)", 1, "invalid args in fetch method 'fc_pp_tlv' : Invalid TLV Type '-1'"),
    ("set-header", "fc_pp_tlv(+5)", 0, ""),
    ("set-header", "fc_pp_tlv(010)", 0, ""),
    ("set-header", "fc_pp_tlv(0x)", 1, "invalid args in fetch method 'fc_pp_tlv' : Could not convert type '0x'"),
    ("set-header", "fc_pp_tlv(ALPN)", 0, ""),
    ("set-header", "fc_pp_tlv(256)", 1, "invalid args in fetch method 'fc_pp_tlv' : Invalid TLV Type '256'"),
    ("set-header", "fc_pp_tlv(09)", 1, "invalid args in fetch method 'fc_pp_tlv' : Could not convert type '09'"),
    ("set-header", "bin(4z)", 1, "invalid args in fetch method 'bin' : an hex digit is expected (found 'z')"),
    ("set-header", "meth(G@T)", 1, "invalid args in fetch method 'meth' : expects valid method"),
    ("set-header", "query(with_qm)", 0, ""),
    ("set-header", "query(x)", 1, "invalid args in fetch method 'query' : supported options are: 'with_qm'"),
    ("set-header", "query()", 0, ""),
    ("set-header", "ssl_f_s_dn(CN,1,xx)", 1, "invalid args in fetch method 'ssl_f_s_dn' : only rfc2253 or a blank value are currently supported as the format argument."),
    ("set-header", "ssl_f_s_dn(CN,1,rfc2253)", 0, ""),
    // T430 row 22: an empty middle argument is refused, an explicit 0 is not.
    ("set-header", "ssl_f_s_dn(,,rfc2253)", 1, "fetch method 'ssl_f_s_dn' : expected ')' before ',rfc2253)'"),
    ("set-header", "ssl_f_s_dn(CN,,rfc2253)", 1, "fetch method 'ssl_f_s_dn' : expected ')' before ',rfc2253)'"),
    ("set-header", "ssl_f_s_dn(,0,rfc2253)", 0, ""),
    ("set-header", "str(a),add_item(;,,)", 1, "invalid args in converter 'add_item' : one of the optional arguments has to be nonempty"),
    ("set-header", "str(a),be2hex(:,1,2)", 1, "invalid args in converter 'be2hex' : Unsupported truncate value (2)"),
    ("set-header", "str(a),when(acl)", 1, "invalid args in converter 'when' : 'acl' selector requires an extra argument with the ACL name"),
    ("acl", "hdr(x),ipmask(abc)", 1, "ACL keyword 'hdr' : invalid arg 1 in converter 'ipmask' : failed to parse 'abc' as type 'IPv4 mask' at position 1"),
    ("acl", "hdr(x)x", 1, "ACL keyword 'hdr' : missing comma after fetch keyword"),
    // T351: fc_rtt is refused by Ibex (no TCP_INFO); fetch_edge_cases covers it.     ("set-header", "fc_rtt()", 1, "invalid args in fetch method 'fc_rtt' : expects 'us' or 'ms', got ''"),
    // T351: fc_rtt is refused by Ibex (no TCP_INFO); fetch_edge_cases covers it.     ("set-header", "fc_rtt", 0, ""),
    ("set-header-uq", "int( 1)", 1, "fetch method 'int' : expected type 'integer' at position 1, but got nothing"),
    ("set-header-uq", "src,ipmask( 24)", 1, "invalid arg 1 in converter 'ipmask' : expected type 'IPv4 mask' at position 1, but got nothing"),
    ("set-header-uq", "str( a b )", 1, "fetch method 'str' : expected ')'"),
    ("set-header-uq", "int(1)", 0, ""),
    ("set-var", "str(a),regsub((,b)", 1, "error in regex '(' in arg 1 of conversion keyword 'regsub' for sample fetch keyword 'str'"),
    ("set-var", "str(a),regsub(a**,b)", 1, "error in regex 'a**' in arg 1 of conversion keyword 'regsub' for sample fetch keyword 'str'"),
    ("stick-on", "str(a),regsub([a,b)", 1, "error in regex '[a' in arg 1 of conversion keyword 'regsub' for sample fetch keyword 'str'"),
    ("set-header", "str(a),map(virt@x)", 0, ""),
    ("set-header", "str(a),map(opt@/nonexistent/m)", 0, ""),
    ("set-header", "str(a),map(/tmp)", 1, "invalid args in converter 'map' : error encountered while reading  </tmp> : Is a directory"),
    ("set-header", "src,ipmask(24)", 0, ""),
    ("set-header", "src,ipmask(255.255.255.0)", 0, ""),
    ("set-header", "src,ipmask(24,64)", 0, ""),
    ("set-header", "src,ipmask(255.255.255.255)", 0, ""),
    ("set-header", "src,ipmask(0)", 0, ""),
    ("set-header", "src,ipmask(33)", 1, "invalid arg 1 in converter 'ipmask' : failed to parse '33' as type 'IPv4 mask' at position 1"),
    ("set-header", "src,ipmask(1.2.3.4)", 0, ""),
    ("set-header", "src,ipmask(24,ffff:ffff::)", 0, ""),
    ("set-header", "src,ipmask(24,129)", 1, "invalid arg 2 in converter 'ipmask' : failed to parse '129' as type 'IPv6 mask' at position 2"),
    ("set-header", "src,ipmask(-1)", 1, "invalid arg 1 in converter 'ipmask' : failed to parse '-1' as type 'IPv4 mask' at position 1"),
    ("set-header", "str(a),bytes(1)", 0, ""),
    ("set-header", "str(a),bytes(1,2)", 0, ""),
    ("set-header", "str(a),bytes(0)", 0, ""),
    ("set-header", "str(a),bytes(-1)", 1, "invalid args in converter 'bytes' : expects a non-negative integer"),
    ("set-header", "str(a),bytes(1,0)", 1, "invalid args in converter 'bytes' : expects a positive integer"),
    ("set-header", "str(a),bytes(txn.x)", 0, ""),
    ("set-header", "str(a),bytes(1,txn.y)", 0, ""),
    ("set-header", "str(a:b),field(1,:)", 0, ""),
    ("set-header", "str(a:b),field(-1,:,2)", 0, ""),
    ("set-header", "str(a:b),field(0,:)", 1, "invalid args in converter 'field' : Unexpected value 0 for index"),
    ("set-header", "str(a:b),field(1,)", 1, "invalid args in converter 'field' : Empty separators list"),
    ("set-header", "str(a:b),word(1,:)", 0, ""),
    ("set-header", "str(a:b),word(1,:,x)", 1, "invalid arg 3 in converter 'word' : failed to parse 'x' as type 'integer' at position 3"),
    ("set-header", "int(-5)", 0, ""),
    ("set-header", "int(+5)", 0, ""),
    ("set-header", "int(0x10)", 1, "fetch method 'int' : failed to parse '0x10' as type 'integer' at position 1"),
    ("set-header", "int(99999999999999999999)", 0, ""),
    ("set-header", "int()", 1, "fetch method 'int' : expected type 'integer' at position 1, but got nothing"),
    ("set-header", "int", 1, "fetch method 'int' : expected type 'integer' at position 1, but got nothing"),
    ("set-header", "int(1),and(-)", 0, ""),
    ("set-header", "int(1),and(+)", 0, ""),
    ("set-header", "int(1),add(txn.x)", 0, ""),
    ("set-header", "int(1),add(-3)", 0, ""),
    ("set-header", "int(1),add(0x10)", 1, "invalid args in converter 'add' : expects an integer or a variable name"),
    ("set-header", "int(1),add( 1)", 1, "invalid args in converter 'add' : expects an integer or a variable name"),
    ("set-header", "int(1),add(1 )", 1, "invalid args in converter 'add' : expects an integer or a variable name"),
    ("set-header", "int(1),add()", 0, ""),
    ("set-header", "int(1),add", 0, ""),
    ("set-header", "int(1),add(proc.x)", 0, ""),
    ("set-header", "int(1),add(var(txn.x))", 1, "invalid args in converter 'add' : expects an integer or a variable name"),
    ("set-header", "date(0,ms)", 0, ""),
    ("set-header", "date(-1,s)", 0, ""),
    ("set-header", "date(0,us)", 0, ""),
    ("set-header", "date(0,ns)", 1, "invalid args in fetch method 'date' : expects 's', 'ms' or 'us', got 'ns'"),
    ("set-header", "date(0,xs)", 1, "invalid args in fetch method 'date' : expects 's', 'ms' or 'us', got 'xs'"),
    ("set-header", "date(,ms)", 1, "fetch method 'date' : expected ')' before ',ms)'"),
    ("set-header", "date()", 0, ""),
    ("set-header", "date", 0, ""),
    ("set-header", "str(a),regsub(a,b,g)", 0, ""),
    ("set-header", "str(a),regsub(a,b,i)", 0, ""),
    ("set-header", "str(a),regsub(a,b,x)", 1, "invalid args in converter 'regsub' : invalid regex flag 'x', only 'i' and 'g' are supported"),
    ("set-header", "str(a),regsub(\\\"a b\\\",c)", 0, ""),
    ("set-header", "str(a),regsub(a,)", 0, ""),
    ("set-header", "str(a),json(utf8)", 0, ""),
    ("set-header", "str(a),json()", 0, ""),
    ("set-header", "str(a),json(ascii)", 0, ""),
    ("set-header", "str(a),json(utf8ps)", 0, ""),
    ("set-header", "int(1),utime(%Y)", 0, ""),
    ("set-header", "int(1),ltime(%Y,3600)", 0, ""),
    ("set-header", "int(1),utime(%Y,-1)", 0, ""),
    ("set-header", "hdr(x,-1)", 0, ""),
    ("set-header", "hdr(x,1)", 0, ""),
    ("set-header", "hdr(x,-10)", 0, ""),
    ("set-header", "hdr(x,-11)", 1, "invalid args in fetch method 'hdr' : header occurrence must be >= -10"),
    ("set-header", "hdr(x,0)", 0, ""),
    ("set-header", "hdr(x,)", 0, ""),
    ("set-header", "hdr(,1)", 0, ""),
    ("set-header", "hdr()", 0, ""),
    ("set-header", "str(a),digest(sha256)", 0, ""),
    ("set-header", "str(a),digest(SHA256)", 0, ""),
    ("set-header", "str(a),digest(md5)", 0, ""),
    ("set-header", "str(a),sha2(256)", 0, ""),
    ("set-header", "str(a),sha2", 0, ""),
    ("set-header", "str(a),sha2(224)", 0, ""),
    ("set-header", "str(a),sha2()", 0, ""),
    ("set-header", "str(a),be2dec(:,2)", 0, ""),
    ("set-header", "str(a),be2dec(:,9)", 1, "invalid args in converter 'be2dec' : chunk_size out of [1..8] range (9)"),
    ("set-header", "str(a),be2dec(:,0)", 1, "invalid args in converter 'be2dec' : chunk_size out of [1..8] range (0)"),
    ("set-header", "str(a),be2dec(:,2,1)", 0, ""),
    ("set-header", "str(a),be2dec(:,2,2)", 1, "invalid args in converter 'be2dec' : Unsupported truncate value (2)"),
    ("set-header", "str(a),be2hex", 0, ""),
    ("set-header", "str(a),be2hex(:,0)", 1, "invalid args in converter 'be2hex' : chunk_size needs to be positive (0)"),
    ("set-header", "str(a),be2hex(,0,1)", 1, "invalid args in converter 'be2hex' : chunk_size needs to be positive (0)"),
    ("set-header", "rand(10)", 0, ""),
    ("set-header", "rand", 0, ""),
    ("set-header", "rand(-1)", 0, ""),
    ("set-header", "payload(0,1)", 0, ""),
    ("set-header", "payload(0,)", 1, "fetch method 'payload' : expected type 'integer' at position 2, but got nothing"),
    ("set-header", "payload(,1)", 1, "fetch method 'payload' : expected type 'integer' at position 1, but got nothing"),
    ("set-header", "payload_lv(0,1)", 0, ""),
    ("set-header", "payload_lv(0,1,x)", 1, "invalid args in fetch method 'payload_lv' : payload offset2 is not a number"),
    ("set-header", "str(a),url_dec(1)", 0, ""),
    ("set-header", "str(a),url_dec", 0, ""),
    ("set-header", "str(a),concat(a,txn.v)", 0, ""),
    ("set-header", "str(a),concat(a,,b)", 0, ""),
    ("set-header", "str(a),concat", 0, ""),
    ("set-header", "str(a),concat(,txn.v,)", 0, ""),
    ("set-header", "str(a),concat(a,b,c)", 1, "invalid args in converter 'concat' : failed to register variable name 'b'"),
    ("set-header", "str(a),lower()", 0, ""),
    ("set-header", "str(a),lower", 0, ""),
    ("set-header", "str(a),crc32(1)", 0, ""),
    ("set-header", "str(a),djb2", 0, ""),
    ("set-header", "str(a),xxh32(-1)", 0, ""),
    ("set-header", "str(a),protobuf(1.2,int32)", 0, ""),
    ("set-header", "str(a),protobuf(1.2,nosuchtype)", 1, "invalid args in converter 'protobuf' : Wrong protocol buffer type 'nosuchtype'"),
    ("set-header", "str(a),base64", 0, ""),
    ("set-header", "str(a),hex", 0, ""),
    ("set-header", "str(a),length", 0, ""),
    ("set-header", "str(a),ltrim(x)", 0, ""),
    ("set-header", "str(a),ltrim", 0, ""),
    ("set-header", "str(a),htonl", 0, ""),
    ("set-header", "int(1),htonl", 0, ""),
    ("set-header", "src,bool", 1, "converter 'bool' cannot be applied"),
    ("set-header", "int(1),bool", 0, ""),
    ("set-header", "str(a),bool", 0, ""),
    ("set-header", "src,hex", 0, ""),
    ("set-header", "src,lower", 0, ""),
    ("set-header", "src,ipmask(24),lower", 0, ""),
    ("set-header", "src,ipmask(24),bool", 1, "converter 'bool' cannot be applied"),
    ("set-header", "ipv4(1.2.3.4)", 0, ""),
    ("set-header", "ipv4(1.2.3)", 1, "fetch method 'ipv4' : failed to parse '1.2.3' as type 'IPv4 address' at position 1"),
    ("set-header", "ipv6(::1)", 0, ""),
    ("set-header", "ipv6(x)", 1, "fetch method 'ipv6' : failed to parse 'x' as type 'IPv6 address' at position 1"),
    ("set-header", "ipv4(1.2.3.4),ipmask(8)", 0, ""),
    ("set-header", "ipv6(::1),ipmask(8)", 0, ""),
    ("set-header", "ipv6(::1),ipmask(8,64)", 0, ""),
    ("set-header", "str(1.2.3.4),ipmask(8)", 0, ""),
    ("set-header", "int(1),ipmask(8)", 0, ""),
    ("set-header", "bin(41)", 0, ""),
    ("set-header", "bin(4)", 1, "invalid args in fetch method 'bin' : an even number of hex digit is expected"),
    ("set-header", "bin(zz)", 1, "invalid args in fetch method 'bin' : an hex digit is expected (found 'z')"),
    ("set-header", "bool(1)", 0, ""),
    ("set-header", "bool(true)", 0, ""),
    ("set-header", "bool(x)", 1, "invalid args in fetch method 'bool' : Expects 'true', 'false', '0' or '1'"),
    ("set-header", "meth(GET)", 0, ""),
    ("set-header", "meth(1)", 0, ""),
    ("set-header", "str()", 0, ""),
    ("set-header", "str", 0, ""),
    ("set-header", "str(a,b)", 1, "fetch method 'str' : expected ')' before ',b)'"),
    ("set-header", "uuid", 0, ""),
    ("set-header", "uuid(4)", 0, ""),
    ("set-header", "uuid(7)", 0, ""),
    ("set-header", "uuid(3)", 1, "invalid args in fetch method 'uuid' : Unsupported UUID version: '3'"),
    ("set-header", "env(HOME)", 0, ""),
    ("set-header", "env", 0, ""),
    ("set-header", "var(txn.x)", 0, ""),
    ("set-header", "var(nosuch.x)", 1, "invalid args in fetch method 'var' : (null)"),
    ("set-header", "var(txn.)", 1, "invalid args in fetch method 'var' : (null)"),
    ("set-header", "var()", 1, "invalid args in fetch method 'var' : Empty variable name cannot be accepted"),
    ("set-header", "url_param(a)", 0, ""),
    ("set-header", "url_param", 0, ""),
    ("set-header", "url_param(a,;)", 0, ""),
    ("set-header", "url_param(a,;,i)", 0, ""),
    ("set-header", "url_param(a,;,x)", 0, ""),
    ("set-header", "cook(a)", 0, ""),
    ("set-header", "cook", 0, ""),
    ("set-header", "req.cook(a,b)", 1, "fetch method 'req.cook' : expected ')' before ',b)'"),
    ("set-header", "req.hdr(x,1)", 0, ""),
    ("set-header", "req.hdr(x,-11)", 1, "invalid args in fetch method 'req.hdr' : header occurrence must be >= -10"),
    ("set-header", "res.hdr(x)", 1, "sample fetch <res.hdr> may not be reliably used here because it needs 'HTTP response headers' which is not available here"),
    ("set-header", "hdr_cnt(x)", 0, ""),
    ("set-header", "hdr_cnt(x,1)", 1, "fetch method 'hdr_cnt' : expected ')' before ',1)'"),
    ("set-header", "fhdr(x,2)", 1, "unknown fetch method 'fhdr'"),
    ("set-header", "req.fhdr_cnt(x)", 0, ""),
    ("set-header", "str(a),field(1,:)", 0, ""),
    ("set-header", "str(a),word(0,:)", 1, "invalid args in converter 'word' : Unexpected value 0 for index"),
    ("set-header", "str(a),word(1,)", 1, "invalid args in converter 'word' : Empty separators list"),
    ("set-header", "str(a),mod(0)", 0, ""),
    ("set-header", "str(a),div(0)", 0, ""),
    ("set-header", "int(1),neg", 0, ""),
    ("set-header", "int(1),neg(1)", 1, "invalid arg 1 in converter 'neg' : expected ')' before '1)'"),
    ("set-header", "int(1),not", 0, ""),
    ("set-header", "int(1),odd", 0, ""),
    ("set-header", "int(1),even(1)", 1, "invalid arg 1 in converter 'even' : expected ')' before '1)'"),
    ("set-header", "str(a),map(/nonexistent/m,def)", 1, "invalid args in converter 'map' : failed to open pattern file </nonexistent/m>"),
    ("set-header", "str(a),map_str(/nonexistent/m)", 1, "invalid args in converter 'map_str' : failed to open pattern file </nonexistent/m>"),
    ("set-header", "str(a),map_beg_ip(/dev/null)", 0, ""),
    ("set-header", "str(a),map(/dev/null)", 0, ""),
    ("set-header", "str(a),map(/dev/null,x,y)", 1, "invalid arg 2 in converter 'map' : expected ')' before ',y)'"),
    ("set-header", "str(a),url_enc(query)", 0, ""),
    ("set-header", "str(a),url_enc(x)", 1, "invalid args in converter 'url_enc' : Unexpected encode type. Allowed value is 'query'"),
    ("set-header", "str(a),strcmp(txn.x)", 0, ""),
    ("set-header", "str(a),secure_memcmp(txn.x)", 0, ""),
    ("set-header", "str(a),hmac(sha256,dGVzdA==)", 0, ""),
    ("set-header", "str(a),aes_gcm_dec(128,txn.n,txn.k,txn.t)", 0, ""),
    ("set-header", "str(a),aes_gcm_dec(x,txn.n,txn.k,txn.t)", 1, "invalid arg 1 in converter 'aes_gcm_dec' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "str(a),set-var(txn.x)", 0, ""),
    ("set-header", "str(a),unset-var(txn.x)", 0, ""),
    ("set-header", "str(a),set-var(x)", 1, "invalid args in converter 'set-var' : (null)"),
    ("set-header", "str(a),debug", 0, ""),
    ("set-header", "str(a),debug(x)", 0, ""),
    ("set-header", "str(a),when(normal)", 0, ""),
    ("set-header", "str(a),when(x)", 1, "invalid args in converter 'when' : expects a supported keyword among {stopping,normal,error,forwarded,toapplet,processed,acl} but got 'x'"),
    ("set-header", "str(a),add_item(;)", 1, "invalid arg 2 in converter 'add_item' : missing arguments (got 1/2), type 'string' expected"),
    ("set-header", "str(a),add_item(;,txn.x)", 0, ""),
    ("set-header", "str(a),add_item(;,x)", 1, "invalid args in converter 'add_item' : failed to register variable name 'x'"),
    ("set-header", "str(a),add_item(;,txn.x,y)", 0, ""),
    ("set-header", "str(a),add_item(;,,y)", 0, ""),
    ("set-header", "str(a),add_item", 1, "invalid arg 2 in converter 'add_item' : missing arguments (got 1/2), type 'string' expected"),
    ("set-header", "str(a),fix_is_valid", 0, ""),
    ("set-header", "str(a),fix_tag_value(35)", 0, ""),
    ("set-header", "str(a),fix_tag_value(MsgType)", 0, ""),
    ("set-header", "str(a),fix_tag_value(x)", 1, "invalid args in converter 'fix_tag_value' : Unknown FIX tag name 'x'"),
    ("set-header", "str(a),mqtt_field_value(connect,1)", 0, ""),
    ("set-header", "str(a),be2dec(,1)", 0, ""),
    ("set-header", "str(a),bytes(,1)", 0, ""),
    ("set-header", "str(a),in_table(t)", 0, ""),
    ("set-header", "src,table_trackers(t)", 0, ""),
    ("set-header", "table_cnt(t)", 0, ""),
    ("set-header", "nbsrv(b)", 0, ""),
    ("set-header", "srv_conn(b/s)", 0, ""),
    ("set-header", "be_conn_free(b)", 0, ""),
    ("set-header", "sc_get_gpc(0,0,t)", 0, ""),
    ("set-header", "src_conn_cnt(t)", 0, ""),
    ("set-header", "str(a),http_date", 0, ""),
    ("set-header", "str(a),http_date(1)", 0, ""),
    ("set-header", "str(a),http_date(0,ms)", 0, ""),
    ("set-header", "str(a),http_date(0,x)", 1, "invalid args in converter 'http_date' : expects 's', 'ms' or 'us', got 'x'"),
    ("set-header", "str(a),http_date(x)", 1, "invalid arg 1 in converter 'http_date' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "accept_date(ms)", 0, ""),
    ("set-header", "accept_date(x)", 1, "invalid args in fetch method 'accept_date' : expects 's', 'ms' or 'us', got 'x'"),
    ("set-header", "accept_date()", 1, "invalid args in fetch method 'accept_date' : expects 's', 'ms' or 'us', got ''"),
    ("set-header", "request_date(s)", 0, ""),
    ("set-header", "str(a),param(x)", 0, ""),
    ("set-header", "str(a),param(x,;)", 0, ""),
    ("set-header", "str(a),param()", 0, ""),
    ("set-header", "str(a),jwt_verify(HS256,txn.k)", 0, ""),
    ("set-header", "str(a),be_sort", 1, "invalid arg 1 in converter 'be_sort' : expected type 'integer' at position 1, but got nothing"),
    ("set-header", "str(a),hex2i", 0, ""),
    ("set-header", "str(a),ub64dec", 0, ""),
    ("set-header", "str(a),cut_crlf", 0, ""),
    ("set-header", "fc_pp_tlv(0x30)", 0, ""),
    ("set-header", "fc_pp_tlv(x)", 1, "invalid args in fetch method 'fc_pp_tlv' : Could not convert type 'x'"),
    ("set-header", "fc_pp_tlv(0x30),bool", 0, ""),
    ("set-header", "fc_pp_tlv(0x30),add", 0, ""),
    ("set-header", "str(a),sdbm(x)", 1, "invalid arg 1 in converter 'sdbm' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "str(a),wt6(1)", 0, ""),
    ("set-header", "str(a),xxh64(1)", 0, ""),
    ("set-header", "str(a),xxh3(1)", 0, ""),
    ("set-header", "str(a),crc32c(x)", 1, "invalid arg 1 in converter 'crc32c' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "capture.req.hdr(0)", 0, ""),
    ("set-header", "capture.req.hdr(x)", 1, "fetch method 'capture.req.hdr' : failed to parse 'x' as type 'integer' at position 1"),
    ("set-header", "req.body_param(a)", 0, ""),
    ("set-header", "req.body_param(a,i)", 0, ""),
    ("set-header", "url_param(,,)", 0, ""),
    ("set-header", "req.ssl_sni,lower", 0, ""),
    ("set-header", "req.payload(0,1),hex", 0, ""),
    ("set-header", "req.payload_lv(0,1,2)", 0, ""),
    // T351:     ("set-header", "fc_rtt(ms)", 0, ""),
    // T351:     ("set-header", "fc_rtt(x)", 1, "invalid args in fetch method 'fc_rtt' : expects 'us' or 'ms', got 'x'"),
    // T351:     ("set-header", "fc_rtt(us)", 0, ""),
    // T351:     ("set-header", "bc_rtt(ms)", 0, ""),
    ("set-header", "srv_id", 1, "sample fetch <srv_id> may not be reliably used here because it needs 'server' which is not available here"),
    ("set-header", "src_port,ipmask(8)", 0, ""),
    ("set-header", "dst_port,bool", 0, ""),
    ("set-header", "str(a),ipmask(24)", 0, ""),
    ("set-header", "str(a),regsub(a**,b)", 1, "error in regex 'a**' in arg 1 of conversion keyword 'regsub' for sample fetch keyword 'str'"),
    ("set-header", "str(a),regsub(\\\\x,b)", 1, "error in regex '\\x' in arg 1 of conversion keyword 'regsub' for sample fetch keyword 'str'"),
    ("set-header", "str(a),regsub([a,b)", 1, "error in regex '[a' in arg 1 of conversion keyword 'regsub' for sample fetch keyword 'str'"),
    ("set-header", "str(a),regsub(a{2,b)", 0, ""),
    ("set-header", "str(a),regsub(a(?=b),c)", 1, "invalid arg 2 in converter 'regsub' : missing arguments (got 1/2), type 'string' expected"),
    ("acl", "src,ipmask(255.255.255.O)", 1, "invalid arg 1 in converter 'ipmask' : failed to parse '255.255.255.O' as type 'IPv4 mask' at position 1"),
    ("acl", "src,ipmask(24)", 0, ""),
    ("acl", "int(1),and(-)", 0, ""),
    ("acl", "hdr(x,-11)", 1, "in argument to 'hdr', header occurrence must be >= -10"),
    ("acl", "str(a),bytes(x)", 1, "invalid args in converter 'bytes' : expects an integer or a variable name"),
    ("acl", "src,bool", 1, "converter 'bool' cannot be applied"),
    ("acl", "int(1),bool", 0, ""),
    ("acl", "req.hdr(x,abc)", 1, "fetch method 'req.hdr' : failed to parse 'abc' as type 'integer' at position 2"),
    ("acl", "hdr(x,abc)", 1, "ACL keyword 'hdr' : failed to parse 'abc' as type 'integer' at position 2"),
    ("acl", "fhdr(x,abc)", 1, "unknown fetch method 'fhdr'"),
    ("acl", "src,ipmask(24),lower", 0, ""),
];
