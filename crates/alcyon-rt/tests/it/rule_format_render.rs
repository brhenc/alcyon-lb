// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T455: what a rule's format prints for the aliases that read the stream (`%ST`, `%Tr`, `%ts`,
//! `%hr`, `%r`, ...), now that rule formats are compiled by the `log-format` compiler. Every
//! expected value was measured on `HAProxy` 3.5-dev8-885761-29 on 2026-10-25 with the same
//! configuration (`/tmp/t455/r.cfg`) and the request `GET /r` with the header `x: hello`.

use crate::common;

use alcyon_config::parse_str;
use alcyon_rt::Engine;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const DEFAULTS: &str = "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n";
const GET: &str = "GET /r HTTP/1.1\r\nHost: x\r\nx: hello\r\nConnection: close\r\n\r\n";

fn exchange(template: &str, request: &str) -> String {
    let addr = common::reserve_addr();
    let srv = common::reserve_addr();
    let cfg = parse_str(&template.replace("ADDR", &addr.to_string()).replace("SRV", &srv.to_string())).expect("parse");
    let mut engine = Engine::new(&cfg, 64).expect("engine");
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_nonblocking(true).unwrap();
    c.write_all(request.as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(3) {
        let _ = engine.run_once().expect("step");
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn body(r: &str) -> &str {
    r.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

fn header<'a>(r: &'a str, name: &str) -> Option<&'a str> {
    r.split("\r\n\r\n").next()?.lines().find_map(|l| l.split_once(": ").filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v))
}

/// Row 2 and 5: the timers of a stream with no response, the status the reply sets, the
/// termination state a `return` has just set, the request line and the captures.
#[test]
fn a_return_body_prints_what_the_stream_has_measured() {
    let r = exchange(
        &format!(
            "{DEFAULTS}frontend fe\n  bind ADDR\n  capture request header x len 10\n  http-request return status 200 content-type text/plain lf-string \"TR=%TR Tw=%Tw Tc=%Tc Tr=%Tr Tq=%Tq Td=%Td|ST=%ST B=%B U=%U ts=%ts tsc=%tsc sq=%sq bq=%bq|CC=%CC CS=%CS hr=%hr hs=%hs hrl=%hrl|r=%r {{+Q}}r=%{{+Q}}r HM=%HM HP=%HP HPO=%HPO HQ=%HQ HU=%HU HV=%HV|ft=%ft f=%f b=%b s=%s\"\n"
        ),
        GET,
    );
    assert_eq!(
        body(&r),
        "TR=-1 Tw=-1 Tc=-1 Tr=-1 Tq=-1 Td=-1|ST=200 B=0 U=0 ts=LR tsc=LR-- sq=0 bq=0|CC= CS= hr={hello} hs= hrl=hello|r=GET /r HTTP/1.1 {+Q}r=\"GET /r HTTP/1.1\" HM=GET HP=/r HPO=/r HQ= HU=/r HV=HTTP/1.1|ft=fe f=fe b=fe s=<NOSRV>",
        "{r}"
    );
}

/// Rows 2 and 6: `%Tr` is -1 and `%ST` the denied status in an `http-after-response` header, and
/// the header name keeps the case the rule gave it.
#[test]
fn an_after_response_header_prints_the_status_of_the_reply() {
    let r = exchange(&format!("{DEFAULTS}frontend fe\n  bind ADDR\n  http-after-response set-header X-B \"b=%b s=%s ST=%ST Tr=%Tr\"\n  http-after-response add-header X-C \"c=%ST\"\n  http-request deny\n"), GET);
    assert_eq!(header(&r, "x-b"), Some("b=fe s=<NOSRV> ST=403 Tr=-1"), "{r}");
    assert_eq!(header(&r, "x-c"), Some("c=403"), "{r}");
    // Row 6: HAProxy sends the names in lower case.
    assert!(r.contains("\r\nx-b: ") && r.contains("\r\nx-c: ") && !r.contains("X-B") && !r.contains("X-C"), "{r}");
}

/// Row 2: once a server has answered, `%Tr` is the real time (0 or more, not -1) and the
/// request-side timers are set too.
#[test]
fn a_response_header_prints_the_timers_of_the_answer() {
    let r = exchange(
        &format!(
            "{DEFAULTS}listen be\n  bind SRV\n  http-request return status 200 content-type text/plain string ok\nlisten fwd\n  bind ADDR\n  http-response set-header x-r \"Tr=%Tr TR=%TR Tw=%Tw Tc=%Tc ST=%ST\"\n  server s1 SRV\n"
        ),
        GET,
    );
    let v = header(&r, "x-r").unwrap_or_default();
    let num = |key: &str| v.split(' ').find_map(|w| w.strip_prefix(key)).and_then(|n| n.parse::<i64>().ok());
    assert!(num("Tr=").is_some_and(|n| n >= 0), "{r}");
    assert!(num("Tc=").is_some_and(|n| n >= 0), "{r}");
    assert_eq!((num("TR="), num("Tw="), num("ST=")), (Some(0), Some(0), Some(200)), "{r}");
}

/// The replacement of a `replace-header`, `replace-value` and `replace-path` is a format
/// (`%[...]`, `%ci`), rendered before the groups are substituted; measured on 3.5-dev8 with the
/// same configuration: `abc-zz-q b-zz /pq`.
#[test]
fn a_replacement_is_a_format() {
    let r = exchange(
        &format!(
            "{DEFAULTS}frontend fe\n  bind ADDR\n  http-request set-header x-in abc\n  http-request set-header x-v a,b\n  http-request replace-header x-in ^(.*)$ \"\\1-%[str(zz)]-%[str(q)]\"\n  http-request replace-value x-v ^(.)$ \"\\1-%[str(zz)]\"\n  http-request replace-path ^(.*)$ \"/p%[str(q)]\"\n  http-request return status 200 content-type text/plain lf-string \"%[req.hdr(x-in)] %[req.hdr(x-v)] %[path]\"\n"
        ),
        GET,
    );
    assert_eq!(body(&r), "abc-zz-q b-zz /pq", "{r}");
}

/// The same for the response rules: `http-after-response replace-header`.
#[test]
fn a_response_replacement_is_a_format() {
    let r = exchange(
        &format!(
            "{DEFAULTS}frontend fe\n  bind ADDR\n  http-after-response set-header x-b abc\n  http-after-response replace-header x-b ^(.*)$ \"\\1-%[str(zz)]\"\n  http-request deny\n"
        ),
        GET,
    );
    assert_eq!(header(&r, "x-b"), Some("abc-zz"), "{r}");
}

/// Request rules that render the stream's measures (`set-var-fmt`, `set-header`, `add-header`):
/// before the request is counted, `%ST` and `%Tq` are -1, `%U` is 0 and `%ts` is `--`. Measured
/// on 3.5-dev8-885761-29 on 2026-10-25 with the same configuration:
/// `v=ST=-1 U=0 ts=-- Tq=-1 r=GET /r HTTP/1.1|s=ft=fe ST=-1|a=U=0`.
#[test]
fn request_rules_print_the_stream_before_it_is_counted() {
    let r = exchange(
        &format!(
            "{DEFAULTS}frontend fe\n  bind ADDR\n  http-request set-var-fmt(txn.t) \"ST=%ST U=%U ts=%ts Tq=%Tq r=%r\"\n  http-request set-header x-s \"ft=%ft ST=%ST\"\n  http-request add-header x-a \"U=%U\"\n  http-request return status 200 content-type text/plain lf-string \"v=%[var(txn.t)]|s=%[req.hdr(x-s)]|a=%[req.hdr(x-a)]\"\n"
        ),
        GET,
    );
    assert_eq!(body(&r), "v=ST=-1 U=0 ts=-- Tq=-1 r=GET /r HTTP/1.1|s=ft=fe ST=-1|a=U=0", "{r}");
}

/// A replacement with an alias, `%ft` (measured on 3.5-dev8 on 2026-10-25: `abc-fe`). The
/// same rule with `%{+Q}[...]` or a `%{+json}o` format differs from `HAProxy` (T471).
#[test]
fn a_replacement_with_an_alias_prints_it() {
    let r = exchange(
        &format!(
            "{DEFAULTS}frontend fe\n  bind ADDR\n  http-request set-header x-in abc\n  http-request replace-header x-in ^(.*)$ \"\\1-%ft\"\n  http-request return status 200 content-type text/plain lf-string \"%[req.hdr(x-in)]\"\n"
        ),
        GET,
    );
    assert_eq!(body(&r), "abc-fe", "{r}");
}

/// `set-timeout` from a string sample (T455 compiles its expression at load): measured on
/// 3.5-dev8 on 2026-10-25, `int(7000)` gives a server timeout of 7000 and `str(9000)` a client
/// timeout of 9000. (`str(7s)` gives 7 on
/// `HAProxy`, which casts the string to an integer, and 7000 on Alcyon: T472.)
#[test]
fn set_timeout_takes_a_string_sample() {
    let r = exchange(
        &format!(
            "{DEFAULTS}listen fe\n  bind ADDR\n  http-request set-timeout server int(7000)\n  http-request set-timeout client str(9000)\n  http-request return status 200 content-type text/plain lf-string \"s=%[cur_server_timeout] c=%[cur_client_timeout]\"\n  server s SRV\n"
        ),
        GET,
    );
    assert_eq!(body(&r), "s=7000 c=9000", "{r}");
}

/// `set-timeout` casts a string sample to an integer of milliseconds (no units), the way the
/// oracle does (3.5-dev8-885761-29): `str(7s)` is 7, `str(1500ms)` 1500, `str(12abc)` 12,
/// `str(abc)` and `str(0)` 0, and a negative value wraps to u32.
#[test]
fn set_timeout_casts_a_string_sample_to_an_integer() {
    for (sample, want) in [
        ("str(7s)", "s=7 c=7"),
        ("str(1500ms)", "s=1500 c=1500"),
        ("str(12abc)", "s=12 c=12"),
        ("str(+8)", "s=8 c=8"),
        ("str(abc)", "s=0 c=0"),
        ("str(0)", "s=0 c=0"),
        ("str(-5)", "s=4294967291 c=4294967291"),
        ("int(-5)", "s=4294967291 c=4294967291"),
        ("int(5000000000)", "s=705032704 c=705032704"),
    ] {
        let r = exchange(
            &format!(
                "{DEFAULTS}listen fe\n  bind ADDR\n  timeout client 3s\n  timeout server 4s\n  http-request set-timeout server {sample}\n  http-request set-timeout client {sample}\n  http-request return status 200 content-type text/plain lf-string \"s=%[cur_server_timeout] c=%[cur_client_timeout]\"\n  server s SRV\n"
            ),
            GET,
        );
        assert_eq!(body(&r), want, "{sample}: {r}");
    }
}
