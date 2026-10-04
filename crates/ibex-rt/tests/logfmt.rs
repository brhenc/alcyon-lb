// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Log-format compiling and rendering, against lines the reference `HAProxy`
//! (3.5-dev8-885761-29) wrote for the same formats, measured 2026-10-03: a frontend
//! with these formats, captures and a server, three requests with curl, and a UDP
//! collector. Each test feeds the renderer the values that transaction had and expects
//! `HAProxy`'s line byte for byte.

use std::net::SocketAddr;

use ibex_rt::{LogData, LogFormat};
use ibex_sample::{sample_registry, SampleContext};

const FORMAT_A: &str = "A r=%r|HM=%HM|HU=%HU|HP=%HP|HPO=%HPO|HQ=%HQ|HV=%HV|Qr=%{+Q}r|ci=%ci|f=%f|ft=%ft|b=%b|s=%s|ST=%ST|B=%B|U=%U|ts=%ts|tsc=%tsc|rt=%rt|ID=%ID|hr=%hr|hrl=%hrl|hs=%hs|pct=%%|esc=a b|Qx=%{+Q}[str(q)]|e=%[str()]|bin=%[str(ab),bytes(0)]|i=%[int(10)]|X=%{+X}[int(255)]|bool=%[bool(1)]|ip=%[src]";

fn addr(s: &str) -> Option<SocketAddr> {
    Some(s.parse().expect("addr"))
}

fn base<'a>(req_caps: &'a [Option<Vec<u8>>], res_caps: &'a [Option<Vec<u8>>]) -> LogData<'a> {
    LogData {
        client: addr("127.0.0.1:40000"),
        frontend_addr: addr("127.0.0.1:29600"),
        server_addr: addr("127.0.0.1:29601"),
        frontend: "fe",
        backend: "be",
        backend_http: true,
        server: Some("s1"),
        accept_date: (1_791_038_898, 622),
        t_handshake: 0,
        t_idle: 0,
        t_request: 0,
        t_queue: 0,
        t_connect: 0,
        t_data: 1,
        t_close: 1,
        status: 201,
        bytes_out: 77,
        bytes_in: 100,
        actconn: 1,
        feconn: 1,
        pid: 1_590_364,
        hostname: "amanet",
        request_line: Some("GET /p/a?x=1 HTTP/1.1"),
        req_captures: Some(req_caps),
        res_captures: Some(res_caps),
        unique_id: Some("ID-7"),
        ..LogData::default()
    }
}

fn render(fmt: &str, d: &LogData) -> String {
    let reg = sample_registry();
    let ctx = SampleContext { client_addr: d.client, ..Default::default() };
    LogFormat::compile(fmt, reg).expect("compiles").render(d, reg, &ctx)
}

#[test]
fn an_http_transaction_renders_as_haproxy_wrote_it() {
    let req = [Some("127.0.0.1:29600".as_bytes().to_vec()), Some("aaaaa".as_bytes().to_vec())];
    let res = [Some("rv".as_bytes().to_vec())];
    let d = base(&req, &res);
    assert_eq!(
        render(FORMAT_A, &d),
        "A r=GET /p/a?x=1 HTTP/1.1|HM=GET|HU=/p/a?x=1|HP=/p/a|HPO=/p/a|HQ=?x=1|HV=HTTP/1.1|Qr=\"GET /p/a?x=1 HTTP/1.1\"|ci=127.0.0.1|f=fe|ft=fe|b=be|s=s1|ST=201|B=77|U=100|ts=--|tsc=----|rt=0|ID=ID-7|hr={127.0.0.1:29600|aaaaa}|hrl=127.0.0.1:29600 aaaaa|hs={rv}|pct=%|esc=a b|Qx=\"q\"|e=-|bin=ab|i=10|X=255|bool=1|ip=127.0.0.1"
    );
}

#[test]
fn a_missing_capture_is_empty_in_hr_and_a_dash_in_hrl() {
    let req = [Some("127.0.0.1:29600".as_bytes().to_vec()), None];
    let res = [Some("rv".as_bytes().to_vec())];
    let d = LogData { request_line: Some("POST /post HTTP/1.1"), uniq_id: 2, bytes_in: 152, ..base(&req, &res) };
    let line = render(FORMAT_A, &d);
    assert!(line.contains("|HQ=|HV=HTTP/1.1|"), "{line}");
    assert!(line.contains("|hr={127.0.0.1:29600|}|hrl=127.0.0.1:29600 -|"), "{line}");
    assert!(line.contains("|rt=2|"), "{line}");
}

#[test]
fn a_bad_request_has_no_request_line_and_no_server() {
    // HAProxy's line for a request it refused with 400 before routing.
    let d = LogData {
        backend: "fe",
        server: None,
        status: 400,
        bytes_out: 0,
        bytes_in: 0,
        term_state: *b"PR",
        uniq_id: 1,
        request_line: None,
        req_captures: None,
        res_captures: None,
        unique_id: None,
        ..base(&[], &[])
    };
    assert_eq!(
        render(FORMAT_A, &d),
        "A r=<BADREQ>|HM=<BADREQ>|HU=<BADREQ>|HP=<BADREQ>|HPO=<BADREQ>|HQ=<BADREQ>|HV=<BADREQ>|Qr=\"<BADREQ>\"|ci=127.0.0.1|f=fe|ft=fe|b=fe|s=<NOSRV>|ST=400|B=0|U=0|ts=PR|tsc=PR--|rt=1|ID=-|hr=|hrl=|hs=|pct=%|esc=a b|Qx=\"q\"|e=-|bin=ab|i=10|X=255|bool=1|ip=127.0.0.1"
    );
}

#[test]
fn dates_timings_counters_and_flags() {
    let d = LogData { req_captures: None, res_captures: None, ..base(&[], &[]) };
    let line = render(
        "t=%t|T=%T|Ts=%Ts|ms=%ms|TR=%TR|Tw=%Tw|Tc=%Tc|Tr=%Tr|Ta=%Ta|Tt=%Tt|Th=%Th|Ti=%Ti|Tq=%Tq|Td=%Td|Tu=%Tu|ac=%ac|fc=%fc|bc=%bc|sc=%sc|rc=%rc|sq=%sq|bq=%bq|lc=%lc|pid=%pid|H=%H|Xci=%{+X}ci|Xcp=%{+X}cp|XB=%{+X}B|Xbin=%{+X}[str(ab),bytes(0)]|QB=%{+Q}B|Qe=%{+Q}[str()]|QID=%{+Q}ID|fi=%fi|fp=%fp|si=%si|sp=%sp|CC=%CC|CS=%CS|Qs=%{+Q}s|Qb=%{+Q}b|QHQ=%{+Q}HQ",
        &LogData { client: addr("127.0.0.1:36510"), ..d },
    );
    // `%t` is local time; the rest of the line is as HAProxy wrote it.
    let (date, rest) = line.split_once("|T=").expect("t");
    assert!(date.starts_with("t=03/Oct/2026:") && date.ends_with(":48:18.622"), "{date}");
    assert_eq!(
        rest,
        "03/Oct/2026:14:48:18 +0000|Ts=1791038898|ms=622|TR=0|Tw=0|Tc=0|Tr=1|Ta=1|Tt=1|Th=0|Ti=0|Tq=0|Td=0|Tu=1|ac=1|fc=1|bc=0|sc=0|rc=0|sq=0|bq=0|lc=0|pid=1590364|H=amanet|Xci=7F000001|Xcp=8E9E|XB=77|Xbin=ab|QB=77|Qe=\"\"|QID=\"ID-7\"|fi=127.0.0.1|fp=29600|si=127.0.0.1|sp=29601|CC=-|CS=-|Qs=\"s1\"|Qb=\"be\"|QHQ=\"?x=1\""
    );
}

#[test]
fn global_options_apply_to_what_follows() {
    // `%{+X}o` (as in proxy_protocol_send_unique_id.vtc) turns on hex for the rest.
    let d = base(&[], &[]);
    assert_eq!(render("%{+X}o\\ %ci:%cp %{-X}ci", &d).trim_start_matches('\\'), " 7F000001:9C40 127.0.0.1");
}

#[test]
fn the_request_line_and_captures_are_encoded() {
    // `url_encode_map` for %r: `"` and `#` as #XX (h1_authority_fragment_char.vtc logs
    // `GET http://hostname#23frag HTTP/1.1`); `hdr_encode_map` adds `{|}` for captures.
    let req = [Some("a{b}|c\"d#".as_bytes().to_vec())];
    let d = LogData { request_line: Some("GET http://hostname#frag HTTP/1.1"), ..base(&req, &[]) };
    assert_eq!(render("%r %hr", &d), "GET http://hostname#23frag HTTP/1.1 {a#7Bb#7D#7Cc#22d#23}");
    assert_eq!(render("%HPO %HP %HU", &LogData { request_line: Some("GET http://localhost/r/4?q=4 HTTP/1.1"), ..d.clone() }),
        "/r/4 http://localhost/r/4 http://localhost/r/4?q=4");
}

#[test]
fn what_haproxy_refuses_or_ibex_does_not_render_is_a_config_error() {
    let reg = sample_registry();
    for (fmt, why) in [
        ("%zz", "no such format alias 'zz'"),
        ("%1", "unexpected alias name"),
        ("%[path", "missing ']'"),
        ("%[no_such_fetch]", "unknown fetch method"),
        ("%[path,no_such_conv]", "unknown converter"),
        ("%{+Q}", "parse argument modifier without alias name"),
        ("%OG", "not implemented"),
        ("%sslv", "not implemented"),
        ("%{+E}r", "not implemented"),
        ("%(name)ci", "not implemented"),
        ("abc %", "truncated"),
    ] {
        let err = LogFormat::compile(fmt, reg).expect_err(fmt);
        assert!(err.contains(why), "{fmt}: {err}");
    }
}

#[test]
fn haproxy_s_default_formats_compile() {
    let reg = sample_registry();
    LogFormat::compile(ibex_rt::DEFAULT_HTTP_LOG_FORMAT, reg).expect("httplog");
    LogFormat::compile(ibex_rt::DEFAULT_TCP_LOG_FORMAT, reg).expect("tcplog");
}

/// A sample that is absent prints `-` in a log line and nothing in a unique ID: `HAProxy`
/// compiles log formats with `LOG_OPT_MANDATORY` and `unique-id-format` without it
/// (proxy.c). Measured 2026-10-03, `unique-id-format U-%[req.hdr(x-a)]` without the
/// header: `%ID` is `U-`, while `%[req.hdr(x-a)]` in the log line is `-`. `+M`/`-M` set it.
#[test]
fn an_absent_sample_is_a_dash_in_a_log_line_only() {
    let reg = sample_registry();
    let d = base(&[], &[]);
    let ctx = SampleContext::default();
    let fmt = "U-%[req.hdr(x-a)]";
    assert_eq!(LogFormat::compile(fmt, reg).expect("log").render(&d, reg, &ctx), "U--");
    assert_eq!(LogFormat::compile_unique_id(fmt, reg).expect("uid").render(&d, reg, &ctx), "U-");
    assert_eq!(LogFormat::compile("a%{-M}[str()]b", reg).expect("-M").render(&d, reg, &ctx), "ab");
    assert_eq!(LogFormat::compile_unique_id("a%{+M}[str()]b", reg).expect("+M").render(&d, reg, &ctx), "a-b");
}

/// Dates and hex forms, against two lines `HAProxy` wrote at accept time 1791044405.009
/// (measured 2026-10-03, local zone +0200), IPv4 then IPv6 client:
///
/// ```text
/// Ts=1791044405 Xts=6AC12B35 ms=009 Xms=09 rt=0 Xrt=0000 pid=1955343 Xpid=1DD60F
///   tr=03/Oct/2026:18:20:05.009 trg=03/Oct/2026:16:20:05 +0000 trl=03/Oct/2026:18:20:05 +0200
///   t=03/Oct/2026:18:20:05.009 T=03/Oct/2026:16:20:05 +0000 Tl=03/Oct/2026:18:20:05 +0200
///   ci=127.0.0.1 Xci=7F000001 Xcp=D9F4 e=- Qe=""
/// ... ci=::1 Xci=00000000000000000000000000000001 Xcp=A0A6
/// ```
///
/// The local-time fields depend on the zone of the machine running the test; they are
/// checked against each other, the rest byte for byte.
#[test]
fn dates_and_hex_forms_are_haproxy_s() {
    let fmt = "Ts=%Ts Xts=%{+X}Ts ms=%ms Xms=%{+X}ms rt=%rt Xrt=%{+X}rt pid=%pid Xpid=%{+X}pid \
               tr=%tr trg=%trg trl=%trl t=%t T=%T Tl=%Tl ci=%ci Xci=%{+X}ci Xcp=%{+X}cp e=%[str(),bytes(0)] Qe=%{+Q}[str(),bytes(0)]";
    let d = LogData {
        accept_date: (1_791_044_405, 9),
        t_idle: 0,
        uniq_id: 0,
        pid: 1_955_343,
        client: addr("127.0.0.1:55796"),
        ..base(&[], &[])
    };
    let line = render(fmt, &d);
    let field = |k: &str| {
        let start = line.find(&format!(" {k}=")).map(|i| i + k.len() + 2).expect(k);
        let rest = &line[start..];
        // A date field runs to the next ` <key>=`.
        let end = rest.find(|c: char| c == '=').and_then(|e| rest[..e].rfind(' ')).unwrap_or(rest.len());
        rest[..end].to_string()
    };
    assert!(line.starts_with("Ts=1791044405 Xts=6AC12B35 ms=009 Xms=09 rt=0 Xrt=0000 pid=1955343 Xpid=1DD60F "), "{line}");
    assert_eq!(field("trg"), "03/Oct/2026:16:20:05 +0000");
    assert_eq!(field("T"), "03/Oct/2026:16:20:05 +0000");
    assert_eq!(field("tr"), field("t"));
    assert!(field("tr").starts_with("03/Oct/2026:") && field("tr").ends_with(":20:05.009"), "{line}");
    assert_eq!(field("trl"), field("Tl"));
    assert_eq!(&field("trl")[..17], &field("tr")[..17], "{line}");
    assert!(line.ends_with(" ci=127.0.0.1 Xci=7F000001 Xcp=D9F4 e=- Qe=\"\""), "{line}");
    let v6 = render("ci=%ci Xci=%{+X}ci Xcp=%{+X}cp", &LogData { client: addr("[::1]:41126"), ..d.clone() });
    assert_eq!(v6, "ci=::1 Xci=00000000000000000000000000000001 Xcp=A0A6");
}

/// `option httplog` / `tcplog` and their `clf` forms are `HAProxy`'s own format strings,
/// and an HTTP format asked of a TCP proxy is the TCP one (`HAProxy` warns and falls back).
#[test]
fn option_formats_are_the_default_strings() {
    use ibex_config::LogFormatSpec as S;
    assert_eq!(ibex_rt::format_string(&S::Http { clf: false }, true), ibex_rt::DEFAULT_HTTP_LOG_FORMAT);
    assert_eq!(ibex_rt::format_string(&S::Http { clf: true }, true), ibex_rt::CLF_HTTP_LOG_FORMAT);
    assert_eq!(ibex_rt::format_string(&S::Http { clf: false }, false), ibex_rt::DEFAULT_TCP_LOG_FORMAT);
    assert_eq!(ibex_rt::format_string(&S::Http { clf: true }, false), ibex_rt::CLF_TCP_LOG_FORMAT);
    assert_eq!(ibex_rt::format_string(&S::Tcp { clf: false }, true), ibex_rt::DEFAULT_TCP_LOG_FORMAT);
    assert_eq!(ibex_rt::format_string(&S::Custom("x %ci".into()), true), "x %ci");
}

/// `haproxy -c` refuses a quote inside a fetch argument it cannot close: `%[str(a"b)]` is
/// "fetch method 'str' : expected ')'" (measured 2026-10-03).
#[test]
fn an_unclosed_quote_in_an_expression_is_refused() {
    let err = LogFormat::compile("%[str(a\"b)] x", sample_registry()).expect_err("refused");
    assert!(err.contains("expected ')'") || err.contains("missing ']'"), "{err}");
}

/// A `unique-id-format` naming an unknown fetch is a configuration error wherever it
/// is, a backend included: `haproxy -c` says "failed to parse unique-id : ... unknown
/// fetch method 'nosuch'" (measured 2026-10-03).
#[test]
fn a_bad_unique_id_format_is_refused_in_every_section() {
    for sec in ["frontend f\n  bind 127.0.0.1:1", "listen l\n  bind 127.0.0.1:1", "backend b"] {
        let cfg = ibex_config::parse_str(&format!("{sec}\n  mode http\n  unique-id-format %[nosuch]\n")).expect("parses");
        let err = ibex_rt::Engine::new(&cfg, 4).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.contains("unique-id") && err.contains("nosuch"), "{sec}: {err:?}");
    }
}

/// Lines the reference `HAProxy` wrote, measured 2026-10-03:
///
/// ```text
/// log-format "a=%{Q}r|u=%{+foo}r|p=100%!|qh=%{+Q}[var(txn.none)]|hrl=%{+Q}hrl|...|rc=%rc|s=%s"
///   a=GET /a/b?q HTTP/1.1|u=GET /a/b?q HTTP/1.1|p=100!|qh=""|hrl="" "v"|...|rc=+1|s=s1
/// log-format "m=%[method]|Qm=%{+Q}[method]|...|si=%si|sp=%sp|Xsp=%{+X}sp|Xsi=%{+X}si|s=%s"
///   m=GET|Qm="GET"|...|si=-|sp=-|Xsp=-|Xsi=-|s=<NOSRV>
/// ```
///
/// (the first a redispatched retry, the second an `http-request return`).
#[test]
fn a_percent_before_anything_but_an_alias_name_is_dropped() {
    let d = base(&[], &[]);
    assert_eq!(render("p=100%!", &d), "p=100!");
    // ... but before a blank `HAProxy` refuses it (`haproxy -c` on `log-format "a % b"`).
    let err = LogFormat::compile("a % b", sample_registry()).expect_err("refused");
    assert_eq!(
        err,
        "unexpected alias name near ' ' at position 3 line : 'a % b'. Maybe you want to write a single '%', use the syntax '%%'"
    );
}

#[test]
fn flags_without_a_sign_or_unknown_are_ignored_and_absent_values_quote_as_empty() {
    let req = [None, Some("v".as_bytes().to_vec())];
    let d = LogData { request_line: Some("GET /a/b?q HTTP/1.1"), redispatched: true, retries: 1, ..base(&req, &[]) };
    assert_eq!(
        render("a=%{Q}r|u=%{+foo}r|qh=%{+Q}[var(txn.none)]|hrl=%{+Q}hrl|rc=%rc", &d),
        "a=GET /a/b?q HTTP/1.1|u=GET /a/b?q HTTP/1.1|qh=\"\"|hrl=\"\" \"v\"|rc=+1"
    );
    // Turning off an encoding Ibex does not render is no error: `HAProxy` logged
    // `a=GET /y HTTP/1.1|b="GET /y HTTP/1.1"` for `a=%{-E}r|b=%{+Q,-json}r` (2026-10-03).
    assert_eq!(render("a=%{-E}r|b=%{+Q,-json}r", &d), "a=GET /a/b?q HTTP/1.1|b=\"GET /a/b?q HTTP/1.1\"");
    let reg = sample_registry();
    let ctx = SampleContext { req_method: Some("GET"), ..Default::default() };
    let nosrv = LogData { server: None, server_addr: None, ..d };
    assert_eq!(
        LogFormat::compile("m=%[method]|Qm=%{+Q}[method]|si=%si|sp=%sp|Xsp=%{+X}sp|Xsi=%{+X}si", reg)
            .expect("compiles")
            .render(&nosrv, reg, &ctx),
        "m=GET|Qm=\"GET\"|si=-|sp=-|Xsp=-|Xsi=-"
    );
}

/// `http_parse_path` finds no path in `*` or an authority-form target, so `%HPO` is
/// empty for them; `%HP` is the target as it is. `HAProxy` logged `HPO=|QHPO=""|HP=*`
/// for `OPTIONS * HTTP/1.1` (measured 2026-10-03).
#[test]
fn hpo_is_empty_for_a_target_with_no_path() {
    let d = LogData { request_line: Some("OPTIONS * HTTP/1.1"), ..base(&[], &[]) };
    assert_eq!(render("HPO=%HPO|QHPO=%{+Q}HPO|HP=%HP", &d), "HPO=|QHPO=\"\"|HP=*");
    let d = LogData { request_line: Some("CONNECT host:443 HTTP/1.1"), ..d };
    assert_eq!(render("HPO=%HPO|HP=%HP", &d), "HPO=|HP=host:443");
}

/// `HAProxy` parses a `log-format` whether or not the proxy has a log address; only the
/// "log format ignored ... since it has no log address" warning follows. `haproxy -c`
/// (3.5-dev8-885761-29, 2026-10-03) on a frontend with no `log` line exits 1 for each of
/// `abc%` ("truncated line after '%'"), `%zz` ("no such format alias 'zz'") and
/// `%[nosuch]` ("unknown fetch method 'nosuch'"), and 0 for a good format. Ibex compiled
/// it only for a proxy that logs, so these loaded.
#[test]
fn a_bad_log_format_is_refused_without_a_log_address_too() {
    for sec in ["frontend f\n  bind 127.0.0.1:0", "listen l\n  bind 127.0.0.1:0"] {
        for bad in ["abc%", "%zz", "%[nosuch]"] {
            let cfg = ibex_config::parse_str(&format!("{sec}\n  mode http\n  log-format \"{bad}\"\n")).expect("parses");
            let err = ibex_rt::Engine::new(&cfg, 4).err().map(|e| e.to_string()).unwrap_or_default();
            assert!(err.contains("failed to parse log-format"), "{sec} with `{bad}` and no log address loaded: {err:?}");
        }
        let cfg = ibex_config::parse_str(&format!("{sec}\n  mode http\n  log-format \"%ci %[src]\"\n")).expect("parses");
        ibex_rt::Engine::new(&cfg, 4).expect("a good format loads without a log address");
    }
}
