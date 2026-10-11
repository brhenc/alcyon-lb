// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `log-format`, `option httplog`/`tcplog`, `unique-id-format`, `unique-id-header` and
//! `capture ... header`, as the reference `HAProxy` (3.5-dev8-885761-29) accepts and
//! refuses them with `haproxy -c`, measured 2026-10-03; which format a frontend logs
//! with was measured by sending it requests.

use ibex_config::{parse_str, HeaderCapture, LogFormatSpec};

fn fe(body: &str) -> Result<ibex_config::Config, ibex_config::ConfigError> {
    parse_str(&format!(
        "defaults d\n  mode http\nfrontend f\n  bind 127.0.0.1:29000\n{body}  default_backend b\nbackend b\n  server s 127.0.0.1:1\n"
    ))
}

#[test]
fn the_last_format_directive_wins() {
    // Measured: `log-format "X %ci"` then `option httplog` logs the httplog line;
    // `option httplog` then `log-format "Y %ci"` logs `Y 127.0.0.1`.
    let c = fe("  log-format \"X %ci\"\n  option httplog\n").expect("parse");
    assert_eq!(c.frontends[0].log_format, Some(LogFormatSpec::Http { clf: false }));
    let c = fe("  option httplog\n  log-format \"Y %ci\"\n").expect("parse");
    assert_eq!(c.frontends[0].log_format, Some(LogFormatSpec::Custom("Y %ci".to_string())));
    let c = fe("  option tcplog clf\n").expect("parse");
    assert_eq!(c.frontends[0].log_format, Some(LogFormatSpec::Tcp { clf: true }));
}

#[test]
fn defaults_are_inherited() {
    let c = parse_str(
        "defaults\n  mode http\n  option httplog\n  unique-id-format ID-%rt\n  unique-id-header X-ID\n\
         frontend f\n  bind 127.0.0.1:29000\n  default_backend b\nbackend b\n  server s 127.0.0.1:1\n",
    )
    .expect("parse");
    assert_eq!(c.frontends[0].log_format, Some(LogFormatSpec::Http { clf: false }));
    assert_eq!(c.frontends[0].unique_id_format.as_deref(), Some("ID-%rt"));
    assert_eq!(c.backends[0].unique_id_header.as_deref(), Some("X-ID"));
}

#[test]
fn captures_keep_their_order_and_length() {
    // Slots in declaration order, shared with `http-request capture` (no `id`).
    let c = fe("  capture request header host len 20\n  capture response header x-r len 10\n  \
                http-request capture req.hdr(x-b) len 3\n  capture request header x-a len 5\n")
    .expect("parse");
    let f = &c.frontends[0];
    assert_eq!(
        f.req_header_captures,
        [HeaderCapture { name: "host".into(), len: 20, slot: 0 }, HeaderCapture { name: "x-a".into(), len: 5, slot: 2 }]
    );
    assert_eq!(f.res_header_captures, [HeaderCapture { name: "x-r".into(), len: 10, slot: 0 }]);
}

#[test]
fn backends_accept_and_ignore_what_only_frontends_use() {
    // HAProxy warns ("ignored in backends", "no frontend capability") and loads.
    parse_str(
        "backend b\n  mode http\n  log-format \"%ci\"\n  option httplog\n  capture request header host len 5\n  \
         unique-id-format x\n  server s 127.0.0.1:1\n",
    )
    .expect("HAProxy loads it");
}

#[test]
fn what_haproxy_refuses_is_refused() {
    for (body, why) in [
        ("  log-format\n", "expects an argument"),
        ("  log-format a b\n", "expects only one argument"),
        ("  unique-id-format a b\n", "expects only one argument"),
        ("  unique-id-format\n", "expects an argument"),
        ("  option httplog foo\n", "only supports option 'clf'"),
        ("  capture request header host\n", "expects 'header' <header_name> 'len' <len>"),
    ] {
        let err = fe(body).expect_err(body);
        assert!(err.message.contains(why), "{body}: {}", err.message);
    }
    // `option httpslog` is the HTTP log with the TLS fields (T165), and takes no argument.
    assert_eq!(fe("  option httpslog\n").expect("loads").frontends[0].log_format, Some(LogFormatSpec::Https));
    assert_eq!(fe("  option httpslog extra\n").expect("loads").frontends[0].log_format, Some(LogFormatSpec::Https));
    // Not implemented in Ibex: refused rather than accepted and dropped.
    for (body, why) in [
        ("  capture cookie c len 5\n", "capture cookie"),
    ] {
        let err = fe(body).expect_err(body);
        assert!(err.message.contains(why) && err.message.contains("not implemented"), "{body}: {}", err.message);
    }
}

/// `proxy-v2-options`, measured with `haproxy -c` 2026-10-03: `unique-id` and the other
/// documented options load; anything else is "'bogus' : proxy v2 option not implemented",
/// on `server` and `default-server` alike, and so is an empty list.
#[test]
fn proxy_v2_options_unique_id_is_kept_and_the_rest_refused() {
    let be = |line: &str| parse_str(&format!("backend b\n  mode http\n{line}\n"));
    let cfg = be("  server s 127.0.0.1:1 send-proxy-v2 proxy-v2-options unique-id").expect("loads");
    assert!(cfg.backends[0].servers[0].proxy_v2_unique_id);
    let cfg = be("  default-server proxy-v2-options unique-id\n  server s 127.0.0.1:1 send-proxy-v2").expect("loads");
    assert!(cfg.backends[0].servers[0].proxy_v2_unique_id, "inherited from default-server");
    let cfg = be("  server s 127.0.0.1:1 send-proxy-v2").expect("loads");
    assert!(!cfg.backends[0].servers[0].proxy_v2_unique_id);
    for (line, why) in [
        ("  server s 127.0.0.1:1 proxy-v2-options bogus", "'bogus' : proxy v2 option not implemented"),
        ("  server s 127.0.0.1:1 proxy-v2-options unique-id,bogus", "'bogus' : proxy v2 option not implemented"),
        ("  server s 127.0.0.1:1 proxy-v2-options", "'' : proxy v2 option not implemented"),
        ("  default-server proxy-v2-options bogus", "'bogus' : proxy v2 option not implemented"),
        // HAProxy has these; Ibex does not send them, so it refuses them rather than
        // sending a header without them.
        ("  server s 127.0.0.1:1 proxy-v2-options unique-id,crc32c", "'crc32c'"),
        ("  server s 127.0.0.1:1 proxy-v2-options ssl", "'ssl'"),
        ("  server s 127.0.0.1:1 proxy-v2-options authority", "'authority'"),
    ] {
        let err = be(line).expect_err(line);
        assert!(err.message.contains(why), "{line}: {}", err.message);
    }
}

/// `unique-id-header` with no name, and malformed `capture` lines, in every section that
/// takes them; the messages are `haproxy -c`'s (measured 2026-10-03).
#[test]
fn unique_id_header_and_capture_errors_are_haproxy_s() {
    for sec in ["defaults d", "frontend f\n  bind 127.0.0.1:1", "listen l\n  bind 127.0.0.1:1", "backend b"] {
        let err = parse_str(&format!("{sec}\n  mode http\n  unique-id-header\n")).expect_err(sec);
        assert!(err.message.contains("unique-id-header expects an argument."), "{sec}: {}", err.message);
        let ok = parse_str(&format!("{sec}\n  mode http\n  unique-id-header X-Id\n")).expect(sec);
        let got = [
            ok.defaults.as_ref().and_then(|d| d.unique_id_header.clone()),
            ok.frontends.first().and_then(|f| f.unique_id_header.clone()),
            ok.listens.first().and_then(|l| l.unique_id_header.clone()),
            ok.backends.first().and_then(|b| b.unique_id_header.clone()),
        ];
        assert!(got.iter().flatten().any(|h| h == "X-Id"), "{sec}: {got:?}");
    }
    for (body, why) in [
        ("  capture foo\n", "'capture' expects 'cookie' or 'request header' or 'response header'."),
        ("  capture request\n", "'capture' expects 'cookie' or 'request header' or 'response header'."),
        ("  capture response header x-r\n", "'capture response' expects 'header' <header_name> 'len' <len>."),
    ] {
        let err = fe(body).expect_err(body);
        assert!(err.message.contains(why), "{body}: {}", err.message);
    }
}

/// `log-format` and `option httplog` in `defaults` and `listen`; a backend's own format
/// and captures are parsed (an error in them is still an error) and ignored.
#[test]
fn formats_in_defaults_listen_and_backend() {
    let cfg = parse_str("defaults\n  mode http\n  log-format \"D %ci\"\nlisten l\n  bind 127.0.0.1:1\n  option httplog clf\n  capture request header host len 3\n").expect("loads");
    assert_eq!(cfg.defaults.as_ref().and_then(|d| d.log_format.clone()), Some(LogFormatSpec::Custom("D %ci".into())));
    let l = &cfg.listens[0];
    assert_eq!(l.log_format, Some(LogFormatSpec::Http { clf: true }));
    assert_eq!(l.req_header_captures, [HeaderCapture { name: "host".into(), len: 3, slot: 0 }]);
    let err = parse_str("backend b\n  capture response header x-r\n").expect_err("bad capture");
    assert!(err.message.contains("'capture response' expects"), "{}", err.message);
    parse_str("backend b\n  log-format-sd \"%ci\"\n").expect("a backend accepts and ignores log-format-sd");
}

/// Health-check words reach the rules as the lexer read them (`parse_line`'s escapes
/// applied once): the configuration loads in `haproxy -c` (measured 2026-10-03).
#[test]
fn health_check_arguments_keep_their_escaped_text() {
    let cfg = parse_str(
        "backend b\n  mode http\n  option httpchk\n  \
         http-check send meth GET uri /a\\ b ver HTTP/1.1 hdr x-h \"v 1\" body \"b\\r\\n\"\n  \
         http-check expect rstatus ^2\n  http-check expect string \"ok\\ yes\"\n  \
         http-check expect rstring ^o\n  http-check expect hdr name x-a value \"b c\"\n  \
         server s 127.0.0.1:1 check\n\
         backend t\n  mode tcp\n  option tcp-check\n  tcp-check send \"PING\\r\\n\"\n  \
         tcp-check expect string \"+PONG\" comment \"says pong\"\n  tcp-check expect rstring ^\\+P\n  \
         server s 127.0.0.1:2 check\n",
    )
    .expect("loads");
    let b = format!("{:?}", cfg.backends[0]);
    for want in ["\"/a b\"", "(\"x-h\", \"v 1\")", "\"b\\r\\n\"", "RStatus(\"^2\")", "String(\"ok yes\")", "RString(\"^o\")", "\"x-a\"", "\"b c\""] {
        assert!(b.contains(want), "{want} in {b}");
    }
    let t = format!("{:?}", cfg.backends[1]);
    for want in ["[80, 73, 78, 71, 13, 10]", "String(\"+PONG\")", "\"says pong\"", "RString(\"^\\\\+P\")"] {
        assert!(t.contains(want), "{want} in {t}");
    }
}

/// `declare capture request|response len <n>` takes a capture slot like a `capture ...
/// header` line, in declaration order, without a header to read: only an
/// `http-request capture ... id <n>` fills it. `haproxy -c`'s refusals, measured
/// 2026-10-03.
#[test]
fn declare_capture_takes_a_slot() {
    let cfg = fe("  capture request header host len 5\n  declare capture request len 4\n  declare capture response len 2\n").expect("loads");
    let f = &cfg.frontends[0];
    assert_eq!(
        f.req_header_captures,
        [HeaderCapture { name: "host".into(), len: 5, slot: 0 }, HeaderCapture { name: String::new(), len: 4, slot: 1 }]
    );
    assert_eq!(f.res_header_captures, [HeaderCapture { name: String::new(), len: 2, slot: 0 }]);
    for (body, why) in [
        ("  declare capture foo len 4\n", "'declare capture' requires a direction ('request' or 'response')"),
        ("  declare capture request 4\n", "'declare capture' requires a capture length ('len')"),
    ] {
        let err = fe(body).expect_err(body);
        assert!(err.message.contains(why), "{body}: {}", err.message);
    }
}

/// A `listen` section takes `log-format` and `declare capture` as a frontend does, and a
/// bad log option is refused in `defaults`, `listen` and `frontend` alike.
#[test]
fn listen_formats_and_log_option_errors_in_every_section() {
    let cfg = parse_str("listen l\n  mode http\n  bind 127.0.0.1:1\n  log-format \"L %ci\"\n  declare capture request len 4\n")
        .expect("loads");
    let l = &cfg.listens[0];
    assert_eq!(l.log_format, Some(LogFormatSpec::Custom("L %ci".into())));
    assert_eq!(l.req_header_captures, [HeaderCapture { name: String::new(), len: 4, slot: 0 }]);
    for cfg in [
        "defaults\n  mode http\n  option httplog foo\n",
        "listen l\n  mode http\n  bind 127.0.0.1:1\n  option tcplog foo\n",
        "frontend f\n  mode http\n  bind 127.0.0.1:1\n  option httplog foo\n",
    ] {
        let err = parse_str(cfg).expect_err(cfg);
        assert!(err.message.contains("only supports option 'clf'"), "{cfg}: {}", err.message);
    }
}

/// An `option` that is not a log format still reaches the section's own options in
/// `defaults`, `listen` and `frontend` (`haproxy -c` loads each, measured 2026-10-03).
#[test]
fn other_options_still_load_in_every_section() {
    for cfg in [
        "defaults\n  mode http\n  option forwardfor\n",
        "listen l\n  mode http\n  bind 127.0.0.1:1\n  option forwardfor\n",
        "frontend f\n  mode http\n  bind 127.0.0.1:1\n  option forwardfor\n",
    ] {
        parse_str(cfg).unwrap_or_else(|e| panic!("{cfg}: {}", e.message));
    }
}

/// `error-log-format` (T296): one argument, kept per frontend or listen, inherited from
/// `defaults` and replaced by the section's own; a backend takes and ignores it, as
/// `HAProxy` ("directive is ignored in backends").
#[test]
fn error_log_format_is_kept_inherited_and_ignored_in_a_backend() {
    let cfg = parse_str(
        "defaults\n  mode http\n  error-log-format \"D %ci\"\n\
         frontend a\n  bind 127.0.0.1:1\n\
         frontend b\n  bind 127.0.0.1:2\n  error-log-format \"B %ft\"\n\
         listen l\n  bind 127.0.0.1:3\n\
         backend k\n  error-log-format \"K\"\n",
    )
    .expect("loads");
    assert_eq!(cfg.defaults.as_ref().and_then(|d| d.error_log_format.as_deref()), Some("D %ci"));
    assert_eq!(cfg.frontends[0].error_log_format.as_deref(), Some("D %ci"));
    assert_eq!(cfg.frontends[1].error_log_format.as_deref(), Some("B %ft"));
    assert_eq!(cfg.listens[0].error_log_format.as_deref(), Some("D %ci"));
    for (body, why) in [("  error-log-format\n", "expects an argument"), ("  error-log-format a b\n", "expects only one argument")] {
        let err = fe(body).expect_err(body);
        assert!(err.message.contains(why), "{body}: {}", err.message);
    }
}

/// A `listen` section's own `error-log-format` (not inherited) replaces `defaults`'.
#[test]
fn a_listen_sections_own_error_log_format_is_kept() {
    let cfg = parse_str("defaults\n  mode http\n  error-log-format \"D\"\nlisten l\n  bind 127.0.0.1:3\n  error-log-format \"L %ci\"\n").expect("loads");
    assert_eq!(cfg.listens[0].error_log_format.as_deref(), Some("L %ci"));
    let err = parse_str("listen l\n  bind 127.0.0.1:3\n  error-log-format a b\n").expect_err("two args");
    assert!(err.message.contains("expects only one argument"), "{}", err.message);
}

/// `log-format-sd` (T303), as `error-log-format`: one argument, kept per frontend or listen,
/// inherited from `defaults` and replaced by the section's own; a backend takes and ignores
/// it (`HAProxy` 3.5-dev8: "'log-format-sd' directive is ignored in backends").
#[test]
fn log_format_sd_is_kept_inherited_and_ignored_in_a_backend() {
    let cfg = parse_str(
        "defaults\n  mode http\n  log-format-sd \"[d@1 f=\\\"%f\\\"]\"\n\
         frontend a\n  bind 127.0.0.1:1\n\
         frontend b\n  bind 127.0.0.1:2\n  log-format-sd \"[b@1]\"\n\
         listen l\n  bind 127.0.0.1:3\n\
         listen m\n  bind 127.0.0.1:4\n  log-format-sd \"[m@1]\"\n\
         backend k\n  log-format-sd \"K\"\n",
    )
    .expect("loads");
    let d = Some("[d@1 f=\"%f\"]");
    assert_eq!(cfg.defaults.as_ref().and_then(|d| d.log_format_sd.as_deref()), d);
    assert_eq!(cfg.frontends[0].log_format_sd.as_deref(), d);
    assert_eq!(cfg.frontends[1].log_format_sd.as_deref(), Some("[b@1]"));
    assert_eq!(cfg.listens[0].log_format_sd.as_deref(), d);
    assert_eq!(cfg.listens[1].log_format_sd.as_deref(), Some("[m@1]"));
    for (body, why) in [("  log-format-sd\n", "log-format-sd expects an argument."), ("  log-format-sd a b\n", "log-format-sd expects only one argument, don't forget to escape spaces!")] {
        let err = fe(body).expect_err(body);
        assert!(err.message.contains(why), "{body}: {}", err.message);
    }
}
