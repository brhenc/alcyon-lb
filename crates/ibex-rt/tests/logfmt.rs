// SPDX-License-Identifier: GPL-2.0-or-later

//! Log-format strings must go through the sample engine, not a parallel expander.
//!
//! The point of these tests is the coupling: a fetch or converter added for ACLs must
//! become usable in a log line for free. If `%[...]` stopped routing through the
//! registry, everything here would still "work" as literals -- so several assert on
//! segment structure, not just on output.

use ibex_rt::{LogFormat, LogNames, LogVars};
use ibex_sample::{Registry, SampleContext};
use std::net::SocketAddr;

fn ctx() -> SampleContext<'static> {
    SampleContext {
        client_addr: Some("192.0.2.10:54321".parse::<SocketAddr>().expect("addr")),
        req_method: Some("GET"),
        req_uri: Some("/api/v1/users"),
        ..Default::default()
    }
}

fn vars() -> LogVars {
    LogVars {
        total_ms: 42,
        bytes_out: 1234,
        status: 200,
        ..Default::default()
    }
}

#[test]
fn sample_expressions_are_evaluated_through_the_registry() {
    let reg = Registry::new();
    let f = LogFormat::compile("%[path]").expect("compile");
    assert_eq!(f.render(&reg, &ctx(), &vars(), &LogNames::default()), "/api/v1/users");
}

#[test]
fn converters_work_inside_a_log_format() {
    // The whole reason to share one engine: a converter written for ACLs is usable
    // here without the log code knowing it exists.
    let reg = Registry::new();
    let f = LogFormat::compile("%[path,upper]").expect("compile");
    let out = f.render(&reg, &ctx(), &vars(), &LogNames::default());
    assert_eq!(out, "/API/V1/USERS", "converter chain must be applied");
}

#[test]
fn a_format_compiles_to_structured_segments_not_one_literal() {
    // Guards against a regression where %[...] stops being recognised and silently
    // degrades to literal text -- which would still "render", just wrongly.
    let f = LogFormat::compile("a %[path] b %ci c").expect("compile");
    assert!(
        f.segment_count() >= 4,
        "expected literals and expressions, got {} segment(s)",
        f.segment_count()
    );
}

#[test]
fn single_letter_aliases_render() {
    let reg = Registry::new();
    let f = LogFormat::compile("%ci:%cp %ST %B %Tt").expect("compile");
    assert_eq!(
        f.render(&reg, &ctx(), &vars(), &LogNames::default()),
        "192.0.2.10:54321 200 1234 42"
    );
}

#[test]
fn two_character_aliases_win_over_one_character_prefixes() {
    // %ST must not be read as %S followed by a literal 'T'.
    let reg = Registry::new();
    let f = LogFormat::compile("%ST").expect("compile");
    assert_eq!(f.render(&reg, &ctx(), &vars(), &LogNames::default()), "200");
}

#[test]
fn percent_percent_is_a_literal_percent() {
    let reg = Registry::new();
    let f = LogFormat::compile("100%% done").expect("compile");
    assert_eq!(f.render(&reg, &ctx(), &vars(), &LogNames::default()), "100% done");
}

#[test]
fn a_missing_value_renders_as_dash_not_empty() {
    // HAProxy writes '-' for an absent field. An empty string and a missing value are
    // different things to a log parser, and collapsing them loses the distinction.
    let reg = Registry::new();
    let f = LogFormat::compile("%b|%s").expect("compile");
    assert_eq!(f.render(&reg, &ctx(), &vars(), &LogNames::default()), "-|-");
}

#[test]
fn names_are_rendered_when_known() {
    let reg = Registry::new();
    let names = LogNames { frontend: Some("fe_main"), backend: Some("be_api"), server: Some("srv1") };
    let f = LogFormat::compile("%f %b %s").expect("compile");
    assert_eq!(f.render(&reg, &ctx(), &vars(), &names), "fe_main be_api srv1");
}

#[test]
fn an_unterminated_expression_is_a_compile_error() {
    // Config-parse time is the right moment to fail: a broken log format should stop
    // a reload, not produce corrupt log lines under load.
    assert!(LogFormat::compile("%[path").is_err());
}

#[test]
fn an_unknown_fetch_is_a_config_error_when_validated() {
    // Deferring this to evaluation means a typo silently logs "-" on every request
    // instead of refusing the reload -- a failure nobody notices until they need the
    // logs. HAProxy rejects unknown fetches at config-parse time.
    let reg = Registry::new();
    assert!(LogFormat::compile_with_registry("%[no_such_fetch_at_all]", &reg).is_err());
    assert!(LogFormat::compile_with_registry("%[path,no_such_converter]", &reg).is_err());
}

#[test]
fn a_known_expression_passes_validation() {
    let reg = Registry::new();
    assert!(LogFormat::compile_with_registry("%[path,upper]", &reg).is_ok());
}

#[test]
fn an_unknown_alias_is_emitted_literally_rather_than_refused() {
    // Log formats get copy-pasted between proxies. Refusing to start over an alias we
    // have not implemented yet is worse than logging it verbatim.
    let reg = Registry::new();
    let f = LogFormat::compile("%zz").expect("unknown alias must not fail compilation");
    assert!(f.render(&reg, &ctx(), &vars(), &LogNames::default()).contains('%'));
}

#[test]
fn the_haproxy_default_http_log_format_compiles() {
    // A realistic format, close to HAProxy's documented HTTP default.
    let f = LogFormat::compile(
        "%ci:%cp [%tr] %ft %b/%s %Tq/%Tw/%Tc/%Tr/%Tt %ST %B %rc %[req.hdr(Host)]",
    )
    .expect("the documented default must compile");
    assert!(f.segment_count() > 8);
}
