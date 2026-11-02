// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T574 (engine slice R1): an expression resolves its fetch and converters to function
//! pointers once; evaluating it looks up no name. The counter is a debug-build one.

#![cfg(debug_assertions)]

use ibex_sample::{name_lookups_on_this_thread, Expr, Registry, Sample, SampleContext};

fn lookups_in_one_eval(text: &str) -> (u64, bool, Option<Sample>) {
    let reg = Registry::new();
    let e = Expr::parse(text).unwrap();
    let ctx = SampleContext::default();
    // The first evaluation resolves the names (and may look them up).
    let _ = e.eval(&reg, &ctx);
    let before = name_lookups_on_this_thread();
    let m = e.eval(&reg, &ctx);
    let smp = e.eval_sample(&reg, &ctx);
    let _ = e.eval_all_samples(&reg, &ctx);
    (name_lookups_on_this_thread() - before, m, smp)
}

#[test]
fn evaluating_a_compiled_expression_looks_up_no_name() {
    for text in [
        "str(abc),upper -m str ABC",
        "str(abc),lower,length -m int 3",
        "req.hdr(host),lower -m str x",
        "path -m beg /a",
        "nbsrv(be) -m int 1",
    ] {
        let (n, _, _) = lookups_in_one_eval(text);
        assert_eq!(n, 0, "{text}: {n} name lookups in a second evaluation");
    }
}

#[test]
fn the_compiled_path_gives_the_by_name_answers() {
    let (_, m, smp) = lookups_in_one_eval("str(abc),upper -m str ABC");
    assert!(m);
    assert_eq!(smp, Some(Sample::Str("ABC".into())));
    let (_, m, smp) = lookups_in_one_eval("str(abc),upper,length -m int 4");
    assert!(!m);
    assert_eq!(smp, Some(Sample::Sint(3)));
}

#[test]
fn a_multi_only_fetch_gives_its_first_sample_through_the_compiled_path() {
    // `req.ssl_alpn` (single and multi fetch) with no payload: nothing, and no name looked up.
    let (n, m, smp) = lookups_in_one_eval("req.ssl_alpn -m found");
    assert_eq!(n, 0);
    assert!(!m);
    assert_eq!(smp, None);
}

#[test]
fn an_expression_with_an_unknown_fetch_is_not_compiled_and_still_evaluates() {
    let reg = Registry::new();
    let ctx = SampleContext::default();
    let e = Expr::parse("t574_no_such_fetch -m found").unwrap();
    assert!(!format!("{e:?}").contains("Compiled"));
    assert!(e.eval_all_samples(&reg, &ctx).is_empty());
    assert_eq!(e.eval_sample(&reg, &ctx), None);
    assert!(e.eval_smp(&reg, &ctx).is_none(), "the bytes form takes the by-name path too (R4)");
    assert!(!e.eval(&reg, &ctx));
    let known = Expr::parse("str(abc),upper -m str ABC").unwrap();
    assert!(format!("{known:?}").contains("Compiled"), "{known:?}");
}

/// R2: the rules scenario's two ACLs (`tools/measure/scenarios/rules.body`) and its
/// `set-var(txn.p) path`, evaluated a second time over a parsed request: what each one costs
/// in spare strings and in UTF-8 checks of the HTX's bytes.
fn rules_scenario_costs() -> (u64, u64, Vec<bool>) {
    let reg = Registry::new();
    let api = Expr::parse("path_reg ^/(api|v[0-9]+)/").unwrap();
    let hosty = Expr::parse("hdr(host) -m sub local").unwrap();
    let path = Expr::parse("path").unwrap();
    crate::bytes_samples::with_request_line(b"GET /api/x HTTP/1.1\r\nHost: localhost\r\nUser-Agent: ab\r\nAccept: */*\r\n\r\n", |ctx| {
        let acls = || vec![api.eval(&reg, ctx), hosty.eval(&reg, ctx)];
        let _ = (acls(), path.eval_sample(&reg, ctx));
        let (spares, utf8) = (ibex_sample::spare::strings_taken_on_this_thread(), ibex_proto::htx::utf8_checks_on_this_thread());
        let mut verdicts = acls();
        let spares = ibex_sample::spare::strings_taken_on_this_thread() - spares;
        verdicts.push(path.eval_sample(&reg, ctx).is_some());
        (spares, ibex_proto::htx::utf8_checks_on_this_thread() - utf8, verdicts)
    })
}

#[test]
fn a_header_acl_takes_no_spare_string() {
    let (spares, _, verdicts) = rules_scenario_costs();
    assert_eq!(verdicts, [true, true, true]);
    // `path` for `set-var` is kept past the rule, as the variable's value (R4): not counted.
    assert_eq!(spares, 0, "{spares} spare strings for `path_reg` and `hdr(host) -m sub`");
}

#[test]
fn a_rule_run_validates_no_utf8() {
    let (_, utf8, _) = rules_scenario_costs();
    assert_eq!(utf8, 0, "{utf8} UTF-8 checks of the request's bytes for 2 ACLs and a path sample");
}

/// R2: the by-name path (an expression with a converter Ibex does not know is not compiled;
/// the configuration refuses one, the CLI and tests can still evaluate it) reads the same
/// samples in their bytes form: a header iterated, a multi fetch, a single fetch, each ending
/// at the unknown converter; `eval_all` of a fetch with a bytes form and of one without.
#[test]
fn the_by_name_path_reads_the_bytes_forms_too() {
    let reg = Registry::new();
    crate::bytes_samples::with_request_line(b"GET /p HTTP/1.1\r\nHost: localhost\r\n\r\n", |ctx| {
        for text in ["req.hdr(host),t574_no_such_conv -m found", "req.ssl_alpn,t574_no_such_conv -m found", "str(a),t574_no_such_conv -m found"] {
            let e = Expr::parse(text).unwrap();
            assert!(!format!("{e:?}").contains("Compiled"), "{text} was compiled");
            assert!(!e.eval(&reg, ctx), "{text}");
        }
        assert_eq!(reg.eval_all("path", &[], &[], ctx), vec![Sample::Str("/p".into())]);
        assert_eq!(reg.eval_all("str", &["x".to_string()], &[("upper", vec![])], ctx), vec![Sample::Str("X".into())]);
    });
}

/// An ACL with no match method takes a boolean or an integer for its truth (`pat_match_nothing`).
#[test]
fn an_acl_without_a_method_reads_a_boolean_or_an_integer() {
    let reg = Registry::new();
    let ctx = SampleContext::default();
    for (text, want) in [("bool(1)", true), ("bool(0)", false), ("int(2)", true), ("int(0)", false), ("str(x)", true)] {
        let e = Expr::parse(text).unwrap();
        assert!(e.matcher.is_none(), "{text} has a method");
        assert_eq!(e.eval(&reg, &ctx), want, "{text}");
    }
}
