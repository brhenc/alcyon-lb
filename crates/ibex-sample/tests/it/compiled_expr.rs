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
    assert!(!e.eval(&reg, &ctx));
    let known = Expr::parse("str(abc),upper -m str ABC").unwrap();
    assert!(format!("{known:?}").contains("Compiled"), "{known:?}");
}
