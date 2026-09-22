// SPDX-License-Identifier: GPL-2.0-or-later
//! Property-based tests for sample expression parsing and evaluation.

use ibex_sample::{Expr, Registry, SampleContext};
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Expression parsing never panics on arbitrary string inputs.
    #[test]
    fn prop_expr_parse_no_panic(input in "\\PC*") {
        let _ = Expr::parse(&input);
    }

    /// Evaluates path expressions with prefix/suffix/contains matchers against generated URIs.
    #[test]
    fn prop_expr_path_matchers(
        prefix in "[a-z]{1,5}",
        middle in "[a-z0-9]{0,8}",
        suffix in "[a-z]{1,5}"
    ) {
        let registry = Registry::new();
        let uri = format!("/{prefix}/{middle}/{suffix}");
        let ctx = SampleContext {
            req_uri: Some(&uri),
            ..Default::default()
        };

        let expr_beg = Expr::parse(&format!("path -m beg /{prefix}")).unwrap();
        prop_assert!(expr_beg.eval(&registry, &ctx));

        let expr_end = Expr::parse(&format!("path -m end /{suffix}")).unwrap();
        prop_assert!(expr_end.eval(&registry, &ctx));

        let expr_sub = Expr::parse(&format!("path -m sub /{prefix}/")).unwrap();
        prop_assert!(expr_sub.eval(&registry, &ctx));
    }

    /// Integer matchers evaluate consistently on client port.
    #[test]
    fn prop_expr_port_integer_matcher(port in 1024u16..=65535) {
        let registry = Registry::new();
        let ctx = SampleContext {
            client_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
            ..Default::default()
        };

        let expr_eq = Expr::parse(&format!("src_port -m eq {port}")).unwrap();
        prop_assert!(expr_eq.eval(&registry, &ctx));

        if port > 1024 {
            let lower = port - 1;
            let expr_gt = Expr::parse(&format!("src_port -m gt {lower}")).unwrap();
            prop_assert!(expr_gt.eval(&registry, &ctx));
        }

        if port < 65535 {
            let higher = port + 1;
            let expr_lt = Expr::parse(&format!("src_port -m lt {higher}")).unwrap();
            prop_assert!(expr_lt.eval(&registry, &ctx));
        }
    }

    /// Converter chains in expressions (e.g. url,len,add(5) -m int eq expected) evaluate correctly.
    #[test]
    fn prop_expr_converter_chain(uri in "[a-zA-Z0-9/]{1,32}", delta in 0i64..100) {
        let registry = Registry::new();
        let ctx = SampleContext {
            req_uri: Some(&uri),
            ..Default::default()
        };

        let uri_len = i64::try_from(uri.len()).unwrap_or(i64::MAX);
        let expected = uri_len + delta;
        let expr_str = format!("url,len,add({delta}) -m eq {expected}");
        let expr = Expr::parse(&expr_str).unwrap();
        prop_assert!(expr.eval(&registry, &ctx));
    }
}
