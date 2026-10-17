// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Property-based and unit tests for sample expression parsing and evaluation.

#![forbid(unsafe_code)]

use ibex_sample::{
    get_proc_var, sample_registry, set_proc_var, Expr, Registry, Sample, SampleContext,
};
use proptest::prelude::*;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::thread;

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

    /// Differential test: sample fetches reading request data produce identical results
    /// whether evaluating against HTX (HtxSliceRef) or against legacy SampleContext fields.
    #[test]
    fn prop_differential_htx_sample_fetches(
        method in "(GET|POST|PUT|DELETE)",
        path_seg in "[a-z]{1,8}",
        query_param in "[a-z]{1,6}",
        query_val in "[a-z0-9]{1,8}",
        host_val in "[a-z]{1,8}\\.example\\.com",
        body_content in "[a-z0-9]{0,32}"
    ) {
        let registry = Registry::new();
        let uri = format!("/{path_seg}?{query_param}={query_val}");
        let wire = format!(
            "{method} {uri} HTTP/1.1\r\nHost: {host_val}\r\nContent-Length: {}\r\n\r\n{body_content}",
            body_content.len()
        );

        let mut parser = ibex_proto::h1::H1Parser::new(false);
        let mut buf = [0u8; 8192];
        let mut htx = ibex_proto::htx::HtxSlice::new(&mut buf);
        parser.parse(wire.as_bytes(), &mut htx).unwrap();

        let ctx_htx = SampleContext {
            htx_slice: Some(htx.as_ref()),
            ..Default::default()
        };

        let headers = vec![
            ("host".to_string(), host_val.clone()),
            ("content-length".to_string(), body_content.len().to_string()),
        ];
        let ctx_current = SampleContext {
            req_uri: Some(&uri),
            req_method: Some(&method),
            req_headers: Some(&headers),
            req_version: Some("HTTP/1.1"),
            req_body: if body_content.is_empty() { None } else { Some(body_content.as_bytes()) },
            ..Default::default()
        };

        let expressions = [
            "path",
            "pathq",
            "url",
            "req.uri",
            "query",
            "method",
            "req.ver",
            "req.hdr(host)",
            "req.hdr_cnt(host)",
            "req.hdr_val(content-length)",
            "req.len",
            "base",
            "baseq",
        ];

        for expr_str in expressions {
            let expr = Expr::parse(expr_str).unwrap();
            let smp_htx = expr.eval_sample(&registry, &ctx_htx);
            let smp_curr = expr.eval_sample(&registry, &ctx_current);
            prop_assert_eq!(
                &smp_htx,
                &smp_curr,
                "Fetch '{}' diverged between HTX and legacy path",
                expr_str
            );
        }

        // Test parameterized url_param
        let url_param_expr = Expr::parse(&format!("url_param({query_param})")).unwrap();
        prop_assert_eq!(
            url_param_expr.eval_sample(&registry, &ctx_htx),
            url_param_expr.eval_sample(&registry, &ctx_current),
            "url_param diverged"
        );
    }
}

/// Concurrent writes and reads to distinct `proc.*` variables across 8 worker threads.
#[test]
fn test_proc_scope_concurrency() {
    const THREADS: usize = 8;
    const ITERATIONS: usize = 2_000;

    let mut handles = Vec::with_capacity(THREADS);

    for t in 0..THREADS {
        let handle = thread::spawn(move || {
            let var_name = format!("proc.concurrency_worker_{t}");
            for i in 0..ITERATIONS {
                let val = format!("val_{t}_{i}");
                set_proc_var(&var_name, val.clone());
                let observed = get_proc_var(&var_name);
                assert_eq!(
                    observed.as_deref(),
                    Some(val.as_str()),
                    "Thread {t} observed unexpected value on iteration {i}: expected {val:?}, got {observed:?}"
                );
            }
            (var_name, format!("val_{t}_{}", ITERATIONS - 1))
        });
        handles.push(handle);
    }

    for handle in handles {
        let (var_name, expected) = handle.join().expect("Worker thread panicked");
        let observed = get_proc_var(&var_name);
        assert_eq!(
            observed.as_deref(),
            Some(expected.as_str()),
            "Thread-written value mismatch after join for {var_name}: expected {expected:?}, got {observed:?}"
        );
    }
}

/// Fetch `uuid` 100 times, validate RFC 4122 v4 format, and assert high entropy / uniqueness.
#[test]
fn test_uuid_generation_entropy() {
    let reg = sample_registry();
    let uuid_fetch = reg
        .get_fetch("uuid")
        .expect("sample fetch 'uuid' must be registered in sample_registry");
    let ctx = SampleContext::default();

    let mut seen = HashSet::with_capacity(100);
    let mut uuids = Vec::with_capacity(100);

    for idx in 0..100 {
        let sample = (uuid_fetch.func)(&ctx, &[]);
        let Some(Sample::Str(ref s)) = sample else {
            panic!("Fetch 'uuid' did not return Sample::Str on iteration {idx}: got {sample:?}");
        };

        // Validate RFC 4122 v4 format: 36 chars, hyphenated xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        assert_eq!(
            s.len(),
            36,
            "UUID must be exactly 36 chars long, got {s:?} (length {})",
            s.len()
        );

        let bytes = s.as_bytes();
        assert_eq!(bytes[8], b'-', "UUID position 8 must be '-', got {s:?}");
        assert_eq!(bytes[13], b'-', "UUID position 13 must be '-', got {s:?}");
        assert_eq!(bytes[18], b'-', "UUID position 18 must be '-', got {s:?}");
        assert_eq!(bytes[23], b'-', "UUID position 23 must be '-', got {s:?}");

        // Version 4 check: nibble at position 14 must be '4'
        assert_eq!(
            bytes[14], b'4',
            "UUID position 14 must be version '4', got {s:?}"
        );

        // Variant check: RFC 4122 variant 1 requires bits 10xx, corresponding to [89ab]
        assert!(
            matches!(bytes[19], b'8' | b'9' | b'a' | b'b' | b'A' | b'B'),
            "UUID position 19 must be variant [89ab], got {s:?}"
        );

        // Check hex characters
        for (pos, &b) in bytes.iter().enumerate() {
            if matches!(pos, 8 | 13 | 18 | 23) {
                continue;
            }
            assert!(
                b.is_ascii_hexdigit(),
                "UUID character at pos {pos} ({}) is not an ASCII hex digit in {s:?}",
                b as char
            );
        }

        uuids.push(s.clone());
        seen.insert(s.clone());
    }

    // Validate that all 100 generated UUIDs are unique (high entropy, no collisions)
    assert_eq!(
        seen.len(),
        100,
        "All 100 generated UUIDs must be unique, but only {} unique entries found (collision)",
        seen.len()
    );

    // Validate entropy: each non-fixed character position must vary across the 100 draws
    let first = uuids[0].as_bytes();
    for (i, &b) in first.iter().enumerate() {
        if matches!(i, 8 | 13 | 14 | 18 | 23) {
            continue;
        }
        let varies = uuids.iter().any(|u| u.as_bytes()[i] != b);
        assert!(
            varies,
            "UUID character at pos {i} never varied across 100 draws, indicating poor entropy"
        );
    }
}

/// Evaluates `fc_src` and `fc_dst` fetches against specific client and server addresses.
#[test]
fn test_fc_src_and_fc_dst_fetches() {
    let reg = sample_registry();

    let client_sock: SocketAddr = "192.0.2.1:12345".parse().unwrap();
    let server_sock: SocketAddr = "198.51.100.1:80".parse().unwrap();
    let fc_src_sock: SocketAddr = "203.0.113.50:54321".parse().unwrap();
    let fc_dst_sock: SocketAddr = "198.51.100.99:443".parse().unwrap();

    let fc_src_fetch = reg.get_fetch("fc_src").expect("fc_src registered");
    let fc_dst_fetch = reg.get_fetch("fc_dst").expect("fc_dst registered");

    // Case 1: Specific client/server and explicit fc_src/fc_dst in SampleContext
    let ctx_explicit = SampleContext {
        client_addr: Some(client_sock),
        server_addr: Some(server_sock),
        fc_src: Some(fc_src_sock),
        fc_dst: Some(fc_dst_sock),
        ..Default::default()
    };

    let src_res = (fc_src_fetch.func)(&ctx_explicit, &[]);
    assert_eq!(
        src_res,
        Some(Sample::Ipv4("203.0.113.50".parse::<Ipv4Addr>().unwrap())),
        "fc_src must return the explicit fc_src IP address"
    );

    let dst_res = (fc_dst_fetch.func)(&ctx_explicit, &[]);
    assert_eq!(
        dst_res,
        Some(Sample::Ipv4("198.51.100.99".parse::<Ipv4Addr>().unwrap())),
        "fc_dst must return the explicit fc_dst IP address"
    );

    // Case 2: Fallback when fc_src/fc_dst are None -> client_addr/server_addr
    let ctx_fallback = SampleContext {
        client_addr: Some(client_sock),
        server_addr: Some(server_sock),
        fc_src: None,
        fc_dst: None,
        ..Default::default()
    };

    let src_fallback = (fc_src_fetch.func)(&ctx_fallback, &[]);
    assert_eq!(
        src_fallback,
        Some(Sample::Ipv4("192.0.2.1".parse::<Ipv4Addr>().unwrap())),
        "fc_src must fall back to client_addr when fc_src is None"
    );

    let dst_fallback = (fc_dst_fetch.func)(&ctx_fallback, &[]);
    assert_eq!(
        dst_fallback,
        Some(Sample::Ipv4("198.51.100.1".parse::<Ipv4Addr>().unwrap())),
        "fc_dst must fall back to server_addr when fc_dst is None"
    );

    // Case 3: IPv6 addresses
    let v6_src: SocketAddr = "[2001:db8:cafe::42]:50000".parse().unwrap();
    let v6_dst: SocketAddr = "[2001:db8:beef::99]:8443".parse().unwrap();
    let ctx_v6 = SampleContext {
        fc_src: Some(v6_src),
        fc_dst: Some(v6_dst),
        ..Default::default()
    };

    assert_eq!(
        (fc_src_fetch.func)(&ctx_v6, &[]),
        Some(Sample::Ipv6("2001:db8:cafe::42".parse::<Ipv6Addr>().unwrap())),
        "fc_src must return IPv6 address correctly"
    );
    assert_eq!(
        (fc_dst_fetch.func)(&ctx_v6, &[]),
        Some(Sample::Ipv6("2001:db8:beef::99".parse::<Ipv6Addr>().unwrap())),
        "fc_dst must return IPv6 address correctly"
    );

    // Case 4: Expr evaluation with IP matching
    let expr_fc_src = Expr::parse("fc_src -m ip 203.0.113.50").unwrap();
    assert!(
        expr_fc_src.eval(reg, &ctx_explicit),
        "Expr evaluation for fc_src -m ip 203.0.113.50 must succeed"
    );

    let expr_fc_dst = Expr::parse("fc_dst -m ip 198.51.100.99").unwrap();
    assert!(
        expr_fc_dst.eval(reg, &ctx_explicit),
        "Expr evaluation for fc_dst -m ip 198.51.100.99 must succeed"
    );
}

/// Asserts `sample_registry()` is non-null, is a singleton, and exposes all required fetches.
#[test]
fn test_sample_registry_singleton() {
    let reg1 = sample_registry();
    let reg2 = sample_registry();

    // Assert non-null and singleton identity
    assert_ne!(
        std::ptr::from_ref(reg1).addr(),
        0,
        "sample_registry() must return a non-null reference"
    );
    assert!(
        std::ptr::eq(reg1, reg2),
        "sample_registry() must return the same static reference on subsequent calls"
    );

    // Verify all fetches explicitly requested by the task
    let required_fetches = [
        "src",
        "dst",
        "fc_src",
        "fc_dst",
        "uuid",
        "req.payload",
        "req.len",
    ];

    for name in &required_fetches {
        assert!(
            reg1.get_fetch(name).is_some(),
            "sample_registry() must expose registered sample fetch '{name}'"
        );
    }

    // Verify additional standard fetches
    let additional_fetches = [
        "src_port",
        "dst_port",
        "fc_src_port",
        "fc_dst_port",
        "var",
        "path",
        "url",
        "method",
        "status",
        "req.hdr",
        "res.hdr",
        "payload",
        "req.body_len",
        "req.body_size",
    ];

    for name in &additional_fetches {
        assert!(
            reg1.get_fetch(name).is_some(),
            "sample_registry() must expose registered sample fetch '{name}'"
        );
    }

    assert!(
        reg1.fetch_count() >= 50,
        "sample_registry() should contain at least 50 sample fetches, found {}",
        reg1.fetch_count()
    );
    assert!(
        reg1.converter_count() >= 50,
        "sample_registry() should contain at least 50 converters, found {}",
        reg1.converter_count()
    );
}

/// Tests `req.payload` and `req.len` fetches with offsets, lengths, and header fallback.
#[test]
fn test_req_payload_and_req_len_fetches() {
    let reg = sample_registry();
    let payload_fetch = reg.get_fetch("req.payload").expect("req.payload registered");
    let len_fetch = reg.get_fetch("req.len").expect("req.len registered");

    let body = b"HTTP request body content 12345";
    let ctx_with_body = SampleContext {
        req_body: Some(body),
        ..Default::default()
    };

    // req.len with req_body
    assert_eq!(
        (len_fetch.func)(&ctx_with_body, &[]),
        Some(Sample::Sint(i64::try_from(body.len()).unwrap()))
    );

    // req.len fallback to content-length header
    let hdrs = vec![("content-length".to_string(), "99".to_string())];
    let ctx_with_hdr = SampleContext {
        req_body: None,
        req_headers: Some(&hdrs),
        ..Default::default()
    };
    assert_eq!(
        (len_fetch.func)(&ctx_with_hdr, &[]),
        Some(Sample::Sint(99))
    );

    // req.payload whole body
    assert_eq!(
        (payload_fetch.func)(&ctx_with_body, &[]),
        Some(Sample::Bin(body.to_vec()))
    );

    // req.payload with offset
    assert_eq!(
        (payload_fetch.func)(&ctx_with_body, &["5".to_string()]),
        Some(Sample::Bin(body[5..].to_vec()))
    );

    // req.payload with offset and length
    assert_eq!(
        (payload_fetch.func)(&ctx_with_body, &["5".to_string(), "7".to_string()]),
        Some(Sample::Bin(body[5..12].to_vec()))
    );

    // req.payload offset out of bounds -> None
    assert_eq!(
        (payload_fetch.func)(&ctx_with_body, &["1000".to_string()]),
        None
    );
}

/// Tests `var` fetch resolving `proc.` variables and fallback default argument.
#[test]
fn test_var_proc_scope_and_fallback() {
    let reg = sample_registry();
    let var_fetch = reg.get_fetch("var").expect("var fetch registered");
    let ctx = SampleContext::default();

    set_proc_var("proc.test_sample_key", "sample_value_123".to_string());

    // Fetching existing proc var
    assert_eq!(
        (var_fetch.func)(&ctx, &["proc.test_sample_key".to_string()]),
        Some(Sample::Str("sample_value_123".to_string()))
    );

    // Fetching non-existent proc var with fallback default
    assert_eq!(
        (var_fetch.func)(&ctx, &["proc.non_existent_key".to_string(), "fallback_val".to_string()]),
        Some(Sample::Str("fallback_val".to_string()))
    );

    // Fetching non-existent proc var without fallback
    assert_eq!(
        (var_fetch.func)(&ctx, &["proc.non_existent_key".to_string()]),
        None
    );

    // Fetching via Expr evaluation
    let expr = Expr::parse("var(proc.test_sample_key) -m str sample_value_123").unwrap();
    assert!(expr.eval(reg, &ctx));
}

/// Tests arithmetic converters resolving `proc.` variable arguments.
#[test]
fn test_converter_with_proc_var_resolution() {
    let reg = sample_registry();
    let ctx = SampleContext::default();

    set_proc_var("proc.delta", "42".to_string());
    set_proc_var("proc.multiplier", "3".to_string());

    let expr_add = Expr::parse("int(100),add(proc.delta) -m eq 142").unwrap();
    assert!(expr_add.eval(reg, &ctx));

    let expr_mul = Expr::parse("int(10),mul(proc.multiplier) -m eq 30").unwrap();
    assert!(expr_mul.eval(reg, &ctx));
}

/// Tests `eval_all_samples` on multi-value sample fetches and matching logic.
#[test]
fn test_expr_eval_all_samples() {
    let reg = sample_registry();

    // PROXY protocol TLV data:
    // Format: type (1 byte), length (2 bytes BE), value (length bytes)
    // TLV type 0x01: "value1" (6 bytes)
    // TLV type 0x01: "value2" (6 bytes)
    let mut tlv_bytes = Vec::new();
    tlv_bytes.extend_from_slice(&[0x01, 0x00, 0x06]);
    tlv_bytes.extend_from_slice(b"value1");
    tlv_bytes.extend_from_slice(&[0x01, 0x00, 0x06]);
    tlv_bytes.extend_from_slice(b"value2");

    let ctx = SampleContext {
        proxy_tlvs: Some(&tlv_bytes),
        ..Default::default()
    };

    let expr = Expr::parse("fc_pp_tlv(0x01)").unwrap();
    let samples = expr.eval_all_samples(reg, &ctx);
    assert_eq!(samples.len(), 2);
    assert_eq!(samples[0], Sample::Bin(b"value1".to_vec()));
    assert_eq!(samples[1], Sample::Bin(b"value2".to_vec()));

    // Matcher matches if any sample in the set satisfies the condition
    let expr_match1 = Expr::parse("fc_pp_tlv(0x01) -m str value1").unwrap();
    assert!(expr_match1.eval(reg, &ctx));

    let expr_match2 = Expr::parse("fc_pp_tlv(0x01) -m str value2").unwrap();
    assert!(expr_match2.eval(reg, &ctx));

    let expr_no_match = Expr::parse("fc_pp_tlv(0x01) -m str value3").unwrap();
    assert!(!expr_no_match.eval(reg, &ctx));
}

/// Tests that bare non-numeric converter arguments like `add(foo)` are rejected at parse time.
#[test]
fn test_bare_non_numeric_converter_args_rejected() {
    let invalid_expressions = [
        "int(100),add(foo)",
        "int(100),sub(bar)",
        "int(100),mul(baz)",
        "int(100),div(qux)",
        "int(100),mod(invalid)",
        "int(100),and(bad)",
        "int(100),or(flag)",
        "int(100),xor(mask)",
        // T341: parentheses do not nest in an argument; HAProxy 3.5-dev8: "invalid args in
        // converter 'add' : expects an integer or a variable name."
        "int(100),add(var(req.offset))",
    ];

    for expr_str in invalid_expressions {
        let res = Expr::parse(expr_str);
        assert!(
            res.is_err(),
            "Expr::parse('{expr_str}') should fail due to bare non-numeric argument, but succeeded: {res:?}"
        );
    }

    // Controls: valid numbers and scoped variables MUST still parse successfully
    let valid_expressions = [
        "int(100),add(10)",
        "int(100),add(-5)",
        "int(100),add(0x10)",
        "int(100),add(proc.delta)",
        "int(100),mul(3)",
    ];

    for expr_str in valid_expressions {
        let res = Expr::parse(expr_str);
        assert!(
            res.is_ok(),
            "Expr::parse('{expr_str}') should succeed, but failed: {res:?}"
        );
    }
}



/// `fc_pp_unique_id` is `fc_pp_tlv(0x05)`'s first occurrence, as a string
/// (`smp_fetch_fc_pp_unique_id`, src/connection.c).
#[test]
fn fc_pp_unique_id_is_the_first_unique_id_tlv() {
    let reg = sample_registry();
    let mut tlvs = vec![0x01, 0x00, 0x01, b'x'];
    tlvs.extend_from_slice(&[0x05, 0x00, 0x03]);
    tlvs.extend_from_slice(b"one");
    tlvs.extend_from_slice(&[0x05, 0x00, 0x03]);
    tlvs.extend_from_slice(b"two");
    let ctx = SampleContext { proxy_tlvs: Some(&tlvs), ..Default::default() };
    let expr = Expr::parse("fc_pp_unique_id").unwrap();
    assert_eq!(expr.eval_all_samples(reg, &ctx), [Sample::Str("one".into())]);
    let none = SampleContext { proxy_tlvs: Some(&[0x01, 0x00, 0x00]), ..Default::default() };
    assert!(expr.eval_all_samples(reg, &none).is_empty());
}
