// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `hmac` and `url_enc` arguments `HAProxy` refuses when the configuration is read (T147
//! item 2). Before this, a bad base64 key, an unknown algorithm or `url_enc(path)` loaded,
//! and the converter then produced no sample (or, for `url_enc`, ignored its argument) on
//! every request.
//!
//! Measured against `HAProxy` 3.5-dev8-885761-29, 2026-10-04, `haproxy -c -f` with
//! `http-request set-var(txn.x) str(a),<converter>`:
//!
//! * `hmac(sha256,Zm9v!)`, `hmac(sha256,Zm9)`, `hmac(sha256,Zm9v==)`, `hmac(sha256,var(txn.k))`:
//!   "invalid args in converter 'hmac' : failed to parse key : argument needs to be base64
//!   encoded, and can either be a string or a variable."
//! * `hmac(nosuch,Zm9v)` and `hmac(,Zm9v)`: "invalid args in converter 'hmac' : algorithm
//!   must be a valid OpenSSL message digest name.."
//! * `hmac(sha256)`, `hmac()`, `hmac`: "invalid arg 2 in converter 'hmac' : missing arguments
//!   (got 1/2), type 'string' expected."
//! * `url_enc(path)`, `(foo)`, `(Query)`, `(fragment)`: "invalid args in converter 'url_enc'
//!   : Unexpected encode type. Allowed value is 'query'."
//! * accepted: `hmac(sha256,Zm9v)`, `hmac(SHA256,Zm9v)`, `hmac(SHA-256,Zm9v)`,
//!   `hmac(sha2-256,Zm9v)`, `hmac(sha256,)`, `hmac(sha256,Zm8=)`, `hmac(sha256,txn.k)`,
//!   `url_enc`, `url_enc()`, `url_enc(query)`.

use std::process::Command;

fn check(expr: &str) -> (Option<i32>, String) {
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind 127.0.0.1:18080\n  http-request set-var(txn.x) {expr}\n  default_backend be\n\
         backend be\n  server s1 127.0.0.1:1\n"
    );
    let path = std::env::temp_dir().join(format!("ibex_convref_{}_{:x}.cfg", std::process::id(), expr.len() * 31 + expr.bytes().map(usize::from).sum::<usize>()));
    std::fs::write(&path, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&path);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

const KEY: &str = "invalid args in converter 'hmac' : failed to parse key : argument needs to be base64 encoded, and can either be a string or a variable.";
const ALG: &str = "invalid args in converter 'hmac' : algorithm must be a valid OpenSSL message digest name..";
const MISSING: &str = "invalid arg 2 in converter 'hmac' : missing arguments (got 1/2), type 'string' expected.";
const ENC: &str = "invalid args in converter 'url_enc' : Unexpected encode type. Allowed value is 'query'.";

#[test]
fn bad_hmac_and_url_enc_arguments_are_refused_at_load() {
    let refused: &[(&str, &str)] = &[
        ("str(a),hmac(sha256,Zm9v!)", KEY),
        ("str(a),hmac(sha256,Zm9)", KEY),
        ("str(a),hmac(sha256,Zm9v==)", KEY),
        ("str(a),hmac(sha256,var(txn.k))", KEY),
        ("str(a),hmac(nosuch,Zm9v)", ALG),
        ("str(a),hmac(,Zm9v)", ALG),
        ("str(a),hmac(sha256)", MISSING),
        ("str(a),hmac()", MISSING),
        ("str(a),hmac", MISSING),
        ("str(a),url_enc(path)", ENC),
        ("str(a),url_enc(foo)", ENC),
        ("str(a),url_enc(Query)", ENC),
        ("str(a),url_enc(fragment)", ENC),
    ];
    for (expr, text) in refused {
        let (code, out) = check(expr);
        assert_eq!(code, Some(1), "`{expr}` must be refused: {out}");
        assert!(out.contains(text), "`{expr}`: expected {text:?} in: {out}");
    }
}

#[test]
fn valid_hmac_and_url_enc_arguments_load() {
    for expr in [
        "str(a),hmac(sha256,Zm9v)",
        "str(a),hmac(SHA256,Zm9v)",
        "str(a),hmac(SHA-256,Zm9v)",
        "str(a),hmac(sha2-256,Zm9v)",
        "str(a),hmac(sha1,Zm9v)",
        "str(a),hmac(sha256,)",
        "str(a),hmac(sha256,Zm8=)",
        "str(a),hmac(sha256,txn.k)",
        "str(a),url_enc",
        "str(a),url_enc()",
        "str(a),url_enc(query)",
    ] {
        let (code, out) = check(expr);
        assert_eq!(code, Some(0), "`{expr}` must load: {out}");
    }
}

/// A digest `OpenSSL` knows and Ibex does not compute is refused rather than loaded to
/// yield no sample.
#[test]
fn a_digest_ibex_does_not_implement_is_refused() {
    let (code, out) = check("str(a),hmac(sha3-256,Zm9v)");
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("hmac"), "{out}");
}

/// T341: `strcmp` and `secure_memcmp` compare with a variable, and `HAProxy` refuses anything
/// else at load (`smp_check_strcmp`, `smp_check_secure_memcmp`); Ibex compared the literal.
/// Measured on 3.5-dev8-885761-29, 2026-10-17: `strcmp(abc)` "failed to register variable name
/// 'abc'." (also `txn.`, `txn.a-b`, `foo.x`, `TXN.x`, `txn.a$`, `var(txn.k` for
/// `secure_memcmp(var(txn.k))`); `strcmp()` and `strcmp` "missing variable name.";
/// `strcmp(txn.k,x)` "invalid arg 2 in converter 'strcmp' : expected ')' before ',x)'.";
/// accepted: `proc.x`, `sess.x`, `txn.x`, `req.x`, `res.x`, `check.x`, `txn.a.b`.
#[test]
fn strcmp_and_secure_memcmp_need_a_variable() {
    for conv in ["strcmp", "secure_memcmp"] {
        let refused = [
            (format!("str(abc),{conv}(abc)"), format!("invalid args in converter '{conv}' : failed to register variable name 'abc'.")),
            (format!("str(abc),{conv}(txn.)"), format!("invalid args in converter '{conv}' : failed to register variable name 'txn.'.")),
            (format!("str(abc),{conv}(txn.a-b)"), format!("invalid args in converter '{conv}' : failed to register variable name 'txn.a-b'.")),
            (format!("str(abc),{conv}(foo.x)"), format!("invalid args in converter '{conv}' : failed to register variable name 'foo.x'.")),
            (format!("str(abc),{conv}(TXN.x)"), format!("invalid args in converter '{conv}' : failed to register variable name 'TXN.x'.")),
            (format!("str(abc),{conv}(var(txn.k))"), format!("invalid args in converter '{conv}' : failed to register variable name 'var(txn.k'.")),
            (format!("str(abc),{conv}()"), format!("invalid args in converter '{conv}' : missing variable name.")),
            (format!("str(abc),{conv}"), format!("invalid args in converter '{conv}' : missing variable name.")),
            (format!("str(abc),{conv}(txn.k,x)"), format!("invalid arg 2 in converter '{conv}' : expected ')' before ',x)'.")),
        ];
        for (expr, text) in &refused {
            let (code, out) = check(expr);
            assert_eq!(code, Some(1), "`{expr}` must be refused: {out}");
            assert!(out.contains(text.as_str()), "`{expr}`: expected {text:?} in: {out}");
        }
        for var in ["proc.x", "sess.x", "txn.x", "req.x", "res.x", "check.x", "txn.a.b"] {
            let expr = format!("str(abc),{conv}({var})");
            let (code, out) = check(&expr);
            assert_eq!(code, Some(0), "`{expr}` must load: {out}");
        }
    }
}

/// T341: `ip.fp(<mode>)` takes one integer (`ARG1(0,SINT)`), and a converter whose input the
/// previous converter's output cannot be cast to is refused (`sample_casts[prev][in]` is
/// NULL: a `bin` is no integer for `bool`). Measured with `haproxy -c` on
/// 3.5-dev8-885761-29, 2026-10-17; Ibex loaded each and the expression gave no sample. An
/// `ANY` output (`set-var`, `when`) leaves any converter applicable after it.
#[test]
fn ip_fp_arguments_and_converter_input_types_are_checked_at_load() {
    let refused = [
        ("src,ip.fp(abc)", "invalid arg 1 in converter 'ip.fp' : failed to parse 'abc' as type 'integer' at position 1."),
        ("src,ip.fp(1a)", "invalid arg 1 in converter 'ip.fp' : failed to parse '1a' as type 'integer' at position 1."),
        ("src,ip.fp(1,2)", "invalid arg 2 in converter 'ip.fp' : expected ')' before ',2)'."),
        ("req.body,ip.data,bool", "converter 'bool' cannot be applied."),
        ("src,ip.data,bool", "converter 'bool' cannot be applied."),
        ("bin(00),ip.data,debug,bool", "converter 'bool' cannot be applied."),
        ("bin(00),ip.data,add(1)", "converter 'add' cannot be applied."),
        ("bin(00),ip.data,ipmask(24)", "converter 'ipmask' cannot be applied."),
        ("bin(00),ip.data,bool(x)", "converter 'bool' cannot be applied."),
    ];
    let accepted = [
        "src,ip.fp", "src,ip.fp()", "src,ip.fp(1)", "src,ip.fp(-1)", "req.body,ip.data", "req.body,ip.data,hex",
        "bin(00),ip.data,hex,bool", "bin(00),ip.data,set-var(txn.y),bool", "bin(00),ip.data,when(normal),bool", "str(a),length,ipmask(24)",
    ];
    let mut wrong = Vec::new();
    for (expr, text) in refused {
        let (code, out) = check(expr);
        if code != Some(1) || !out.contains(text) {
            wrong.push(format!("`{expr}`: exit {code:?}, expected {text:?}: {}", out.trim()));
        }
    }
    for expr in accepted {
        let (code, out) = check(expr);
        if code != Some(0) {
            wrong.push(format!("`{expr}` must load: {}", out.trim()));
        }
    }
    assert!(wrong.is_empty(), "{} cases differ from HAProxy:\n{}", wrong.len(), wrong.join("\n"));
}

/// T341: `sample_parse_expr` skips a run of commas between converters (`while (*endt == ',')`),
/// and at the end of a rule's expression; in a `%[...]` the `]` is left, and the converter
/// after a trailing comma is the empty name. Measured with `haproxy -c` on
/// 3.5-dev8-885761-29, 2026-10-17: Ibex refused `str(a),,lower` everywhere ("Invalid
/// converter name ''") once expressions were parsed at load (2ea14cbe).
#[test]
fn repeated_commas_between_converters_are_skipped() {
    for expr in ["str(a),,lower", "str(a),,,lower", "str(a),lower,,upper", "str(a),", "str(a),lower,"] {
        let (code, out) = check(expr);
        assert_eq!(code, Some(0), "`{expr}` must load: {out}");
    }
    for expr in ["str(a),,lower", "str(a),lower,,upper"] {
        let (code, out) = check(&format!("str(b)\n  http-request set-header x %[{expr}]\n  log-format %[{expr}]"));
        assert_eq!(code, Some(0), "`%[{expr}]` must load: {out}");
    }
    for expr in ["str(a),", "str(a),lower,", "str(a),,"] {
        let (code, out) = check(&format!("str(b)\n  http-request set-header x %[{expr}]"));
        assert!(code == Some(1) && out.contains("unknown converter ''"), "`%[{expr}]`: exit {code:?}: {out}");
    }
    for line in ["log-format %[str(a),]", "log-format %[str(a),lower,]", "unique-id-format %[str(a),,]"] {
        let (code, out) = check(&format!("str(b)\n  {line}"));
        assert!(code == Some(1) && out.contains("unknown converter ''"), "`{line}`: exit {code:?}: {out}");
    }
}
