// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `aes_cbc_enc`, `aes_cbc_dec`, `aes_gcm_enc`, `aes_gcm_dec` and `language` (T140).
//! Every expected value was measured on `HAProxy` 3.5-dev8-885761-29 with the same
//! expression (`http-request return` with one header per converter), requests as given.
//! The AES values are ciphertexts and tags of the fixed plaintext below.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

const PRE: &str = "  http-request set-var(txn.plain) str(\"Hello from HAProxy AES-CBC\")\n\
  http-request set-var(txn.nonce) str(\"MTIzNDU2Nzg5MDEyMzQ1Ng==\")\n\
  http-request set-var(txn.short) str(\"MTIzNDU2Nzg5MDEy\")\n\
  http-request set-var(txn.key) str(\"Zm9vb2Zvb29mb29vb29vbw==\")\n\
  http-request set-var(txn.aad) str(\"dGVzdAo=\")\n";
const K256: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
const K192: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3";
const PLAIN_REQ: &str = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";

/// Run `rules` in a frontend, send each raw request; return the `x-*` header lines of
/// each response as `name: value`.
fn run(rules: &str, requests: &[String]) -> Vec<Vec<String>> {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n{rules}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let reqs = requests.to_vec();
    let client = thread::spawn(move || {
        reqs.iter()
            .map(|r| {
                let mut c = TcpStream::connect(fe).expect("connect");
                c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                c.write_all(r.as_bytes()).expect("send");
                let mut out = String::new();
                let _ = c.read_to_string(&mut out);
                out.lines()
                    .filter(|l| l.to_ascii_lowercase().starts_with("x-"))
                    .map(|l| l.trim_end().to_string())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    client.join().expect("client")
}

/// Each row is `(converter chain applied to txn.plain, lines expected)`. Row `i` stores its
/// result in `txn.r<i>` (`r:` line) and, when it names `txn.t<i>`, a tag (`t:` line). A
/// chain that yields no sample leaves its variable unset, which `HAProxy` shows as no header.
fn chain(rows: &[(&str, &[&str])]) {
    let mut rules = String::from(PRE);
    for (i, (expr, _)) in rows.iter().enumerate() {
        rules.push_str(&format!("  http-request set-var(txn.r{i}) var(txn.plain),{expr}\n"));
    }
    rules.push_str("  http-request return status 200");
    for i in 0..rows.len() {
        rules.push_str(&format!(" hdr x-r{i} \"%[var(txn.r{i})]\" hdr x-t{i} \"%[var(txn.t{i})]\""));
    }
    rules.push('\n');
    let got = run(&rules, &[PLAIN_REQ.to_string()]);
    for (i, (expr, want)) in rows.iter().enumerate() {
        let mine: Vec<String> = got[0]
            .iter()
            .filter_map(|l| {
                l.strip_prefix(&format!("x-r{i}:"))
                    .map(|v| format!("r:{v}"))
                    .or_else(|| l.strip_prefix(&format!("x-t{i}:")).map(|v| format!("t:{v}")))
            })
            .collect();
        let want: Vec<String> = want.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(mine, want, "`{expr}`");
    }
}

#[test]
fn aes_cbc_encrypts_as_haproxy_does() {
    let k256 = format!("aes_cbc_enc(256,txn.nonce,\"{K256}\"),base64");
    let k192 = format!("aes_cbc_enc(192,txn.nonce,\"{K192}\"),base64");
    let k192_long = format!("aes_cbc_enc(192,txn.nonce,\"{K256}\"),base64");
    let k128_long = format!("aes_cbc_enc(128,txn.nonce,\"{K192}\"),base64");
    chain(&[
        ("aes_cbc_enc(128,txn.nonce,txn.key),base64", &["r: XJxppHFb7/atHE5XLwst52Ok8eWRd+NV/xYR09OWugs="]),
        // the aad is accepted and ignored
        ("aes_cbc_enc(128,txn.nonce,txn.key,txn.aad),base64", &["r: XJxppHFb7/atHE5XLwst52Ok8eWRd+NV/xYR09OWugs="]),
        ("aes_cbc_enc(128,txn.nonce,txn.key,\"\"),base64", &["r: XJxppHFb7/atHE5XLwst52Ok8eWRd+NV/xYR09OWugs="]),
        // literals instead of variables
        (
            "aes_cbc_enc(128,\"MTIzNDU2Nzg5MDEyMzQ1Ng==\",\"Zm9vb2Zvb29mb29vb29vbw==\"),base64",
            &["r: XJxppHFb7/atHE5XLwst52Ok8eWRd+NV/xYR09OWugs="],
        ),
        // a nonce shorter than a block is padded with zeros, a longer one cut
        ("aes_cbc_enc(128,txn.short,txn.key),base64", &["r: TbqJjpKNIrc2CAa+NqiZ5mqaDF5XZ59nsLvLxDJ7Bwg="]),
        ("aes_cbc_enc(128,\"MTIz\",txn.key),base64", &["r: oo0f+WXdKnKUXPDpVaVjObTz9qG245mjmo8Qaj6Cy18="]),
        ("aes_cbc_enc(128,\"\",txn.key),base64", &["r: zFfdYtgEdBh7ASPUgX/fpXqFEGTRhahPhnGboSR9SZE="]),
        (
            "aes_cbc_enc(128,\"MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=\",txn.key),base64",
            &["r: XJxppHFb7/atHE5XLwst52Ok8eWRd+NV/xYR09OWugs="],
        ),
        (&k256, &["r: rh9z/ousFIlvqZY+4HoGf8bUgYY74Wk6tLLKBiivqlQ="]),
        (&k192, &["r: O9oU9k3dxWUB/JwWTX2dQ1iv9bh0ZaAk18/lwrmYMaA="]),
        // a key longer than the size asked for is cut, a shorter one yields nothing
        (&k192_long, &["r: O9oU9k3dxWUB/JwWTX2dQ1iv9bh0ZaAk18/lwrmYMaA="]),
        (&k128_long, &["r: iqCqi/6TJEqtpgHJwQbll6wYKkW1m5ocGIBLqSy4zQE="]),
        ("aes_cbc_enc(256,txn.nonce,txn.key),base64", &[]),
        ("aes_cbc_enc(128,txn.nonce,\"\"),base64", &[]),
        ("aes_cbc_enc(128,txn.nonce,txn.nokey),base64", &[]),
        ("aes_cbc_enc(128,txn.nonset,txn.key),base64", &[]),
    ]);
}

#[test]
fn aes_cbc_decrypts_as_haproxy_does() {
    chain(&[
        (
            "aes_cbc_enc(128,txn.nonce,txn.key),aes_cbc_dec(128,txn.nonce,txn.key)",
            &["r: Hello from HAProxy AES-CBC"],
        ),
        (
            "aes_cbc_enc(128,txn.nonce,txn.key),aes_cbc_dec(128,txn.nonce,txn.key,txn.aad)",
            &["r: Hello from HAProxy AES-CBC"],
        ),
        (
            "aes_cbc_enc(128,txn.short,txn.key),aes_cbc_dec(128,\"MTIzNDU2Nzg5MDEy\",\"Zm9vb2Zvb29mb29vb29vbw==\")",
            &["r: Hello from HAProxy AES-CBC"],
        ),
        // another nonce garbles bytes 12..16 of the first block only
        (
            "aes_cbc_enc(128,txn.nonce,txn.key),aes_cbc_dec(128,txn.short,txn.key),hex",
            &["r: 48656C6C6F2066726F6D2048726447597879204145532D434243"],
        ),
        // a wrong size or key breaks the padding; the plain text is no cipher text
        ("aes_cbc_enc(128,txn.nonce,txn.key),aes_cbc_dec(192,txn.nonce,txn.key)", &[]),
        ("aes_cbc_dec(128,txn.nonce,txn.key)", &[]),
        (
            "aes_cbc_enc(128,txn.nonce,txn.key),aes_cbc_enc(128,txn.nonce,txn.key),aes_cbc_dec(128,txn.nonce,txn.key),aes_cbc_dec(128,txn.nonce,txn.key)",
            &["r: Hello from HAProxy AES-CBC"],
        ),
        ("aes_cbc_enc(128,txn.nonce,txn.key),aes_cbc_dec(128,txn.nonce,txn.nokey)", &[]),
    ]);
}

#[test]
fn aes_gcm_encrypts_as_haproxy_does() {
    let g256 = format!("aes_gcm_enc(256,txn.short,\"{K256}\",txn.t5),base64");
    let g192 = format!("aes_gcm_enc(192,txn.short,\"{K192}\",txn.t6),base64");
    chain(&[
        (
            "aes_gcm_enc(128,txn.short,txn.key,txn.t0),base64",
            &["r: qWRhBzAKeMtbgdzzmICFTrNrxugSc5zpQFI=", "t: AZEgdtjrCGaNpF1PLC/Qog=="],
        ),
        // an empty aad is no aad; a real one changes the tag only
        (
            "aes_gcm_enc(128,txn.short,txn.key,txn.t1,\"\"),base64",
            &["r: qWRhBzAKeMtbgdzzmICFTrNrxugSc5zpQFI=", "t: AZEgdtjrCGaNpF1PLC/Qog=="],
        ),
        (
            "aes_gcm_enc(128,txn.short,txn.key,txn.t2,txn.aad),base64",
            &["r: qWRhBzAKeMtbgdzzmICFTrNrxugSc5zpQFI=", "t: T0Q/oJEE9Z9khphqi5ovEw=="],
        ),
        // any nonce length is taken as it comes
        (
            "aes_gcm_enc(128,\"MTIz\",txn.key,txn.t3),base64",
            &["r: ZHP9GGutrevfHIip7waYQ6vWbtUl7rWI+VQ=", "t: su2rbT87+a8kn4FiV3u37w=="],
        ),
        (
            "aes_gcm_enc(128,\"MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=\",txn.key,txn.t4),base64",
            &["r: QEjm3CvBIoZTAJXoLVYSGuhnfJBQHpGMRSE=", "t: EMny2gj/R/k9RGHJCOAsbQ=="],
        ),
        (&g256, &["r: wT+ln8lYViw88iGtR79x/O6TyTN9rzXTBR4=", "t: 8WSfPBl8MHd3vv+IxqPD7A=="]),
        (&g192, &["r: 4Nw2QsEtqe/jNUawhMaRUIZ+vcI8pW/wBAY=", "t: teIUiD+HEBS/+/FITFzPUA=="]),
        // an empty nonce, a key too short for the size: nothing
        ("aes_gcm_enc(128,\"\",txn.key,txn.t7),base64", &[]),
        ("aes_gcm_enc(256,txn.short,txn.key,txn.t8),base64", &[]),
    ]);
}

#[test]
fn aes_gcm_decrypts_and_checks_the_tag() {
    chain(&[
        (
            "aes_gcm_enc(128,txn.short,txn.key,txn.t0),aes_gcm_dec(128,txn.short,txn.key,txn.t0)",
            &["r: Hello from HAProxy AES-CBC", "t: AZEgdtjrCGaNpF1PLC/Qog=="],
        ),
        // a literal tag
        (
            "aes_gcm_enc(128,txn.short,txn.key,txn.t1),aes_gcm_dec(128,txn.short,txn.key,\"AZEgdtjrCGaNpF1PLC/Qog==\")",
            &["r: Hello from HAProxy AES-CBC", "t: AZEgdtjrCGaNpF1PLC/Qog=="],
        ),
        (
            "aes_gcm_enc(128,txn.short,txn.key,txn.t2,txn.aad),aes_gcm_dec(128,txn.short,txn.key,txn.t2,txn.aad)",
            &["r: Hello from HAProxy AES-CBC", "t: T0Q/oJEE9Z9khphqi5ovEw=="],
        ),
        // the tag, the aad, the nonce or the key not those of the encryption: no sample
        (
            "aes_gcm_enc(128,txn.short,txn.key,txn.t3,txn.aad),aes_gcm_dec(128,txn.short,txn.key,txn.t3)",
            &["t: T0Q/oJEE9Z9khphqi5ovEw=="],
        ),
        (
            "aes_gcm_enc(128,txn.short,txn.key,txn.t4),aes_gcm_dec(128,txn.short,txn.key,\"AAAAAAAAAAAAAAAAAAAAAA==\")",
            &["t: AZEgdtjrCGaNpF1PLC/Qog=="],
        ),
        (
            "aes_gcm_enc(128,txn.short,txn.key,txn.t5),aes_gcm_dec(128,txn.short,txn.key,\"AAAA\")",
            &["t: AZEgdtjrCGaNpF1PLC/Qog=="],
        ),
        (
            "aes_gcm_enc(128,txn.short,txn.key,txn.t6),aes_gcm_dec(128,txn.short,txn.key,txn.nonexist)",
            &["t: AZEgdtjrCGaNpF1PLC/Qog=="],
        ),
        (
            "aes_gcm_enc(128,txn.short,txn.key,txn.t7),aes_gcm_dec(128,txn.nonce,txn.key,txn.t7)",
            &["t: AZEgdtjrCGaNpF1PLC/Qog=="],
        ),
        // the tag variable may have any scope
        (
            "aes_gcm_enc(128,txn.short,txn.key,sess.t),aes_gcm_dec(128,txn.short,txn.key,sess.t)",
            &["r: Hello from HAProxy AES-CBC"],
        ),
    ]);
}

#[test]
fn the_tag_variable_outlives_the_rule_that_set_it() {
    let rules = format!(
        "{PRE}  http-request set-var(txn.r) var(txn.plain),aes_gcm_enc(128,txn.short,txn.key,txn.t),base64\n\
         \x20 http-request return status 200\n\
         \x20 http-after-response set-header x-t \"%[var(txn.t)]\"\n\
         \x20 http-after-response set-header x-th \"%[var(txn.t),hex]\"\n"
    );
    let got = run(&rules, &[PLAIN_REQ.to_string()]);
    // The variable holds the base64 text of the tag, so its hex is that text's.
    assert_eq!(
        got[0],
        vec!["x-t: AZEgdtjrCGaNpF1PLC/Qog==", "x-th: 415A456764746A724347614E704631504C432F516F673D3D"]
    );
}

#[test]
fn process_variables_hold_the_key_and_the_tag() {
    let rules = format!(
        "{PRE}  http-request set-var(proc.t140key) str(\"Zm9vb2Zvb29mb29vb29vbw==\")\n\
         \x20 http-request set-var(txn.r) var(txn.plain),aes_gcm_enc(128,txn.short,proc.t140key,proc.t140tag),base64\n\
         \x20 http-request set-var(txn.d) var(txn.r),b64dec,aes_gcm_dec(128,txn.short,proc.t140key,proc.t140tag)\n\
         \x20 http-request return status 200 hdr x-r \"%[var(txn.r)]\" hdr x-t \"%[var(proc.t140tag)]\" hdr x-d \"%[var(txn.d)]\"\n"
    );
    let got = run(&rules, &[PLAIN_REQ.to_string()]);
    assert_eq!(
        got[0],
        vec![
            "x-r: qWRhBzAKeMtbgdzzmICFTrNrxugSc5zpQFI=",
            "x-t: AZEgdtjrCGaNpF1PLC/Qog==",
            "x-d: Hello from HAProxy AES-CBC"
        ]
    );
}

fn check(expr: &str) -> (Option<i32>, String) {
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind 127.0.0.1:18080\n  http-request set-var(txn.x) {expr}\n  default_backend be\n\
         backend be\n  server s1 127.0.0.1:1\n"
    );
    let sum: usize = expr.bytes().map(usize::from).sum();
    let path = std::env::temp_dir().join(format!("ibex_aes_{}_{:x}.cfg", std::process::id(), expr.len() * 31 + sum));
    std::fs::write(&path, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&path);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn bad_aes_arguments_are_refused_at_load() {
    let b64 = "argument needs to be base64 encoded, and can either be a string or a variable.";
    let size = |c: &str| format!("invalid args in converter '{c}' : key size must be 128, 192 or 256 (bits)..");
    let missing = |n: u8, c: &str, got: u8, of: u8| {
        format!("invalid arg {n} in converter '{c}' : missing arguments (got {got}/{of}), type 'string' expected.")
    };
    let null = "invalid args in converter 'aes_gcm_enc' : failed to parse aead_tag : (null).".to_string();
    let refused: Vec<(&str, String)> = vec![
        ("str(a),aes_cbc_enc(100,txn.n,txn.k)", size("aes_cbc_enc")),
        ("str(a),aes_gcm_dec(512,txn.n,txn.k,txn.t)", size("aes_gcm_dec")),
        ("str(a),aes_cbc_enc(128,txn.n)", missing(3, "aes_cbc_enc", 2, 3)),
        ("str(a),aes_cbc_dec(128)", missing(2, "aes_cbc_dec", 1, 3)),
        ("str(a),aes_gcm_enc(128,txn.n,txn.k)", missing(4, "aes_gcm_enc", 3, 4)),
        (
            "str(a),aes_cbc_enc(abc,txn.n,txn.k)",
            "invalid arg 1 in converter 'aes_cbc_enc' : failed to parse 'abc' as type 'integer' at position 1.".into(),
        ),
        (
            "str(a),aes_cbc_enc(128,\"!!!\",txn.k)",
            format!("invalid args in converter 'aes_cbc_enc' : failed to parse nonce : {b64}"),
        ),
        (
            "str(a),aes_cbc_enc(128,txn.n,\"!!!\")",
            format!("invalid args in converter 'aes_cbc_enc' : failed to parse key : {b64}"),
        ),
        (
            "str(a),aes_cbc_dec(128,txn.n,txn.k,\"!!\")",
            format!("invalid args in converter 'aes_cbc_dec' : failed to parse aad : {b64}"),
        ),
        (
            "str(a),aes_gcm_enc(128,txn.n,txn.k,txn.t,\"!!\")",
            format!("invalid args in converter 'aes_gcm_enc' : failed to parse aad : {b64}"),
        ),
        (
            "str(a),aes_gcm_dec(128,txn.n,txn.k,\"abc\")",
            format!("invalid args in converter 'aes_gcm_dec' : failed to parse aead_tag : {b64}"),
        ),
        (
            "str(a),aes_cbc_enc",
            "invalid arg 1 in converter 'aes_cbc_enc' : expected type 'integer' at position 1, but got nothing.".into(),
        ),
        (
            "str(a),aes_gcm_dec(,txn.n,txn.k,txn.t)",
            "invalid arg 1 in converter 'aes_gcm_dec' : expected type 'integer' at position 1, but got nothing.".into(),
        ),
        (
            "str(a),aes_gcm_dec(128,txn.n,txn.k,txn.t,txn.aad,x)",
            "invalid arg 5 in converter 'aes_gcm_dec' : expected ')' before ',x)'.".into(),
        ),
        (
            "str(a),aes_cbc_enc(128,txn.n,txn.k,txn.a,x)",
            "invalid arg 4 in converter 'aes_cbc_enc' : expected ')' before ',x".into(),
        ),
        (
            "str(a),aes_gcm_enc(128,txn.n,txn.k,)",
            "invalid args in converter 'aes_gcm_enc' : failed to parse aead_tag : Empty variable name cannot be accepted.".into(),
        ),
        // the encryption's tag is an output, so it names a variable
        ("str(a),aes_gcm_enc(128,txn.n,txn.k,\"abc\")", null.clone()),
        ("str(a),aes_gcm_enc(128,txn.n,txn.k,foo.t)", null),
    ];
    for (expr, text) in &refused {
        let (code, out) = check(expr);
        assert_eq!(code, Some(1), "`{expr}` must be refused: {out}");
        assert!(out.contains(text.as_str()), "`{expr}`: expected {text:?} in: {out}");
    }
}

#[test]
fn good_aes_arguments_load() {
    for expr in [
        "str(a),aes_cbc_enc(128,txn.n,txn.k)",
        "str(a),aes_cbc_enc(256,txn.n,txn.k,txn.a)",
        "str(a),aes_cbc_dec(192,\"MTIz\",\"Zm9v\",\"dGVzdAo=\")",
        "str(a),aes_gcm_enc(128,txn.n,txn.k,txn.t)",
        "str(a),aes_gcm_enc(128,\"\",\"\",sess.t,\"\")",
        "str(a),aes_gcm_dec(128,txn.n,txn.k,\"AZEgdtjrCGaNpF1PLC/Qog==\",txn.a)",
    ] {
        let (code, out) = check(expr);
        assert_eq!(code, Some(0), "`{expr}` must load: {out}");
    }
}

/// `language(list)` on each `Accept-Language` value (`""` sends none): `want` is the value
/// the variable gets, `""` for no sample.
fn lang(list: &str, header_values: &[(&str, &str)]) {
    let rules = format!(
        "  http-request set-var(txn.l) req.fhdr(accept-language),language({list})\n\
         \x20 http-request return status 200 hdr x-l \"[%[var(txn.l)]]\" if {{ var(txn.l) -m found }}\n\
         \x20 http-request return status 200 hdr x-none y\n"
    );
    let reqs: Vec<String> = header_values
        .iter()
        .map(|(h, _)| {
            if h.is_empty() {
                PLAIN_REQ.to_string()
            } else {
                format!("GET / HTTP/1.1\r\nHost: x\r\nAccept-Language: {h}\r\nConnection: close\r\n\r\n")
            }
        })
        .collect();
    let got = run(&rules, &reqs);
    for ((h, want), got) in header_values.iter().zip(got) {
        let want = if want.is_empty() { "x-none: y".to_string() } else { format!("x-l: [{want}]") };
        assert_eq!(got, vec![want], "language({list}) on Accept-Language: {h:?}");
    }
}

#[test]
fn language_picks_the_listed_language_with_the_highest_q() {
    lang(
        "es;fr;en",
        &[
            ("fr;q=0.2, en;q=0.8, de", "en"),
            ("es-AR", "es"),
            ("fr;q=0, en;q=0.1", "en"),
            ("ja", ""),
            ("*", ""),
            ("en;q=0.5, *;q=0.9", "en"),
            // the comparison is case sensitive
            ("FR", ""),
            ("fr;q=1.000, en;q=0.999", "fr"),
            // equal q: the first in the header
            ("fr;q=0.5, en;q=0.5", "fr"),
            ("en;q=0.5, fr;q=0.5", "en"),
            ("en ; q = 0.3 , fr;q=0.2", "en"),
            ("fr;q= 0.1, en;q=0.05", "fr"),
            ("en;q=0.0001, fr;q=0.0002", ""),
            ("fr,en", "fr"),
            ("en-GB-oxendict", "en"),
            ("en_US", ""),
            ("", ""),
        ],
    );
}

#[test]
fn language_reads_a_q_value_as_haproxy_does() {
    lang(
        "fr;en",
        &[
            // not a q-value, or out of range: it counts as 1
            ("en, fr;q=2", "en"),
            ("en;q=0.9, fr;q=abc", "fr"),
            ("en;q=0.9, fr;q=1.5", "fr"),
            ("en;q=0.9, fr;q=-1", "fr"),
            ("en;q=0.9, fr;q=.6", "fr"),
            ("en;q=0.9, fr;q=", "fr"),
            ("en;q=0.9, fr;x=0.1", "fr"),
            ("en;q=0.9, fr;x=1;q=0.1", "fr"),
            // three decimals count
            ("en;q=0.5, fr;q=0.501", "fr"),
            ("en;q=0.5, fr;q=0.5001", "en"),
            ("en;q=0.5, fr;q=0.9x", "fr"),
            // a 0 that is not followed by a dot and digits is a null q
            ("fr;q=00.9", ""),
            ("fr;q=0,9", ""),
            ("fr;q=0.x", ""),
            ("fr;q=0.", ""),
            ("fr;q=0.000", ""),
            ("fr;q=0 .1", ""),
            ("fr;q=0.001", "fr"),
            // only a lower case q, and only straight after the language
            ("fr;Q=0.1, en;q=0.05", "fr"),
            ("fr;q=0.1;x=1, en;q=0.05", "fr"),
            ("fr ;q=0.1, en;q=0.2", "en"),
            // a token ends at a space, ';', ',' or the end, and then comes ';' or ','
            ("fr  en", ""),
            ("fr en;q=0.1", ""),
            ("-fr", ""),
            (",,fr", "fr"),
            ("fr,,en", "fr"),
            ("fr;", "fr"),
            ("fr;q", "fr"),
            ("fra", ""),
            ("f", ""),
        ],
    );
}

#[test]
fn language_matches_variants_on_their_dash_prefix() {
    lang("fr;fr-CA", &[("fr-CA", "fr"), ("fr-CA-x", "fr"), ("fr", "fr"), ("fr-US", "fr")]);
    // the first listed entry that the token is, or starts with followed by '-'
    lang("fr-CA;fr", &[("fr-CA", "fr-CA"), ("fr-CA-x", "fr-CA"), ("fr", "fr"), ("fr-US", "fr")]);
    lang("fr-CA-x", &[("fr-CA", ""), ("fr-CA-x", "fr-CA-x"), ("fr-CA-x-y", "fr-CA-x")]);
    lang("fr-CA;fr-CA-x", &[("fr-CA-x", "fr-CA")]);
    lang(
        "fr-CA;fr",
        &[("fr-CA;q=0.1, fr;q=0.5", "fr"), ("fr;q=0.1, fr-CA;q=0.5", "fr-CA"), ("fr-CA;q=0.5, fr;q=0.5", "fr-CA")],
    );
    lang("es-AR;fr-CA;*;en", &[("es-ar", ""), ("es-419", ""), ("*", "*"), ("en-GB;q=0.3, fr;q=0.2", "en")]);
    // any character but a space, ';' and ',' belongs to the token
    lang(
        "en_US;en.x;x/y;a+b;1;e",
        &[("en_US", "en_US"), ("en.x", "en.x"), ("x/y", "x/y"), ("a+b", "a+b"), ("1", "1"), ("e-", "e")],
    );
}

#[test]
fn language_default_is_used_when_nothing_matches() {
    lang(
        "de;it,none",
        &[("fr;q=0.2, en;q=0.8, de", "de"), ("es-AR", "none"), ("ja", "none"), ("*", "none"), ("fr;q=0", "none")],
    );
    lang(",x", &[("fr", "x"), ("en", "x")]);
    lang("en;fr,\"a b\"", &[("es", "a b"), ("fr", "fr")]);
    // no header, the fetch fails before the converter
    lang("de;it,none", &[("", "")]);
}

#[test]
fn language_applies_to_any_string() {
    let rules = "  http-request set-var(txn.l) str(en),language(fr;en)\n\
                 \x20 http-request return status 200 hdr x-l \"%[var(txn.l)]\"\n";
    let got = run(rules, &[PLAIN_REQ.to_string()]);
    assert_eq!(got[0], vec!["x-l: en"]);
}

/// `host_only` and `port_only` split at the last colon unless a `]` follows it; the port is
/// every byte after it read as a digit in an unsigned 32-bit number, 0 when there is none.
/// The strings.vtc test of `HAProxy` needs `[::1]:80` to give `[::1]`, which was `::1`.
#[test]
fn host_only_and_port_only_split_at_the_last_colon() {
    let cases: &[(&str, &str, &str)] = &[
        ("Example.COM:8080", "example.com", "8080"),
        ("[::1]:80", "[::1]", "80"),
        ("example.com", "example.com", "0"),
        ("[::1]", "[::1]", "0"),
        ("[::1", "[:", "1"),
        ("::1", ":", "1"),
        ("example.com:", "example.com", "0"),
        (":80", "", "80"),
        ("[::1]:", "[::1]", "0"),
        ("[::1]x", "[::1]x", "0"),
        ("[::1]:x", "[::1]", "72"),
        ("example.com:80:90", "example.com:80", "90"),
        ("[::1]:80:90", "[::1]:80", "90"),
        ("example.com:abc", "example.com", "5451"),
        ("example.com:80x", "example.com", "872"),
        ("[Ab::C]:8", "[ab::c]", "8"),
        ("a:65536", "a", "65536"),
        ("a:99999999999", "a", "1215752191"),
        ("a:4294967296", "a", "0"),
        ("a:-5", "a", "4294967271"),
        ("a: 5", "a", "4294967141"),
    ];
    let mut rules = String::new();
    for (i, (input, _, _)) in cases.iter().enumerate() {
        rules.push_str(&format!(
            "  http-request set-var(txn.h{i}) str(\"{input}\"),host_only\n\
             \x20 http-request set-var(txn.p{i}) str(\"{input}\"),port_only\n\
             \x20 http-after-response set-header x-h{i} \"[%[var(txn.h{i})]]\"\n\
             \x20 http-after-response set-header x-p{i} \"[%[var(txn.p{i})]]\"\n"
        ));
    }
    rules.push_str("  http-request return status 200\n");
    let got = run(&rules, &[PLAIN_REQ.to_string()]);
    for (i, (input, host, port)) in cases.iter().enumerate() {
        assert!(got[0].contains(&format!("x-h{i}: [{host}]")), "host_only of {input:?}: {:?}", got[0]);
        assert!(got[0].contains(&format!("x-p{i}: [{port}]")), "port_only of {input:?}: {:?}", got[0]);
    }
}
