// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T364 S2: a variable keeps the type of the sample stored in it (`var_set` / `smp_fetch_var`,
//! src/vars.c), so what reads it casts from that type, as it would straight from the fetch.
//!
//! Alcyon stored the text of every sample: a `bin` variable lost its NUL cut (`c_bin2str`), an `int`
//! or an address hashed as its decimal text, an `ipv4` added as the number its text starts with.
//! One cell per class T1-T6 of docs/design/typed-variables-2026-10-18.md §1, the converter
//! arguments that name a variable (`sample_conv_var2smp`), and each scope. Every expected value is
//! `HAProxy` 3.5-dev8's answer to this configuration (measured 2026-10-18).

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

/// (expression in the `lf-string`, `HAProxy`'s output for it).
const CELLS: &[(&str, &str)] = &[
    // T1: `bin -> str` stops at the first NUL.
    ("%[var(txn.b),length]", "0"),
    ("%[var(txn.b),lower,length]", "0"),
    ("%[var(txn.b2),length]", "0"),
    ("%[var(txn.x),concat(x)]", "ABCx"),
    // T2: a scalar into a `bin` converter is its 8- or 4-byte value, not its text.
    ("%[var(txn.i),hex]", "0000000000000005"),
    ("%[var(txn.n),hex]", "FFFFFFFFFFFFFFFD"),
    ("%[var(txn.p),hex]", "0A010203"),
    ("%[var(txn.p),crc32]", "3825493623"),
    ("%[var(txn.n),bytes(1),hex]", "FFFFFFFFFFFFFD"),
    // T3: `ipv4 -> sint` is the address as an integer.
    ("%[var(txn.p),add(0)]", "167838211"),
    ("%[var(txn.p),neg]", "-167838211"),
    // T4: no cast to `sint`/`bool` from `ipv6`, `bin` or `meth`: no sample.
    ("%[var(txn.q),add(0)]", ""),
    ("%[var(txn.b),add(0)]", ""),
    ("%[var(txn.m),neg]", ""),
    ("%[var(txn.q),not]", ""),
    // T5: `sint -> addr` is `int2ip`.
    ("%[var(txn.i),ipmask(8)]", "0.0.0.0"),
    ("%[var(txn.n),ipmask(16,64)]", "255.255.0.0"),
    // T6: `ipv6 -> bin` is the 16 bytes.
    ("%[var(txn.m6),hex]", "00000000000000000000FFFF0A010203"),
    ("%[var(txn.q),hex]", "20010DB8000000000000000000000001"),
    ("%[var(txn.q),base64]", "IAENuAAAAAAAAAAAAAAAAQ=="),
    // Converter arguments naming a variable: cast from the stored type, `c_str2int` lenient
    // (`Abc` is 0, an empty string no sample).
    ("%[int(1),add(txn.p)]", "167838212"),
    ("%[int(1),add(txn.s)]", "1"),
    ("%[int(100),div(txn.s)]", "9223372036854775807"),
    ("%[str(Abcdef),bytes(txn.s)]", "Abcdef"),
    ("%[str(),concat(<,txn.x,>)]", "<ABC>"),
    ("%[int(1),add(txn.e)]", ""),
    // Scopes: `sess`, `proc`, a copy from another variable, `set-var-fmt` (a `str`), the global
    // section's `set-var` (typed) and `set-var-fmt` (a `str`), the `set-var` converter.
    ("%[var(sess.i),hex]", "0000000000000005"),
    ("%[var(proc.i),hex]", "0000000000000005"),
    ("%[var(txn.w),hex]", "0A010203"),
    ("%[var(txn.f),hex]", "35"),
    ("%[var(proc.g),hex]", "0000000000000005"),
    ("%[var(proc.gf),hex]", "35"),
    ("%[var(txn.c),hex]", "0000000000000005"),
    // As is, in a log-format.
    ("%[var(txn.i)]", "5"),
    ("%[var(txn.p)]", "10.1.2.3"),
    ("%[var(txn.m)]", "GET"),
    ("%[var(txn.o)]", "1"),
];

/// (ACL, whether `HAProxy` matches it).
const ACLS: &[(&str, bool)] = &[
    ("var(txn.b) -m len 0", true),
    ("var(txn.b) -m int 0", false),
    ("var(txn.m) -m int 0", false),
    ("var(txn.q) -m int gt 0", false),
    ("var(txn.x) -m len 3", true),
    ("var(txn.m6) -m int 0", false),
];

fn config(addr: std::net::SocketAddr) -> String {
    let mut c = format!(
        "global\n  set-var proc.g int(5)\n  set-var-fmt proc.gf \"%[int(5)]\"\n\
         defaults\n  mode http\n  timeout client 2s\n  timeout server 2s\n  timeout connect 2s\n\
         frontend f\n  bind {addr}\n"
    );
    for (n, e) in [
        ("b", "bin(000102)"),
        ("b2", "bin(00010280ff)"),
        ("x", "bin(41424300ff)"),
        ("i", "int(5)"),
        ("n", "int(-3)"),
        ("p", "ipv4(10.1.2.3)"),
        ("q", "ipv6(2001:db8::1)"),
        ("m6", "ipv6(::ffff:10.1.2.3)"),
        ("s", "str(Abc)"),
        ("e", "str()"),
        ("m", "method"),
        ("o", "bool(1)"),
    ] {
        c += &format!("  http-request set-var(txn.{n}) {e}\n");
    }
    c += "  http-request set-var(sess.i) int(5)\n  http-request set-var(proc.i) int(5)\n";
    c += "  http-request set-var(txn.w) var(txn.p)\n  http-request set-var-fmt(txn.f) \"%[int(5)]\"\n";
    c += "  http-request set-var(txn.z) int(5),set-var(txn.c)\n";
    for (k, (acl, _)) in ACLS.iter().enumerate() {
        c += &format!(
            "  acl a{k} {acl}\n  http-request set-var(txn.r{k}) int(1) if a{k}\n  http-request set-var(txn.r{k}) int(0) unless a{k}\n"
        );
    }
    let mut items: Vec<String> = CELLS.iter().map(|(e, _)| (*e).to_string()).collect();
    items.extend((0..ACLS.len()).map(|k| format!("%[var(txn.r{k})]")));
    c += &format!("  http-request return status 200 content-type text/plain lf-string \"{}\"\n", items.join("|"));
    c
}

#[test]
fn a_variable_gives_back_the_type_it_was_set_with() {
    let addr = common::reserve_addr();
    let path = std::env::temp_dir().join(format!("alcyon-t364-typed-{}.cfg", std::process::id()));
    std::fs::write(&path, config(addr)).expect("write cfg");
    let mut alcyon = common::Alcyon(
        Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-db").arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn alcyon"),
    );
    assert!(common::wait_listening(addr), "alcyon did not listen");
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").expect("send");
    let mut d = Vec::new();
    let _ = s.read_to_end(&mut d);
    common::stop(&mut alcyon);
    let _ = std::fs::remove_file(&path);
    let d = String::from_utf8_lossy(&d).into_owned();
    let body = d.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    let got: Vec<&str> = body.split('|').collect();
    let mut want: Vec<(String, String)> = CELLS.iter().map(|(e, v)| ((*e).to_string(), (*v).to_string())).collect();
    want.extend(ACLS.iter().map(|(a, m)| (format!("acl {a}"), if *m { "1" } else { "0" }.to_string())));
    let wrong: Vec<String> = want
        .iter()
        .enumerate()
        .filter(|(k, (_, v))| got.get(*k) != Some(&v.as_str()))
        .map(|(k, (e, v))| format!("{e}: want {v:?}, got {:?}", got.get(k)))
        .collect();
    assert!(wrong.is_empty(), "{} cells differ from HAProxy:\n{}", wrong.len(), wrong.join("\n"));
}
