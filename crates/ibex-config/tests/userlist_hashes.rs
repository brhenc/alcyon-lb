// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T155: what `user <u> password <hash>` accepts and refuses at load. Every verdict was
//! measured with `haproxy -c` (3.5-dev8-885761-29, glibc `crypt`) on 2026-10-04.

use ibex_config::parse_config;

fn with_user(line: &str) -> Result<ibex_config::Config, String> {
    parse_config(&format!(
        "userlist ul\n    {line}\ndefaults\n    mode http\n    timeout client 5s\nfrontend fe\n    bind 127.0.0.1:8080\n    http-request return status 200\n"
    ))
    .map_err(|e| e.to_string())
}

#[test]
fn the_formats_ibex_can_verify_load_as_hashes() {
    for h in [
        "$6$fQ6HnDPa64.3Z6.O$GjsvUJiFS2JYIZa3urNVWBoQ0C.wK18sKYqqn853aGzhYHEjP6bbDM2zYkNna8mCV/S6xlSI4v9rjADlEJ037.",
        "$6$rounds=1000$BLlpd4DDOChXrHSH$5TZWbB7HWmA2x6tDw6y0Z2yKoXXzTxusdjTxnwMd/MLirF6e5bi7UUHwfkRlwzWPXy2DS544/HljqTUOOFijI0",
        "$5$IZZu.tdofQvnNaZk$KXPkRxltAZIwLOSV29AmLeAl/A/.R6Lr8JGVYwzqa9B",
        "$1$1G0VykCx$OwomHlpoy3dfHps5jUrK81",
        "$2a$05$fDT1s53J9hc2GdGrAK.LQOtqRsu5pcbLSuKdbfWmKNcCLmW5Y6rgu",
        "$2b$05$fDT1s53J9hc2GdGrAK.LQOtqRsu5pcbLSuKdbfWmKNcCLmW5Y6rgu",
        "$2y$05$fDT1s53J9hc2GdGrAK.LQOtqRsu5pcbLSuKdbfWmKNcCLmW5Y6rgu",
        // Accepted by glibc, never matches anything.
        "$6$salt$short",
    ] {
        let c = with_user(&format!("user u password {h}")).unwrap_or_else(|e| panic!("{h}: {e}"));
        let u = &c.userlists[0].users[0];
        assert_eq!(u.password.as_deref(), Some(h));
        assert!(u.password_is_hash, "{h}");
    }
    let c = with_user("user u insecure-password $6$x").expect("accepted");
    assert!(!c.userlists[0].users[0].password_is_hash);
}

#[test]
fn what_crypt_cannot_use_is_refused_with_haproxys_message() {
    // crypt(3) returns NULL for all of these in glibc: "not supported by crypt(3)".
    for h in [
        "$9$salt$abc",
        "$6$rounds=999$x",
        "$5$rounds=10$x",
        "$6$rounds=1000000000$x",
        "$6$rounds=+1000$x",
        "$2b$03$fDT1s53J9hc2GdGrAK.LQOtqRsu5pcbLSuKdbfWmKNcCLmW5Y6rgu",
        "$2b$05$short",
        "$1",
        "!",
        "*",
        "$",
    ] {
        let err = with_user(&format!("user u password {h}")).expect_err(h);
        assert!(err.contains("the encrypted password used for user 'u' is not supported by crypt(3)."), "{h}: {err}");
    }
}

#[test]
fn what_glibc_verifies_and_ibex_does_not_is_refused_naming_the_format() {
    for (h, name) in [
        ("KX9oOBGuoeCIs", "DES crypt"),
        ("$y$j9T$1nZAl.AiE9fK3YIKl7dej.$fm26plQOfV3uymBaBxn65uVem0IUdbHYe6PLwrZdu30", "yescrypt ($y$)"),
        ("$sha1$1$abc", "SunMD5/sha1crypt"),
        ("$3$abc", "NT-hash"),
        ("$2x$05$fDT1s53J9hc2GdGrAK.LQOtqRsu5pcbLSuKdbfWmKNcCLmW5Y6rgu", "bcrypt $2x$"),
    ] {
        let err = with_user(&format!("user u password {h}")).expect_err(h);
        assert!(err.contains(name) && err.contains("user 'u'"), "{h}: {err}");
    }
}
