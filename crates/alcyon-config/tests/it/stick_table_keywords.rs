// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T250: `stick-table` refuses what it does not know, in HAProxy's words, and keeps `len`.
//!
//! Every text below was measured on HAProxy 3.5-dev8-885761-29 (`haproxy -c` on a backend
//! holding the line); the key `len` is the key size of a `string` or `binary` table.

use alcyon_config::parse_config;

fn cfg(line: &str) -> String {
    format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nbackend b\n  server s 127.0.0.1:1\n  {line}\n")
}

fn refused(line: &str, want: &str) {
    match parse_config(&cfg(line)) {
        Ok(_) => panic!("accepted: {line}"),
        Err(e) => {
            let got = e.to_string();
            assert!(got.contains(want), "{line}: wanted {want:?}, got {got:?}");
        }
    }
}

#[test]
fn unknown_keyword_is_refused() {
    refused("stick-table type ip size 10 bogus 3", "stick-table: unknown argument 'bogus'.");
}

#[test]
fn unknown_type_is_refused() {
    refused("stick-table type foo size 10", "stick-table: unknown type 'foo'.");
    refused("stick-table type int size 10", "stick-table: unknown type 'int'.");
    refused("stick-table type str size 10", "stick-table: unknown type 'str'.");
    refused("stick-table type bin size 10", "stick-table: unknown type 'bin'.");
    refused("stick-table type", "stick-table: unknown type ''.");
}

#[test]
fn missing_type_or_size_is_refused() {
    refused("stick-table size 10", "stick-table: missing type.");
    refused("stick-table type ip", "stick-table: missing size.");
}

#[test]
fn missing_arguments_are_refused() {
    refused("stick-table type ip size", "stick-table: missing argument after 'size'.");
    refused("stick-table type ip expire", "stick-table: missing argument after 'expire'.");
}

#[test]
fn len_wants_a_positive_integer_and_a_string_or_binary_table() {
    refused("stick-table type string len 0 size 10", "'len' expects a positive integer argument.");
    refused("stick-table type string len abc size 10", "'len' expects a positive integer argument.");
    refused("stick-table type binary len size 10", "'len' expects a positive integer argument.");
    refused("stick-table type ip len 8 size 10", "stick-table: unknown argument 'len'.");
}

#[test]
fn accepted_forms_parse() {
    for line in [
        "stick-table type ipv4 size 10",
        "stick-table type string len 5 size 10 expire 1m",
        "stick-table size 10 type binary len 7",
        "stick-table type integer size 1k store gpc0",
    ] {
        parse_config(&cfg(line)).unwrap_or_else(|e| panic!("{line}: {e}"));
    }
}

#[test]
fn len_reaches_the_ast() {
    let c = parse_config(&cfg("stick-table type string len 5 size 10")).expect("parse");
    let st = c.backends[0].stick_table.as_ref().expect("table");
    assert_eq!(st.key_len, Some(5));
    let c = parse_config(&cfg("stick-table type string size 10")).expect("parse");
    assert_eq!(c.backends[0].stick_table.as_ref().expect("table").key_len, None);
}

#[test]
fn what_alcyon_does_not_implement_is_refused() {
    for kw in ["nopurge", "recv-only", "srvkey name", "write-to x", "brates-factor 2"] {
        let word = kw.split(' ').next().unwrap();
        refused(&format!("stick-table type ip size 10 {kw}"), &format!("'stick-table ... {word}' is not supported by Alcyon"));
    }
}
