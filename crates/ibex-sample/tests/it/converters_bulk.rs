// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Bulk test suite for sample converters.
// Five test cases per converter minimum:
// 1. Documented behaviour
// 2. Empty input
// 3. Boundaries / negative indices / overflow
// 4. Division / modulo by zero (where applicable)
// 5. Refused types

use ibex_sample::registry::{set_current_vars, Registry};
use ibex_sample::sample::Sample;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

fn eval_conv(name: &str, input: Sample, args: &[&str]) -> Option<Sample> {
    let reg = Registry::new();
    let conv = reg.get_converter(name).expect(name);
    let args_vec: Vec<String> = args.iter().map(|&s| s.to_string()).collect();
    (conv.func)(input, &args_vec)
}

// =========================================================================
// TIER 1: String & Encoding Converters
// =========================================================================

#[test]
fn test_conv_base64() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("base64", Sample::Bin(b"hello".to_vec()), &[]),
        Some(Sample::Str("aGVsbG8=".into()))
    );
    assert_eq!(
        eval_conv("base64", Sample::Bin(b"test data 123".to_vec()), &[]),
        Some(Sample::Str("dGVzdCBkYXRhIDEyMw==".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("base64", Sample::Bin(b"".to_vec()), &[]),
        Some(Sample::Str(String::new()))
    );
    // 3. Boundaries (1 byte, 2 bytes, 3 bytes)
    assert_eq!(
        eval_conv("base64", Sample::Bin(vec![0xFF]), &[]),
        Some(Sample::Str("/w==".into()))
    );
    assert_eq!(
        eval_conv("base64", Sample::Bin(vec![0xFF, 0x00]), &[]),
        Some(Sample::Str("/wA=".into()))
    );
    assert_eq!(
        eval_conv("base64", Sample::Bin(vec![0xFF, 0x00, 0xAA]), &[]),
        Some(Sample::Str("/wCq".into()))
    );
    // 4. Multi-chunk data
    assert_eq!(
        eval_conv("base64", Sample::Bin(vec![1, 2, 3, 4]), &[]),
        Some(Sample::Str("AQIDBA==".into()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("base64", Sample::Sint(42), &[]), None);
    assert_eq!(eval_conv("base64", Sample::Bool(true), &[]), None);
}

#[test]
fn test_conv_b64dec() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("b64dec", Sample::Str("aGVsbG8=".into()), &[]),
        Some(Sample::Bin(b"hello".to_vec()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("b64dec", Sample::Str(String::new()), &[]),
        Some(Sample::Bin(vec![]))
    );
    // 3. Boundaries & padding
    assert_eq!(
        eval_conv("b64dec", Sample::Str("/w==".into()), &[]),
        Some(Sample::Bin(vec![0xFF]))
    );
    assert_eq!(
        eval_conv("b64dec", Sample::Str("/wCq".into()), &[]),
        Some(Sample::Bin(vec![0xFF, 0x00, 0xAA]))
    );
    // 4. Invalid input rejected
    assert_eq!(eval_conv("b64dec", Sample::Str("!invalid!".into()), &[]), None);
    assert_eq!(eval_conv("b64dec", Sample::Str("aGVsbG8".into()), &[]), None); // missing padding
    // 5. Refused types
    assert_eq!(eval_conv("b64dec", Sample::Sint(42), &[]), None);
    assert_eq!(eval_conv("b64dec", Sample::Bool(false), &[]), None);
}

#[test]
fn test_conv_upper() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("upper", Sample::Str("hello world".into()), &[]),
        Some(Sample::Str("HELLO WORLD".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("upper", Sample::Str(String::new()), &[]),
        Some(Sample::Str(String::new()))
    );
    // 3. Boundaries (already uppercase, mixed case, non-ascii)
    assert_eq!(
        eval_conv("upper", Sample::Str("ALREADY_UPPER_123".into()), &[]),
        Some(Sample::Str("ALREADY_UPPER_123".into()))
    );
    assert_eq!(
        eval_conv("upper", Sample::Str("MixEd 456!".into()), &[]),
        Some(Sample::Str("MIXED 456!".into()))
    );
    // 4. Whitespace only
    assert_eq!(
        eval_conv("upper", Sample::Str("   \t\n".into()), &[]),
        Some(Sample::Str("   \t\n".into()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("upper", Sample::Bin(b"abc".to_vec()), &[]), None);
    assert_eq!(eval_conv("upper", Sample::Sint(10), &[]), None);
}

#[test]
fn test_conv_lower() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("lower", Sample::Str("HELLO WORLD".into()), &[]),
        Some(Sample::Str("hello world".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("lower", Sample::Str(String::new()), &[]),
        Some(Sample::Str(String::new()))
    );
    // 3. Boundaries (already lowercase, mixed case, digits)
    assert_eq!(
        eval_conv("lower", Sample::Str("already_lower_123".into()), &[]),
        Some(Sample::Str("already_lower_123".into()))
    );
    assert_eq!(
        eval_conv("lower", Sample::Str("MiXeD 456!".into()), &[]),
        Some(Sample::Str("mixed 456!".into()))
    );
    // 4. Symbols
    assert_eq!(
        eval_conv("lower", Sample::Str("!@#$%^&*()".into()), &[]),
        Some(Sample::Str("!@#$%^&*()".into()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("lower", Sample::Bin(b"ABC".to_vec()), &[]), None);
    assert_eq!(eval_conv("lower", Sample::Sint(10), &[]), None);
}

#[test]
fn test_conv_hex() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("hex", Sample::Bin(vec![0xDE, 0xAD, 0xBE, 0xEF]), &[]),
        Some(Sample::Str("DEADBEEF".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("hex", Sample::Bin(vec![]), &[]),
        Some(Sample::Str(String::new()))
    );
    // 3. Boundaries (single bytes 0x00 and 0xFF)
    assert_eq!(
        eval_conv("hex", Sample::Bin(vec![0x00]), &[]),
        Some(Sample::Str("00".into()))
    );
    assert_eq!(
        eval_conv("hex", Sample::Bin(vec![0xFF]), &[]),
        Some(Sample::Str("FF".into()))
    );
    // 4. Multi-byte sequential
    assert_eq!(
        eval_conv("hex", Sample::Bin(vec![1, 2, 3, 4]), &[]),
        Some(Sample::Str("01020304".into()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("hex", Sample::Str("deadbeef".into()), &[]), None);
    assert_eq!(eval_conv("hex", Sample::Sint(123), &[]), None);
}

#[test]
fn test_conv_hex2i() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("hex2i", Sample::Str("FF".into()), &[]),
        Some(Sample::Sint(255))
    );
    assert_eq!(
        eval_conv("hex2i", Sample::Str("1a2b".into()), &[]),
        Some(Sample::Sint(0x1a2b))
    );
    // 2. Empty input (HAProxy returns 0)
    assert_eq!(
        eval_conv("hex2i", Sample::Str(String::new()), &[]),
        Some(Sample::Sint(0))
    );
    // 3. Boundaries & rejected prefixes (0x prefix is refused in HAProxy)
    assert_eq!(eval_conv("hex2i", Sample::Str("0x12".into()), &[]), None);
    assert_eq!(eval_conv("hex2i", Sample::Str("12g".into()), &[]), None);
    // 4. Zero hex
    assert_eq!(
        eval_conv("hex2i", Sample::Str("0".into()), &[]),
        Some(Sample::Sint(0))
    );
    // 5. Refused types
    assert_eq!(eval_conv("hex2i", Sample::Bin(b"FF".to_vec()), &[]), None);
    assert_eq!(eval_conv("hex2i", Sample::Sint(255), &[]), None);
}

#[test]
fn test_conv_be2dec() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("be2dec", Sample::Bin(vec![1, 2, 3, 4]), &["-", "1"]),
        Some(Sample::Str("1-2-3-4".into()))
    );
    assert_eq!(
        eval_conv("be2dec", Sample::Bin(vec![1, 2, 3, 4]), &["-", "2"]),
        Some(Sample::Str("258-772".into()))
    );
    assert_eq!(
        eval_conv("be2dec", Sample::Bin(vec![1, 2, 3, 4]), &["-", "4"]),
        Some(Sample::Str("16909060".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("be2dec", Sample::Bin(vec![]), &["-", "2"]),
        Some(Sample::Str(String::new()))
    );
    // 3. Truncation flag (truncate=1 ignores partial trailing chunk)
    assert_eq!(
        eval_conv("be2dec", Sample::Bin(vec![1, 2, 3, 4, 5]), &["-", "2", "0"]),
        Some(Sample::Str("258-772-5".into()))
    );
    assert_eq!(
        eval_conv("be2dec", Sample::Bin(vec![1, 2, 3, 4, 5]), &["-", "2", "1"]),
        Some(Sample::Str("258-772".into()))
    );
    // 4. Invalid chunk_size (0 or >8)
    assert_eq!(eval_conv("be2dec", Sample::Bin(vec![1, 2]), &["-", "0"]), None);
    assert_eq!(eval_conv("be2dec", Sample::Bin(vec![1, 2]), &["-", "9"]), None);
    // 5. Refused types
    assert_eq!(eval_conv("be2dec", Sample::Str("1234".into()), &["-", "1"]), None);
}

#[test]
fn test_conv_be2hex() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("be2hex", Sample::Bin(vec![1, 2, 3, 4]), &[":", "1"]),
        Some(Sample::Str("01:02:03:04".into()))
    );
    assert_eq!(
        eval_conv("be2hex", Sample::Bin(vec![1, 2, 3, 4]), &[":", "2"]),
        Some(Sample::Str("0102:0304".into()))
    );
    assert_eq!(
        eval_conv("be2hex", Sample::Bin(vec![1, 2, 3, 4]), &[]),
        Some(Sample::Str("01020304".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("be2hex", Sample::Bin(vec![]), &[":", "1"]),
        Some(Sample::Str(String::new()))
    );
    // 3. Truncate flag
    assert_eq!(
        eval_conv("be2hex", Sample::Bin(vec![1, 2, 3, 4, 5]), &[":", "2", "0"]),
        Some(Sample::Str("0102:0304:05".into()))
    );
    assert_eq!(
        eval_conv("be2hex", Sample::Bin(vec![1, 2, 3, 4, 5]), &[":", "2", "1"]),
        Some(Sample::Str("0102:0304".into()))
    );
    // 4. No separator full dump
    assert_eq!(
        eval_conv("be2hex", Sample::Bin(vec![0xAA, 0xBB, 0xCC]), &[]),
        Some(Sample::Str("AABBCC".into()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("be2hex", Sample::Str("1234".into()), &[]), None);
}

#[test]
fn test_conv_cut_crlf() {
    // 1. Documented behaviour: truncates at FIRST \r or \n
    assert_eq!(
        eval_conv("cut_crlf", Sample::Str("hello\rworld".into()), &[]),
        Some(Sample::Str("hello".into()))
    );
    assert_eq!(
        eval_conv("cut_crlf", Sample::Str("line1\nline2".into()), &[]),
        Some(Sample::Str("line1".into()))
    );
    assert_eq!(
        eval_conv("cut_crlf", Sample::Str("trailing\r\n".into()), &[]),
        Some(Sample::Str("trailing".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("cut_crlf", Sample::Str(String::new()), &[]),
        Some(Sample::Str(String::new()))
    );
    // 3. Leading CRLF -> empty result
    assert_eq!(
        eval_conv("cut_crlf", Sample::Str("\r\nhello".into()), &[]),
        Some(Sample::Str(String::new()))
    );
    // 4. No CRLF
    assert_eq!(
        eval_conv("cut_crlf", Sample::Str("no line breaks".into()), &[]),
        Some(Sample::Str("no line breaks".into()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("cut_crlf", Sample::Bin(b"hello\r\n".to_vec()), &[]), None);
    assert_eq!(eval_conv("cut_crlf", Sample::Sint(100), &[]), None);
}

#[test]
fn test_conv_concat() {
    let mut vars = HashMap::new();
    vars.insert("txn.v".to_string(), "BAR".to_string());
    set_current_vars(vars);

    // 1. Documented behaviour: concat(start, var, end)
    assert_eq!(
        eval_conv("concat", Sample::Str("foo".into()), &["_", "txn.v", "!"]),
        Some(Sample::Str("foo_BAR!".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("concat", Sample::Str(String::new()), &["pre_", "txn.v"]),
        Some(Sample::Str("pre_BAR".into()))
    );
    // 3. Unset variable (skipped, suffix appended)
    assert_eq!(
        eval_conv("concat", Sample::Str("foo".into()), &["_", "txn.unset", "!"]),
        Some(Sample::Str("foo_!".into()))
    );
    // 4. Single arg / no args
    assert_eq!(
        eval_conv("concat", Sample::Str("foo".into()), &["_"]),
        Some(Sample::Str("foo_".into()))
    );
    assert_eq!(
        eval_conv("concat", Sample::Str("foo".into()), &[]),
        Some(Sample::Str("foo".into()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("concat", Sample::Bin(b"foo".to_vec()), &["_"]), None);
}

#[test]
fn test_conv_add_item() {
    let mut vars = HashMap::new();
    vars.insert("txn.tag1".to_string(), "item1".to_string());
    set_current_vars(vars);

    // 1. Documented behaviour: add_item(delim, var, suff)
    assert_eq!(
        eval_conv("add_item", Sample::Str("prev".into()), &[",", "txn.tag1"]),
        Some(Sample::Str("prev,item1".into()))
    );
    assert_eq!(
        eval_conv("add_item", Sample::Str("prev".into()), &[",", "txn.tag1", "(suff)"]),
        Some(Sample::Str("prev,item1(suff)".into()))
    );
    // 2. Empty input: delimiter not prepended
    assert_eq!(
        eval_conv("add_item", Sample::Str(String::new()), &[",", "txn.tag1"]),
        Some(Sample::Str("item1".into()))
    );
    assert_eq!(
        eval_conv("add_item", Sample::Str(String::new()), &[",", "", "(suff)"]),
        Some(Sample::Str("(suff)".into()))
    );
    // 3. Unset var on empty vs non-empty input
    assert_eq!(
        eval_conv("add_item", Sample::Str(String::new()), &[",", "txn.unset"]),
        Some(Sample::Str(String::new()))
    );
    assert_eq!(
        eval_conv("add_item", Sample::Str("prev".into()), &[",", "txn.unset"]),
        Some(Sample::Str("prev".into()))
    );
    // 4. Non-empty input with suffix only
    assert_eq!(
        eval_conv("add_item", Sample::Str("prev".into()), &[",", "", "(suff)"]),
        Some(Sample::Str("prev,(suff)".into()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("add_item", Sample::Bin(b"prev".to_vec()), &[",", "txn.tag1"]), None);
}

#[test]
fn test_conv_bytes() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("bytes", Sample::Bin(b"abcdef".to_vec()), &["1", "2"]),
        Some(Sample::Bin(b"bc".to_vec()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("bytes", Sample::Bin(vec![]), &["0", "5"]),
        Some(Sample::Bin(vec![]))
    );
    // 3. Boundaries: offset >= len -> empty bin
    assert_eq!(
        eval_conv("bytes", Sample::Bin(b"abcdef".to_vec()), &["10", "2"]),
        Some(Sample::Bin(vec![]))
    );
    // 4. Negative offset or negative length -> None
    assert_eq!(eval_conv("bytes", Sample::Bin(b"abcdef".to_vec()), &["-1", "2"]), None);
    assert_eq!(eval_conv("bytes", Sample::Bin(b"abcdef".to_vec()), &["1", "-2"]), None);
    // 5. Refused types
    assert_eq!(eval_conv("bytes", Sample::Str("abcdef".into()), &["1", "2"]), None);
}

#[test]
fn test_conv_ltrim() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("ltrim", Sample::Str("  \t\nhello world".into()), &[" \t\n"]),
        Some(Sample::Str("hello world".into()))
    );
    assert_eq!(
        eval_conv("ltrim", Sample::Str("///path/to/file".into()), &["/"]),
        Some(Sample::Str("path/to/file".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("ltrim", Sample::Str(String::new()), &[" "]),
        Some(Sample::Str(String::new()))
    );
    // 3. Nothing to trim
    assert_eq!(
        eval_conv("ltrim", Sample::Str("hello".into()), &[" "]),
        Some(Sample::Str("hello".into()))
    );
    // 4. Everything trimmed
    assert_eq!(
        eval_conv("ltrim", Sample::Str("aaaaa".into()), &["a"]),
        Some(Sample::Str(String::new()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("ltrim", Sample::Bin(b"  hello".to_vec()), &[" "]), None);
}

#[test]
fn test_conv_rtrim() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("rtrim", Sample::Str("hello world  \t\n".into()), &[" \t\n"]),
        Some(Sample::Str("hello world".into()))
    );
    assert_eq!(
        eval_conv("rtrim", Sample::Str("path/to/file///".into()), &["/"]),
        Some(Sample::Str("path/to/file".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("rtrim", Sample::Str(String::new()), &[" "]),
        Some(Sample::Str(String::new()))
    );
    // 3. Nothing to trim
    assert_eq!(
        eval_conv("rtrim", Sample::Str("hello".into()), &[" "]),
        Some(Sample::Str("hello".into()))
    );
    // 4. Everything trimmed
    assert_eq!(
        eval_conv("rtrim", Sample::Str("bbbbb".into()), &["b"]),
        Some(Sample::Str(String::new()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("rtrim", Sample::Bin(b"hello  ".to_vec()), &[" "]), None);
}

#[test]
fn test_conv_regsub() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("regsub", Sample::Str("foo123bar".into()), &[r"\d+", "NUM"]),
        Some(Sample::Str("fooNUMbar".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("regsub", Sample::Str(String::new()), &[r"\d+", "NUM"]),
        Some(Sample::Str(String::new()))
    );
    // 3. Flags: global (g) and ignore-case (i)
    assert_eq!(
        eval_conv("regsub", Sample::Str("a1b2c3".into()), &[r"\d", "X", "g"]),
        Some(Sample::Str("aXbXcX".into()))
    );
    assert_eq!(
        eval_conv("regsub", Sample::Str("FooBar".into()), &["foobar", "OK", "i"]),
        Some(Sample::Str("OK".into()))
    );
    // 4. Group capture \1 \2
    assert_eq!(
        eval_conv("regsub", Sample::Str("hello-world".into()), &[r"([a-z]+)-([a-z]+)", r"\2_\1"]),
        Some(Sample::Str("world_hello".into()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("regsub", Sample::Bin(b"foo123bar".to_vec()), &[r"\d+", "NUM"]), None);
}

// =========================================================================
// TIER 2: Arithmetic & Logic Converters
// =========================================================================

#[test]
fn test_conv_add() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("add", Sample::Sint(10), &["5"]), Some(Sample::Sint(15)));
    assert_eq!(eval_conv("add", Sample::Sint(-10), &["5"]), Some(Sample::Sint(-5)));
    // 2. Empty / missing arg: `read_int64` of nothing is 0 (`check_operator`); HAProxy
    // 3.5-dev8 answers 5 for `int(5),add` (T343).
    assert_eq!(eval_conv("add", Sample::Sint(10), &[]), Some(Sample::Sint(10)));
    // 3. Boundaries / saturation
    assert_eq!(
        eval_conv("add", Sample::Sint(i64::MAX - 5), &["10"]),
        Some(Sample::Sint(i64::MAX))
    );
    assert_eq!(
        eval_conv("add", Sample::Sint(i64::MIN + 5), &["-10"]),
        Some(Sample::Sint(i64::MIN))
    );
    // 4. Negative arg
    assert_eq!(eval_conv("add", Sample::Sint(10), &["-3"]), Some(Sample::Sint(7)));
    // 5. Refused types
    assert_eq!(eval_conv("add", Sample::Str("10".into()), &["5"]), None);
}

#[test]
fn test_conv_sub() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("sub", Sample::Sint(10), &["3"]), Some(Sample::Sint(7)));
    assert_eq!(eval_conv("sub", Sample::Sint(5), &["10"]), Some(Sample::Sint(-5)));
    // 2. Empty / missing arg
    assert_eq!(eval_conv("sub", Sample::Sint(10), &[]), Some(Sample::Sint(10))); // T343: HAProxy 3.5-dev8 reads no argument as 0
    // 3. Boundaries / saturation
    assert_eq!(
        eval_conv("sub", Sample::Sint(i64::MIN + 5), &["10"]),
        Some(Sample::Sint(i64::MIN))
    );
    assert_eq!(
        eval_conv("sub", Sample::Sint(i64::MAX - 5), &["-10"]),
        Some(Sample::Sint(i64::MAX))
    );
    // 4. Sub zero
    assert_eq!(eval_conv("sub", Sample::Sint(42), &["0"]), Some(Sample::Sint(42)));
    // 5. Refused types
    assert_eq!(eval_conv("sub", Sample::Str("10".into()), &["3"]), None);
}

#[test]
fn test_conv_mul() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("mul", Sample::Sint(6), &["7"]), Some(Sample::Sint(42)));
    assert_eq!(eval_conv("mul", Sample::Sint(-6), &["7"]), Some(Sample::Sint(-42)));
    // 2. Multiply by 0
    assert_eq!(eval_conv("mul", Sample::Sint(100), &["0"]), Some(Sample::Sint(0)));
    assert_eq!(eval_conv("mul", Sample::Sint(0), &["100"]), Some(Sample::Sint(0)));
    // 3. Boundaries / saturation
    assert_eq!(
        eval_conv("mul", Sample::Sint(i64::MAX / 2 + 1), &["3"]),
        Some(Sample::Sint(i64::MAX))
    );
    assert_eq!(
        eval_conv("mul", Sample::Sint(i64::MIN / 2 - 1), &["3"]),
        Some(Sample::Sint(i64::MIN))
    );
    // 4. Missing arg
    assert_eq!(eval_conv("mul", Sample::Sint(10), &[]), Some(Sample::Sint(0))); // T343: HAProxy 3.5-dev8 reads no argument as 0
    // 5. Refused types
    assert_eq!(eval_conv("mul", Sample::Str("6".into()), &["7"]), None);
}

#[test]
fn test_conv_div() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("div", Sample::Sint(10), &["2"]), Some(Sample::Sint(5)));
    assert_eq!(eval_conv("div", Sample::Sint(-10), &["2"]), Some(Sample::Sint(-5)));
    // 2. Division by zero returns i64::MAX (HAProxy behavior)
    assert_eq!(eval_conv("div", Sample::Sint(10), &["0"]), Some(Sample::Sint(i64::MAX)));
    assert_eq!(eval_conv("div", Sample::Sint(-10), &["0"]), Some(Sample::Sint(i64::MAX)));
    // 3. Boundaries (i64::MIN / -1 -> i64::MAX)
    assert_eq!(
        eval_conv("div", Sample::Sint(i64::MIN), &["-1"]),
        Some(Sample::Sint(i64::MAX))
    );
    // 4. Missing arg
    assert_eq!(eval_conv("div", Sample::Sint(10), &[]), Some(Sample::Sint(i64::MAX))); // T343: HAProxy 3.5-dev8 reads no argument as 0
    // 5. Refused types
    assert_eq!(eval_conv("div", Sample::Str("10".into()), &["2"]), None);
}

#[test]
fn test_conv_mod() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("mod", Sample::Sint(10), &["3"]), Some(Sample::Sint(1)));
    assert_eq!(eval_conv("mod", Sample::Sint(-10), &["3"]), Some(Sample::Sint(-1)));
    // 2. Modulo by zero returns 0 (HAProxy behavior)
    assert_eq!(eval_conv("mod", Sample::Sint(10), &["0"]), Some(Sample::Sint(0)));
    assert_eq!(eval_conv("mod", Sample::Sint(-10), &["0"]), Some(Sample::Sint(0)));
    // 3. Boundaries (i64::MIN % -1 -> 0)
    assert_eq!(
        eval_conv("mod", Sample::Sint(i64::MIN), &["-1"]),
        Some(Sample::Sint(0))
    );
    // 4. Missing arg
    assert_eq!(eval_conv("mod", Sample::Sint(10), &[]), Some(Sample::Sint(0))); // T343: HAProxy 3.5-dev8 reads no argument as 0
    // 5. Refused types
    assert_eq!(eval_conv("mod", Sample::Str("10".into()), &["3"]), None);
}

#[test]
fn test_conv_neg() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("neg", Sample::Sint(42), &[]), Some(Sample::Sint(-42)));
    assert_eq!(eval_conv("neg", Sample::Sint(-42), &[]), Some(Sample::Sint(42)));
    // 2. Zero input
    assert_eq!(eval_conv("neg", Sample::Sint(0), &[]), Some(Sample::Sint(0)));
    // 3. Boundaries (i64::MIN negates to i64::MAX)
    assert_eq!(
        eval_conv("neg", Sample::Sint(i64::MIN), &[]),
        Some(Sample::Sint(i64::MAX))
    );
    assert_eq!(
        eval_conv("neg", Sample::Sint(i64::MAX), &[]),
        Some(Sample::Sint(-i64::MAX))
    );
    // 4. Non-zero arguments ignored
    assert_eq!(eval_conv("neg", Sample::Sint(5), &["ignored"]), Some(Sample::Sint(-5)));
    // 5. Refused types
    assert_eq!(eval_conv("neg", Sample::Str("42".into()), &[]), None);
}

#[test]
fn test_conv_and() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("and", Sample::Sint(15), &["6"]), Some(Sample::Sint(6)));
    // 2. Mask with 0
    assert_eq!(eval_conv("and", Sample::Sint(15), &["0"]), Some(Sample::Sint(0)));
    // 3. Mask with -1
    assert_eq!(eval_conv("and", Sample::Sint(15), &["-1"]), Some(Sample::Sint(15)));
    // 4. Missing arg: 0, as `check_operator` reads it; HAProxy 3.5-dev8 answers 0 for
    // `int(5),and(-)` (T343).
    assert_eq!(eval_conv("and", Sample::Sint(15), &[]), Some(Sample::Sint(0)));
    // 5. Refused types
    assert_eq!(eval_conv("and", Sample::Str("15".into()), &["6"]), None);
}

#[test]
fn test_conv_or() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("or", Sample::Sint(15), &["16"]), Some(Sample::Sint(31)));
    // 2. Mask with 0
    assert_eq!(eval_conv("or", Sample::Sint(15), &["0"]), Some(Sample::Sint(15)));
    // 3. Mask with -1
    assert_eq!(eval_conv("or", Sample::Sint(15), &["-1"]), Some(Sample::Sint(-1)));
    // 4. Missing arg
    assert_eq!(eval_conv("or", Sample::Sint(15), &[]), Some(Sample::Sint(15))); // T343: HAProxy 3.5-dev8 reads no argument as 0
    // 5. Refused types
    assert_eq!(eval_conv("or", Sample::Str("15".into()), &["16"]), None);
}

#[test]
fn test_conv_xor() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("xor", Sample::Sint(15), &["6"]), Some(Sample::Sint(9)));
    // 2. Self XOR -> 0
    assert_eq!(eval_conv("xor", Sample::Sint(42), &["42"]), Some(Sample::Sint(0)));
    // 3. XOR with 0 -> unchanged
    assert_eq!(eval_conv("xor", Sample::Sint(42), &["0"]), Some(Sample::Sint(42)));
    // 4. Missing arg
    assert_eq!(eval_conv("xor", Sample::Sint(15), &[]), Some(Sample::Sint(15))); // T343: HAProxy 3.5-dev8 reads no argument as 0
    // 5. Refused types
    assert_eq!(eval_conv("xor", Sample::Str("15".into()), &["6"]), None);
}

#[test]
fn test_conv_cpl() {
    // 1. Documented behaviour (bitwise NOT)
    assert_eq!(eval_conv("cpl", Sample::Sint(0), &[]), Some(Sample::Sint(-1)));
    assert_eq!(eval_conv("cpl", Sample::Sint(-1), &[]), Some(Sample::Sint(0)));
    // 2. cpl of positive
    assert_eq!(eval_conv("cpl", Sample::Sint(1), &[]), Some(Sample::Sint(-2)));
    // 3. Boundaries (i64::MAX and i64::MIN)
    assert_eq!(
        eval_conv("cpl", Sample::Sint(i64::MAX), &[]),
        Some(Sample::Sint(i64::MIN))
    );
    assert_eq!(
        eval_conv("cpl", Sample::Sint(i64::MIN), &[]),
        Some(Sample::Sint(i64::MAX))
    );
    // 4. Args ignored
    assert_eq!(eval_conv("cpl", Sample::Sint(0), &["extra"]), Some(Sample::Sint(-1)));
    // 5. Refused types
    assert_eq!(eval_conv("cpl", Sample::Str("0".into()), &[]), None);
}

#[test]
fn test_conv_bool() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("bool", Sample::Sint(42), &[]), Some(Sample::Bool(true)));
    assert_eq!(eval_conv("bool", Sample::Sint(0), &[]), Some(Sample::Bool(false)));
    // 2. Negative integer is true
    assert_eq!(eval_conv("bool", Sample::Sint(-1), &[]), Some(Sample::Bool(true)));
    // 3. Bool passthrough
    assert_eq!(eval_conv("bool", Sample::Bool(true), &[]), Some(Sample::Bool(true)));
    assert_eq!(eval_conv("bool", Sample::Bool(false), &[]), Some(Sample::Bool(false)));
    // 4. Boundaries (i64::MAX, i64::MIN)
    assert_eq!(eval_conv("bool", Sample::Sint(i64::MAX), &[]), Some(Sample::Bool(true)));
    assert_eq!(eval_conv("bool", Sample::Sint(i64::MIN), &[]), Some(Sample::Bool(true)));
    // 5. Refused types
    assert_eq!(eval_conv("bool", Sample::Str("true".into()), &[]), None);
}

#[test]
fn test_conv_not() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("not", Sample::Sint(0), &[]), Some(Sample::Bool(true)));
    assert_eq!(eval_conv("not", Sample::Sint(42), &[]), Some(Sample::Bool(false)));
    // 2. Negative integer not is false
    assert_eq!(eval_conv("not", Sample::Sint(-1), &[]), Some(Sample::Bool(false)));
    // 3. Bool inversion
    assert_eq!(eval_conv("not", Sample::Bool(true), &[]), Some(Sample::Bool(false)));
    assert_eq!(eval_conv("not", Sample::Bool(false), &[]), Some(Sample::Bool(true)));
    // 4. Boundaries
    assert_eq!(eval_conv("not", Sample::Sint(i64::MAX), &[]), Some(Sample::Bool(false)));
    assert_eq!(eval_conv("not", Sample::Sint(i64::MIN), &[]), Some(Sample::Bool(false)));
    // 5. Refused types
    assert_eq!(eval_conv("not", Sample::Str("0".into()), &[]), None);
}

#[test]
fn test_conv_odd() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("odd", Sample::Sint(1), &[]), Some(Sample::Bool(true)));
    assert_eq!(eval_conv("odd", Sample::Sint(2), &[]), Some(Sample::Bool(false)));
    // 2. Zero is not odd
    assert_eq!(eval_conv("odd", Sample::Sint(0), &[]), Some(Sample::Bool(false)));
    // 3. Negative odd / even
    assert_eq!(eval_conv("odd", Sample::Sint(-1), &[]), Some(Sample::Bool(true)));
    assert_eq!(eval_conv("odd", Sample::Sint(-2), &[]), Some(Sample::Bool(false)));
    // 4. Boundaries
    assert_eq!(eval_conv("odd", Sample::Sint(i64::MAX), &[]), Some(Sample::Bool(true)));
    assert_eq!(eval_conv("odd", Sample::Sint(i64::MIN), &[]), Some(Sample::Bool(false)));
    // 5. Refused types
    assert_eq!(eval_conv("odd", Sample::Str("1".into()), &[]), None);
}

#[test]
fn test_conv_even() {
    // 1. Documented behaviour
    assert_eq!(eval_conv("even", Sample::Sint(2), &[]), Some(Sample::Bool(true)));
    assert_eq!(eval_conv("even", Sample::Sint(1), &[]), Some(Sample::Bool(false)));
    // 2. Zero is even
    assert_eq!(eval_conv("even", Sample::Sint(0), &[]), Some(Sample::Bool(true)));
    // 3. Negative even / odd
    assert_eq!(eval_conv("even", Sample::Sint(-2), &[]), Some(Sample::Bool(true)));
    assert_eq!(eval_conv("even", Sample::Sint(-1), &[]), Some(Sample::Bool(false)));
    // 4. Boundaries
    assert_eq!(eval_conv("even", Sample::Sint(i64::MIN), &[]), Some(Sample::Bool(true)));
    assert_eq!(eval_conv("even", Sample::Sint(i64::MAX), &[]), Some(Sample::Bool(false)));
    // 5. Refused types
    assert_eq!(eval_conv("even", Sample::Str("2".into()), &[]), None);
}

#[test]
fn test_conv_ipmask() {
    let v4: Ipv4Addr = "192.168.1.150".parse().unwrap();
    let v6: Ipv6Addr = "2001:db8::1234".parse().unwrap();

    // 1. Documented behaviour
    assert_eq!(
        eval_conv("ipmask", Sample::Ipv4(v4), &["24"]),
        Some(Sample::Ipv4("192.168.1.0".parse().unwrap()))
    );
    assert_eq!(
        eval_conv("ipmask", Sample::Ipv4(v4), &["255.255.255.0"]),
        Some(Sample::Ipv4("192.168.1.0".parse().unwrap()))
    );
    // 2. IPv4 boundaries (prefix 0 and 32)
    assert_eq!(
        eval_conv("ipmask", Sample::Ipv4(v4), &["0"]),
        Some(Sample::Ipv4("0.0.0.0".parse().unwrap()))
    );
    assert_eq!(
        eval_conv("ipmask", Sample::Ipv4(v4), &["32"]),
        Some(Sample::Ipv4(v4))
    );
    // 3. IPv6 with mask6 (prefix 64, 0, 128)
    assert_eq!(
        eval_conv("ipmask", Sample::Ipv6(v6), &["24", "64"]),
        Some(Sample::Ipv6("2001:db8::".parse().unwrap()))
    );
    assert_eq!(
        eval_conv("ipmask", Sample::Ipv6(v6), &["24", "0"]),
        Some(Sample::Ipv6("::".parse().unwrap()))
    );
    assert_eq!(
        eval_conv("ipmask", Sample::Ipv6(v6), &["24", "128"]),
        Some(Sample::Ipv6(v6))
    );
    // 4. IPv6 without mask6 returns None (HAProxy behavior)
    assert_eq!(eval_conv("ipmask", Sample::Ipv6(v6), &["24"]), None);
    // 5. Refused types
    assert_eq!(eval_conv("ipmask", Sample::Sint(123), &["24"]), None);
}

#[test]
fn test_conv_sdbm() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("sdbm", Sample::Bin(b"test".to_vec()), &[]),
        Some(Sample::Sint(1_195_757_874))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("sdbm", Sample::Bin(b"".to_vec()), &[]),
        Some(Sample::Sint(0))
    );
    // 3. Avalanche flag (1)
    let non_av = eval_conv("sdbm", Sample::Bin(b"test".to_vec()), &[]).unwrap();
    let av = eval_conv("sdbm", Sample::Bin(b"test".to_vec()), &["1"]).unwrap();
    assert_ne!(non_av, av);
    // 4. Deterministic across multiple calls
    assert_eq!(
        eval_conv("sdbm", Sample::Bin(b"project-ibex".to_vec()), &[]),
        eval_conv("sdbm", Sample::Bin(b"project-ibex".to_vec()), &[])
    );
    // 5. Refused types
    assert_eq!(eval_conv("sdbm", Sample::Sint(123), &[]), None);
}

#[test]
fn test_conv_wt6() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("wt6", Sample::Bin(b"test".to_vec()), &[]),
        Some(Sample::Sint(1_132_164_424))
    );
    // 2. Empty input
    let empty_h = eval_conv("wt6", Sample::Bin(b"".to_vec()), &[]);
    assert!(empty_h.is_some());
    // 3. Avalanche flag
    let non_av = eval_conv("wt6", Sample::Bin(b"test".to_vec()), &[]).unwrap();
    let av = eval_conv("wt6", Sample::Bin(b"test".to_vec()), &["1"]).unwrap();
    assert_ne!(non_av, av);
    // 4. Deterministic
    assert_eq!(
        eval_conv("wt6", Sample::Bin(b"sample data".to_vec()), &[]),
        eval_conv("wt6", Sample::Bin(b"sample data".to_vec()), &[])
    );
    // 5. Refused types
    assert_eq!(eval_conv("wt6", Sample::Sint(123), &[]), None);
}

#[test]
fn test_conv_crc32() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("crc32", Sample::Bin(b"test".to_vec()), &[]),
        Some(Sample::Sint(3_632_233_996))
    );
    // 2. Empty input (CRC32 of empty is 0)
    assert_eq!(
        eval_conv("crc32", Sample::Bin(b"".to_vec()), &[]),
        Some(Sample::Sint(0))
    );
    // 3. Avalanche flag
    assert_eq!(
        eval_conv("crc32", Sample::Bin(b"test".to_vec()), &["1"]),
        Some(Sample::Sint(1_274_467_367))
    );
    // 4. Standard test vector b"123456789" -> 0xCBF43926 = 3421780262
    assert_eq!(
        eval_conv("crc32", Sample::Bin(b"123456789".to_vec()), &[]),
        Some(Sample::Sint(3_421_780_262))
    );
    // 5. Refused types
    assert_eq!(eval_conv("crc32", Sample::Sint(123), &[]), None);
}

#[test]
fn test_conv_crc32c() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("crc32c", Sample::Bin(b"test".to_vec()), &[]),
        Some(Sample::Sint(2_258_662_080))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("crc32c", Sample::Bin(b"".to_vec()), &[]),
        Some(Sample::Sint(0))
    );
    // 3. Avalanche flag
    let non_av = eval_conv("crc32c", Sample::Bin(b"test".to_vec()), &[]).unwrap();
    let av = eval_conv("crc32c", Sample::Bin(b"test".to_vec()), &["1"]).unwrap();
    assert_ne!(non_av, av);
    // 4. Standard test vector b"123456789" -> 0xE3069283 = 3808858755
    assert_eq!(
        eval_conv("crc32c", Sample::Bin(b"123456789".to_vec()), &[]),
        Some(Sample::Sint(3_808_858_755))
    );
    // 5. Refused types
    assert_eq!(eval_conv("crc32c", Sample::Sint(123), &[]), None);
}

// =========================================================================
// TIER 3 & Additional Non-Cipher Converters
// =========================================================================

#[test]
fn test_conv_le2dec() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("le2dec", Sample::Bin(vec![1, 2, 3, 4]), &["-", "1"]),
        Some(Sample::Str("1-2-3-4".into()))
    );
    assert_eq!(
        eval_conv("le2dec", Sample::Bin(vec![1, 2, 3, 4]), &["-", "2"]),
        Some(Sample::Str("513-1027".into()))
    );
    assert_eq!(
        eval_conv("le2dec", Sample::Bin(vec![1, 2, 3, 4]), &["-", "4"]),
        Some(Sample::Str("67305985".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("le2dec", Sample::Bin(vec![]), &["-", "2"]),
        Some(Sample::Str(String::new()))
    );
    // 3. Truncation flag
    assert_eq!(
        eval_conv("le2dec", Sample::Bin(vec![1, 2, 3, 4, 5]), &["-", "2", "0"]),
        Some(Sample::Str("513-1027-5".into()))
    );
    assert_eq!(
        eval_conv("le2dec", Sample::Bin(vec![1, 2, 3, 4, 5]), &["-", "2", "1"]),
        Some(Sample::Str("513-1027".into()))
    );
    // 4. Invalid chunk_size
    assert_eq!(eval_conv("le2dec", Sample::Bin(vec![1, 2]), &["-", "0"]), None);
    assert_eq!(eval_conv("le2dec", Sample::Bin(vec![1, 2]), &["-", "9"]), None);
    // 5. Refused types
    assert_eq!(eval_conv("le2dec", Sample::Str("1234".into()), &["-", "1"]), None);
}

#[test]
fn test_conv_word() {
    // 1. Documented behaviour (positive index)
    assert_eq!(
        eval_conv("word", Sample::Str("foo   bar  baz".into()), &["2", " "]),
        Some(Sample::Str("bar".into()))
    );
    // 2. Empty input has no word (HAProxy 3.5-dev8: no sample)
    assert_eq!(eval_conv("word", Sample::Str(String::new()), &["1", " "]), None);
    // 3. Negative index
    assert_eq!(
        eval_conv("word", Sample::Str("foo   bar  baz".into()), &["-1", " "]),
        Some(Sample::Str("baz".into()))
    );
    assert_eq!(
        eval_conv("word", Sample::Str("foo   bar  baz".into()), &["-2", " "]),
        Some(Sample::Str("bar".into()))
    );
    // 4. Count argument (count=2 extracts 2 words with intervening separators; count=0 extracts all remaining)
    assert_eq!(
        eval_conv("word", Sample::Str("foo   bar  baz".into()), &["1", " ", "2"]),
        Some(Sample::Str("foo   bar".into()))
    );
    assert_eq!(
        eval_conv("word", Sample::Str("foo   bar  baz".into()), &["2", " ", "0"]),
        Some(Sample::Str("bar  baz".into()))
    );
    // 5. Index 0 and refused types
    assert_eq!(eval_conv("word", Sample::Str("foo bar".into()), &["0", " "]), None);
    assert_eq!(eval_conv("word", Sample::Bin(b"foo bar".to_vec()), &["1", " "]), None);
}

#[test]
fn test_conv_field() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("field", Sample::Str("a|b|c|d".into()), &["2", "|"]),
        Some(Sample::Str("b".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("field", Sample::Str(String::new()), &["1", "|"]),
        Some(Sample::Str(String::new()))
    );
    // 3. Negative index
    assert_eq!(
        eval_conv("field", Sample::Str("a|b|c|d".into()), &["-1", "|"]),
        Some(Sample::Str("d".into()))
    );
    assert_eq!(
        eval_conv("field", Sample::Str("a|b|c|d".into()), &["-2", "|"]),
        Some(Sample::Str("c".into()))
    );
    // 4. Count argument
    assert_eq!(
        eval_conv("field", Sample::Str("a|b|c|d".into()), &["2", "|", "2"]),
        Some(Sample::Str("b|c".into()))
    );
    assert_eq!(
        eval_conv("field", Sample::Str("a|b|c|d".into()), &["2", "|", "0"]),
        Some(Sample::Str("b|c|d".into()))
    );
    // 5. Index 0 and refused types
    assert_eq!(eval_conv("field", Sample::Str("a|b".into()), &["0", "|"]), None);
    assert_eq!(eval_conv("field", Sample::Bin(b"a|b".to_vec()), &["1", "|"]), None);
}

#[test]
fn test_conv_strcmp() {
    let mut vars = HashMap::new();
    vars.insert("txn.cmp".to_string(), "beta".to_string());
    set_current_vars(vars);

    // 1. Documented behaviour
    assert_eq!(
        eval_conv("strcmp", Sample::Str("alpha".into()), &["txn.cmp"]),
        Some(Sample::Sint(-1))
    );
    assert_eq!(
        eval_conv("strcmp", Sample::Str("beta".into()), &["txn.cmp"]),
        Some(Sample::Sint(0))
    );
    assert_eq!(
        eval_conv("strcmp", Sample::Str("gamma".into()), &["txn.cmp"]),
        Some(Sample::Sint(1))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("strcmp", Sample::Str(String::new()), &["txn.cmp"]),
        Some(Sample::Sint(-1))
    );
    // 3. Missing arg -> None
    assert_eq!(eval_conv("strcmp", Sample::Str("alpha".into()), &[]), None);
    // 4. A literal is no variable: refused at load in HAProxy (T341), no value here
    assert_eq!(eval_conv("strcmp", Sample::Str("foo".into()), &["foo"]), None);
    // 5. Refused types
    assert_eq!(eval_conv("strcmp", Sample::Sint(42), &["foo"]), None);
}

#[test]
fn test_conv_reverse() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("reverse", Sample::Str("hello".into()), &[]),
        Some(Sample::Str("olleh".into()))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("reverse", Sample::Str(String::new()), &[]),
        Some(Sample::Str(String::new()))
    );
    // 3. Palindrome
    assert_eq!(
        eval_conv("reverse", Sample::Str("racecar".into()), &[]),
        Some(Sample::Str("racecar".into()))
    );
    // 4. Single char
    assert_eq!(
        eval_conv("reverse", Sample::Str("x".into()), &[]),
        Some(Sample::Str("x".into()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("reverse", Sample::Sint(123), &[]), None);
}

#[test]
fn test_conv_reverse_dom() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("reverse_dom", Sample::Str("api.example.com".into()), &[]),
        Some(Sample::Str("com.example.api".into()))
    );
    // 2. Single label
    assert_eq!(
        eval_conv("reverse_dom", Sample::Str("localhost".into()), &[]),
        Some(Sample::Str("localhost".into()))
    );
    // 3. Empty input
    assert_eq!(eval_conv("reverse_dom", Sample::Str(String::new()), &[]), None);
    // 4. Two labels
    assert_eq!(
        eval_conv("reverse_dom", Sample::Str("example.com".into()), &[]),
        Some(Sample::Str("com.example".into()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("reverse_dom", Sample::Sint(123), &[]), None);
}

#[test]
fn test_conv_host_only() {
    // 1. Documented behaviour (strips port, lowercases)
    assert_eq!(
        eval_conv("host_only", Sample::Str("Example.COM:8080".into()), &[]),
        Some(Sample::Str("example.com".into()))
    );
    // 2. IPv6 bracketed host: the brackets stay (measured on HAProxy 3.5-dev8)
    assert_eq!(
        eval_conv("host_only", Sample::Str("[2001:db8::1]:443".into()), &[]),
        Some(Sample::Str("[2001:db8::1]".into()))
    );
    // 3. Host without port
    assert_eq!(
        eval_conv("host_only", Sample::Str("HostName".into()), &[]),
        Some(Sample::Str("hostname".into()))
    );
    // 4. Empty input
    assert_eq!(
        eval_conv("host_only", Sample::Str(String::new()), &[]),
        Some(Sample::Str(String::new()))
    );
    // 5. Refused types
    assert_eq!(eval_conv("host_only", Sample::Sint(80), &[]), None);
}

#[test]
fn test_conv_port_only() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("port_only", Sample::Str("example.com:8080".into()), &[]),
        Some(Sample::Sint(8080))
    );
    assert_eq!(
        eval_conv("port_only", Sample::Str("[::1]:443".into()), &[]),
        Some(Sample::Sint(443))
    );
    // 2. No port is port 0 (measured on HAProxy 3.5-dev8)
    assert_eq!(
        eval_conv("port_only", Sample::Str("example.com".into()), &[]),
        Some(Sample::Sint(0))
    );
    // 3. Empty input
    assert_eq!(
        eval_conv("port_only", Sample::Str(String::new()), &[]),
        Some(Sample::Sint(0))
    );
    // 4. Port boundary (65535)
    assert_eq!(
        eval_conv("port_only", Sample::Str("host:65535".into()), &[]),
        Some(Sample::Sint(65535))
    );
    // 5. Refused types
    assert_eq!(eval_conv("port_only", Sample::Bin(b"host:80".to_vec()), &[]), None);
}

#[test]
fn test_conv_iif() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("iif", Sample::Bool(true), &["YES", "NO"]),
        Some(Sample::Str("YES".into()))
    );
    assert_eq!(
        eval_conv("iif", Sample::Bool(false), &["YES", "NO"]),
        Some(Sample::Str("NO".into()))
    );
    // 2. Default args (empty strings)
    assert_eq!(
        eval_conv("iif", Sample::Bool(true), &[]),
        Some(Sample::Str(String::new()))
    );
    assert_eq!(
        eval_conv("iif", Sample::Bool(false), &[]),
        Some(Sample::Str(String::new()))
    );
    // 3. One arg given
    assert_eq!(
        eval_conv("iif", Sample::Bool(false), &["YES"]),
        Some(Sample::Str(String::new()))
    );
    // 4. Refused types
    assert_eq!(eval_conv("iif", Sample::Str("true".into()), &["YES", "NO"]), None);
    assert_eq!(eval_conv("iif", Sample::Sint(1), &["YES", "NO"]), None);
}

#[test]
fn test_conv_when() {
    use ibex_sample::registry::{SampleContext, StreamFacts};
    let reg = Registry::new();
    let when = |facts: Option<StreamFacts>, args: &[&str]| {
        let ctx = SampleContext { stream: facts, ..Default::default() };
        let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
        reg.eval("str", &["v".to_string()], &[("when", args)], &ctx)
    };
    let v = Some(Sample::Str("v".into()));
    let err = Some(StreamFacts { error: true, forwarded: true, toapplet: false, ..Default::default() });
    let app = Some(StreamFacts { error: false, forwarded: false, toapplet: true, ..Default::default() });
    // a stream that has done nothing yet
    assert_eq!(when(None, &["normal"]), v);
    assert_eq!(when(None, &["error"]), None);
    assert_eq!(when(None, &["!error"]), v);
    assert_eq!(when(None, &["forwarded"]), None);
    assert_eq!(when(None, &["stopping"]), None);
    // an error on a forwarded request
    assert_eq!(when(err, &["error"]), v);
    assert_eq!(when(err, &["normal"]), None);
    assert_eq!(when(err, &["forwarded"]), v);
    assert_eq!(when(err, &["processed"]), v);
    assert_eq!(when(err, &["toapplet"]), None);
    // an applet
    assert_eq!(when(app, &["toapplet"]), v);
    assert_eq!(when(app, &["processed"]), v);
    assert_eq!(when(app, &["forwarded"]), None);
    // no ACLs known, unknown condition, missing arguments: no sample
    assert_eq!(when(None, &["acl", "x"]), None);
    assert_eq!(when(None, &["bogus"]), None);
    assert_eq!(when(None, &[]), None);
}

#[test]
fn test_conv_djb2() {
    // 1. Documented behaviour
    assert_eq!(
        eval_conv("djb2", Sample::Bin(b"test".to_vec()), &[]),
        Some(Sample::Sint(2_090_756_197))
    );
    // 2. Empty input
    assert_eq!(
        eval_conv("djb2", Sample::Bin(b"".to_vec()), &[]),
        Some(Sample::Sint(5381))
    );
    // 3. Avalanche
    let non_av = eval_conv("djb2", Sample::Bin(b"test".to_vec()), &[]).unwrap();
    let av = eval_conv("djb2", Sample::Bin(b"test".to_vec()), &["1"]).unwrap();
    assert_ne!(non_av, av);
    // 4. Deterministic
    assert_eq!(
        eval_conv("djb2", Sample::Bin(b"hello".to_vec()), &[]),
        eval_conv("djb2", Sample::Bin(b"hello".to_vec()), &[])
    );
    // 5. Refused types
    assert_eq!(eval_conv("djb2", Sample::Sint(123), &[]), None);
}

#[test]
fn test_conv_sha1() {
    // 1. Documented behaviour
    let res = eval_conv("sha1", Sample::Bin(b"abc".to_vec()), &[]).unwrap();
    assert_eq!(
        res,
        Sample::Bin(vec![
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
            0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ])
    );
    // 2. Empty input sha1
    let empty_res = eval_conv("sha1", Sample::Bin(b"".to_vec()), &[]).unwrap();
    assert_eq!(
        empty_res,
        Sample::Bin(vec![
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
            0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ])
    );
    // 3. Length is 20 bytes
    if let Sample::Bin(b) = res {
        assert_eq!(b.len(), 20);
    }
    // 4. Deterministic
    assert_eq!(
        eval_conv("sha1", Sample::Bin(b"test".to_vec()), &[]),
        eval_conv("sha1", Sample::Bin(b"test".to_vec()), &[])
    );
    // 5. Refused types
    assert_eq!(eval_conv("sha1", Sample::Sint(123), &[]), None);
}
