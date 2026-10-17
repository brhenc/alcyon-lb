// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `field` and `word` with a huge third argument (T358 #3).
//!
//! `start + count` overflowed `usize` for a count of 2^64 - 1 and panicked (the process
//! aborts on a panic). Measured on `HAProxy` 3.5-dev8-885761-29 with `x-a: a,b,,c`, the
//! count clamps to the end of the input, whatever its size, 2^64 and 10^20 included:
//!
//! ```text
//! req.fhdr(x-a),field(2,',',18446744073709551615)  [b,,c]     field(2,',',2)  [b,]
//! req.fhdr(x-a),word(3,',',18446744073709551615)   [c]
//! ```
//!
//! A count below 1 is "to the end", as 0 (measured with `a: a:b:c:d`):
//! `field(2,:,-1)` and `field(2,:,-7)` `[b:c:d]`, `word(2,:,-1)` `[b:c:d]`.

use ibex_sample::registry::Registry;
use ibex_sample::sample::Sample;

fn eval(name: &str, input: &str, args: &[&str]) -> Option<Sample> {
    let reg = Registry::new();
    let conv = reg.get_converter(name).expect(name);
    let args: Vec<String> = args.iter().map(|&s| s.to_string()).collect();
    (conv.func)(Sample::Str(input.into()), &args)
}

const HUGE: &[&str] = &["18446744073709551615", "9223372036854775807", "4294967296", "18446744073709551616", "99999999999999999999"];

#[test]
fn field_with_a_huge_count_takes_the_rest() {
    for count in HUGE {
        assert_eq!(eval("field", "a,b,,c", &["2", ",", count]), Some(Sample::Str("b,,c".into())), "{count}");
    }
    assert_eq!(eval("field", "a,b,,c", &["2", ",", "2"]), Some(Sample::Str("b,".into())));
}

#[test]
fn word_with_a_huge_count_takes_the_rest() {
    for count in HUGE {
        assert_eq!(eval("word", "a,b,,c", &["3", ",", count]), Some(Sample::Str("c".into())), "{count}");
        assert_eq!(eval("word", "a,b,,c", &["2", ",", count]), Some(Sample::Str("b,,c".into())), "{count}");
    }
}

#[test]
fn a_count_below_one_takes_the_rest() {
    for count in ["-1", "-7", "0"] {
        assert_eq!(eval("field", "a:b:c:d", &["2", ":", count]), Some(Sample::Str("b:c:d".into())), "field {count}");
        assert_eq!(eval("word", "a:b:c:d", &["2", ":", count]), Some(Sample::Str("b:c:d".into())), "word {count}");
    }
}
