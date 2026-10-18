// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T334: the seed (or avalanche flag) argument of the hash converters is `ARGT_SINT`
//! (`read_int64`, saturating) in HAProxy, and `xxh3` is the real XXH3-64. Every expected
//! value was measured on the 3.5-dev8 oracle with `str(abc),<conv>(<arg>)`.

use ibex_sample::registry::{check_converter_args, Registry};
use ibex_sample::sample::Sample;

fn hash(name: &str, arg: &str) -> Option<Sample> {
    let reg = Registry::new();
    let conv = reg.get_converter(name).expect(name);
    let args: Vec<String> = if arg.is_empty() { vec![] } else { vec![arg.to_string()] };
    (conv.func)(Sample::Bin(b"abc".to_vec()), &args)
}

const NOT_INTEGERS: [&str; 5] = ["abc", "1x", "0x10", " ", "1.5"];
const NONZERO: [&str; 8] = ["1", "-1", "4294967296", "9223372036854775808", "18446744073709551615", "99999999999999999999", "-99999999999999999999", "+5"];

#[test]
fn avalanche_flag_is_any_nonzero_integer_saturated() {
    // (converter, plain, avalanched)
    for (name, plain, full) in [("crc32", 891_568_578, 930_845_320), ("crc32c", 910_901_175, 1_285_784_220), ("djb2", 193_485_963, 2_235_766_107), ("sdbm", 807_794_786, 659_243_622), ("wt6", 2_483_038_440, 266_135_527)] {
        assert_eq!(hash(name, ""), Some(Sample::Sint(plain)), "{name}()");
        assert_eq!(hash(name, "0"), Some(Sample::Sint(plain)), "{name}(0)");
        for a in NONZERO {
            assert_eq!(hash(name, a), Some(Sample::Sint(full)), "{name}({a})");
        }
    }
}

#[test]
fn non_integer_seeds_are_refused_at_load_for_every_seeded_hash() {
    for name in ["crc32", "crc32c", "djb2", "sdbm", "wt6", "xxh32", "xxh64", "xxh3"] {
        for a in NOT_INTEGERS {
            assert_eq!(
                check_converter_args(name, &[a.to_string()]),
                Some(format!("invalid arg 1 in converter '{name}' : failed to parse '{a}' as type 'integer' at position 1.")),
                "{name}({a})"
            );
        }
        for a in ["", "0", "-1", "99999999999999999999", "+5"] {
            assert_eq!(check_converter_args(name, &[a.to_string()]), None, "{name}({a})");
        }
    }
}

#[test]
fn xxh3_seeds_as_the_oracle() {
    for (a, want) in [
        ("", 8_696_274_497_037_089_104_i64),
        ("0", 8_696_274_497_037_089_104),
        ("1", 7_729_416_884_403_528_232),
        ("-1", 2_962_310_483_463_817_673),
        ("2147483648", -1_081_156_832_777_739_594),
        ("4294967296", -3_240_327_457_178_524_844),
        ("4294967297", 69_210_497_401_382_848),
        ("9223372036854775807", 4_293_879_458_369_310_057),
        ("18446744073709551615", 4_293_879_458_369_310_057),
        ("99999999999999999999", 4_293_879_458_369_310_057),
        ("-99999999999999999999", 6_348_497_719_430_634_268),
        ("+5", 6_167_986_026_487_092_235),
    ] {
        assert_eq!(hash("xxh3", a), Some(Sample::Sint(want)), "xxh3({a})");
    }
}

#[test]
fn xxh32_and_xxh64_saturate_like_the_oracle() {
    assert_eq!(hash("xxh32", "99999999999999999999"), Some(Sample::Sint(2_989_167_648)));
    assert_eq!(hash("xxh32", "-99999999999999999999"), Some(Sample::Sint(852_579_327)));
    assert_eq!(hash("xxh32", "+5"), Some(Sample::Sint(1_562_728_233)));
    assert_eq!(hash("xxh64", "99999999999999999999"), Some(Sample::Sint(-6_843_889_581_911_917_747)));
    assert_eq!(hash("xxh64", "-99999999999999999999"), Some(Sample::Sint(-2_991_377_997_648_133_420)));
    assert_eq!(hash("xxh64", "+5"), Some(Sample::Sint(-1_753_195_980_308_443_340)));
}
