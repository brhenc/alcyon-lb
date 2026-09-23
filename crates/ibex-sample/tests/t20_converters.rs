use ibex_sample::registry::Registry;
use ibex_sample::sample::Sample;

fn eval_conv(name: &str, input: Sample, args: &[&str]) -> Option<Sample> {
    let reg = Registry::new();
    let conv = reg.get_converter(name).expect(name);
    let args_vec: Vec<String> = args.iter().map(|&s| s.to_string()).collect();
    (conv.func)(input, &args_vec)
}

#[test]
fn test_div() {
    assert_eq!(eval_conv("div", Sample::Sint(10), &["2"]), Some(Sample::Sint(5)));
    assert_eq!(eval_conv("div", Sample::Sint(10), &["0"]), Some(Sample::Sint(i64::MAX)));
    assert_eq!(eval_conv("div", Sample::Str("10".into()), &["2"]), None);
    assert_eq!(eval_conv("div", Sample::Sint(10), &[]), None); // missing arg
}

#[test]
fn test_mod() {
    assert_eq!(eval_conv("mod", Sample::Sint(10), &["3"]), Some(Sample::Sint(1)));
    assert_eq!(eval_conv("mod", Sample::Sint(10), &["0"]), Some(Sample::Sint(0)));
    assert_eq!(eval_conv("mod", Sample::Str("10".into()), &["3"]), None);
}

#[test]
fn test_hex2i() {
    assert_eq!(eval_conv("hex2i", Sample::Str("010203".into()), &[]), Some(Sample::Sint(66051)));
    assert_eq!(eval_conv("hex2i", Sample::Str("0x12".into()), &[]), None); // HAProxy rejects 0x
    assert_eq!(eval_conv("hex2i", Sample::Str("nothex".into()), &[]), None);
    assert_eq!(eval_conv("hex2i", Sample::Str(String::new()), &[]), None);
}


#[test]
fn test_bytes() {
    assert_eq!(eval_conv("bytes", Sample::Bin(b"abcdef".to_vec()), &["1", "2"]), Some(Sample::Bin(b"bc".to_vec())));
    assert_eq!(eval_conv("bytes", Sample::Bin(b"abcdef".to_vec()), &["0", "10"]), Some(Sample::Bin(b"abcdef".to_vec())));
    assert_eq!(eval_conv("bytes", Sample::Bin(b"abcdef".to_vec()), &["10", "2"]), Some(Sample::Bin(b"".to_vec())));
    assert_eq!(eval_conv("bytes", Sample::Bin(b"abcdef".to_vec()), &["1"]), Some(Sample::Bin(b"bcdef".to_vec())));
    assert_eq!(eval_conv("bytes", Sample::Bin(b"abcdef".to_vec()), &[]), Some(Sample::Bin(b"abcdef".to_vec())));
    assert_eq!(eval_conv("bytes", Sample::Bin(b"".to_vec()), &[]), Some(Sample::Bin(b"".to_vec())));
    assert_eq!(eval_conv("bytes", Sample::Str("abc".into()), &[]), None);
}

#[test]
fn test_field() {
    assert_eq!(eval_conv("field", Sample::Str("a|b|c".into()), &["1", "|"]), Some(Sample::Str("a".into())));
    assert_eq!(eval_conv("field", Sample::Str("a|b|c".into()), &["4", "|"]), Some(Sample::Str(String::new())));
    assert_eq!(eval_conv("field", Sample::Str("a|b|c".into()), &["0", "|"]), None);
    assert_eq!(eval_conv("field", Sample::Str(String::new()), &["1", "|"]), Some(Sample::Str(String::new())));
    assert_eq!(eval_conv("field", Sample::Bin(b"abc".to_vec()), &["1", "|"]), None);
}

#[test]
fn test_word() {
    assert_eq!(eval_conv("word", Sample::Str("a b c".into()), &["2"]), Some(Sample::Str("b".into())));
    assert_eq!(eval_conv("word", Sample::Str("a b c".into()), &["0"]), None);
    assert_eq!(eval_conv("word", Sample::Str(String::new()), &["1"]), Some(Sample::Str(String::new())));
    assert_eq!(eval_conv("word", Sample::Bin(b"abc".to_vec()), &["1"]), None);
}

/// `field` regressed once: negative indices and the `count` argument were deleted and the
/// test only covered positive two-argument calls, so the suite stayed green over it.
/// doc/configuration.txt:21961 -- negative index counts from the end; count 0 means all
/// remaining fields.
#[test]
fn field_negative_index_counts_from_the_end() {
    let s = || Sample::Str("a|b|c".into());
    assert_eq!(eval_conv("field", s(), &["-1", "|"]), Some(Sample::Str("c".into())));
    assert_eq!(eval_conv("field", s(), &["-2", "|"]), Some(Sample::Str("b".into())));
    assert_eq!(eval_conv("field", s(), &["-3", "|"]), Some(Sample::Str("a".into())));
}

#[test]
fn field_count_extracts_several_fields() {
    let s = || Sample::Str("a|b|c|d".into());
    assert_eq!(eval_conv("field", s(), &["2", "|", "2"]), Some(Sample::Str("b|c".into())));
    assert_eq!(eval_conv("field", s(), &["2", "|", "0"]), Some(Sample::Str("b|c|d".into())));
    assert_eq!(eval_conv("field", s(), &["1", "|", "1"]), Some(Sample::Str("a".into())));
}
