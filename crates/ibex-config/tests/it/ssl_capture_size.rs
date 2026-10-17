// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.ssl.capture-buffer-size` (T344 C1) sizes the `ClientHello` capture that the
//! `ssl_fc_cipherlist_*` family reads; it was accepted and dropped. `HAProxy` parses it with
//! `ssl_parse_global_int` (`atoi`, so a word is 0) and refuses a second occurrence of either
//! spelling; `tune.ssl.capture-cipherlist-size` is the deprecated alias and warns. Every text
//! below is measured with `haproxy -c` (3.5-dev8-885761-29).

use ibex_config::ast::GlobalSection;
use ibex_config::parse_str;

fn global(cfg: &str) -> GlobalSection {
    parse_str(cfg).unwrap_or_else(|e| panic!("refused: {}", e.message)).global.expect("global")
}

fn refusal(cfg: &str) -> (usize, String) {
    match parse_str(cfg) {
        Ok(_) => panic!("accepted:\n{cfg}"),
        Err(e) => (e.line, e.message),
    }
}

#[test]
fn the_size_is_stored() {
    assert_eq!(global("global\n tune.ssl.capture-buffer-size 1024\n").tune_ssl_capture_buffer_size, 1024);
    assert_eq!(global("global\n tune.ssl.capture-buffer-size 0\n").tune_ssl_capture_buffer_size, 0);
    assert_eq!(global("global\n daemon\n").tune_ssl_capture_buffer_size, 0, "unset is 0: nothing captured");
    // `atoi`: a word is 0, a number stops at the first non-digit; both load.
    assert_eq!(global("global\n tune.ssl.capture-buffer-size abc\n").tune_ssl_capture_buffer_size, 0);
    assert_eq!(global("global\n tune.ssl.capture-buffer-size 12abc\n").tune_ssl_capture_buffer_size, 12);
}

#[test]
fn syntax_errors_are_haproxys() {
    let k = "tune.ssl.capture-buffer-size";
    assert_eq!(refusal(&format!("global\n {k}\n")).1, format!("'{k}' expects an integer argument."));
    assert_eq!(refusal(&format!("global\n {k} -1\n")).1, format!("'{k}' expects a positive numeric value."));
    assert_eq!(refusal(&format!("global\n {k} 16 extra\n")).1, format!("'{k}' cannot handle unexpected argument 'extra'."));
    assert_eq!(refusal(&format!("global\n {k} 16\n {k} 32\n")), (3, format!("'{k}' is already configured.")));
}

#[test]
fn the_deprecated_alias_sets_the_same_size_and_warns() {
    let g = global("global\n tune.ssl.capture-cipherlist-size 16\n");
    assert_eq!(g.tune_ssl_capture_buffer_size, 16);
    let w: Vec<(usize, &str, bool)> = g.load_warnings.iter().map(|w| (w.line, w.text.as_str(), w.alert)).collect();
    assert_eq!(
        w,
        [(
            2,
            "'tune.ssl.capture-cipherlist-size' is deprecated and will be removed in version 2.7. Please use 'tune.ssl.capture-buffer-size' instead.",
            false
        )]
    );
    assert_eq!(g.load_warnings[0].style, ibex_config::ast::global::WarnStyle::Tight);
    // Either spelling after the other is a second occurrence.
    assert_eq!(
        refusal("global\n tune.ssl.capture-cipherlist-size 16\n tune.ssl.capture-buffer-size 16\n"),
        (3, "'tune.ssl.capture-buffer-size' is already configured.".to_string())
    );
}
