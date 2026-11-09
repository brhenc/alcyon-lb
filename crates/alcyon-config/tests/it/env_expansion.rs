// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T430 rows 11 and 21: `$VAR` in double quotes and `setenv` and its three siblings.
//! Every expected value was measured on HAProxy 3.5-dev8 with `.notice`, which prints the
//! argument after `parse_line` has expanded it.

use alcyon_config::parse_str;

/// The text of each `.notice`, in order.
fn notices(cfg: &str) -> Vec<String> {
    parse_str(cfg).unwrap().directive_messages.into_iter().map(|m| m.text).collect()
}

/// The tests set, read and (one of them) wipe the process environment, which they share:
/// each holds this for its whole run, so no other sees the variables of the one running.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn refusal(cfg: &str) -> String {
    parse_str(cfg).unwrap_err().message
}

#[test]
fn a_variable_in_double_quotes_is_expanded_in_any_keyword() {
    let _env = env_lock();
    std::env::set_var("ALCYON_T430_P", "127.0.0.1:18431");
    let c = parse_str(
        "defaults\n mode http\nfrontend f\n bind 127.0.0.1:18999\n http-request return status 200 hdr x1 \"${ALCYON_T430_P}\" hdr x2 ${ALCYON_T430_P}\n",
    )
    .unwrap();
    let dump = format!("{c:?}");
    assert!(dump.contains("127.0.0.1:18431"), "x1 was not expanded");
    assert!(dump.contains("${ALCYON_T430_P}"), "x2 (unquoted) must stay literal");
}

#[test]
fn the_forms_of_a_reference() {
    let _env = env_lock();
    std::env::set_var("ALCYON_T430_Q", "hello");
    let cfg = "global\n\
        .notice \"$ALCYON_T430_Q\"\n\
        .notice \"a${ALCYON_T430_Q}b\"\n\
        .notice '$ALCYON_T430_Q'\n\
        .notice $ALCYON_T430_Q\n\
        .notice \"x${ALCYON_T430_NO}y\"\n\
        .notice \"${ALCYON_T430_NO-def}\"\n\
        .notice \"${ALCYON_T430_Q-def}\"\n\
        .notice \"${ALCYON_T430_NO-a b}\"\n\
        .notice \"\\$ALCYON_T430_Q\"\n\
        .notice \"\\\\$ALCYON_T430_Q\"\n\
        .notice \"$ALCYON_T430_Q-x ${ALCYON_T430_Q}-x\"\n\
        .notice \"${ALCYON_T430_Q-a}b}\"\n\
        .notice \"${ALCYON_T430_NO-}x\"\n\
        .notice \"$.LINE ${.SECTION}\"\n";
    assert_eq!(
        notices(cfg),
        [
            "hello",
            "ahellob",
            "$ALCYON_T430_Q",
            "$ALCYON_T430_Q",
            "xy",
            "def",
            "hello",
            "a b",
            "$ALCYON_T430_Q",
            "\\hello",
            "hello-x hello-x",
            "hellob}",
            "x",
            "15 global",
        ]
    );
}

#[test]
fn a_reference_that_cannot_be_read_is_refused() {
    let _env = env_lock();
    assert!(refusal("global\n.notice \"$\"\n").contains("forbidden first char in environment variable name at position 11"));
    assert!(refusal("global\n.notice \"$1\"\n").contains("forbidden first char in environment variable name"));
    assert!(refusal("global\n.notice \"${.FOO}\"\n").contains("forbidden first char in environment variable name at position 12"));
    assert!(refusal("global\n.notice \"${P\"\n").contains("unmatched brace in environment variable name at position 11"));
    assert!(refusal("global\n.notice \"${P:-d}\"\n").contains("unmatched brace"));
    assert!(refusal("global\n.notice \"a\n").contains("unmatched quote at position 9"));
    assert!(refusal("global\n.notice \"${P[x]}\"\n").contains("truncated or invalid word expansion sequence"));
}

#[test]
fn an_argument_left_empty_by_an_unset_variable_is_refused() {
    let _env = env_lock();
    let e = refusal("frontend f\n bind 127.0.0.1:18999\n http-request return status 200 hdr x \"${ALCYON_T430_NO}\" hdr y z\n");
    assert!(e.contains("argument number 6 at position 42 is empty and marks the end of the argument list"), "{e}");
    let e = refusal("frontend f\n bind 127.0.0.1:18999\n http-request return status 200 hdr x \"\"\n");
    assert!(e.contains("argument number 6 at position 40 is empty"), "{e}");
}

#[test]
fn the_words_of_a_reference_in_brackets_are_split() {
    let _env = env_lock();
    let e = refusal("global\nsetenv ALCYON_T430_W \"a  b c\"\n.notice \"${ALCYON_T430_W[*]}\"\n");
    assert!(e.contains("Unexpected argument 'b' for '.notice'"), "{e}");
    let e = refusal("global\nsetenv ALCYON_T430_W \" a  b \"\n.notice x \"${ALCYON_T430_W[*]}\"\n");
    assert!(e.contains("Unexpected argument 'a' for '.notice'"), "{e}");
    // Without the brackets the value stays one word.
    assert_eq!(notices("global\nsetenv ALCYON_T430_W \"a  b c\"\n.notice \"${ALCYON_T430_W}\"\n"), ["a  b c"]);
}

#[test]
fn setenv_acts_on_the_lines_after_it_and_before_it() {
    let _env = env_lock();
    // HAProxy reads the file twice and runs the environment keywords on the first pass: the
    // first `.notice` already sees the last value.
    let cfg = "global\n.notice \"${ALCYON_T430_A-unset}\"\nsetenv ALCYON_T430_A one\n.notice \"${ALCYON_T430_A-unset}\"\nsetenv ALCYON_T430_A two\n.notice \"${ALCYON_T430_A-unset}\"\n";
    assert_eq!(notices(cfg), ["two", "one", "two"]);
}

#[test]
fn presetenv_unsetenv_and_resetenv() {
    let _env = env_lock();
    let cfg = "global\npresetenv ALCYON_T430_B one\npresetenv ALCYON_T430_B two\n.notice \"${ALCYON_T430_B}\"\n";
    assert_eq!(notices(cfg), ["one"]);
    std::env::set_var("ALCYON_T430_C", "inherited");
    let cfg = "global\npresetenv ALCYON_T430_C other\n.notice \"${ALCYON_T430_C}\"\n";
    assert_eq!(notices(cfg), ["inherited"]);
    let cfg = "global\nunsetenv ALCYON_T430_C ALCYON_T430_D\n.notice \"${ALCYON_T430_C-gone}${ALCYON_T430_D-gone}\"\n";
    assert_eq!(notices(cfg), ["gonegone"]);
    std::env::set_var("ALCYON_T430_E", "1");
    std::env::set_var("ALCYON_T430_F", "2");
    let cfg = "global\nresetenv ALCYON_T430_E\n.notice \"${ALCYON_T430_E-gone}${ALCYON_T430_F-gone}${PATH-gone}\"\n";
    assert_eq!(notices(cfg), ["1gonegone"]);
}

#[test]
fn a_setenv_in_a_branch_that_is_left_out_does_nothing() {
    let _env = env_lock();
    let cfg = "global\n.if 0\nsetenv ALCYON_T430_G b\n.endif\n.notice \"${ALCYON_T430_G-unset}\"\n.if defined(ALCYON_T430_H)\n.notice yes\n.else\n.notice no\n.endif\nsetenv ALCYON_T430_H x\n";
    assert_eq!(notices(cfg), ["unset", "yes"]);
}

#[test]
fn setenv_is_reported_for_the_process_and_refused_outside_global() {
    let _env = env_lock();
    let c = parse_str("global\nsetenv ALCYON_T430_I v\nunsetenv ALCYON_T430_J\nresetenv ALCYON_T430_K\n").unwrap();
    assert_eq!(c.env_ops.len(), 6, "each keyword is run by both passes: {:?}", c.env_ops);
    assert!(refusal("global\nsetenv A b\nfrontend f\n setenv C d\n").contains("unknown keyword 'setenv' in 'frontend' section"));
}

#[test]
fn the_refusals_of_the_keywords_are_haproxys() {
    let _env = env_lock();
    assert!(refusal("global\nsetenv A\n").contains("'setenv' expects environment variable value for 'A'."));
    assert!(refusal("global\nsetenv\n").contains("'setenv' expects environment variable name."));
    assert!(refusal("global\nsetenv \"\" c\n").contains("'setenv' expects environment variable name."));
    assert!(refusal("global\nsetenv A \"\"\n").contains("'setenv' expects environment variable value for 'A'."));
    assert!(refusal("global\npresetenv A\n").contains("'presetenv' expects environment variable value for 'A'."));
    assert!(refusal("global\nsetenv A b c\n").contains("'setenv' cannot handle unexpected argument 'c'."));
    assert!(refusal("global\nunsetenv\n").contains("'unsetenv' expects at least one variable name."));
    assert!(refusal("global\nsetenv A=B c\n").contains("'setenv' failed on variable 'A=B' : Invalid argument."));
    assert!(refusal("global\nunsetenv A=B\n").contains("'unsetenv' failed on variable 'A=B' : Invalid argument."));
}

#[test]
fn the_recorded_changes_can_be_replayed_on_the_process() {
    let _env = env_lock();
    use alcyon_config::env::{apply_to_process, EnvOp};
    std::env::set_var("ALCYON_T430_R1", "old");
    apply_to_process(&[
        EnvOp::Set { name: "ALCYON_T430_R1".into(), value: "ignored".into(), overwrite: false },
        EnvOp::Set { name: "ALCYON_T430_R2".into(), value: "new".into(), overwrite: true },
    ]);
    assert_eq!(std::env::var("ALCYON_T430_R1").unwrap(), "old");
    assert_eq!(std::env::var("ALCYON_T430_R2").unwrap(), "new");
    apply_to_process(&[EnvOp::Unset(vec!["ALCYON_T430_R1".into()])]);
    assert!(std::env::var_os("ALCYON_T430_R1").is_none());
}

#[test]
fn file_reset_replay_empty_single_quotes_open_default_and_vanishing_line() {
    let _env = env_lock();
    // env.rs file(): `${.FILE}` is the name given to `set_file`.
    alcyon_config::env::set_file("t430.cfg");
    assert_eq!(notices("global\n.notice \"${.FILE}\"\n"), ["t430.cfg"]);
    // env.rs Reset replay: keep everything but one variable.
    std::env::set_var("ALCYON_T430_RESET_ME", "1");
    let keep: Vec<String> = std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()).filter(|k| k != "ALCYON_T430_RESET_ME").collect();
    alcyon_config::env::apply_to_process(&[alcyon_config::env::EnvOp::Reset(keep)]);
    assert!(std::env::var_os("ALCYON_T430_RESET_ME").is_none());
    // lexer.rs: closing an empty '' makes an empty word (a directive may have one).
    assert_eq!(notices("global\n.notice ''\n"), [""]);
    // lexer.rs: a default value that is never closed is an unmatched brace.
    assert!(refusal("global\n.notice \"${ALCYON_T430_NO-abc\"\n").contains("unmatched brace"));
    // preproc.rs: a line whose only word is an unset `[*]` reference has no words and is dropped.
    assert!(notices("global\n\"${ALCYON_T430_NO[*]}\"\n.notice ok\n") == ["ok"]);
}

#[test]
fn preprocess_skips_a_line_without_tokens() {
    let _env = env_lock();
    // `lex` never yields one that parse_str lets through (a token-less line is kept only
    // with a lex error), but `Line` is public and `preprocess` indexes the first token.
    let mut lines = alcyon_config::lexer::lex("global\n.notice ok\n");
    lines.insert(1, alcyon_config::lexer::Line { line_number: 2, tokens: Vec::new(), error: None, raw: String::new() });
    let out = alcyon_config::preproc::preprocess(lines).unwrap();
    assert_eq!(out.len(), 1);
}
