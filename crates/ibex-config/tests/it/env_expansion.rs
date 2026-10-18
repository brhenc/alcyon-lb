// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T430 rows 11 and 21: `$VAR` in double quotes and `setenv` and its three siblings.
//! Every expected value was measured on HAProxy 3.5-dev8 with `.notice`, which prints the
//! argument after `parse_line` has expanded it.

use ibex_config::parse_str;

/// The text of each `.notice`, in order.
fn notices(cfg: &str) -> Vec<String> {
    parse_str(cfg).unwrap().directive_messages.into_iter().map(|m| m.text).collect()
}

fn refusal(cfg: &str) -> String {
    parse_str(cfg).unwrap_err().message
}

#[test]
fn a_variable_in_double_quotes_is_expanded_in_any_keyword() {
    std::env::set_var("IBEX_T430_P", "127.0.0.1:18431");
    let c = parse_str(
        "defaults\n mode http\nfrontend f\n bind 127.0.0.1:18999\n http-request return status 200 hdr x1 \"${IBEX_T430_P}\" hdr x2 ${IBEX_T430_P}\n",
    )
    .unwrap();
    let dump = format!("{c:?}");
    assert!(dump.contains("127.0.0.1:18431"), "x1 was not expanded");
    assert!(dump.contains("${IBEX_T430_P}"), "x2 (unquoted) must stay literal");
}

#[test]
fn the_forms_of_a_reference() {
    std::env::set_var("IBEX_T430_Q", "hello");
    let cfg = "global\n\
        .notice \"$IBEX_T430_Q\"\n\
        .notice \"a${IBEX_T430_Q}b\"\n\
        .notice '$IBEX_T430_Q'\n\
        .notice $IBEX_T430_Q\n\
        .notice \"x${IBEX_T430_NO}y\"\n\
        .notice \"${IBEX_T430_NO-def}\"\n\
        .notice \"${IBEX_T430_Q-def}\"\n\
        .notice \"${IBEX_T430_NO-a b}\"\n\
        .notice \"\\$IBEX_T430_Q\"\n\
        .notice \"\\\\$IBEX_T430_Q\"\n\
        .notice \"$IBEX_T430_Q-x ${IBEX_T430_Q}-x\"\n\
        .notice \"${IBEX_T430_Q-a}b}\"\n\
        .notice \"${IBEX_T430_NO-}x\"\n\
        .notice \"$.LINE ${.SECTION}\"\n";
    assert_eq!(
        notices(cfg),
        [
            "hello",
            "ahellob",
            "$IBEX_T430_Q",
            "$IBEX_T430_Q",
            "xy",
            "def",
            "hello",
            "a b",
            "$IBEX_T430_Q",
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
    let e = refusal("frontend f\n bind 127.0.0.1:18999\n http-request return status 200 hdr x \"${IBEX_T430_NO}\" hdr y z\n");
    assert!(e.contains("argument number 6 at position 42 is empty and marks the end of the argument list"), "{e}");
    let e = refusal("frontend f\n bind 127.0.0.1:18999\n http-request return status 200 hdr x \"\"\n");
    assert!(e.contains("argument number 6 at position 40 is empty"), "{e}");
}

#[test]
fn the_words_of_a_reference_in_brackets_are_split() {
    let e = refusal("global\nsetenv IBEX_T430_W \"a  b c\"\n.notice \"${IBEX_T430_W[*]}\"\n");
    assert!(e.contains("Unexpected argument 'b' for '.notice'"), "{e}");
    let e = refusal("global\nsetenv IBEX_T430_W \" a  b \"\n.notice x \"${IBEX_T430_W[*]}\"\n");
    assert!(e.contains("Unexpected argument 'a' for '.notice'"), "{e}");
    // Without the brackets the value stays one word.
    assert_eq!(notices("global\nsetenv IBEX_T430_W \"a  b c\"\n.notice \"${IBEX_T430_W}\"\n"), ["a  b c"]);
}

#[test]
fn setenv_acts_on_the_lines_after_it_and_before_it() {
    // HAProxy reads the file twice and runs the environment keywords on the first pass: the
    // first `.notice` already sees the last value.
    let cfg = "global\n.notice \"${IBEX_T430_A-unset}\"\nsetenv IBEX_T430_A one\n.notice \"${IBEX_T430_A-unset}\"\nsetenv IBEX_T430_A two\n.notice \"${IBEX_T430_A-unset}\"\n";
    assert_eq!(notices(cfg), ["two", "one", "two"]);
}

#[test]
fn presetenv_unsetenv_and_resetenv() {
    let cfg = "global\npresetenv IBEX_T430_B one\npresetenv IBEX_T430_B two\n.notice \"${IBEX_T430_B}\"\n";
    assert_eq!(notices(cfg), ["one"]);
    std::env::set_var("IBEX_T430_C", "inherited");
    let cfg = "global\npresetenv IBEX_T430_C other\n.notice \"${IBEX_T430_C}\"\n";
    assert_eq!(notices(cfg), ["inherited"]);
    let cfg = "global\nunsetenv IBEX_T430_C IBEX_T430_D\n.notice \"${IBEX_T430_C-gone}${IBEX_T430_D-gone}\"\n";
    assert_eq!(notices(cfg), ["gonegone"]);
    std::env::set_var("IBEX_T430_E", "1");
    std::env::set_var("IBEX_T430_F", "2");
    let cfg = "global\nresetenv IBEX_T430_E\n.notice \"${IBEX_T430_E-gone}${IBEX_T430_F-gone}${PATH-gone}\"\n";
    assert_eq!(notices(cfg), ["1gonegone"]);
}

#[test]
fn a_setenv_in_a_branch_that_is_left_out_does_nothing() {
    let cfg = "global\n.if 0\nsetenv IBEX_T430_G b\n.endif\n.notice \"${IBEX_T430_G-unset}\"\n.if defined(IBEX_T430_H)\n.notice yes\n.else\n.notice no\n.endif\nsetenv IBEX_T430_H x\n";
    assert_eq!(notices(cfg), ["unset", "yes"]);
}

#[test]
fn setenv_is_reported_for_the_process_and_refused_outside_global() {
    let c = parse_str("global\nsetenv IBEX_T430_I v\nunsetenv IBEX_T430_J\nresetenv IBEX_T430_K\n").unwrap();
    assert_eq!(c.env_ops.len(), 6, "each keyword is run by both passes: {:?}", c.env_ops);
    assert!(refusal("global\nsetenv A b\nfrontend f\n setenv C d\n").contains("unknown keyword 'setenv' in 'frontend' section"));
}

#[test]
fn the_refusals_of_the_keywords_are_haproxys() {
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
    use ibex_config::env::{apply_to_process, EnvOp};
    std::env::set_var("IBEX_T430_R1", "old");
    apply_to_process(&[
        EnvOp::Set { name: "IBEX_T430_R1".into(), value: "ignored".into(), overwrite: false },
        EnvOp::Set { name: "IBEX_T430_R2".into(), value: "new".into(), overwrite: true },
    ]);
    assert_eq!(std::env::var("IBEX_T430_R1").unwrap(), "old");
    assert_eq!(std::env::var("IBEX_T430_R2").unwrap(), "new");
    apply_to_process(&[EnvOp::Unset(vec!["IBEX_T430_R1".into()])]);
    assert!(std::env::var_os("IBEX_T430_R1").is_none());
}
