//! Address forms, measured against what the reference binary accepts.
//!
//! `${VAR}` expansion landed in `parser/address.rs` under T62 and matches HAProxy on the
//! common forms: `${UNDEF}:8080` and `${UNDEF_A}:${UNDEF_B}` are accepted by both, because
//! a missing variable expands to nothing and what is left still parses.
//!
//! It did not match on one: an address that is *entirely* a single undefined variable.
//! HAProxy 3.5-dev7 refuses that with
//!
//!     'bind' : '${NO_SUCH_VAR}' resolves to an empty address (environment variable missing?)
//!
//! and Ibex accepted it. That is the case worth refusing -- an operator whose deployment
//! forgot to set the variable gets a listener on an address they did not choose, rather than
//! a daemon that will not start.

use ibex_config::parse_str;

fn cfg(bind: &str) -> String {
    format!(
        "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\ttimeout server 10s\n\
         frontend f\n\tbind {bind}\n\tdefault_backend b\n\
         backend b\n\tserver s1 127.0.0.1:9000\n"
    )
}

/// The whole address is one variable that is not set: refuse it, as HAProxy does.
#[test]
fn an_address_that_is_only_an_unset_variable_is_refused() {
    let err = parse_str(&cfg("${IBEX_NO_SUCH_VAR_XYZ}"))
        .expect_err("an address that expands to nothing must be a config error");
    let msg = format!("{err:?}").to_lowercase();
    assert!(
        msg.contains("empty address") || msg.contains("environment variable"),
        "the message should say what went wrong the way HAProxy's does, got: {err:?}"
    );
}

/// The forms HAProxy accepts must keep parsing -- this is not a licence to refuse `${...}`.
#[test]
fn the_variable_forms_haproxy_accepts_still_parse() {
    parse_str(&cfg("${IBEX_NO_SUCH_VAR_XYZ}:8080"))
        .expect("HAProxy accepts this: the port survives the missing variable");
    std::env::set_var("IBEX_TEST_ADDR_OK", "127.0.0.1:8081");
    parse_str(&cfg("${IBEX_TEST_ADDR_OK}")).expect("a variable that is set must work");
}
