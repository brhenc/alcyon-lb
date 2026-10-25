// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The server-state file keywords (T490): `server-state-file` and `server-state-base` in
//! `global`, `load-server-state-from-file` in `defaults`/`backend`/`listen`,
//! `server-state-file-name` in `backend`/`listen`. The texts were measured with
//! `haproxy -c` on 3.5-dev8-885761-29 (2026-10-25), less the `parsing [file:line] :`
//! prefix (`cfg_parse_global`, `cfg_parse_listen`). What the file does at start is in
//! `ibex-rt` `tests/it/server_state_file.rs`.

use ibex_config::ast::LoadServerState;
use ibex_config::{parse_str, Config};

const D: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";

fn ok(cfg: &str) -> Config {
    parse_str(cfg).unwrap_or_else(|e| panic!("refused {cfg:?}: {}", e.message))
}

fn refusal(cfg: &str) -> String {
    match parse_str(cfg) {
        Ok(_) => panic!("accepted:\n{cfg}"),
        Err(e) => e.message,
    }
}

#[test]
fn the_global_keywords_keep_their_path() {
    let c = ok("global\n  server-state-file st\n  server-state-base /var/lib/st\n");
    let g = c.global.expect("global");
    assert_eq!(g.server_state_file.as_deref(), Some("st"));
    assert_eq!(g.server_state_base.as_deref(), Some("/var/lib/st"));
    // A second argument is not looked at (HAProxy: no message, the first is kept).
    let g = ok("global\n  server-state-file /a /b\n").global.expect("global");
    assert_eq!(g.server_state_file.as_deref(), Some("/a"));
}

#[test]
fn the_global_keywords_need_their_argument() {
    assert_eq!(refusal("global\n  server-state-file\n"), "'server-state-file' expect one argument: a file path.");
    assert_eq!(refusal("global\n  server-state-base\n"), "'server-state-base' expects one argument: a directory path.");
}

#[test]
fn a_second_global_keyword_keeps_the_first_with_an_alert() {
    let g = ok("global\n  server-state-file /a\n  server-state-file /b\n  server-state-base /x\n  server-state-base /y\n")
        .global
        .expect("global");
    assert_eq!((g.server_state_file.as_deref(), g.server_state_base.as_deref()), (Some("/a"), Some("/x")));
    let w: Vec<(usize, &str, bool)> = g.load_warnings.iter().map(|w| (w.line, w.text.as_str(), w.alert)).collect();
    assert_eq!(
        w,
        [
            (3, "'server-state-file' already specified. Continuing.", true),
            (5, "'server-state-base' already specified. Continuing.", true),
        ]
    );
}

#[test]
fn load_server_state_from_file_takes_one_of_three_words() {
    for (word, want) in [("global", LoadServerState::Global), ("local", LoadServerState::Local), ("none", LoadServerState::None)] {
        let c = ok(&format!("{D}backend b\n  load-server-state-from-file {word}\n"));
        assert_eq!(c.backends[0].load_server_state, want, "{word}");
        let c = ok(&format!("{D}listen l\n  bind 127.0.0.1:19899\n  load-server-state-from-file {word}\n"));
        assert_eq!(c.listens[0].load_server_state, want, "{word}");
    }
    // Words after the first are not looked at.
    assert_eq!(ok(&format!("{D}backend b\n  load-server-state-from-file global x\n")).backends[0].load_server_state, LoadServerState::Global);
    assert_eq!(
        refusal(&format!("{D}backend b\n  load-server-state-from-file foo\n")),
        "'load-server-state-from-file' expects 'global', 'local' or 'none'. Got 'foo'"
    );
    assert_eq!(
        refusal(&format!("{D}backend b\n  load-server-state-from-file\n")),
        "'load-server-state-from-file' expects 'global', 'local' or 'none'. Got ''"
    );
}

#[test]
fn load_server_state_from_file_is_inherited_from_defaults() {
    let c = ok(&format!("{D}  load-server-state-from-file global\nbackend b\nbackend c\n  load-server-state-from-file none\nlisten l\n  bind 127.0.0.1:19899\n"));
    assert_eq!(c.backends[0].load_server_state, LoadServerState::Global);
    assert_eq!(c.backends[1].load_server_state, LoadServerState::None);
    assert_eq!(c.listens[0].load_server_state, LoadServerState::Global);
    // Nothing anywhere: no file is read.
    assert_eq!(ok(&format!("{D}backend b\n")).backends[0].load_server_state, LoadServerState::None);
}

#[test]
fn server_state_file_name_defaults_to_the_backend_name() {
    let c = ok(&format!("{D}backend b\n  server-state-file-name x\nbackend c\n  server-state-file-name use-backend-name\nbackend d\n  server-state-file-name x\n  server-state-file-name\nbackend e\n"));
    let names: Vec<Option<&str>> = c.backends.iter().map(|b| b.server_state_file_name.as_deref()).collect();
    assert_eq!(names, [Some("x"), Some("c"), Some("d"), None]);
    assert_eq!(
        refusal(&format!("{D}backend b\n  server-state-file-name x y\n")),
        "'server-state-file-name' cannot handle unexpected argument 'y'."
    );
}

#[test]
fn a_frontend_warns_and_ignores_both() {
    let c = ok(&format!("{D}frontend f\n  bind 127.0.0.1:19899\n  load-server-state-from-file none\n  server-state-file-name x\n"));
    let w: Vec<(usize, &str)> = c.proxy_warnings.iter().map(|w| (w.line, w.text.as_str())).collect();
    assert_eq!(
        w,
        [
            (8, "'load-server-state-from-file' ignored because frontend 'f' has no backend capability."),
            (9, "'server-state-file-name' ignored because frontend 'f' has no backend capability."),
        ]
    );
}

/// `HAProxy` accepts `server-state-file-name` in `defaults` and never copies it to a backend
/// (measured: the backend reads `<base>/<backend name>`). Ibex says so instead of dropping it
/// in silence (AGENTS.md §5); the text is Ibex's own.
#[test]
fn server_state_file_name_in_defaults_warns_that_it_does_nothing() {
    let c = ok(&format!("{D}  server-state-file-name x\nbackend b\n"));
    assert_eq!(c.backends[0].server_state_file_name, None);
    let w: Vec<(usize, &str)> = c.proxy_warnings.iter().map(|w| (w.line, w.text.as_str())).collect();
    assert_eq!(
        w,
        [(6, "'server-state-file-name' is ignored in a 'defaults' section (as HAProxy does): set it in the backend.")]
    );
}
