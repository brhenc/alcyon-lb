// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `be-unpublished`: where it is read and where it is refused (T637 DYNUSEBE). The
//! messages are `haproxy -c`'s (3.5-dev11), after its `parsing [file:line] : `.

use alcyon_config::{parse_str, BackendSection, ListenSection};

#[test]
fn be_unpublished_is_read_in_backend_and_listen() {
    let cfg = parse_str(
        "listen li\n  bind 127.0.0.1:8080\n  be-unpublished\n\
         backend be\n  be-unpublished\n  server s 127.0.0.1:8001\n",
    )
    .expect("parse");
    assert!(cfg.listens[0].be_unpublished);
    assert!(cfg.backends[0].be_unpublished);

    // Without the keyword, the flag starts off: the defaults the builders read.
    let cfg = parse_str(
        "listen li\n  bind 127.0.0.1:8080\n\
         backend be\n  server s 127.0.0.1:8001\n",
    )
    .expect("parse");
    assert!(!cfg.listens[0].be_unpublished);
    assert!(!cfg.backends[0].be_unpublished);
    assert!(!ListenSection::default().be_unpublished);
    assert!(!BackendSection::default().be_unpublished);
}

#[test]
fn be_unpublished_is_refused_where_haproxy_refuses_it() {
    match parse_str("frontend fe\n  bind 127.0.0.1:8080\n  be-unpublished\n") {
        Ok(_) => panic!("accepted in a frontend"),
        Err(e) => assert!(
            e.to_string().ends_with("'be-unpublished' only available in backend or listen section."),
            "{e}"
        ),
    }
    match parse_str("defaults\n  be-unpublished\n") {
        Ok(_) => panic!("accepted in a defaults"),
        Err(e) => assert!(
            e.to_string().ends_with("'be-unpublished' not allowed in 'defaults' section."),
            "{e}"
        ),
    }
}
