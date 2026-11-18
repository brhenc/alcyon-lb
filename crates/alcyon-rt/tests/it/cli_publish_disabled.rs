// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `unpublish backend` and `publish backend` on a backend the configuration `disabled`:
//! the name is still one of the backends (`cli_find_backend` finds it), but the flag the
//! command would set is unreachable, and the answer is `HAProxy`'s -- `No effect on a
//! disabled backend.` (`cli_parse_*_backend`, `src/proxy.c`), not `No such backend.`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use alcyon_config::parse_str;
use alcyon_rt::engine::Engine;

/// The one-shot CLI answer to `cmd` on the engine's socket: the command's output, read to
/// what the applet wrote by then.
fn cli(engine: &mut Engine, sock: &std::path::Path, cmd: &str) -> String {
    let mut c = UnixStream::connect(sock).expect("connect");
    c.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    for _ in 0..10 {
        let _ = engine.run_once();
    }
    c.set_nonblocking(true).expect("nonblocking");
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    out
}

#[test]
fn publish_and_unpublish_answer_haproxy_on_a_disabled_backend() {
    // One live backend keeps the table, and the disabled one's name in every proxy's
    // list of what the configuration took out of the switching rules.
    let cfg = parse_str(
        "defaults\n  mode http\n  timeout client 1s\n  timeout server 1s\n\
         backend be\n  disabled\n  server s 127.0.0.1:1\n\
         backend ok\n  server s 127.0.0.1:1\n",
    )
    .expect("parse");
    let mut engine = Engine::new(&cfg, 64).expect("engine");
    let dir = tempfile::tempdir().expect("tmp");
    let sock = dir.path().join("cli.sock");
    engine.bind_cli_socket(&sock).expect("bind");

    for cmd in ["unpublish backend be", "publish backend be"] {
        let out = cli(&mut engine, &sock, cmd);
        assert!(out.contains("No effect on a disabled backend."), "{cmd}: {out:?}");
    }
    // The name that is no backend, on either command: the other answer.
    for cmd in ["unpublish backend no_such", "publish backend no_such"] {
        let out = cli(&mut engine, &sock, cmd);
        assert!(out.contains("No such backend."), "{cmd}: {out:?}");
    }
    drop(engine);
}
