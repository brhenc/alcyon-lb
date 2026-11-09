// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The stats socket's command line (T242): the bytes a CLI client sends, through the
//! applet's line splitting, `;` sub-commands, payload (`<<`) handling and dispatch, at
//! the `user` or `operator` level so that only read-only commands run (no admin command
//! changes the shared state between runs). First byte: bit 0 enters `prompt` mode
//! (every line runs), bit 1 picks operator.
#![no_main]
use alcyon_rt::applet::CliLevel;
use alcyon_rt::engine::Proxies;
use alcyon_rt::mailbox::Mailboxes;
use alcyon_rt::{AppletContext, CliApplet, Engine};
use alcyon_sched::task::TaskRef;
use alcyon_sched::Tick;
use libfuzzer_sys::fuzz_target;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

const CONFIG: &str = "
global
    stats socket /tmp/alcyon-fuzz-cli.sock level admin
defaults
    mode http
    timeout connect 1s
    timeout client 1s
    timeout server 1s
frontend fe
    bind 127.0.0.1:1
    default_backend be
backend be
    stick-table type ip size 10 store conn_cur,http_req_rate(10s)
    server s1 127.0.0.1:2 weight 10
    server s2 127.0.0.1:3 backup
";

static STATE: LazyLock<(Proxies, Arc<Mailboxes>)> = LazyLock::new(|| {
    let cfg = alcyon_config::parse_str(CONFIG).expect("fuzz config parses");
    let proxies = Engine::build_shared_state(&cfg).expect("fuzz config builds");
    (proxies, Mailboxes::new(1).expect("mailboxes"))
});

fuzz_target!(|data: &[u8]| {
    let Some((&sel, input)) = data.split_first() else { return };
    let (proxies, mailboxes) = &*STATE;
    let mut proxies = proxies.clone();
    let Ok((a, _b)) = UnixStream::pair() else { return };
    let mut applet = CliApplet::new(a, Tick(0));
    applet.level = if sel & 2 != 0 { CliLevel::Operator } else { CliLevel::User };
    if sel & 1 != 0 {
        applet.in_buf.extend_from_slice(b"prompt\n");
    }
    applet.in_buf.extend_from_slice(input);
    applet.in_buf.push(b'\n');
    let mut ctx = AppletContext {
        proxies: &mut proxies,
        checks: &mut [],
        sessions: None,
        wake_queue: None,
        start_time: Instant::now(),
        pid: 1,
        total_tasks: 0,
        run_queue_len: 0,
        now: Tick(0),
        mailboxes,
        worker_id: 0,
        task: TaskRef::NONE,
    };
    applet.process_commands(&mut ctx);
});
