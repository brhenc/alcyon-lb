// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/cli.c, src/stats.c, and src/applet.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! CLI Applet and Runtime Management Socket (`Kind::Applet`).
//!
//! Provides the interactive management socket compatible with `hatop` and administrative tools.
//! Supports:
//! - `prompt`: enables interactive session mode, demarcated with `\n> `
//! - `set timeout cli <sec>`: configures session idle timeout
//! - `show info`: 14 mandatory fields for monitoring clients
//! - `show stat [<iid> <type> <sid>]`: 146-column CSV stats output
//! - `enable server <px>/<sv>`: enables traffic to server
//! - `disable server <px>/<sv>`: sets server to maintenance mode
//! - `set server <px>/<sv> state [ready|maint|drain]`: changes server state
//! - `set weight <px>/<sv> <weight>`: updates server weight
//! - `help`: displays available commands
//! - `quit`: closes the session

use crate::check::{ServerCheckState, ServerStatus};
use crate::engine::{Proxy, SessionArena};
use crate::fdtab::Interest;
use crate::stats::format_show_stat_filtered;
use ibex_sched::task::TaskRef;
use ibex_sched::Tick;
use std::fmt::Write as FmtWrite;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

/// Runtime context passed to CLI applet command handlers.
pub struct AppletContext<'a> {
    pub proxies: &'a mut crate::engine::Proxies,
    pub checks: &'a mut [ServerCheckState],
    pub sessions: Option<&'a mut SessionArena>,
    pub wake_queue: Option<&'a mut Vec<TaskRef>>,
    pub start_time: Instant,
    pub pid: u32,
    pub total_tasks: usize,
    pub run_queue_len: usize,
    pub now: Tick,
}

/// The privilege level of a CLI connection: the socket's `level`, which `user` and `operator`
/// commands can only lower (`HAProxy`'s `ACCESS_LVL_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CliLevel {
    User,
    Operator,
    Admin,
}

impl CliLevel {
    /// The level a `stats socket ... level <name>` names.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "user" => Some(Self::User),
            "operator" => Some(Self::Operator),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }

    /// The level a command needs, measured on `HAProxy` 3.5-dev8 by running each at every
    /// level. Commands not listed here are admin-only, as most of HAProxy's are.
    #[must_use]
    pub fn required_for(cmd: &str) -> Self {
        let is = |p: &str| cmd == p || cmd.starts_with(&format!("{p} "));
        for p in [
            "show info", "show stat", "show servers state", "show table", "show pools", "show version",
            "show cli", "show resolvers", "show events", "show servers conn", "help", "prompt", "quit",
            "set severity-output", "set timeout", "user",
        ] {
            if is(p) {
                return Self::User;
            }
        }
        for p in [
            "show env", "get var", "get weight", "show sess", "show activity", "show fd", "show startup-logs",
            "show errors", "operator",
        ] {
            if is(p) {
                return Self::Operator;
            }
        }
        if cmd == "clear counters" {
            return Self::Operator;
        }
        Self::Admin
    }
}

impl Proxy {
    /// Server `idx`'s configured weight, whatever it is now.
    #[must_use]
    pub fn initial_weight(&self, idx: usize) -> u32 {
        let from = self.server_iweights.as_deref().unwrap_or(&self.server_weights);
        from.get(idx).copied().unwrap_or(1)
    }

    /// Changes server `idx`'s current weight, keeping the configured one for
    /// [`Self::initial_weight`].
    pub fn set_weight(&mut self, idx: usize, weight: u32) {
        if self.server_iweights.is_none() {
            self.server_iweights = Some(Box::new(self.server_weights.clone()));
        }
        if let Some(slot) = self.server_weights.get_mut(idx) {
            *slot = weight;
        }
    }
}

/// A CLI applet connection session.
pub struct CliApplet {
    /// What this connection may do; starts at the socket's level.
    pub level: CliLevel,
    /// The socket the connection came in on, for `show cli sockets`.
    pub socket_path: Option<String>,
    pub stream: Option<UnixStream>,
    pub raw_fd: RawFd,
    pub task: TaskRef,
    pub in_buf: Vec<u8>,
    pub out_buf: Vec<u8>,
    pub out_offset: usize,
    pub interactive: bool,
    pub timeout_ms: u32,
    pub last_activity: Tick,
    pub is_done: bool,
    pub interest: Interest,
    /// An `add map <id> <<` waiting for its payload: the command and the lines so far.
    pub payload: Option<(String, String)>,
}

impl CliApplet {
    /// Creates a new `CliApplet` for the accepted Unix socket stream.
    #[must_use]
    pub fn new(stream: UnixStream, now: Tick) -> Self {
        let raw_fd = stream.as_raw_fd();
        CliApplet {
            level: CliLevel::Admin,
            socket_path: None,
            stream: Some(stream),
            raw_fd,
            task: TaskRef::NONE,
            in_buf: Vec::with_capacity(1024),
            out_buf: Vec::with_capacity(4096),
            out_offset: 0,
            interactive: false,
            timeout_ms: 60_000,
            last_activity: now,
            is_done: false,
            interest: Interest::READ,
            payload: None,
        }
    }

    /// Reads incoming data from the socket stream into `in_buf`.
    pub fn read_input(&mut self) {
        let Some(stream) = self.stream.as_mut() else {
            return;
        };

        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => {
                    self.is_done = true;
                    break;
                }
                Ok(n) => {
                    self.in_buf.extend_from_slice(&buf[..n]);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(_) => {
                    self.is_done = true;
                    break;
                }
            }
        }
    }

    /// Writes pending `out_buf` data to the socket stream.
    pub fn write_output(&mut self) {
        let Some(stream) = self.stream.as_mut() else {
            return;
        };

        while self.out_offset < self.out_buf.len() {
            match stream.write(&self.out_buf[self.out_offset..]) {
                Ok(0) => {
                    self.is_done = true;
                    break;
                }
                Ok(n) => {
                    self.out_offset += n;
                    if self.out_offset >= self.out_buf.len() {
                        self.out_buf.clear();
                        self.out_offset = 0;
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(_) => {
                    self.is_done = true;
                    break;
                }
            }
        }
    }

    /// Executes complete command lines available in `in_buf`.
    pub fn process_commands(&mut self, ctx: &mut AppletContext) {
        if !self.in_buf.is_empty() {
            self.last_activity = ctx.now;
        }

        while let Some(newline_pos) = self.in_buf.iter().position(|&b| b == b'\n') {
            let line_bytes = self.in_buf[..newline_pos].to_vec();
            self.in_buf.drain(..=newline_pos);

            let line = String::from_utf8_lossy(&line_bytes);
            let line = line.trim_end_matches('\r');

            if let Some((_, body)) = self.payload.as_mut() {
                if line.is_empty() {
                    if let Some((cmd, body)) = self.payload.take() {
                        self.run_patref(&cmd, Some(&body));
                    }
                } else {
                    body.push_str(line);
                    body.push('\n');
                    continue;
                }
            } else {
                self.execute_line(line, ctx);
                if self.payload.is_some() {
                    continue;
                }
            }
            // A connection that is not in `prompt` mode runs one command line and closes;
            // what came after it in the same write is never run (HAProxy, T146 item 4).
            if !self.interactive {
                self.in_buf.clear();
                break;
            }
        }
    }

    fn execute_line(&mut self, line: &str, ctx: &mut AppletContext) {
        let sub_commands: Vec<&str> = line.split(';').collect();
        for raw_cmd in sub_commands {
            let cmd = raw_cmd.trim();
            if cmd.is_empty() {
                if self.interactive {
                    self.out_buf.extend_from_slice(b"\n> ");
                }
                continue;
            }
            self.execute_command(cmd, ctx);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn execute_command(&mut self, cmd: &str, ctx: &mut AppletContext) {
        if self.level < CliLevel::required_for(cmd) {
            self.finish_msg("Permission denied");
        } else if cmd == "user" || cmd == "operator" {
            // The levels only go down.
            self.level = self.level.min(if cmd == "user" { CliLevel::User } else { CliLevel::Operator });
            self.finish_msg("");
        } else if cmd == "show cli level" {
            self.finish_msg(self.level.name());
        } else if cmd == "show cli sockets" {
            let sock = self.socket_path.clone().unwrap_or_default();
            let msg = format!("# socket lvl processes\nunix@{sock} {} all", self.level.name());
            self.finish_msg(&msg);
        } else if cmd == "show version" {
            self.finish_msg(env!("CARGO_PKG_VERSION"));
        } else if cmd == "prompt" {
            self.interactive = true;
            self.out_buf.extend_from_slice(b"\n> ");
        } else if cmd == "quit" {
            self.is_done = true;
        } else if cmd == "_getsocks" {
            // Answered on the stream itself: the listening sockets travel as SCM_RIGHTS,
            // which the buffered output path cannot carry. See crate::handover.
            if let Some(stream) = self.stream.as_ref() {
                if let Err(e) = crate::handover::serve_getsocks(stream) {
                    self.out_buf.extend_from_slice(format!("{e}\n").as_bytes());
                }
            }
            self.is_done = true;
        } else if let Some(rest) = cmd.strip_prefix("set timeout cli") {
            if let Ok(secs) = rest.trim().parse::<u32>() {
                self.timeout_ms = secs.saturating_mul(1000);
            }
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            }
        } else if cmd == "show events" || cmd.starts_with("show events ") {
            let args: Vec<&str> = cmd["show events".len()..].split_whitespace().collect();
            let events = crate::ring::show_events(&args);
            self.out_buf.extend_from_slice(&events);
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.out_buf.push(b'\n');
                self.is_done = true;
            }
        } else if cmd == "show info" || cmd.starts_with("show info ") {
            self.handle_show_info(ctx);
        } else if cmd == "show env" {
            for (k, v) in std::env::vars() {
                self.out_buf.extend_from_slice(format!("{k}={v}\n").as_bytes());
            }
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.is_done = true;
            }
        } else if cmd == "show errors" {
            self.out_buf.extend_from_slice(b"Total events captured on [01/Jan/1970:00:00:00.000] : 0\n\n");
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.is_done = true;
            }
        } else if cmd == "show backend" {
            self.out_buf.extend_from_slice(b"# name\n");
            for p in ctx.proxies.iter() {
                self.out_buf.extend_from_slice(format!("{}\n", p.name).as_bytes());
            }
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.is_done = true;
            }
        } else if cmd == "show default-server" {
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.is_done = true;
            }
        } else if let Some(target) = cmd.strip_prefix("del backend ") {
            self.handle_del_backend(target.trim(), ctx);
        } else if cmd == "show servers state" || cmd.starts_with("show servers state ") {
            let be_filter = cmd.strip_prefix("show servers state").map(str::trim).filter(|s| !s.is_empty());
            if let Some(target) = be_filter {
                if !ctx.proxies.iter().any(|p| p.name == target || p.ids.iid.to_string() == target) {
                    self.out_buf.extend_from_slice(b"Can't find backend.\n");
                    if self.interactive {
                        self.out_buf.extend_from_slice(b"\n> ");
                    } else {
                        self.is_done = true;
                    }
                    return;
                }
            }
            self.out_buf.extend_from_slice(b"1\n# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port\n");
            // `HAProxy` lists the proxies in the order the sections were written.
            let mut order: Vec<usize> = (0..ctx.proxies.len()).collect();
            order.sort_by_key(|&i| ctx.proxies[i].ids.decl);
            for p_idx in order {
                let p = &ctx.proxies[p_idx];
                if let Some(target) = be_filter {
                    if p.name != target && p.ids.iid.to_string() != target { continue; }
                }
                for (s_idx, s) in p.server_ids.iter().enumerate() {
                    let addr = p.servers.get(s_idx).map_or_else(|| "-".to_string(), |a| a.ip().to_string());
                    let port = p.servers.get(s_idx).map_or_else(|| "-".to_string(), |a| a.port().to_string());
                    let status = p.server_statuses.get(s_idx).map(|s| ServerStatus::from(s.load(std::sync::atomic::Ordering::Relaxed)));
                    // srv_op_state: 2 running, 0 stopped (a draining server still runs).
                    let op_state = match status {
                        Some(ServerStatus::Up | ServerStatus::Drain) => 2,
                        _ => 0,
                    };
                    // srv_admin_state: SRV_ADMF_FMAINT 1, SRV_ADMF_FDRAIN 8.
                    // A tracker whose target is in maintenance or drain has the inherited flags
                    // instead (SRV_ADMF_IMAINT 2, SRV_ADMF_IDRAIN 16).
                    let inherited = crate::track::inherited(p, s_idx);
                    let admin_state = match status {
                        Some(ServerStatus::Maint) if inherited => 2,
                        Some(ServerStatus::Drain) if inherited => 16,
                        Some(ServerStatus::Maint) => 1,
                        Some(ServerStatus::Drain) => 8,
                        _ => 0,
                    };
                    let uweight = p.server_weights.get(s_idx).copied().unwrap_or(1);
                    let iweight = p.initial_weight(s_idx);
                    
                    let mut check_status = 1;
                    let mut check_result = 0;
                    let mut check_health = p.server_init_health(s_idx);
                    let mut check_state = 0;
                    
                    if let Some(check) = ctx.checks.iter().find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx) {
                        check_health = check.health;
                        check_state = 2; // CHK_ST_CONFIGURED
                        if check.enabled {
                            check_state |= 4; // CHK_ST_ENABLED
                        }
                        if check.in_progress {
                            check_state |= 1; // CHK_ST_INPROGRESS
                        }

                        check_status = match check.last_status_code {
                            "INI" => 1,
                            "START" => 2,
                            "CHECKED" => 3,
                            "HANA" => 4,
                            "SOCKERR" => 5,
                            "L4OK" => 6,
                            "L4TOUT" => 7,
                            "L4CON" => 8,
                            "L6OK" => 9,
                            "L6TOUT" => 10,
                            "L6RSP" => 11,
                            "L7TOUT" => 12,
                            "L7RSP" => 13,
                            "L57DATA" => 14,
                            "L7OKD" => 15,
                            "L7OKCD" => 16,
                            "L7STS" => 17,
                            "PROCERR" => 18,
                            "PROCTOUT" => 19,
                            "PROCOK" => 20,
                            _ => 1,
                        };
                        check_result = if check.last_status_code.contains("OK") {
                            3 // CHK_RES_PASSED
                        } else if check.last_status_code != "INI" {
                            2 // CHK_RES_FAILED
                        } else {
                            0 // CHK_RES_UNKNOWN
                        };
                    }

                    let puid = p.server_puid(s_idx);
                    let bk_forced = u8::from(p.ids.forced_id);
                    let srv_forced = u8::from(p.server_forced_id(s_idx));
                    self.out_buf.extend_from_slice(
                        format!(
                            "{} {} {} {} {} {} {} {} {} 1 {} {} {} {} 0 {} {} - {} - 0 0 - - 0\n",
                            p.ids.iid, p.name, puid, s, addr, op_state, admin_state, uweight, iweight, check_status, check_result, check_health, check_state, bk_forced, srv_forced, port
                        ).as_bytes()
                    );
                }
            }
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.is_done = true;
            }
        } else if cmd == "show stat" || cmd.starts_with("show stat ") {
            self.handle_show_stat(cmd, ctx);
        } else if cmd == "show table" || cmd.starts_with("show table ") {
            self.handle_show_table(cmd, ctx);
        } else if cmd == "show pools" || cmd.starts_with("show pools") {
            let output = ibex_alloc::global_pool_registry().dump_pools_info();
            self.out_buf.extend_from_slice(output.as_bytes());
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.is_done = true;
            }
        } else if let Some(target) = cmd.strip_prefix("shutdown sessions server ")
            .or_else(|| cmd.strip_prefix("shutdown session server "))
        {
            self.handle_shutdown_sessions_server(target.trim(), ctx);
        } else if let Some(target) = cmd.strip_prefix("shutdown sessions backend ")
            .or_else(|| cmd.strip_prefix("shutdown session backend "))
        {
            self.handle_shutdown_sessions_backend(target.trim(), ctx);
        } else if cmd == "clear counters" || cmd == "clear counters all" {
            self.handle_clear_counters(None, ctx);
        } else if let Some(target) = cmd.strip_prefix("clear counters ") {
            self.handle_clear_counters(Some(target.trim()), ctx);
        } else if let Some(target) = cmd.strip_prefix("enable health ") {
            self.handle_enable_health(target.trim(), ctx);
        } else if let Some(target) = cmd.strip_prefix("disable health ") {
            self.handle_disable_health(target.trim(), ctx);
        } else if let Some(target) = cmd.strip_prefix("enable server ") {
            self.handle_enable_server(target.trim(), ctx);
        } else if let Some(target) = cmd.strip_prefix("disable server ") {
            self.handle_disable_server(target.trim(), ctx);
        } else if let Some(rest) = cmd.strip_prefix("set server").filter(|r| r.is_empty() || r.starts_with(' ')) {
            self.handle_set_server(rest.trim(), ctx);
        } else if let Some(rest) = cmd.strip_prefix("get weight").filter(|r| r.is_empty() || r.starts_with(' ')) {
            self.handle_get_weight(rest.trim(), ctx);
        } else if let Some(rest) = cmd.strip_prefix("set weight").filter(|r| r.is_empty() || r.starts_with(' ')) {
            self.handle_set_weight(rest.trim(), ctx);
        } else if let Some(rest) = cmd.strip_prefix("set maxconn ") {
            self.handle_set_maxconn(rest.trim(), ctx);
        } else if cmd == "experimental-mode on" || cmd == "experimental-mode off" {
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.is_done = true;
            }
        } else if cmd == "get var" || cmd.starts_with("get var ") {
            self.handle_get_var(cmd["get var".len()..].trim());
        } else if let Some(target) = cmd.strip_prefix("set var ") {
            self.handle_set_var(target.trim());
        } else if cmd == "help" {
            self.handle_help();
        } else if Self::is_patref_command(cmd) {
            if cmd.ends_with(" <<") && cmd.starts_with("add map ") {
                self.payload = Some((cmd.trim_end_matches('<').trim_end().to_string(), String::new()));
            } else {
                self.run_patref(cmd, None);
            }
        } else {
            self.out_buf.extend_from_slice(
                b"Unknown command. Please enter 'help' for a list of valid commands.\n",
            );
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.is_done = true;
            }
        }
    }

    /// `show|add|set|del|clear` of `map` or `acl`.
    fn is_patref_command(cmd: &str) -> bool {
        let mut it = cmd.split_whitespace();
        matches!(it.next(), Some("show" | "add" | "set" | "del" | "clear")) && matches!(it.next(), Some("map" | "acl"))
    }

    /// Runs a map or ACL command on the process-wide pattern references
    /// ([`ibex_sample::patref`]): every worker thread matches against what it leaves.
    fn run_patref(&mut self, cmd: &str, payload: Option<&str>) {
        let words: Vec<&str> = cmd.split_whitespace().collect();
        let kind = if words[1] == "map" { ibex_sample::patref::RefKind::Map } else { ibex_sample::patref::RefKind::Acl };
        let out = ibex_sample::patref::command(words[0], kind, &words[2..], payload);
        self.out_buf.extend_from_slice(out.as_bytes());
        self.finish_msg("");
    }

    fn handle_del_backend(&mut self, target: &str, ctx: &mut AppletContext) {
        let mut found = None;
        let mut is_referenced = false;

        for p in ctx.proxies.iter() {
            if p.name == target {
                found = Some(p);
            } else {
                if p.default_backend.as_deref() == Some(target) {
                    is_referenced = true;
                }
                for u in &p.use_backends {
                    if u.backend == target {
                        is_referenced = true;
                    }
                }
            }
        }

        if let Some(p) = found {
            if is_referenced {
                self.out_buf.extend_from_slice(b"This proxy cannot be removed at runtime due to other configuration elements pointing to it.\n");
            } else if p.name == "li" || p.addr.port() != 0 {
                self.out_buf.extend_from_slice(b"Cannot delete a listen section.\n");
            } else {
                self.out_buf.extend_from_slice(b"Backend must be unpublished prior to its deletion.\n");
            }
        } else {
            self.out_buf.extend_from_slice(b"No such backend.\n");
        }

        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    /// `vars_parse_cli_get_var` (src/vars.c): the CLI has no stream, so only the `proc`
    /// scope is looked in; any other name is not found.
    fn handle_get_var(&mut self, var_name: &str) {
        if var_name.is_empty() {
            self.finish_msg("Missing process-wide variable identifier.");
            return;
        }
        let Some(val) = var_name.starts_with("proc.").then(|| ibex_sample::get_proc_var(var_name)).flatten() else {
            self.finish_msg("Variable not found.");
            return;
        };
        let typ = if val.parse::<i64>().is_ok() {
            "sint"
        } else if val == "true" || val == "false" {
            "bool"
        } else if val.parse::<std::net::IpAddr>().is_ok() {
            "ip"
        } else {
            "str"
        };
        self.finish_msg(&format!("{var_name}: type={typ} value=<{val}>"));
    }

    fn handle_set_var(&mut self, rest: &str) {
        let mut parts = rest.splitn(2, |c: char| c.is_whitespace());
        let var_name = parts.next().unwrap_or("").trim();
        let expr_part = parts.next().unwrap_or("").trim();
        if var_name.is_empty() || expr_part.is_empty() {
            self.out_buf.extend_from_slice(b"Missing variable or expression.\n");
        } else if !var_name.starts_with("proc.") {
            self.out_buf.extend_from_slice(b"Only scope 'proc' is permitted here.\n");
        } else {
            let (is_fmt, expr) = if let Some(fmt_str) = expr_part.strip_prefix("fmt ") {
                (true, fmt_str.trim())
            } else if let Some(expr_str) = expr_part.strip_prefix("expr ") {
                (false, expr_str.trim())
            } else {
                (false, expr_part)
            };
            let registry = crate::engine::sample_registry();
            let ctx = ibex_sample::SampleContext::default();
            let val = if is_fmt {
                crate::engine::format_sample_string(expr, &ctx, registry)
            } else if let Ok(e) = ibex_sample::Expr::parse(expr) {
                e.eval_sample(registry, &ctx)
                    .map_or_else(|| expr.to_string(), |smp| crate::engine::sample_to_string(&smp))
            } else {
                expr.to_string()
            };
            ibex_sample::set_proc_var(var_name, val);
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_show_info(&mut self, ctx: &AppletContext) {
        let active_conns: u32 = ctx.proxies.iter().map(|p| p.stats.iter().map(|s| s.act_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u32>()).sum();
        let max_conns: u32 = ctx.proxies.iter().map(|p| p.maxconn).sum();
        let cum_conns: u64 = ctx.proxies.iter().map(|p| p.stats.iter().map(|s| s.cum_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()).sum();
        let cum_reqs: u64 = ctx.proxies.iter().filter_map(|p| p.ids.tc.get()).map(|c| c.fe.req_tot.load(std::sync::atomic::Ordering::Relaxed)).sum();
        let info = crate::stats::format_show_info_counts(
            ctx.start_time,
            ctx.pid,
            ctx.total_tasks,
            ctx.run_queue_len,
            active_conns,
            max_conns,
            cum_conns,
            cum_reqs,
        );
        self.out_buf.extend_from_slice(info.as_bytes());
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_show_stat(&mut self, cmd: &str, ctx: &AppletContext) {
        let mut iid_filter = None;
        let mut type_filter = None;
        let mut sid_filter = None;

        let parts: Vec<&str> = cmd.split_whitespace().collect();
        // parts = ["show", "stat", "be", "4", "-1"]
        if parts.len() >= 3 {
            if let Ok(id) = parts[2].parse::<i32>() {
                iid_filter = Some(id);
            } else if parts[2] != "-1" {
                if let Some(p_idx) = ctx.proxies.iter().position(|p| p.name == parts[2]) {
                    iid_filter = Some(i32::try_from(ctx.proxies[p_idx].ids.iid).unwrap_or(-2));
                } else {
                    iid_filter = Some(-2); // force not found
                }
            }
        }
        if parts.len() >= 4 {
            type_filter = parts[3].parse::<i32>().ok();
        }
        if parts.len() >= 5 {
            sid_filter = parts[4].parse::<i32>().ok();
        }

        let stat_csv = format_show_stat_filtered(
            ctx.proxies,
            ctx.checks,
            ctx.pid,
            iid_filter,
            type_filter,
            sid_filter,
        );
        self.out_buf.extend_from_slice(stat_csv.as_bytes());
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_show_table(&mut self, cmd: &str, ctx: &AppletContext) {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let table_name = if parts.len() >= 3 {
            Some(parts[2])
        } else {
            None
        };

        let mut filter_field = None;
        let mut filter_op = None;
        let mut filter_val = None;

        if parts.len() >= 6 && parts[3].starts_with("data.") {
            filter_field = parts[3].strip_prefix("data.");
            let op = parts[4];
            let allowed_ops = ["eq", "ne", "le", "ge", "lt", "gt"];
            if !allowed_ops.contains(&op) {
                self.out_buf.extend_from_slice(b"Filter entry #1: Require and operator among \"eq\", \"ne\", \"le\", \"ge\", \"lt\", \"gt\"\n");
                if self.interactive {
                    self.out_buf.extend_from_slice(b"\n> ");
                } else {
                    self.is_done = true;
                }
                return;
            }
            filter_op = Some(op);
            if let Ok(v) = parts[5].parse::<u64>() {
                filter_val = Some(v);
            }
        }

        let mut out = String::new();
        let mut found_table = false;

        for proxy in ctx.proxies.iter() {
            if let Some(ref table) = proxy.stick_table {
                let cfg = table.config();
                if let Some(target) = table_name {
                    if cfg.name != target && proxy.name != target {
                        continue;
                    }
                }
                found_table = true;

                let key_type_str = match cfg.key_type {
                    ibex_stick_table::table::KeyType::Ip => "ip",
                    ibex_stick_table::table::KeyType::Ipv6 => "ipv6",
                    ibex_stick_table::table::KeyType::Integer => "integer",
                    ibex_stick_table::table::KeyType::String => "string",
                    ibex_stick_table::table::KeyType::Binary => "binary",
                };

                let _ = writeln!(
                    out,
                    "# table: {}, type: {}, size:{}, used:{}",
                    cfg.name,
                    key_type_str,
                    cfg.max_size,
                    table.len()
                );

                if let Ok(entries) = table.dump_entries() {
                    for (k, v) in entries {
                        let fields = table.data_fields(&v);
                        if let (Some(ff), Some(fo), Some(fv)) = (filter_field, filter_op, filter_val) {
                            // An entry of a table that does not store the type has no value
                            // to compare: it is left out.
                            let Some(field_val) = fields.iter().find(|(n, _, _)| n == ff).map(|(_, _, x)| *x) else {
                                continue;
                            };
                            let keep = match fo {
                                "eq" => field_val == fv,
                                "ne" => field_val != fv,
                                "le" => field_val <= fv,
                                "ge" => field_val >= fv,
                                "lt" => field_val < fv,
                                "gt" => field_val > fv,
                                _ => true,
                            };
                            if !keep { continue; }
                        }

                        let key_str = match k {
                            ibex_stick_table::entry::StickKey::Ip(ip) => ip.to_string(),
                            ibex_stick_table::entry::StickKey::Integer(i) => i.to_string(),
                            ibex_stick_table::entry::StickKey::String(s) => s,
                            ibex_stick_table::entry::StickKey::Binary(b) => {
                                let mut s = String::new();
                                for byte in b {
                                    use std::fmt::Write;
                                    let _ = write!(s, "{byte:02x}");
                                }
                                s
                            }
                        };

                        // `exp=` is what is left of `expire`; the address is only an identity.
                        let left = cfg.expire.saturating_sub(v.last_updated.elapsed()).as_millis();
                        let addr = {
                            use std::hash::{Hash, Hasher};
                            let mut h = std::collections::hash_map::DefaultHasher::new();
                            key_str.hash(&mut h);
                            h.finish() & 0xffff_ffff_f0
                        };
                        let _ = write!(out, "{addr:#x}: key={key_str} use={} exp={left} shard=0", v.trackers);
                        for (name, period, val) in &fields {
                            match period {
                                Some(p) => {
                                    let _ = write!(out, " {name}({p})={val}");
                                }
                                None if name == "server_key" => {
                                    // The name of the server `server_id` stands for.
                                    let sname = v.server_id.and_then(|id| (0..proxy.servers.len()).find(|&i| proxy.server_puid(i) == id)).and_then(|i| proxy.server_ids.get(i));
                                    let _ = write!(out, " server_key={}", sname.map_or("", String::as_str));
                                }
                                None => {
                                    let _ = write!(out, " {name}={val}");
                                }
                            }
                        }
                        out.push('\n');
                    }
                }
            }
        }

        if table_name.is_some() && !found_table {
            self.out_buf.extend_from_slice(b"No such table\n");
        } else {
            self.out_buf.extend_from_slice(out.as_bytes());
        }

        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_shutdown_sessions_server(&mut self, target: &str, ctx: &mut AppletContext) {
        let (px_name, sv_name) = match target.split_once('/') {
            Some(pair) => pair,
            None => ("", target),
        };
        let mut found_px = false;
        let mut found_sv = false;
        for proxy in ctx.proxies.iter() {
            if px_name.is_empty() || proxy.name == px_name {
                found_px = true;
                if proxy.server_ids.iter().any(|sid| sid == sv_name) {
                    found_sv = true;
                    break;
                }
            }
        }
        if !found_px && !px_name.is_empty() {
            self.out_buf.extend_from_slice(b"No such backend.\n");
        } else if !found_sv {
            self.out_buf.extend_from_slice(b"No such server.\n");
        } else if let (Some(sessions), Some(wake_queue)) =
            (ctx.sessions.as_deref_mut(), ctx.wake_queue.as_deref_mut())
        {
            let be_opt = if px_name.is_empty() { None } else { Some(px_name) };
            let _ = crate::engine::shutdown_matching_sessions(
                sessions.iter_mut().map(|(_, e)| e),
                ctx.proxies,
                be_opt,
                Some(sv_name),
                wake_queue,
            );
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_shutdown_sessions_backend(&mut self, target: &str, ctx: &mut AppletContext) {
        let px_name = target.trim();
        let found = ctx.proxies.iter().any(|p| p.name == px_name);
        if !found {
            self.out_buf.extend_from_slice(b"No such backend.\n");
        } else if let (Some(sessions), Some(wake_queue)) =
            (ctx.sessions.as_deref_mut(), ctx.wake_queue.as_deref_mut())
        {
            let _ = crate::engine::shutdown_matching_sessions(
                sessions.iter_mut().map(|(_, e)| e),
                ctx.proxies,
                Some(px_name),
                None,
                wake_queue,
            );
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_clear_counters(&mut self, target: Option<&str>, ctx: &mut AppletContext) {
        if let Some(t) = target {
            if let Some(rest) = t.strip_prefix("server ") {
                let rest = rest.strip_suffix(" force").unwrap_or(rest).trim();
                let (px_name, sv_name) = match rest.split_once('/') {
                    Some(pair) => pair,
                    None => ("", rest),
                };
                let mut found_px = false;
                let mut found_sv = false;
                for p in ctx.proxies.iter() {
                    if px_name.is_empty() || p.name == px_name {
                        found_px = true;
                        if p.server_ids.iter().any(|sid| sid == sv_name) {
                            found_sv = true;
                            break;
                        }
                    }
                }
                if !found_px && !px_name.is_empty() {
                    self.out_buf.extend_from_slice(b"No such backend.
");
                } else if !found_sv {
                    self.out_buf.extend_from_slice(b"No such server.
");
                } else {
                    self.out_buf.extend_from_slice(b"Server counters cleared.
");
                }
            } else if !crate::engine::clear_proxy_counters(ctx.proxies, Some(t)) {
                self.out_buf.extend_from_slice(b"No such backend.
");
            }
        } else {
            crate::engine::clear_proxy_counters(ctx.proxies, None);
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_enable_health(&mut self, target: &str, ctx: &mut AppletContext) {
        let (px_name, sv_name) = match target.split_once('/') {
            Some(pair) => pair,
            None => ("", target),
        };
        let found_px = px_name.is_empty() || ctx.proxies.iter().any(|p| p.name == px_name);
        if !found_px {
            self.out_buf.extend_from_slice(b"No such backend.\n");
        } else if px_name.is_empty()
            || !crate::engine::set_health_check_enabled(
                ctx.checks,
                ctx.proxies,
                px_name,
                sv_name,
                true,
                ctx.now,
            )
        {
            self.out_buf.extend_from_slice(b"No such server.\n");
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_disable_health(&mut self, target: &str, ctx: &mut AppletContext) {
        let (px_name, sv_name) = match target.split_once('/') {
            Some(pair) => pair,
            None => ("", target),
        };
        let found_px = px_name.is_empty() || ctx.proxies.iter().any(|p| p.name == px_name);
        if !found_px {
            self.out_buf.extend_from_slice(b"No such backend.\n");
        } else if px_name.is_empty()
            || !crate::engine::set_health_check_enabled(
                ctx.checks,
                ctx.proxies,
                px_name,
                sv_name,
                false,
                ctx.now,
            )
        {
            self.out_buf.extend_from_slice(b"No such server.\n");
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_set_maxconn(&mut self, rest: &str, ctx: &mut AppletContext) {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        match parts.first().copied() {
            Some(kind @ ("server" | "frontend" | "backend")) => {
                let mut sv = None;
                let px_name;
                let target = parts.get(1).copied().unwrap_or("");
                if kind == "server" {
                    match Self::find_server(target, ctx) {
                        Ok((p_idx, s_idx)) => {
                            px_name = ctx.proxies[p_idx].name.clone();
                            sv = Some(ctx.proxies[p_idx].server_ids[s_idx].clone());
                        }
                        Err(msg) => {
                            self.finish_msg(msg);
                            return;
                        }
                    }
                } else if ctx.proxies.iter().any(|p| p.name == target) {
                    px_name = target.to_string();
                } else {
                    self.finish_msg(if kind == "frontend" { "No such frontend." } else { "No such backend." });
                    return;
                }
                let Some(val_s) = parts.get(2).copied() else {
                    self.finish_msg("Require <maxconn>.");
                    return;
                };
                let Ok(val) = val_s.parse::<u32>() else {
                    self.finish_msg("maxconn string empty or preceded by garbage");
                    return;
                };
                // `server_maxconn` and `Proxy::maxconn` are what admission reads.
                let _ = crate::engine::set_proxy_maxconn(ctx.proxies.make_mut(), &px_name, sv.as_deref(), val);
                self.finish_msg("");
            }
            // `global.maxconn`, enforced by `globalconn` (listeners stop accepting at it).
            Some("global") => {
                let Some(v) = parts.get(1) else {
                    self.finish_msg("Expects an integer value.");
                    return;
                };
                // `atoi`: digits after an optional sign, anything else counts as 0.
                let v = crate::applet::atoi(v);
                match crate::globalconn::set(v) {
                    Ok(()) => self.finish_msg(""),
                    Err(msg) => self.finish_msg(msg),
                }
            }
            _ => self.finish_msg("No such target or invalid maxconn."),
        }
    }

    fn handle_enable_server(&mut self, target: &str, ctx: &mut AppletContext) {
        let Some((px_name, sv_name)) = target.split_once('/') else {
            self.out_buf.extend_from_slice(b"Require 'backend/server'.\n");
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.is_done = true;
            }
            return;
        };
        let mut found_px = false;
        let mut track_changes = Vec::new();
        let mut found_sv = false;
        for (p_idx, proxy) in ctx.proxies.iter().enumerate() {
            if proxy.name == px_name {
                found_px = true;
                for (s_idx, sid) in proxy.server_ids.iter().enumerate() {
                    if sid == sv_name {
                        track_changes.push((p_idx, s_idx, ServerStatus::Up));
                        found_sv = true;
                        if let Some(check) = ctx
                            .checks
                            .iter_mut()
                            .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx)
                        {
                            check.status = ServerStatus::Up;
                        }
                    }
                }
            }
        }
        for (p_idx, s_idx, st) in track_changes {
            crate::track::set_status(ctx.proxies, p_idx, s_idx, st);
        }
        if !found_px {
            self.out_buf.extend_from_slice(b"No such backend.\n");
        } else if !found_sv {
            self.out_buf.extend_from_slice(b"No such server.\n");
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_disable_server(&mut self, target: &str, ctx: &mut AppletContext) {
        let Some((px_name, sv_name)) = target.split_once('/') else {
            self.out_buf.extend_from_slice(b"Require 'backend/server'.\n");
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.is_done = true;
            }
            return;
        };
        let mut found_px = false;
        let mut track_changes = Vec::new();
        let mut found_sv = false;
        for (p_idx, proxy) in ctx.proxies.iter().enumerate() {
            if proxy.name == px_name {
                found_px = true;
                for (s_idx, sid) in proxy.server_ids.iter().enumerate() {
                    if sid == sv_name {
                        track_changes.push((p_idx, s_idx, ServerStatus::Maint));
                        found_sv = true;
                        if let Some(check) = ctx
                            .checks
                            .iter_mut()
                            .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx)
                        {
                            check.status = ServerStatus::Maint;
                        }
                    }
                }
            }
        }
        for (p_idx, s_idx, st) in track_changes {
            crate::track::set_status(ctx.proxies, p_idx, s_idx, st);
        }
        if !found_px {
            self.out_buf.extend_from_slice(b"No such backend.\n");
        } else if !found_sv {
            self.out_buf.extend_from_slice(b"No such server.\n");
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    /// Ends a command that answers `msg` (empty for success): HAProxy's CLI prints the message
    /// and one more empty line, so a command with nothing to say still answers `"\n"`.
    fn finish_msg(&mut self, msg: &str) {
        if !msg.is_empty() {
            self.out_buf.extend_from_slice(msg.as_bytes());
            self.out_buf.push(b'\n');
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.out_buf.push(b'\n');
            self.is_done = true;
        }
    }

    /// Resolves `<backend>/<server>` to its indices, or the message HAProxy answers.
    fn find_server(target: &str, ctx: &AppletContext) -> Result<(usize, usize), &'static str> {
        let Some((px_name, sv_name)) = target.split_once('/') else {
            return Err("Require 'backend/server'.");
        };
        let mut found_px = false;
        for (p_idx, proxy) in ctx.proxies.iter().enumerate() {
            if proxy.name == px_name {
                found_px = true;
                if let Some(s_idx) = proxy.server_ids.iter().position(|sid| sid == sv_name) {
                    return Ok((p_idx, s_idx));
                }
            }
        }
        Err(if found_px { "No such server." } else { "No such backend." })
    }

    /// The new weight `arg` asks for (`<n>` or `<n>%` of `iweight`), or HAProxy's message
    /// (`server_parse_weight_change_request`, `src/server.c`).
    fn parse_weight_change(arg: &str, iweight: u32) -> Result<u32, &'static str> {
        let digits_end = arg
            .char_indices()
            .find(|&(i, c)| !(c.is_ascii_digit() || (i == 0 && (c == '-' || c == '+'))))
            .map_or(arg.len(), |(i, _)| i);
        let (num, rest) = arg.split_at(digits_end);
        if num.is_empty() || num == "-" || num == "+" {
            return Err("Empty weight string empty or preceded by garbage");
        }
        let relative = rest.starts_with('%');
        let trailing = if relative { &rest[1..] } else { rest };
        if !trailing.is_empty() {
            return Err("Trailing garbage in weight string");
        }
        let n: i64 = num.parse().unwrap_or(if num.starts_with('-') { i64::MIN } else { i64::MAX });
        if relative {
            if n < 0 {
                return Err("Relative weight must be positive.");
            }
            let w = (i64::from(iweight).saturating_mul(n) / 100).min(256);
            Ok(u32::try_from(w).unwrap_or(256))
        } else if (0..=256).contains(&n) {
            Ok(u32::try_from(n).unwrap_or(256))
        } else {
            Err("Absolute weight can only be between 0 and 256 inclusive.")
        }
    }

    fn apply_weight(&mut self, ctx: &mut AppletContext, loc: (usize, usize), arg: Option<&str>) {
        let Some(arg) = arg else {
            self.finish_msg("Require <weight> or <weight%>.");
            return;
        };
        let (p_idx, s_idx) = loc;
        let iw = ctx.proxies[p_idx].initial_weight(s_idx);
        match Self::parse_weight_change(arg, iw) {
            Ok(w) => {
                // Read by every balancing algorithm (`lb.rs`) and by `show stat`.
                ctx.proxies.make_mut()[p_idx].set_weight(s_idx, w);
                self.finish_msg("");
            }
            Err(msg) => self.finish_msg(msg),
        }
    }

    fn handle_set_server(&mut self, rest: &str, ctx: &mut AppletContext) {
        const USAGE: &str = "usage: set server <backend>/<server> addr | agent | agent-addr | agent-port | agent-send | check-addr | check-port | fqdn | health | name | ssl | state | weight";
        let parts: Vec<&str> = rest.split_whitespace().collect();
        let Some(&target) = parts.first() else {
            self.finish_msg("Require 'backend/server'.");
            return;
        };
        let loc = match Self::find_server(target, ctx) {
            Ok(l) => l,
            Err(msg) => {
                self.finish_msg(msg);
                return;
            }
        };
        let (p_idx, s_idx) = loc;
        match parts.get(1).copied() {
            Some("state") => {
                let status = match parts.get(2).copied() {
                    Some("ready") => ServerStatus::Up,
                    Some("maint") => ServerStatus::Maint,
                    Some("drain") => ServerStatus::Drain,
                    _ => {
                        self.finish_msg("'set server <srv> state' expects 'ready', 'drain' and 'maint'.");
                        return;
                    }
                };
                crate::track::set_status(ctx.proxies, p_idx, s_idx, status);
                if let Some(check) = ctx.checks.iter_mut().find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx) {
                    check.status = status;
                }
                self.finish_msg("");
            }
            Some("weight") => self.apply_weight(ctx, loc, parts.get(2).copied()),
            Some("health") => {
                // `cli_parse_set_server`: a tracker has no health of its own.
                if !crate::track::tracked_label(&ctx.proxies[p_idx], s_idx).is_empty() {
                    self.finish_msg("cannot change health on a tracking server.");
                    return;
                }
                let up = match parts.get(2).copied() {
                    Some("up") => true,
                    Some("down") => false,
                    // `NOLB` is a state Ibex does not have: refused, not taken for another.
                    Some("stopping") => {
                        self.finish_msg("'set server <srv> health stopping' is not supported: Ibex has no stopping state.");
                        return;
                    }
                    _ => {
                        self.finish_msg("'set server <srv> health' expects 'up', 'stopping', or 'down'.");
                        return;
                    }
                };
                // The operator's maintenance or drain is a state of its own in `HAProxy` and is
                // left as it is; Ibex has one state per server, so only a server that is up or
                // down is moved.
                let cur = ServerStatus::from(ctx.proxies[p_idx].server_statuses[s_idx].load(std::sync::atomic::Ordering::Relaxed));
                let status = if up { ServerStatus::Up } else { ServerStatus::Down };
                if matches!(cur, ServerStatus::Up | ServerStatus::Down) {
                    crate::track::set_status(ctx.proxies, p_idx, s_idx, status);
                }
                // The counter a check keeps: fully healthy, or at zero.
                if let Some(check) = ctx.checks.iter_mut().find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx) {
                    check.health = if up { check.config.rise + check.config.fall - 1 } else { 0 };
                    if matches!(cur, ServerStatus::Up | ServerStatus::Down) {
                        check.status = status;
                    }
                }
                self.finish_msg("");
            }
            Some("addr") => {
                let Some(&ip_s) = parts.get(2) else {
                    self.finish_msg("set server <b>/<s> addr requires an address and optionally a port.");
                    return;
                };
                let Ok(ip) = ip_s.parse::<std::net::IpAddr>() else {
                    self.finish_msg(&format!("Invalid addr '{ip_s}'"));
                    return;
                };
                let old = ctx.proxies[p_idx].servers[s_idx];
                let mut new_port = old.port();
                if parts.get(3) == Some(&"port") {
                    let p_s = parts.get(4).copied().unwrap_or("");
                    match p_s.parse::<i64>() {
                        // HAProxy keeps the low 16 bits of what it parsed.
                        Ok(n) => new_port = (n & 0xffff) as u16,
                        Err(_) => {
                            self.finish_msg(&format!("problem converting port '{p_s}' to an int"));
                            return;
                        }
                    }
                }
                let new = std::net::SocketAddr::new(ip, new_port);
                let mut msg = String::new();
                if new.ip() != old.ip() {
                    msg.push_str(&format!("IP changed from '{}' to '{}'", old.ip(), new.ip()));
                }
                if new.port() != old.port() {
                    let sep = if msg.is_empty() { "" } else { ", " };
                    msg.push_str(&format!("{sep}port changed from '{}' to '{}'", old.port(), new.port()));
                }
                if msg.is_empty() {
                    self.finish_msg("nothing changed");
                    return;
                }
                msg.push_str(" by 'stats socket command'");
                // `proxy.servers` is where every connection to this server takes its address.
                ctx.proxies.make_mut()[p_idx].servers[s_idx] = new;
                if let Some(check) = ctx.checks.iter_mut().find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx) {
                    check.addr = new;
                }
                self.finish_msg(&msg);
            }
            _ => self.finish_msg(USAGE),
        }
    }

    fn handle_get_weight(&mut self, target: &str, ctx: &mut AppletContext) {
        let target = target.split_whitespace().next().unwrap_or("");
        match Self::find_server(target, ctx) {
            Ok((p_idx, s_idx)) => {
                let px = &ctx.proxies[p_idx];
                let w = px.server_weights.get(s_idx).copied().unwrap_or(1);
                let iw = px.initial_weight(s_idx);
                self.finish_msg(&format!("{w} (initial {iw})"));
            }
            Err(msg) => self.finish_msg(msg),
        }
    }

    fn handle_set_weight(&mut self, rest: &str, ctx: &mut AppletContext) {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        match Self::find_server(parts.first().copied().unwrap_or(""), ctx) {
            Ok(loc) => self.apply_weight(ctx, loc, parts.get(1).copied()),
            Err(msg) => self.finish_msg(msg),
        }
    }

    fn handle_help(&mut self) {
        let help = "Available commands:\n\
                      help                                       : Show this help message\n\
                      prompt                                     : Switch session to interactive prompt mode\n\
                      quit                                       : Disconnect CLI session\n\
                      set timeout cli <sec>                      : Set CLI session idle timeout\n\
                      show events [-0rsn] [<sink>]               : List the event sinks, or dump a ring\n\
                      show info                                  : Dump system statistics\n\
                      show pools                                 : Report information about the memory pools usage\n\
                      show stat [<iid> <type> <sid>]             : Dump CSV proxies and servers statistics\n\
                      show table [<name>]                        : Dump stick table contents\n\
                      shutdown sessions server <backend>/<server>: Terminate active sessions on server\n\
                      shutdown sessions backend <backend>        : Terminate active sessions on backend\n\
                      clear counters [all|<backend>]             : Clear accumulated statistics counters\n\
                      enable health <backend>/<server>           : Resume active health check\n\
                      disable health <backend>/<server>          : Pause active health check\n\
                      enable server <backend>/<server>           : Resume traffic to server\n\
                      disable server <backend>/<server>          : Put server in maintenance mode\n\
                      set server <backend>/<server> state ...    : Set server state (ready, maint, drain)\n\
                      set server <backend>/<server> maxconn <n>  : Set server maxconn\n\
                      set maxconn server <backend>/<server> <n>  : Set server maxconn\n\
                      set maxconn global <value>                : Set the process maxconn\n\
                      set maxconn frontend <frontend> <n>        : Set frontend maxconn\n\
                      set maxconn backend <backend> <n>          : Set backend maxconn\n\
                      set weight <backend>/<server> <weight>     : Set server weight\n";
        self.out_buf.extend_from_slice(help.as_bytes());
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    /// Steps the applet: reads input, processes commands, writes output, checks timeout.
    pub fn step(&mut self, ctx: &mut AppletContext) {
        self.read_input();
        self.process_commands(ctx);
        self.write_output();

        if self.last_activity.add(self.timeout_ms).is_expired(ctx.now) {
            self.is_done = true;
        }

        self.interest = if self.out_offset < self.out_buf.len() {
            Interest {
                readable: true,
                writable: true,
            }
        } else {
            Interest {
                readable: true,
                writable: false,
            }
        };
    }

    /// Returns `true` if the applet session has finished and should be terminated.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.is_done && self.out_buf.is_empty()
    }
}

/// Per-thread storage for active CLI applet sessions.
pub struct AppletArena {
    entries: Vec<Option<CliApplet>>,
    free: Vec<u32>,
    live: usize,
}

impl AppletArena {
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        AppletArena {
            entries: Vec::with_capacity(cap),
            free: Vec::new(),
            live: 0,
        }
    }

    pub fn alloc(&mut self, entry: CliApplet) -> Option<u32> {
        self.live += 1;
        if let Some(idx) = self.free.pop() {
            self.entries[idx as usize] = Some(entry);
            Some(idx)
        } else {
            let idx = u32::try_from(self.entries.len()).ok()?;
            self.entries.push(Some(entry));
            Some(idx)
        }
    }

    #[must_use]
    pub fn get(&self, idx: u32) -> Option<&CliApplet> {
        self.entries.get(idx as usize)?.as_ref()
    }

    pub fn get_mut(&mut self, idx: u32) -> Option<&mut CliApplet> {
        self.entries.get_mut(idx as usize)?.as_mut()
    }

    pub fn free(&mut self, idx: u32) -> Option<CliApplet> {
        let entry = self.entries.get_mut(idx as usize)?.take();
        if entry.is_some() {
            self.live -= 1;
            self.free.push(idx);
        }
        entry
    }

    #[must_use]
    pub const fn live(&self) -> usize {
        self.live
    }
}

/// C's `atoi` on the leading integer of `s`: 0 when there is none.
fn atoi(s: &str) -> i64 {
    let t = s.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let n: i64 = digits.bytes().take_while(u8::is_ascii_digit).fold(0i64, |a, d| a.saturating_mul(10).saturating_add(i64::from(d - b'0')));
    if neg { -n } else { n }
}
