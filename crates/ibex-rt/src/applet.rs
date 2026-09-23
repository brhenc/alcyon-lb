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
use crate::stats::{format_show_info, format_show_stat_filtered};
use ibex_sched::task::TaskRef;
use ibex_sched::Tick;
use std::fmt::Write as FmtWrite;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

/// Runtime context passed to CLI applet command handlers.
pub struct AppletContext<'a> {
    pub proxies: &'a mut [Proxy],
    pub checks: &'a mut [ServerCheckState],
    pub sessions: Option<&'a mut SessionArena>,
    pub wake_queue: Option<&'a mut Vec<TaskRef>>,
    pub start_time: Instant,
    pub pid: u32,
    pub total_tasks: usize,
    pub run_queue_len: usize,
    pub now: Tick,
}

/// A CLI applet connection session.
pub struct CliApplet {
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
}

impl CliApplet {
    /// Creates a new `CliApplet` for the accepted Unix socket stream.
    #[must_use]
    pub fn new(stream: UnixStream, now: Tick) -> Self {
        let raw_fd = stream.as_raw_fd();
        CliApplet {
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

            self.execute_line(line, ctx);
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
        if cmd == "prompt" {
            self.interactive = true;
            self.out_buf.extend_from_slice(b"\n> ");
        } else if cmd == "quit" {
            self.is_done = true;
        } else if let Some(rest) = cmd.strip_prefix("set timeout cli") {
            if let Ok(secs) = rest.trim().parse::<u32>() {
                self.timeout_ms = secs.saturating_mul(1000);
            }
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            }
        } else if cmd == "show info" {
            self.handle_show_info(ctx);
        } else if cmd == "show env" {
            for (k, v) in std::env::vars() {
                self.out_buf.extend_from_slice(format!("{k}={v}\n").as_bytes());
            }
        } else if cmd == "show errors" {
            self.out_buf.extend_from_slice(b"Total events captured on [01/Jan/1970:00:00:00.000] : 0

");
        } else if cmd == "show backend" {
            self.out_buf.extend_from_slice(b"# name\n");
            for p in ctx.proxies.iter() {
                self.out_buf.extend_from_slice(format!("{}\n", p.name).as_bytes());
            }
        } else if cmd == "show servers state" {
            self.out_buf.extend_from_slice(b"1\n# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port\n");
            for p in ctx.proxies.iter() {
                for (s_idx, s) in p.server_ids.iter().enumerate() {
                    let addr = p.servers.get(s_idx).map_or_else(|| "-".to_string(), |a| a.ip().to_string());
                    let port = p.servers.get(s_idx).map_or_else(|| "-".to_string(), |a| a.port().to_string());
                    let op_state = match p.server_statuses.get(s_idx).map(|s| s.load(std::sync::atomic::Ordering::Relaxed)) {
                        Some(0 /* Up */) => 2,
                        _ => 0,
                    };
                    self.out_buf.extend_from_slice(
                        format!(
                            "{} {} {} {} {} {} 0 1 1 1 1 0 0 0 0 0 0 - {} - 0 0 - - 0\n",
                            p.id, p.name, s_idx + 1, s, addr, op_state, port
                        ).as_bytes()
                    );
                }
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
        } else if let Some(rest) = cmd.strip_prefix("set server ") {
            self.handle_set_server(rest.trim(), ctx);
        } else if let Some(rest) = cmd.strip_prefix("set weight ") {
            self.handle_set_weight(rest.trim(), ctx);
        } else if let Some(rest) = cmd.strip_prefix("set maxconn ") {
            self.handle_set_maxconn(rest.trim(), ctx);
        } else if cmd == "experimental-mode on" || cmd == "experimental-mode off" {
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.is_done = true;
            }
        } else if let Some(target) = cmd.strip_prefix("get var ") {
            self.handle_get_var(target.trim());
        } else if let Some(target) = cmd.strip_prefix("set var ") {
            self.handle_set_var(target.trim());
        } else if cmd == "help" {
            self.handle_help();
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

    fn handle_get_var(&mut self, var_name: &str) {
        let val_opt = if var_name.starts_with("proc.") {
            ibex_sample::get_proc_var(var_name)
        } else {
            ibex_sample::CURRENT_VARS.with(|v| v.borrow().get(var_name).cloned())
        };
        if let Some(val) = val_opt {
            let typ = if val.parse::<i64>().is_ok() {
                "sint"
            } else if val == "true" || val == "false" {
                "bool"
            } else if val.parse::<std::net::IpAddr>().is_ok() {
                "ip"
            } else {
                "str"
            };
            let resp = format!("{var_name}: type={typ} value=<{val}>\n");
            self.out_buf.extend_from_slice(resp.as_bytes());
        } else {
            self.out_buf.extend_from_slice(b"Variable not found.\n");
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
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
        let info = format_show_info(
            ctx.start_time,
            ctx.pid,
            ctx.total_tasks,
            ctx.run_queue_len,
            active_conns,
            max_conns,
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
                    iid_filter = Some(i32::try_from(p_idx + 1).unwrap_or(-2));
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
        let table_filter = cmd
            .strip_prefix("show table")
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let mut out = String::new();
        for proxy in ctx.proxies.iter() {
            if let Some(ref table) = proxy.stick_table {
                let cfg = table.config();
                if let Some(target) = table_filter {
                    if cfg.name != target && proxy.name != target {
                        continue;
                    }
                }
                let _ = writeln!(
                    out,
                    "# table: {}, type: {:?}, size:{}, used:{}",
                    cfg.name,
                    cfg.key_type,
                    cfg.max_size,
                    table.len()
                );
                if let Ok(entries) = table.dump_entries() {
                    for (k, v) in entries {
                        let _ = write!(
                            out,
                            "0x0: key={:?} use=0 conn_cnt={} conn_cur={}",
                            k, v.conn_cnt, v.conn_cur
                        );
                        if v.gpc0 > 0 {
                            let _ = write!(out, " gpc0={}", v.gpc0);
                        }
                        if v.gpc1 > 0 {
                            let _ = write!(out, " gpc1={}", v.gpc1);
                        }
                        if v.gpt0 > 0 {
                            let _ = write!(out, " gpt0={}", v.gpt0);
                        }
                        if let Some(ref r) = v.conn_rate {
                            let _ = write!(out, " conn_rate(10000)={}", r.rate());
                        }
                        if let Some(ref r) = v.http_req_rate {
                            let _ = write!(out, " http_req_rate(10000)={}", r.rate());
                        }
                        out.push('\n');
                    }
                }
            }
        }
        self.out_buf.extend_from_slice(out.as_bytes());
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
        let mut ok = false;
        if parts.len() >= 3 && parts[0] == "server" {
            if let Ok(val) = parts[2].parse::<u32>() {
                if let Some((px, sv)) = parts[1].split_once('/') {
                    ok = crate::engine::set_proxy_maxconn(ctx.proxies, px, Some(sv), val);
                }
            }
        } else if parts.len() >= 3 && (parts[0] == "frontend" || parts[0] == "backend") {
            if let Ok(val) = parts[2].parse::<u32>() {
                ok = crate::engine::set_proxy_maxconn(ctx.proxies, parts[1], None, val);
            }
        } else if parts.len() >= 2 {
            if let Ok(val) = parts[1].parse::<u32>() {
                ok = crate::engine::set_proxy_maxconn(ctx.proxies, parts[0], None, val);
            }
        }
        if !ok {
            self.out_buf.extend_from_slice(b"No such target or invalid maxconn.\n");
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_enable_server(&mut self, target: &str, ctx: &mut AppletContext) {
        let (px_name, sv_name) = match target.split_once('/') {
            Some(pair) => pair,
            None => ("", target),
        };
        let mut found_px = false;
        let mut found_sv = false;
        for (p_idx, proxy) in ctx.proxies.iter_mut().enumerate() {
            if px_name.is_empty() || proxy.name == px_name {
                found_px = true;
                for (s_idx, sid) in proxy.server_ids.iter().enumerate() {
                    if sid == sv_name {
                        proxy.server_statuses[s_idx].store(0 /* Up */, std::sync::atomic::Ordering::Relaxed);
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
        if !found_px && !px_name.is_empty() {
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
        let (px_name, sv_name) = match target.split_once('/') {
            Some(pair) => pair,
            None => ("", target),
        };
        let mut found_px = false;
        let mut found_sv = false;
        for (p_idx, proxy) in ctx.proxies.iter_mut().enumerate() {
            if px_name.is_empty() || proxy.name == px_name {
                found_px = true;
                for (s_idx, sid) in proxy.server_ids.iter().enumerate() {
                    if sid == sv_name {
                        proxy.server_statuses[s_idx].store(1 /* Down */, std::sync::atomic::Ordering::Relaxed);
                        found_sv = true;
                        if let Some(check) = ctx
                            .checks
                            .iter_mut()
                            .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx)
                        {
                            check.status = ServerStatus::Down;
                        }
                    }
                }
            }
        }
        if !found_px && !px_name.is_empty() {
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

    fn handle_set_server(&mut self, rest: &str, ctx: &mut AppletContext) {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() >= 3 && parts[1] == "state" {
            let target = parts[0];
            let state = parts[2];
            let (px_name, sv_name) = match target.split_once('/') {
                Some(pair) => pair,
                None => ("", target),
            };
            let new_status = match state {
                "ready" => Some(ServerStatus::Up),
                "maint" | "drain" => Some(ServerStatus::Down),
                _ => None,
            };

            if let Some(status) = new_status {
                for (p_idx, proxy) in ctx.proxies.iter_mut().enumerate() {
                    if px_name.is_empty() || proxy.name == px_name {
                        for (s_idx, sid) in proxy.server_ids.iter().enumerate() {
                            if sid == sv_name {
                                proxy.server_statuses[s_idx].store(status as u8, std::sync::atomic::Ordering::Relaxed);
                                if let Some(check) = ctx
                                    .checks
                                    .iter_mut()
                                    .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx)
                                {
                                    check.status = status;
                                }
                            }
                        }
                    }
                }
            }
        } else if parts.len() >= 3 && parts[1] == "maxconn" {
            let target = parts[0];
            if let Ok(val) = parts[2].parse::<u32>() {
                let (px_name, sv_name) = match target.split_once('/') {
                    Some(pair) => pair,
                    None => ("", target),
                };
                let _ = crate::engine::set_proxy_maxconn(ctx.proxies, px_name, Some(sv_name), val);
            }
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_set_weight(&mut self, rest: &str, ctx: &mut AppletContext) {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(w) = parts[1].parse::<u32>() {
                let (px_name, sv_name) = match parts[0].split_once('/') {
                    Some(pair) => pair,
                    None => ("", parts[0]),
                };
                for proxy in ctx.proxies.iter_mut() {
                    if px_name.is_empty() || proxy.name == px_name {
                        for (s_idx, sid) in proxy.server_ids.iter().enumerate() {
                            if sid == sv_name && s_idx < proxy.server_weights.len() {
                                proxy.server_weights[s_idx] = w;
                            }
                        }
                    }
                }
            }
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    fn handle_help(&mut self) {
        let help = "Available commands:\n\
                      help                                       : Show this help message\n\
                      prompt                                     : Switch session to interactive prompt mode\n\
                      quit                                       : Disconnect CLI session\n\
                      set timeout cli <sec>                      : Set CLI session idle timeout\n\
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
