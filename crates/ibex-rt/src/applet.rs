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
use crate::mailbox::{Gather, Mailboxes, Msg, SessFilter, SessSnap};
use crate::stats::format_show_stat_as;
use ibex_sched::task::TaskRef;
use ibex_sched::Tick;
use std::fmt::Write as FmtWrite;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use crate::cli_listener::CliStream;
use std::sync::Arc;
use std::time::Instant;

/// The largest payload a CLI command takes (`tune.cli.max-payload-size`, 128 kB by
/// default, which Ibex does not let the configuration change): measured on `HAProxy
/// 3.5-dev8-885761-29`, 131070 bytes of lines with their LFs pass and 131071 are refused.
const CLI_MAX_PAYLOAD: usize = 131_070;

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
    /// Every worker's mailbox: `show sess` and `shutdown session(s)` ask them all.
    pub mailboxes: &'a Arc<Mailboxes>,
    /// The worker serving this CLI connection, and the connection's task, woken when every
    /// worker has answered.
    pub worker_id: usize,
    pub task: TaskRef,
}

/// A command waiting for every worker's answer (`crate::mailbox`). The connection reads no
/// further command until it is answered.
enum Pending {
    Sess(Arc<Gather<Vec<SessSnap>>>, SessOpts),
    /// `shutdown session(s)`; `by_id` answers HAProxy's message when nothing matched.
    Shut(Arc<Gather<usize>>, bool),
}

/// `show sess` options (`cli_parse_show_sess`).
#[derive(Default)]
struct SessOpts {
    fe: Option<usize>,
    be: Option<usize>,
    srv: Option<(usize, usize)>,
    uri: bool,
}

/// `show sess help`, as HAProxy answers it.
const SHOW_SESS_HELP: &str = "Usage: show sess [<id> | all | help] [<options>*]\n\
Dumps active streams (formerly called 'sessions'). Available selectors:\n   \
<id>         dump only this stream identifier (0x...)\n   \
all          dump all matching streams in large format\n   \
help         show this message\n   \
susp         report streams considered suspicious\n\
Available options: \n   \
show-uri     also display the transaction URI, if available\n   \
older <age>  only display streams older than <age> seconds\n   \
server <b/s> only show streams attached to this backend+server\n   \
backend <b>  only show streams attached to this backend\n   \
frontend <f> only show streams attached to this frontend\n\
Without any argument, all streams are dumped in a shorter format.";

/// C's `strtoul(s, NULL, 0)`: the leading number in base 16 (`0x`), 8 (`0`) or 10; 0 when
/// there is none.
fn strtoul0(s: &str) -> u64 {
    let t = s.trim_start();
    let (radix, digits) = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        (16, h)
    } else if let Some(o) = t.strip_prefix('0') {
        (8, o)
    } else {
        (10, t)
    };
    let end = digits.find(|c: char| !c.is_digit(radix)).unwrap_or(digits.len());
    u64::from_str_radix(&digits[..end], radix).unwrap_or(if end == 0 { 0 } else { u64::MAX })
}

/// A timer of `show sess`: `HAProxy`'s `human_time(TICKS_TO_MS(exp - now_ms), 1000)`.
fn sess_timer(ms: Option<i64>) -> String {
    match ms {
        None => String::new(),
        Some(ms) if ms < 0 => "?".into(),
        Some(ms) => crate::mailbox::human_time(ms / 1000),
    }
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
            // Checked by its handler: without `expert-mode on`, which only an admin can
            // set, it answers "restricted to expert mode only" whatever the level.
            "debug dev loop",
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
        self.server_weights.initial(idx).unwrap_or(1)
    }

    /// Changes server `idx`'s current weight, keeping the configured one for
    /// [`Self::initial_weight`]. The weights are shared: every worker's next balancing
    /// decision sees it.
    pub fn set_weight(&self, idx: usize, weight: u32) {
        self.server_weights.set(idx, weight);
    }
}

/// `stats maxconn` when unset (`HAProxy`: 10, measured).
pub const DEFAULT_CLI_MAXCONN: usize = 10;

/// `HAProxy`'s CLI idle timeout when `stats timeout` is not set (`cli_fe->timeout.client`,
/// src/cli.c).
pub const DEFAULT_CLI_TIMEOUT_MS: u32 = 10_000;

/// A CLI applet connection session.
pub struct CliApplet {
    /// What this connection may do; starts at the socket's level.
    pub level: CliLevel,
    /// The name of the socket the connection came in on (`unix@/p`, `ipv4@a:p`, `abns@n`),
    /// for `show cli sockets`.
    pub socket_name: Option<String>,
    /// Every CLI socket of the process with the level it was bound at, one line each, for
    /// `show cli sockets`; the engine fills it for every applet.
    pub socket_list: String,
    pub stream: Option<CliStream>,
    pub raw_fd: RawFd,
    pub task: TaskRef,
    pub in_buf: Vec<u8>,
    pub out_buf: Vec<u8>,
    pub out_offset: usize,
    pub interactive: bool,
    /// `experimental-mode on` was sent on this connection.
    experimental: bool,
    /// `expert-mode on` was sent on this connection, and the level has not gone down since.
    expert: bool,
    pub timeout_ms: u32,
    pub last_activity: Tick,
    pub is_done: bool,
    /// The client shut its write side. What it sent is still run and answered, as
    /// `HAProxy` does: `echo "show sess" | socat - UNIX-CONNECT:...` stops writing before
    /// the workers have answered (T226).
    pub read_shut: bool,
    pub interest: Interest,
    /// An `add map <id> <<` waiting for its payload: the command and the lines so far.
    pub payload: Option<(String, String)>,
    /// When the connection was accepted, for its own `show sess` line.
    pub created: Instant,
    /// A command waiting for the other workers, and what followed it on its line.
    pending: Option<Pending>,
    pending_rest: Option<String>,
    /// A `show table` being written, a chunk at a time (`pump_table`).
    table_dump: Option<TableDump>,
}

/// Where a `show table` is: the filters, the proxy and the slot of its table to read next.
struct TableDump {
    target: Option<String>,
    filter: Option<(String, String, u64)>,
    proxy: usize,
    slot: usize,
    /// The `# table:` line of the current table is out.
    header: bool,
}

/// About how much of a `show table` is put in the output buffer at a time.
const TABLE_CHUNK: usize = 64 * 1024;
/// How much of a `show table` one turn of the connection writes before it yields.
const PUMP_BUDGET: usize = 1024 * 1024;

impl CliApplet {
    /// Creates a new `CliApplet` for an accepted CLI connection.
    #[must_use]
    pub fn new(stream: impl Into<CliStream>, now: Tick) -> Self {
        let stream = stream.into();
        let raw_fd = stream.as_raw_fd();
        CliApplet {
            level: CliLevel::Admin,
            socket_name: None,
            socket_list: String::new(),
            stream: Some(stream),
            raw_fd,
            task: TaskRef::NONE,
            in_buf: Vec::with_capacity(1024),
            out_buf: Vec::with_capacity(4096),
            out_offset: 0,
            interactive: false,
            experimental: false,
            expert: false,
            timeout_ms: DEFAULT_CLI_TIMEOUT_MS,
            last_activity: now,
            is_done: false,
            read_shut: false,
            interest: Interest::READ,
            payload: None,
            created: Instant::now(),
            pending: None,
            pending_rest: None,
            table_dump: None,
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
                    self.read_shut = true;
                    break;
                }
                Ok(n) => {
                    self.in_buf.extend_from_slice(&buf[..n]);
                    // A command line is at most one buffer (`tune.bufsize`): HAProxy answers
                    // this and closes (measured, T239). Nothing longer is kept.
                    let tail = self.in_buf.iter().rposition(|&b| b == b'\n').map_or(self.in_buf.len(), |p| self.in_buf.len() - p - 1);
                    // A payload line (after `<cmd> <<`) is limited by the payload cap
                    // instead (T251).
                    let in_payload = self.payload.is_some()
                        || self.in_buf[..self.in_buf.len() - tail].split(|&b| b == b'\n').any(|l| l.trim_ascii_end().ends_with(b"<<"));
                    if in_payload {
                        if tail > CLI_MAX_PAYLOAD {
                            self.refuse_payload();
                            break;
                        }
                    } else if tail >= crate::buf::get_bufsize() {
                        self.in_buf.clear();
                        self.out_buf.extend_from_slice(
                            b"The command line is too big for the buffer size. Please change 'tune.bufsize' in the configuration to use a bigger command.\n",
                        );
                        self.is_done = true;
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

    /// Writes pending `out_buf` data to the socket stream.
    pub fn write_output(&mut self) {
        let Some(stream) = self.stream.as_mut() else {
            return;
        };

        while self.out_offset < self.out_buf.len() {
            match stream.write(&self.out_buf[self.out_offset..]) {
                Ok(n) if n > 0 => {
                    self.out_offset += n;
                    crate::raw::count_out(n);
                    if self.out_offset >= self.out_buf.len() {
                        self.out_buf.clear();
                        self.out_offset = 0;
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                // The client is gone (an error, or a socket that takes nothing): what was
                // left of the answer has nowhere to go.
                _ => {
                    self.is_done = true;
                    self.out_buf.clear();
                    self.out_offset = 0;
                    break;
                }
            }
        }
    }

    /// Executes complete command lines available in `in_buf`.
    pub fn process_commands(&mut self, ctx: &mut AppletContext) {
        // Nothing new runs while a `show table` is still being written.
        if self.table_dump.is_some() {
            return;
        }
        if let Some(p) = self.pending.take() {
            if !self.resume_pending(p, ctx) {
                return;
            }
            if let Some(rest) = self.pending_rest.take() {
                self.execute_line(&rest, ctx);
                if self.pending.is_some() {
                    return;
                }
            }
            // Out of `prompt` mode, the line that waited was the connection's only one.
            if !self.interactive {
                self.in_buf.clear();
                return;
            }
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
                    if body.len() > CLI_MAX_PAYLOAD {
                        self.refuse_payload();
                        return;
                    }
                    continue;
                }
            } else {
                self.execute_line(line, ctx);
                if self.pending.is_some() {
                    // Answered once every worker has; what follows waits until then.
                    return;
                }
                if self.table_dump.is_some() {
                    // A `show table` is written first; in `prompt` mode what follows runs
                    // once it is out (`pump_table`), otherwise nothing more runs.
                    if !self.interactive {
                        self.in_buf.clear();
                    }
                    return;
                }
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
        // A payload line that has not ended yet counts as well.
        if self.payload.as_ref().is_some_and(|(_, body)| body.len() + self.in_buf.len() > CLI_MAX_PAYLOAD) {
            self.refuse_payload();
        }
    }

    /// A payload over [`CLI_MAX_PAYLOAD`]: refused whole, and the connection closed, in
    /// `prompt` mode too.
    fn refuse_payload(&mut self) {
        self.payload = None;
        self.in_buf.clear();
        self.out_buf.extend_from_slice(
            b"The payload is too big. Please change 'tune.cli.max-payload-size' in the configuration to use a bigger payload.\n",
        );
        self.is_done = true;
    }

    fn execute_line(&mut self, line: &str, ctx: &mut AppletContext) {
        let sub_commands = split_commands(line);
        for (i, raw_cmd) in sub_commands.iter().enumerate() {
            let cmd = raw_cmd.trim();
            if cmd.is_empty() {
                if self.interactive {
                    self.out_buf.extend_from_slice(b"\n> ");
                }
                continue;
            }
            self.execute_command(cmd, ctx);
            // Each command is a run of HAProxy's CLI task, after which its scheduler counts
            // the thread as making progress (measured: 20 x `debug dev loop 80` on one line
            // are not reported, T361).
            crate::watchdog::progress();
            if self.pending.is_some() {
                // The rest of the line runs once this command is answered.
                self.pending_rest = Some(sub_commands[i + 1..].join(";")).filter(|r| !r.is_empty());
                return;
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn execute_command(&mut self, cmd: &str, ctx: &mut AppletContext) {
        // Every command line is cut into words with `cli_parse_request`'s unescaping. The
        // handlers that need the word boundaries (map, ACL, `set var`) cut the raw line
        // themselves; for the others the words are put back, single-spaced.
        let normalized;
        let cmd = if Self::is_patref_command(cmd) || cmd.starts_with("set var ") || !cmd.contains('\\') {
            cmd
        } else {
            normalized = cli_words(cmd).join(" ");
            &normalized
        };
        if self.level < CliLevel::required_for(cmd) {
            self.finish_msg("Permission denied");
        } else if cmd == "user" || cmd == "operator" {
            // The levels only go down.
            self.level = self.level.min(if cmd == "user" { CliLevel::User } else { CliLevel::Operator });
            // HAProxy replaces the whole level, mode bits included.
            self.expert = false;
            self.finish_msg("");
        } else if cmd == "show cli level" {
            self.finish_msg(self.level.name());
        } else if cmd == "show cli sockets" {
            let msg = format!("# socket lvl processes\n{}", self.socket_list);
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
            // Over TCP no descriptor can travel (`SCM_RIGHTS` is unix-only; HAProxy's sendmsg
            // goes out without them): the connection is closed with nothing sent.
            if let Some(stream) = self.stream.as_ref().and_then(CliStream::as_unix) {
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
            self.handle_show_info(cmd, ctx);
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
                    let rmaint = p.server_rmaint(s_idx);
                    let addr = p.servers.get(s_idx).filter(|_| !rmaint).map_or_else(|| "-".to_string(), |a| a.ip().to_string());
                    let port = p.servers.get(s_idx).map_or_else(|| "-".to_string(), |a| a.port().to_string());
                    let raw = p.server_statuses.get(s_idx).map(|s| s.load(std::sync::atomic::Ordering::Relaxed));
                    let status = raw.map(ServerStatus::from);
                    // srv_op_state: 2 running, 0 stopped (a draining server still runs).
                    let op_state = match status {
                        Some(ServerStatus::Up | ServerStatus::Drain) => 2,
                        _ => 0,
                    };
                    // srv_admin_state: SRV_ADMF_FMAINT 1, SRV_ADMF_FDRAIN 8.
                    // A tracker whose target is in maintenance or drain has the inherited flags
                    // instead (SRV_ADMF_IMAINT 2, SRV_ADMF_IDRAIN 16).
                    let inherited = crate::track::inherited(p, s_idx);
                    // A server the file disabled keeps SRV_ADMF_CMAINT (4) for good.
                    let admin_state = match status {
                        Some(ServerStatus::Maint) if inherited => 2,
                        Some(ServerStatus::Drain) if inherited => 16,
                        Some(ServerStatus::Maint) => 1,
                        Some(ServerStatus::Drain) => 8,
                        // Drained, and found dead by its checks.
                        _ if raw == Some(crate::check::DRAIN_DOWN) => 8,
                        _ => 0,
                    } | if p.server_cmaint(s_idx) { 4 } else { 0 };
                    // No address: SRV_ADMF_RMAINT (32) is the maintenance, not the operator's.
                    let admin_state = if rmaint { (admin_state & !1) | 32 } else { admin_state };
                    let uweight = p.server_weights.get(s_idx).unwrap_or(1);
                    let iweight = p.initial_weight(s_idx);
                    
                    let mut check_status = 1;
                    let mut check_result = 0;
                    let mut check_health = p.server_init_health(s_idx);
                    let mut check_state = 0;
                    
                    if let Some(check) = ctx.checks.iter().find(|c| c.proxy() == p_idx && c.server() == s_idx) {
                        check_health = check.health;
                        check_state = 2; // CHK_ST_CONFIGURED
                        if check.enabled {
                            check_state |= 4; // CHK_ST_ENABLED
                        }
                        if check.in_progress {
                            check_state |= 1; // CHK_ST_INPROGRESS
                        }

                        check_status = crate::check::check_status_number(check.last_status_code);
                        check_result = crate::check::check_result_of(check.last_status_code);
                        // CHK_ST_PAUSED while the server is in maintenance.
                        if check.status == ServerStatus::Maint {
                            check_state |= 8;
                        }
                    } else if p.server_cmaint(s_idx) {
                        // A server with no check that the configuration disabled keeps
                        // CHK_ST_PAUSED, also once it is enabled (measured).
                        check_state = 8;
                    }
                    let lastchg = p.ids.server_lastchg(
                        s_idx,
                        p.ids.tc.get().and_then(|c| c.srv.get(s_idx)).map_or(0, |c| c.last_chg.load(std::sync::atomic::Ordering::Relaxed)),
                    );
                    let use_ssl = u8::from(p.server_tls.get(s_idx).is_some_and(Option::is_some));

                    let puid = p.server_puid(s_idx);
                    let bk_forced = u8::from(p.ids.forced_id);
                    let srv_forced = u8::from(p.server_forced_id(s_idx));
                    self.out_buf.extend_from_slice(
                        format!(
                            "{} {} {} {} {} {} {} {} {} {} {} {} {} {} 0 {} {} {} {} - {} 0 - - 0\n",
                            p.ids.iid, p.name, puid, s, addr, op_state, admin_state, uweight, iweight, lastchg, check_status, check_result, check_health, check_state, bk_forced, srv_forced,
                            p.server_fqdn(s_idx).unwrap_or("-"), port, use_ssl
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
        } else if let Some(rest) = cmd.strip_prefix("set ssl crypto-provider").filter(|r| r.is_empty() || r.starts_with(' ')) {
            // T460 (Ibex-only, admin): the provider of the handshakes from now on.
            let msg = crate::crypto_provider::set(rest);
            self.finish_msg(&msg);
        } else if cmd == "show ssl crypto-provider" {
            // T460 (Ibex-only): the provider and the handshakes of each, then the empty line.
            self.finish_msg(&crate::crypto_provider::show());
        } else if cmd == "show pools" || cmd.starts_with("show pools ") {
            let args: Vec<&str> = cmd["show pools".len()..].split_whitespace().collect();
            // The answer ends with the empty line already, also when it is the error.
            let output = ibex_alloc::global_pool_registry().show_pools(&args);
            self.out_buf.extend_from_slice(output.as_bytes());
            if self.interactive {
                self.out_buf.extend_from_slice(b"> ");
            } else {
                self.is_done = true;
            }
        } else if cmd == "show sess" || cmd.starts_with("show sess ") {
            self.handle_show_sess(&cmd["show sess".len()..], ctx);
        } else if let Some(target) = cmd.strip_prefix("shutdown sessions server ")
            .or_else(|| cmd.strip_prefix("shutdown session server "))
        {
            self.handle_shutdown_sessions_server(target.trim(), ctx);
        } else if let Some(target) = cmd.strip_prefix("shutdown sessions backend ")
            .or_else(|| cmd.strip_prefix("shutdown session backend "))
        {
            self.handle_shutdown_sessions_backend(target.trim(), ctx);
        } else if cmd == "shutdown session" || cmd.starts_with("shutdown session ") {
            self.handle_shutdown_session(cmd["shutdown session".len()..].trim(), ctx);
        } else if cmd == "clear counters" || cmd.starts_with("clear counters ") {
            self.handle_clear_counters(cmd["clear counters".len()..].trim(), ctx);
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
        } else if cmd == "expert-mode" || cmd.starts_with("expert-mode ") {
            // `cli_parse_expert_experimental_mode` (src/cli.c:2254): no argument reports
            // it, `on` sets it and any other word clears it.
            match cmd.split_whitespace().nth(1) {
                None => {
                    let msg = format!("expert-mode is {}", if self.expert { "ON" } else { "OFF" });
                    self.finish_msg(&msg);
                }
                Some(arg) => {
                    self.expert = arg == "on";
                    self.finish_msg("");
                }
            }
        } else if cmd == "debug dev loop" || cmd.starts_with("debug dev loop ") {
            if !self.expert {
                self.finish_msg("This command is restricted to expert mode only.");
            } else if cmd.split_whitespace().nth(4) == Some("isolated") {
                // HAProxy stops every other thread for the loop; Ibex cannot (T361 slice 5).
                self.finish_msg("'debug dev loop ... isolated' is not supported: Ibex has no thread isolation.");
            } else {
                Self::debug_dev_loop(cmd);
                self.finish_msg("");
            }
        } else if cmd == "experimental-mode on" || cmd == "experimental-mode off" {
            self.experimental = cmd.ends_with(" on");
            if self.interactive {
                self.out_buf.extend_from_slice(b"\n> ");
            } else {
                self.is_done = true;
            }
        } else if cmd == "get var" || cmd.starts_with("get var ") {
            self.handle_get_var(cmd["get var".len()..].trim());
        } else if cmd.starts_with("set var ") && !self.experimental {
            self.finish_msg("This command is restricted to experimental mode only.");
        } else if let Some(target) = cmd.strip_prefix("set var ") {
            self.handle_set_var(&cli_words(target).join(" "));
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
        let owned = cli_words(cmd);
        let words: Vec<&str> = owned.iter().map(String::as_str).collect();
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
        let Some(smp) = var_name.starts_with("proc.").then(|| ibex_sample::vars::get_proc(var_name)).flatten() else {
            self.finish_msg("Variable not found.");
            return;
        };
        // The value cast to a string (`bin` stops at its first NUL byte), a byte that is not printable
        // ASCII shown as `.`: `isprint` in the oracle's loop. The type is the stored one (T364 S4).
        let bytes: Vec<u8> = match &smp {
            ibex_sample::Sample::Bin(b) => b.iter().copied().take_while(|&c| c != 0).collect(),
            ibex_sample::Sample::Str(t) => ibex_regex::bytetext::text_to_bytes(t).into_owned(),
            other => ibex_sample::registry::sample_to_string(other).into_bytes(),
        };
        let shown: String = bytes.iter().map(|&c| if (0x20..0x7f).contains(&c) { char::from(c) } else { '.' }).collect();
        self.finish_msg(&format!("{var_name}: type={} value=<{shown}>", smp.sample_type().as_str()));
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
            // `set var ... expr` keeps the sample's type, `fmt` stores a string (T364).
            let val = if is_fmt {
                ibex_sample::Sample::Str(crate::engine::format_sample_string(expr, &ctx, registry))
            } else {
                // An expression that does not parse is refused with the parser's message, and
                // the variable is left alone (cli_parse_set_var).
                let parsed = crate::rule_exprs::check_sample_expr(expr, registry).and_then(|()| ibex_sample::Expr::parse(expr));
                match parsed {
                    Ok(e) => e.eval_sample(registry, &ctx).unwrap_or_else(|| ibex_sample::Sample::Str(expr.to_string())),
                    Err(err) => {
                        self.finish_msg(&err);
                        return;
                    }
                }
            };
            ibex_sample::vars::set_proc(var_name, val);
        }
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.is_done = true;
        }
    }

    /// `show info [typed|json]`. `desc` and `float` change the output in ways Ibex does not
    /// implement: they are refused rather than ignored.
    fn handle_show_info(&mut self, cmd: &str, ctx: &AppletContext) {
        let args: Vec<&str> = cmd.split_whitespace().skip(2).collect();
        let fmt = Self::stat_format(&args);
        if let Some(a) = args.iter().find(|a| matches!(**a, "desc" | "float")) {
            self.finish_msg(&format!("'show info {a}' is not supported by Ibex."));
            return;
        }
        // `actconn`: includes the QUIC connections `maxconn` holds (T504).
        let active_conns = crate::globalconn::current();
        let max_conns: u32 = ctx.proxies.iter().map(|p| p.maxconn.get()).sum();
        let cum_conns: u64 = ctx.proxies.iter().map(|p| p.stats.iter().map(|s| s.cum_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()).sum();
        let cum_reqs: u64 = ctx.proxies.iter().filter_map(|p| p.ids.tc.get()).map(|c| c.fe.req_tot.load(std::sync::atomic::Ordering::Relaxed)).sum();
        let info = crate::stats::format_show_info_as(
            fmt,
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
        self.end_stat_answer();
    }

    /// The format a `show info` / `show stat` command asks for (`json` wins over `typed`).
    fn stat_format(args: &[&str]) -> crate::stats::StatFormat {
        if args.contains(&"json") {
            crate::stats::StatFormat::Json
        } else if args.contains(&"typed") {
            crate::stats::StatFormat::Typed
        } else {
            crate::stats::StatFormat::Csv
        }
    }

    /// Ends a `show info` / `show stat` answer: the prompt in interactive mode, otherwise the
    /// empty line `HAProxy` sends after the last row.
    fn end_stat_answer(&mut self) {
        if self.interactive {
            self.out_buf.extend_from_slice(b"\n> ");
        } else {
            self.out_buf.push(b'\n');
            self.is_done = true;
        }
    }

    fn handle_show_stat(&mut self, cmd: &str, ctx: &AppletContext) {
        let mut iid_filter = None;
        let mut type_filter = None;
        let mut sid_filter = None;

        // `show stat [domain <d>] [{<iid>|<proxy>} <type> <sid>] [typed|json] [desc] [up|no-maint]`:
        // the keywords can come anywhere after `stat`; what is left are the three filters.
        let all: Vec<&str> = cmd.split_whitespace().skip(2).collect();
        let fmt = Self::stat_format(&all);
        if all.contains(&"desc") {
            self.finish_msg("'show stat desc' is not supported by Ibex.");
            return;
        }
        let mut parts: Vec<&str> = vec!["show", "stat"];
        parts.extend(all.iter().copied().filter(|p| !matches!(*p, "typed" | "json")));
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

        let stat_csv = format_show_stat_as(ctx.proxies, ctx.checks, ctx.pid, iid_filter, type_filter, sid_filter, fmt);
        self.out_buf.extend_from_slice(stat_csv.as_bytes());
        self.end_stat_answer();
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

        let found = ctx
            .proxies
            .iter()
            .any(|p| p.stick_table.as_ref().is_some_and(|t| table_name.is_none_or(|n| t.config().name == n || p.name == n)));
        if table_name.is_some() && !found {
            // An answer ends with an empty line (HAProxy); the prompt carries it.
            self.finish_msg("No such table");
            return;
        }
        // The dump is written in chunks by `pump_table` (T250), not built here.
        self.table_dump = Some(TableDump {
            target: table_name.map(str::to_string),
            filter: match (filter_field, filter_op, filter_val) {
                (Some(f), Some(o), Some(v)) => Some((f.to_string(), o.to_string(), v)),
                _ => None,
            },
            proxy: 0,
            slot: 0,
            header: false,
        });
    }

    /// Writes the next chunk of a `show table` into `out_buf`, until about `budget` bytes are
    /// out or the dump is over (`table_dump` is then `None`). The table is read a few entries at a
    /// time and its lock is never held across a write: a table of millions of entries
    /// neither sits in memory twice nor stops the data path (`HAProxy`'s applet does the
    /// same).
    fn table_chunk(&mut self, ctx: &AppletContext, budget: usize) {
        use std::fmt::Write;
        let Some(mut dump) = self.table_dump.take() else { return };
        let mut out = String::new();
        let mut scanned = 0usize;
        // Also bounded by the entries looked at: a filter that keeps none must not read a
        // whole table in one turn.
        while out.len() < budget && scanned < 4096 {
            let Some(proxy) = ctx.proxies.get(dump.proxy) else {
                // Past the last proxy: the dump is over.
                self.out_buf.extend_from_slice(out.as_bytes());
                self.finish_msg("");
                return;
            };
            let Some(table) = proxy.stick_table.as_ref().filter(|t| dump.target.as_deref().is_none_or(|n| t.config().name == n || proxy.name == n)) else {
                dump.proxy += 1;
                continue;
            };
            let cfg = table.config();
            if !dump.header {
                let key_type_str = match cfg.key_type {
                    ibex_stick_table::table::KeyType::Ip => "ip",
                    ibex_stick_table::table::KeyType::Ipv6 => "ipv6",
                    ibex_stick_table::table::KeyType::Integer => "integer",
                    ibex_stick_table::table::KeyType::String => "string",
                    ibex_stick_table::table::KeyType::Binary => "binary",
                };
                let _ = writeln!(out, "# table: {}, type: {}, size:{}, used:{}", cfg.name, key_type_str, cfg.max_size, table.len());
                dump.header = true;
            }
            let (entries, next) = table.dump_from(dump.slot, 64);
            // The entries come with the end of the table: they are written, then the next
            // table is started.
            match next {
                Some(n) => dump.slot = n,
                None => {
                    dump.proxy += 1;
                    dump.slot = 0;
                    dump.header = false;
                }
            }
            scanned += 64;
            for (k, v) in entries {
                let fields = table.data_fields(&v);
                if let Some((ff, fo, fv)) = dump.filter.as_ref().map(|(f, o, v)| (f.as_str(), o.as_str(), *v)) {
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
                    if !keep {
                        continue;
                    }
                }
                let key_str = match k {
                    ibex_stick_table::entry::StickKey::Ip(ip) => ip.to_string(),
                    ibex_stick_table::entry::StickKey::Integer(i) => i.to_string(),
                    ibex_stick_table::entry::StickKey::String(s) => s,
                    ibex_stick_table::entry::StickKey::Binary(b) => {
                        let mut s = String::new();
                        for byte in b {
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
        self.out_buf.extend_from_slice(out.as_bytes());
        self.table_dump = Some(dump);
    }

    /// Fills `out_buf` from a running `show table` and writes it, until the socket takes
    /// no more, the dump is over, or [`PUMP_BUDGET`] bytes have gone (the connection's task
    /// is then due again at once, so that one dump does not hold the worker).
    pub fn pump_table(&mut self, ctx: &AppletContext) {
        let mut sent = 0usize;
        while self.table_dump.is_some() && sent < PUMP_BUDGET && !self.is_done {
            if self.out_buf.is_empty() {
                self.out_offset = 0;
                // The last chunk ends the answer, so it is never empty.
                self.table_chunk(ctx, TABLE_CHUNK);
            }
            let before = self.out_buf.len() - self.out_offset;
            self.write_output();
            let left = if self.out_buf.is_empty() { 0 } else { self.out_buf.len() - self.out_offset };
            sent += before - left;
            if left > 0 {
                return;
            }
        }
        // The client is gone (a write failed, or it left before this call): the rest of the
        // dump has nowhere to go.
        if self.is_done {
            self.table_dump = None;
        }
    }

    /// Whether a `show table` has more to send once what is queued is written.
    #[must_use]
    pub fn table_pending(&self) -> bool {
        self.table_dump.is_some()
    }

    /// `shutdown sessions server <be>/<srv>` (`cli_parse_shutdown_sessions_server`): every
    /// stream on the server, on every worker.
    fn handle_shutdown_sessions_server(&mut self, target: &str, ctx: &mut AppletContext) {
        match Self::find_server(target, ctx) {
            Err(msg) => self.finish_msg(msg),
            Ok((be, srv)) => self.ask_shutdown(SessFilter::Server { be, srv }, false, ctx),
        }
    }

    /// `shutdown sessions backend <be>` (Ibex's; HAProxy has no such command): every stream
    /// on the backend's servers, on every worker.
    fn handle_shutdown_sessions_backend(&mut self, target: &str, ctx: &mut AppletContext) {
        match ctx.proxies.iter().position(|p| p.name == target.trim()) {
            None => self.finish_msg("No such backend."),
            Some(be) => self.ask_shutdown(SessFilter::Backend(be), false, ctx),
        }
    }

    /// `shutdown session <id>` (`cli_parse_shutdown_session`): the stream `show sess` listed
    /// as `<id>`, on whichever worker it is.
    fn handle_shutdown_session(&mut self, arg: &str, ctx: &mut AppletContext) {
        let id = strtoul0(arg.split_whitespace().next().unwrap_or(""));
        if id == 0 {
            self.finish_msg("Session pointer expected (use 'show sess').");
        } else {
            self.ask_shutdown(SessFilter::Id(id), true, ctx);
        }
    }

    /// Asks every worker to shut down the streams `f` names; answered in `resume_pending`.
    fn ask_shutdown(&mut self, f: SessFilter, by_id: bool, ctx: &mut AppletContext) {
        let g = Gather::new(ctx.mailboxes, ctx.worker_id, ctx.task);
        let f = Arc::new(f);
        ctx.mailboxes.broadcast(|| Msg::Shutdown(Arc::clone(&f), Arc::clone(&g)));
        self.pending = Some(Pending::Shut(g, by_id));
    }

    /// `show sess [<options>]` (`cli_parse_show_sess`, `src/stream.c`), the one-line-per-stream
    /// format only: the forms that select the long format answer an explicit refusal.
    fn handle_show_sess(&mut self, rest: &str, ctx: &mut AppletContext) {
        let args: Vec<&str> = rest.split_whitespace().collect();
        let mut i = 0;
        match args.first().copied() {
            Some("help") => return self.finish_msg(SHOW_SESS_HELP),
            Some(a @ ("all" | "older")) => {
                return self.finish_msg(&format!(
                    "'show sess {a}' is not supported by Ibex: it prints the long format, of which Ibex has only the one-line form."
                ));
            }
            Some(a) if strtoul0(a) != 0 => {
                return self.finish_msg(
                    "'show sess <id>' is not supported by Ibex: it prints the long format, of which Ibex has only the one-line form.",
                );
            }
            _ => {}
        }
        let mut opts = SessOpts::default();
        let one_of = "Only one of backend, frontend or server may be set.";
        while let Some(&a) = args.get(i) {
            let set = opts.fe.is_some() || opts.be.is_some() || opts.srv.is_some();
            let next = args.get(i + 1).copied();
            match a {
                "show-uri" => opts.uri = true,
                "susp" => return self.finish_msg("'show sess susp' is not supported by Ibex."),
                "server" | "backend" | "frontend" if set => return self.finish_msg(one_of),
                "server" => {
                    let Some(t) = next else {
                        return self.finish_msg("Missing server name (<backend>/<server>).");
                    };
                    match Self::find_server(t, ctx) {
                        Ok(bs) => opts.srv = Some(bs),
                        Err(msg) => return self.finish_msg(msg),
                    }
                    i += 1;
                }
                "backend" => {
                    let Some(n) = next else {
                        return self.finish_msg("Missing backend name.");
                    };
                    let Some(be) = ctx.proxies.iter().position(|p| p.has_backend && p.name == n) else {
                        return self.finish_msg("No such backend.");
                    };
                    opts.be = Some(be);
                    i += 1;
                }
                "frontend" => {
                    let Some(n) = next else {
                        return self.finish_msg("Missing frontend name.");
                    };
                    let Some(fe) = ctx.proxies.iter().position(|p| p.has_frontend && p.name == n) else {
                        return self.finish_msg("No such frontend.");
                    };
                    opts.fe = Some(fe);
                    i += 1;
                }
                _ => return self.finish_msg(&format!("Unsupported option '{a}', try 'help' for more info.")),
            }
            i += 1;
        }
        let g = Gather::new(ctx.mailboxes, ctx.worker_id, ctx.task);
        ctx.mailboxes.broadcast(|| Msg::ShowSess(Arc::clone(&g)));
        self.pending = Some(Pending::Sess(g, opts));
    }

    /// Answers the command waiting for the workers once all have replied; `false` while it
    /// still waits.
    fn resume_pending(&mut self, p: Pending, ctx: &AppletContext) -> bool {
        match p {
            Pending::Shut(g, by_id) => {
                let Some(counts) = g.take() else {
                    self.pending = Some(Pending::Shut(g, by_id));
                    return false;
                };
                let hit = counts.iter().sum::<usize>() > 0;
                self.finish_msg(if by_id && !hit { "No such session (use 'show sess')." } else { "" });
                true
            }
            Pending::Sess(g, opts) => {
                let Some(per_worker) = g.take() else {
                    self.pending = Some(Pending::Sess(g, opts));
                    return false;
                };
                let now = Instant::now();
                for snap in per_worker.iter().flatten() {
                    if opts.fe.is_some_and(|f| snap.fe != Some(f))
                        || opts.be.is_some_and(|b| snap.be != Some(b))
                        || opts.srv.is_some_and(|(b, s)| snap.be != Some(b) || snap.srv != Some(s))
                    {
                        continue;
                    }
                    let line = Self::sess_line(snap, &opts, ctx, now);
                    self.out_buf.extend_from_slice(line.as_bytes());
                }
                self.finish_msg("");
                true
            }
        }
    }

    /// One stream as HAProxy's `show sess` prints it. The fields Ibex has no value for --
    /// `ts`, `epoch`, `calls`, `rate`, `cpu`, `lat`, the channel and stream-connector flag
    /// words and analysers, `ax`, the server side's `wex` -- are printed in their place with a neutral value.
    fn sess_line(s: &SessSnap, opts: &SessOpts, ctx: &AppletContext, now: Instant) -> String {
        let name = |i: Option<usize>, none: &str| {
            i.and_then(|i| ctx.proxies.get(i)).map_or_else(|| none.to_string(), |p| p.name.clone())
        };
        let srv = s
            .srv
            .and_then(|sv| s.be.and_then(|b| ctx.proxies.get(b)).and_then(|p| p.server_ids.get(sv)))
            .map_or("<none>", String::as_str);
        let src = s.src.map_or_else(|| "unix:1".to_string(), |a| a.to_string());
        let age = i64::try_from(now.saturating_duration_since(s.since).as_secs()).unwrap_or(i64::MAX);
        let scb_state = if s.srv_fd >= 0 || s.src.is_none() { 8 } else { 0 };
        let mut l = format!(
            "0x{:x}: proto={} src={src} fe={} be={} srv={srv} ts=00 epoch=0 age={} calls=0 rate=0 cpu=0 lat=0 \
             rq[f=000000h,i={},an=00h,ax=] rp[f=000000h,i={},an=00h,ax=] \
             scf=[8,0h,fd=1/{},rex={},wex={}] scb=[{scb_state},0h,fd=1/{},rex={},wex=] exp={} rc={} c_exp={}",
            s.id,
            s.proto,
            name(s.fe, "GLOBAL"),
            name(s.be, "<NONE>"),
            crate::mailbox::human_time(age),
            s.req_in,
            s.rep_in,
            s.cli_fd,
            sess_timer(s.cli_rex),
            sess_timer(s.cli_wex),
            s.srv_fd,
            sess_timer(s.srv_rex),
            sess_timer(s.exp),
            s.retries,
            sess_timer(s.c_exp),
        );
        if opts.uri {
            if let Some(u) = &s.uri {
                let _ = write!(l, " uri=\"{u}\"");
            }
        }
        l.push('\n');
        l
    }

    /// `clear counters [all | server <be>/<sv> [force] | <anything>]` (`cli_parse_clear_counters`,
    /// `src/stats.c`; measured on HAProxy 3.5-dev8-885761-29): `all` resets every counter of
    /// every proxy, `server` those of one server, and anything else -- no word, or one that is
    /// neither, there is no per-proxy form -- only the maxima of every proxy.
    fn handle_clear_counters(&mut self, rest: &str, ctx: &mut AppletContext) {
        let first = rest.split_whitespace().next();
        if first == Some("server") {
            let rest = rest["server".len()..].trim();
            let rest = rest.strip_suffix(" force").unwrap_or(rest).trim();
            let Some((px_name, sv_name)) = rest.split_once('/') else {
                self.finish_msg("Require 'backend/server'.");
                return;
            };
            let mut found_px = false;
            let mut found = None;
            for (p_idx, p) in ctx.proxies.iter().enumerate() {
                if p.name == px_name {
                    found_px = true;
                    if let Some(s_idx) = p.server_ids.iter().position(|sid| sid == sv_name) {
                        found = Some((p_idx, s_idx));
                        break;
                    }
                }
            }
            if !found_px {
                self.finish_msg("No such backend.");
            } else if let Some((p_idx, s_idx)) = found {
                crate::engine::clear_server_counters(&ctx.proxies[p_idx], s_idx);
                self.finish_msg("Server counters cleared.");
            } else {
                self.finish_msg("No such server.");
            }
            return;
        } else if first == Some("all") {
            crate::engine::clear_proxy_counters(ctx.proxies, None);
            crate::engine::MAX_CONN_RATE.store(0, std::sync::atomic::Ordering::Relaxed);
            crate::engine::MAX_SESS_RATE.store(0, std::sync::atomic::Ordering::Relaxed);
            crate::stats::SSL_MAX.store(0, std::sync::atomic::Ordering::Relaxed); // T320
            self.finish_msg("");
            return;
        } else {
            crate::engine::clear_proxy_maxima(ctx.proxies);
            crate::engine::MAX_CONN_RATE.store(0, std::sync::atomic::Ordering::Relaxed);
            crate::engine::MAX_SESS_RATE.store(0, std::sync::atomic::Ordering::Relaxed);
            crate::stats::SSL_MAX.store(0, std::sync::atomic::Ordering::Relaxed); // T320
            self.finish_msg("");
            return;
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
                let _ = crate::engine::set_proxy_maxconn(ctx.proxies, &px_name, sv.as_deref(), val);
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
            self.finish_msg("Require 'backend/server'.");
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
                    }
                }
            }
        }
        for (p_idx, s_idx, st) in track_changes {
            crate::track::apply_admin(ctx.proxies, ctx.checks, p_idx, s_idx, st);
        }
        // `HAProxy` ends every answer, an empty one too, with an empty line.
        self.finish_msg(if !found_px {
            "No such backend."
        } else if !found_sv {
            "No such server."
        } else {
            ""
        });
    }

    fn handle_disable_server(&mut self, target: &str, ctx: &mut AppletContext) {
        let Some((px_name, sv_name)) = target.split_once('/') else {
            self.finish_msg("Require 'backend/server'.");
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
                    }
                }
            }
        }
        for (p_idx, s_idx, st) in track_changes {
            crate::track::apply_admin(ctx.proxies, ctx.checks, p_idx, s_idx, st);
        }
        // `HAProxy` ends every answer, an empty one too, with an empty line.
        self.finish_msg(if !found_px {
            "No such backend."
        } else if !found_sv {
            "No such server."
        } else {
            ""
        });
    }

    /// Ends a command that answers `msg` (empty for success): HAProxy's CLI prints the message
    /// and one more empty line, so a command with nothing to say still answers `"\n"`.
    /// `debug dev loop <ms> [warn]` (src/debug.c:1281): spins this thread for `<ms>` of
    /// wall time, which is how the watchdog is tested (T361). `warn` says the loop is under
    /// control, so it is reported but not killed. A missing or bad `<ms>` is 0 (`atoi`).
    /// `isolated` is refused by the caller.
    fn debug_dev_loop(cmd: &str) {
        let mut words = cmd.split_whitespace().skip(3);
        let ms = words.next().map_or(0, |w| {
            let digits = w.bytes().take_while(u8::is_ascii_digit).count();
            w[..digits].parse::<u64>().unwrap_or(0)
        });
        let warn = words.next() == Some("warn");
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(ms);
        while std::time::Instant::now() < deadline {
            if warn {
                crate::watchdog::under_control();
            }
        }
    }

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
                ctx.proxies[p_idx].set_weight(s_idx, w);
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
                crate::track::apply_admin(ctx.proxies, ctx.checks, p_idx, s_idx, status);
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
                // The operator's maintenance or drain is kept: the operational state moves
                // under it (`DRAIN` becomes `DOWN`, `MAINT` keeps only the counter).
                crate::track::apply_health(ctx.proxies, ctx.checks, p_idx, s_idx, up);
                self.finish_msg("");
            }
            Some("addr") => {
                // No address, so no family to keep (`srv_update_addr_port`, measured).
                if ctx.proxies[p_idx].server_rmaint(s_idx) {
                    self.finish_msg("Update for the current server address family is only supported through configuration file.");
                    return;
                }
                let Some(&ip_s) = parts.get(2) else {
                    self.finish_msg("set server <b>/<s> addr requires an address and optionally a port.");
                    return;
                };
                let Ok(ip) = ip_s.parse::<std::net::IpAddr>() else {
                    self.finish_msg(&format!("Invalid addr '{ip_s}'"));
                    return;
                };
                let old = ctx.proxies[p_idx].servers.at(s_idx);
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
                ctx.proxies[p_idx].servers.set(s_idx, new);
                if let Some(check) = ctx.checks.iter_mut().find(|c| c.proxy() == p_idx && c.server() == s_idx) {
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
                let w = px.server_weights.get(s_idx).unwrap_or(1);
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
                      show sess [help|<id>|all] [opts...]     : report the list of current streams or dump this exact stream\n\
                      show stat [<iid> <type> <sid>]             : Dump CSV proxies and servers statistics\n\
                      show table [<name>]                        : Dump stick table contents\n\
                      shutdown sessions server <backend>/<server>: Terminate active sessions on server\n\
                      shutdown sessions backend <backend>        : Terminate active sessions on backend\n\
                      shutdown session [id]                   : kill a specific session\n\
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

    /// What the connection waits for: the client's next bytes until it shuts its side or
    /// the connection ends, and room for the answer while some of it is unsent. Neither,
    /// while a command waits for the workers after the client shut its side.
    #[must_use]
    pub fn wants(&self) -> Interest {
        Interest {
            readable: !self.read_shut && !self.is_done,
            writable: self.out_offset < self.out_buf.len(),
        }
    }

    /// Whether the connection is over: its answer is all written, and it has ended
    /// (`quit`, one command out of `prompt` mode, the client gone) or the client shut its
    /// side and nothing it sent is left to answer.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.out_buf.is_empty() && self.table_dump.is_none() && (self.is_done || (self.read_shut && self.pending.is_none()))
    }
}

/// Slots of every worker's [`AppletArena`], for `show pools` (pool `appctx`).
pub static APPCTX_POOL: ibex_alloc::ArenaStats = ibex_alloc::ArenaStats::new(
    "appctx",
    std::mem::size_of::<Option<CliApplet>>(),
    std::mem::align_of::<Option<CliApplet>>(),
    file!(),
    line!(),
);

/// `show pools` provider for the `appctx` pool: the slots ever created, those in use.
#[allow(clippy::unnecessary_wraps)]
pub fn appctx_pool_stats() -> Option<ibex_alloc::PoolHead> {
    Some(APPCTX_POOL.head())
}

impl Drop for AppletArena {
    fn drop(&mut self) {
        APPCTX_POOL.retire(&mut self.published);
    }
}

/// Per-thread storage for active CLI applet sessions: an [`ibex_alloc::Arena`] (design 3.7).
pub struct AppletArena {
    entries: Vec<Option<CliApplet>>,
    free: Vec<u32>,
    live: usize,
    floor: usize,
    peak: usize,
    published: ibex_alloc::arena::Published,
}

impl AppletArena {
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        AppletArena {
            entries: Vec::with_capacity(cap),
            free: Vec::with_capacity(cap),
            live: 0,
            floor: cap,
            peak: 0,
            published: ibex_alloc::arena::Published::default(),
        }
    }

    /// Slots the arena can hold before it grows.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    /// Adds this arena's change since the last pass to `show pools` (once per loop pass).
    #[inline]
    pub fn publish(&mut self) {
        let mut last = self.published;
        APPCTX_POOL.publish_arena::<CliApplet>(&mut last, self);
        self.published = last;
    }

    /// A slot for `entry`, or `None` when the arena is full and cannot grow: the CLI
    /// connection is refused.
    pub fn alloc(&mut self, entry: CliApplet) -> Option<u32> {
        if let Some(idx) = self.free.pop() {
            self.entries[idx as usize] = Some(entry);
            self.live += 1;
            return Some(idx);
        }
        let idx = u32::try_from(self.entries.len()).ok()?;
        if !ibex_alloc::arena::grow_for_one(&mut self.entries, &mut self.free) {
            APPCTX_POOL.failed();
            return None;
        }
        self.live += 1;
        self.entries.push(Some(entry));
        self.peak = self.peak.max(self.entries.len());
        Some(idx)
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

    pub fn iter(&self) -> impl Iterator<Item = (u32, &CliApplet)> {
        self.entries.iter().enumerate().filter_map(|(i, a)| Some((u32::try_from(i).ok()?, a.as_ref()?)))
    }
}

impl ibex_alloc::Arena<CliApplet> for AppletArena {
    fn slots(&self) -> usize {
        self.entries.len()
    }

    fn live(&self) -> usize {
        self.live
    }

    fn compact(&mut self) -> usize {
        ibex_alloc::arena::compact_slots(&mut self.entries, &mut self.free, self.live, self.floor, &mut self.peak, &APPCTX_POOL)
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

/// The commands of a line, cut at each `;` that no backslash protects: `cli_parse_request`
/// skips the character after a backslash when it looks for the end of a command, so `\;`
/// stays in its command (and `cli_words` later turns it into `;`).
pub fn split_commands(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut escaped) = (0, false);
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ';' {
            out.push(&line[start..i]);
            start = i + 1;
        }
    }
    out.push(&line[start..]);
    out
}

/// The words of a CLI command line the way `cli_parse_request` cuts them: blanks (space,
/// tab) separate words, `\\` is one backslash, and a backslash before any other character
/// (a blank included) goes, the character staying in the word. A lone backslash at the
/// end stays. There is no quoting.
pub fn cli_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\r' | '\n' => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\\' => {
                in_word = true;
                cur.push(chars.next().unwrap_or('\\'));
            }
            _ => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}
