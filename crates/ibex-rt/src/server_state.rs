// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The server-state file (T490): what `show servers state` printed before a reload, read
//! back when the proxies are built so the servers start where the old process left them
//! (`apply_server_state`, `src/server_state.c`, version 1 of the format).
//!
//! [`apply`] runs in `Engine::build_shared_state`, before any worker exists, so before any
//! check runs or any request picks a server. It writes the operational and admin state
//! into `Proxy::server_statuses`, the weight into `Proxy::server_weights`, the port into
//! `Proxy::servers`, and leaves the rest ([`Restored`]) in `ProxyIdInfo::server_restored`,
//! which `init_checks` (health, `disable health`, last check status) and the `lastchg`
//! columns read.
//!
//! Memory is bounded by the configuration, not by the file: a file is read twice, a line
//! at a time into one buffer of [`LINE_MAX`] bytes (`HAProxy`'s `fgets` of
//! `SRV_STATE_LINE_MAXLEN`), first to check its shape (a bad line voids the whole file,
//! the lines before it included), then to apply the first line of each configured server.
//!
//! `srv_fqdn` and the address of a server written as a name (`init-addr last`) are read
//! before, while the configuration loads (`ibex_config::server_state_file::read_names`):
//! they decide the address the server starts with. The address of a server written as an
//! address is not restored by `HAProxy` either. `srv_check_port` goes into the server's
//! check configuration (`Proxy::server_check_configs`). Not applied, with a warning:
//! `srv_use_ssl` that differs from the configuration, `srv_check_addr` and `srv_agent_*`
//! (Ibex refuses `addr` and has no agent checks), and `srv_op_state` 3 (`NOLB`, no
//! `http-check disable-on-404` in Ibex).

use crate::check::{ServerStatus, DRAIN_DOWN};
use crate::engine::Proxy;
use ibex_config::ast::LoadServerState;
use ibex_config::server_state_file::{check_fields, file_path, next_line, parse_line, strtol, version, Line, MAX_FIELDS};
use ibex_config::Config;
use std::io::BufReader;
use std::sync::atomic::Ordering;

/// What the file gave a server beyond its status, weight and port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Restored {
    /// The health counter (`srv_check_health`, adjusted to the operational state).
    pub health: u32,
    /// The admin state: `Up` (ready), `Drain` or `Maint`.
    pub admin: ServerStatus,
    /// `disable health` was in force (`srv_check_state` configured and not enabled).
    pub check_disabled: bool,
    /// The last check status, code and description, for a server with a check.
    pub check_code: Option<(&'static str, &'static str)>,
    /// `srv_time_since_last_change`: the server's state is that old at start.
    pub age_s: u64,
}


fn warning(msg: &str) {
    crate::stderr_line!("[WARNING]  ({}) : {msg}", std::process::id());
}

fn notice(msg: &str) {
    crate::stderr_line!("[NOTICE]   ({}) : {msg}", std::process::id());
}

/// `strerror` of an open that failed, without Rust's ` (os error N)`.
fn why(e: &std::io::Error) -> String {
    let s = e.to_string();
    s.split(" (os error").next().unwrap_or(&s).to_string()
}


/// Applies the checked line `f` to server `i` of `p` (`srv` is its configuration line).
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
fn apply_server(p: &mut Proxy, i: usize, srv: &ibex_config::Server, f: &[&str; MAX_FIELDS]) {
    let who = format!("{}/{}", p.name, srv.id);
    let v = match check_fields(f) {
        Ok(v) => v,
        Err(msg) => {
            warning(&format!("server-state application failed for server '{who}'{msg}"));
            return;
        }
    };
    let mut partial = String::new();
    let has_check = srv.check;
    let (rise, fall) = (srv.rise.unwrap_or(2).max(1), srv.fall.unwrap_or(3).max(1));
    let mut health = u32::try_from(v.health.max(0)).unwrap_or(u32::MAX);
    // The operational state.
    let stopped = match v.op {
        0 => {
            health = 0;
            true
        }
        1 if rise == 1 => {
            health = rise.saturating_add(fall) - 1;
            false
        }
        1 => {
            if health < 1 || health >= rise {
                health = rise - 1;
            }
            false
        }
        3 if fall == 1 => {
            health = 0;
            true
        }
        3 => {
            if health < rise || health > rise.saturating_add(fall) - 2 {
                health = rise;
            }
            partial.push_str(", srv_op_state 3 (stopping, NOLB) is not implemented in Ibex: the server runs");
            false
        }
        _ => {
            health = rise.saturating_add(fall) - 1;
            false
        }
    };
    let cfg_cmaint = srv.disabled;
    let mut cur = if cfg_cmaint { ServerStatus::Maint as u8 } else if stopped { ServerStatus::Down as u8 } else { ServerStatus::Up as u8 };
    let to_maint = |cur: &mut u8, health: &mut u32| {
        if *cur != ServerStatus::Maint as u8 {
            *health = 0;
        }
        *cur = ServerStatus::Maint as u8;
    };
    // Leaving maintenance here keeps the counter the operational state set (measured: a
    // `disabled` server with a check that the file had running shows 4, `UP`).
    let to_ready = |cur: &mut u8| {
        if *cur == ServerStatus::Maint as u8 {
            *cur = ServerStatus::Up as u8;
        }
    };
    // A configuration change wins; otherwise the file's admin state does.
    let (cmaint_in_file, fmaint_in_file) = (v.admin & 4 != 0, v.admin & 1 != 0);
    if cmaint_in_file != cfg_cmaint {
        if cfg_cmaint {
            to_maint(&mut cur, &mut health);
        } else {
            to_ready(&mut cur);
        }
    } else if fmaint_in_file && !cfg_cmaint {
        to_maint(&mut cur, &mut health);
    } else if !fmaint_in_file && cfg_cmaint {
        to_ready(&mut cur);
    }
    let cfg_iweight = p.server_weights.initial(i).unwrap_or(1);
    let mut admin = if cur == ServerStatus::Maint as u8 { ServerStatus::Maint } else { ServerStatus::Up };
    // A drain that came from an initial weight of 0 ends once the weight is no longer 0.
    if admin != ServerStatus::Maint && v.admin & 8 != 0 && (v.iweight > 0 || cfg_iweight == 0) {
        cur = if cur == ServerStatus::Down as u8 { DRAIN_DOWN } else { ServerStatus::Drain as u8 };
        admin = ServerStatus::Drain;
    }
    // A server left without an address (`init-addr ...,none`) is in maintenance whatever
    // the file said: `HAProxy` sets `SRV_ADMF_RMAINT` after applying the file. The state the
    // file gave (33: FMAINT, 40: FDRAIN) is kept under it, the one the server takes back when
    // its name resolves (T513). A `disabled` server already keeps `Maint` from the start.
    if p.server_rmaint(i) {
        if admin != ServerStatus::Up {
            p.set_server_rmaint(i, Some(admin));
        }
        cur = ServerStatus::Maint as u8;
        admin = ServerStatus::Maint;
    }
    let before = p.server_statuses.get(i).map_or(cur, |slot| slot.swap(cur, Ordering::Relaxed));
    p.fwrr.changed();
    // `srv_set_stopped` from the file: written on stderr only, the log is not up yet.
    // (The administrative changes are not: `_srv_update_status_adm` keeps quiet while
    // `MODE_STARTING`.)
    // The file's operational state is applied before its administrative one, so a server
    // stopped and in maintenance says it went DOWN; one the configuration disabled does not
    // (`srv_set_stopped` ignores a server in maintenance).
    // An unresolved server (`init-addr none`) is already in maintenance here, but only because
    // `HAProxy` puts it there after applying the file: the file stops a server that was up, and
    // that is said (T522).
    if stopped && !cfg_cmaint {
        let down = ServerStatus::Down as u8;
        let was = if p.server_rmaint(i) { ServerStatus::Up as u8 } else { before };
        if let Some((_, text)) = crate::srvlog::describe(p, i, was, down, crate::srvlog::Kind::Op, crate::srvlog::Cause::StateFile) {
            crate::srvlog::stderr(false, &text);
        }
    }
    // A server the configuration disabled and the file enables says so; going into
    // maintenance is not said at start.
    if before == ServerStatus::Maint as u8 && cur != before {
        if let Some((_, text)) = crate::srvlog::describe(p, i, before, cur, crate::srvlog::Kind::Admin, crate::srvlog::Cause::StateFile) {
            crate::srvlog::stderr(false, &text);
        }
    }
    // The CLI's weight is kept unless the configuration's changed.
    if v.iweight == cfg_iweight {
        p.server_weights.set(i, v.uweight);
        p.fwrr.changed();
    }
    // `i` is a server of the configuration, so of `p.servers`.
    let addr = p.servers.at(i);
    p.servers.set(i, std::net::SocketAddr::new(addr.ip(), v.port));
    if !has_check {
        // What `show servers state` prints as the health of a server with no check.
        let n = p.servers.len();
        let h = &mut p.ids.server_init_health;
        if h.len() < n {
            h.resize(n, 0);
        }
        h[i] = health;
    }
    let restored = Restored {
        health,
        admin,
        check_disabled: has_check && v.check_state & 2 != 0 && v.check_state & 4 == 0,
        check_code: if has_check { crate::check::check_status_of(v.check_status) } else { None },
        age_s: u64::try_from(v.age.max(0)).unwrap_or(0),
    };
    let n = p.servers.len();
    let slots = &mut p.ids.server_restored;
    if slots.len() < n {
        slots.resize(n, None);
    }
    slots[i] = Some(restored);
    // What Ibex cannot apply, said rather than dropped. HAProxy turns TLS off when the file
    // says 0 for a server with TLS (a server without has nothing to turn on: no message).
    let ssl = p.server_tls.get(i).is_some_and(Option::is_some);
    if ssl && v.use_ssl == Some(false) {
        partial.push_str(", srv_use_ssl 0 is not applied: Ibex has no 'set server ssl'");
    }
    let mut agent = v.agent_addr.is_some() || v.agent_port.is_some();
    if v.check_port.is_some() || v.check_addr.is_some() {
        if !has_check || restored.check_disabled {
            // HAProxy's text (`srv_update_check_addr_port`), and it stops there.
            partial.push_str(", health checks are not enabled on this server");
            agent = false;
        } else {
            match check_port(v.check_port.as_deref()) {
                Err(e) => {
                    partial.push_str(e);
                    agent = false;
                }
                Ok(port) => {
                    // The checks connect there (`srv_update_check_addr_port`); their TLS is
                    // what the configuration made it, as `HAProxy`'s `check.use_ssl`.
                    if let (Some(port), Some(slot)) = (port, p.server_check_configs.get_mut(i)) {
                        if let Some(cfg) = slot.as_deref() {
                            *slot = Some(std::sync::Arc::new(crate::check::ServerCheckConfig { check_port: Some(port), ..cfg.clone() }));
                        }
                    }
                    if v.check_addr.is_some() {
                        partial.push_str(", srv_check_addr is not applied: Ibex refuses the server keyword 'addr'");
                    }
                }
            }
        }
    }
    if agent {
        // HAProxy's text (`srv_update_agent_addr_port`): Ibex has no agent checks.
        partial.push_str(", agent checks are not enabled on this server");
    }
    if !partial.is_empty() {
        warning(&format!("server-state partially applied for server '{who}'{partial}"));
    }
}

/// The file's `srv_check_port`, checked as `srv_update_check_addr_port` does (`strl2irc`).
fn check_port(field: Option<&str>) -> Result<Option<u16>, &'static str> {
    let Some(f) = field else { return Ok(None) };
    let digits = f.strip_prefix('-').unwrap_or(f);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(", provided port is not an integer");
    }
    match f.parse::<i32>() {
        Err(_) => Err(", provided port is not an integer"),
        Ok(n) => u16::try_from(n).map(Some).map_err(|_| ", provided port is invalid"),
    }
}

/// Opens `path` and checks its version and the shape of its lines; `None` (with `HAProxy`'s
/// message) when it is not to be read. `local` is the backend of a local file.
fn open(path: &str, local: Option<&str>) -> Option<BufReader<std::fs::File>> {
    let (pre, kind) = match local {
        None => ("config: ".to_string(), "global server state file"),
        Some(px) => (format!("Proxy '{px}': "), "server state file"),
    };
    let dot = if local.is_some() { "." } else { "" };
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            let msg = format!("{pre}Can't open {kind} '{path}': {}{dot}", why(&e));
            if e.kind() == std::io::ErrorKind::NotFound { notice(&msg) } else { warning(&msg) }
            return None;
        }
    };
    let mut r = BufReader::new(f);
    let mut buf = Vec::with_capacity(256);
    match version(&mut r, &mut buf) {
        None => {
            notice(&format!("{pre}Empty {kind} '{path}'."));
            return None;
        }
        Some(0) => {
            warning(&format!("{pre}Can't get version of the {kind} '{path}'."));
            return None;
        }
        Some(_) => {}
    }
    // The shape of every line first: one bad line voids the file.
    let mut linenum = 1;
    while next_line(&mut r, &mut buf) {
        if matches!(parse_line(&buf), Line::Bad) {
            warning(&format!("{pre}corrupted {kind} '{path}' at line {linenum}."));
            return None;
        }
        linenum += 1;
    }
    let mut f = r.into_inner();
    std::io::Seek::rewind(&mut f).ok()?;
    let mut r = BufReader::new(f);
    next_line(&mut r, &mut buf);
    Some(r)
}

/// A backend section of the configuration: its name, servers and file settings.
struct Section<'a> {
    name: &'a str,
    servers: &'a [ibex_config::Server],
    load: LoadServerState,
    file_name: Option<&'a str>,
}

fn sections(config: &Config) -> Vec<Section<'_>> {
    let listens = config.listens.iter().filter(|l| !l.disabled).map(|l| Section {
        name: &l.name,
        servers: &l.servers,
        load: l.load_server_state,
        file_name: l.server_state_file_name.as_deref(),
    });
    let backends = config.backends.iter().filter(|b| !b.disabled).map(|b| Section {
        name: &b.name,
        servers: &b.servers,
        load: b.load_server_state,
        file_name: b.server_state_file_name.as_deref(),
    });
    listens.chain(backends).collect()
}

/// Reads the server-state files of `config` into `proxies` (see the module documentation).
pub fn apply(config: &Config, proxies: &mut [Proxy]) {
    let global = config.global.as_ref();
    let base = global.and_then(|g| g.server_state_base.as_deref());
    let mut secs = sections(config);
    if secs.iter().all(|s| s.load == LoadServerState::None) {
        return;
    }
    // HAProxy walks the proxies in the order they were written.
    let decl = |name: &str| proxies.iter().find(|p| p.has_backend && p.name == name).map_or(u32::MAX, |p| p.ids.decl);
    secs.sort_by_key(|s| decl(s.name));
    let global_file = global.and_then(|g| g.server_state_file.as_deref());
    for s in secs.iter().filter(|s| s.load == LoadServerState::Global && global_file.is_none()) {
        warning(&format!(
            "backend '{}' configured to load server state file from global section 'server-state-file' directive. Unfortunately, 'server-state-file' is not set!",
            s.name
        ));
    }
    for s in secs.iter().filter(|s| s.file_name.is_some() && s.load != LoadServerState::Local) {
        warning(&format!("Proxy '{}': 'server-state-file-name' is ignored without 'load-server-state-from-file local'.", s.name));
    }
    // The global file: one line per server of the backends that read it, the first wins.
    if let Some(name) = global_file {
        let path = file_path(base, name);
        let users: Vec<&Section<'_>> = secs.iter().filter(|s| s.load == LoadServerState::Global && !s.servers.is_empty()).collect();
        if !users.is_empty() {
            if let Some(r) = open(&path, None) {
                apply_file(r, &users, proxies, None);
            }
        }
    }
    for s in secs.iter().filter(|s| s.load == LoadServerState::Local && !s.servers.is_empty()) {
        let path = file_path(base, s.file_name.unwrap_or(s.name));
        if let Some(r) = open(&path, Some(s.name)) {
            apply_file(r, &[s], proxies, Some(s.name));
        }
    }
}

/// Applies the lines of a checked file to the servers of `users`. `local` is the backend of
/// a local file: its lines must name it, and lines for servers it lacks are warned about.
fn apply_file(mut r: BufReader<std::fs::File>, users: &[&Section<'_>], proxies: &mut [Proxy], local: Option<&str>) {
    // The first line of each server, as (section, server) -> line offset in the file.
    let mut first: Vec<Vec<Option<u64>>> = users.iter().map(|s| vec![None; s.servers.len()]).collect();
    let mut buf = Vec::with_capacity(256);
    // The version line was read; count from there.
    let Ok(mut offset) = std::io::Seek::stream_position(&mut r) else { return };
    let px_of = |name: &str, proxies: &[Proxy]| proxies.iter().position(|p| p.has_backend && p.name == name);
    let mut unknown: Vec<String> = Vec::new();
    while next_line(&mut r, &mut buf) {
        let at = offset;
        offset += buf.len() as u64;
        let Line::Fields(f) = parse_line(&buf) else { continue };
        let (be, srv) = (f[1], f[3]);
        let u = if let Some(px) = local {
            let Some(p) = px_of(px, proxies).map(|i| &proxies[i]) else { continue };
            let id_ok = strtol(f[0]) == Some(i64::from(p.ids.iid));
            let name_ok = be == px;
            if !id_ok && !name_ok {
                continue;
            }
            if !id_ok {
                warning(&format!("Proxy '{px}': backend ID mismatch: from server state file: '{}', from running config '{}'", f[0], p.ids.iid));
            } else if !name_ok {
                // HAProxy would keep the line when the old backend's id was forced, but it
                // tests the 0/1 field against PR_O_FORCED_ID (0x80): it never keeps it.
                warning(&format!("Proxy '{px}': backend name mismatch: from server state file: '{be}', from running config '{px}'"));
                continue;
            }
            Some(0)
        } else {
            users.iter().position(|s| s.name == be)
        };
        let Some(u) = u else { continue };
        match users[u].servers.iter().position(|s| s.id == srv) {
            Some(i) => {
                if first[u][i].is_none() {
                    first[u][i] = Some(at);
                }
            }
            None if local.is_some() && !unknown.iter().any(|n| n == srv) => unknown.push(srv.to_string()),
            None => {}
        }
    }
    // Applied in the order of the configuration, re-reading each line where it was.
    let mut f = r.into_inner();
    for (u, s) in users.iter().enumerate() {
        let Some(pi) = px_of(s.name, proxies) else { continue };
        for (i, at) in first[u].iter().enumerate() {
            let Some(at) = at else { continue };
            if std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(*at)).is_err() {
                continue;
            }
            let mut rr = BufReader::with_capacity(2048, &mut f);
            if !next_line(&mut rr, &mut buf) {
                continue;
            }
            if let Line::Fields(fields) = parse_line(&buf) {
                apply_server(&mut proxies[pi], i, &s.servers[i], &fields);
            }
        }
    }
    if let Some(px) = local {
        for srv in unknown {
            warning(&format!("Proxy '{px}': can't find server '{srv}' in backend '{px}'"));
        }
    }
}
