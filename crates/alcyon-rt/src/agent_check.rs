// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/check.c and src/tcpcheck.c (tcpcheck_agent_expect_reply).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Auxiliary `agent-check` engine for backend servers.
//!
//! Each server with `agent-check` enabled runs an independent [`alcyon_sched::task::Kind::AgentCheck`]
//! task on worker 0. On each `agent-inter` tick, it connects to `agent-addr:agent-port`
//! (defaulting to the server's address/port), sends `agent-send` if configured, reads one
//! ASCII line terminated by `\r` or `\n`, and applies weight, maxconn, admin state, and
//! health state changes to the server.

use crate::check::ServerCheckState;
use crate::fdtab::{FdState, FdTab, Interest};
use crate::poller::Poller;
use crate::raw::{self, Io};
use alcyon_config::ast::AgentCheckConfig;
use alcyon_sched::task::TaskRef;
use alcyon_sched::Tick;
use std::borrow::Cow;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::time::Duration;

const MAX_AGENT_REPLY: usize = 4096;

/// Sub-state of an in-progress agent check.
#[derive(Debug)]
pub enum AgentSubState {
    Idle,
    Connecting { sock: OwnedFd, start_tick: Tick },
    Sending { sock: OwnedFd, start_tick: Tick, offset: usize },
    Reading { sock: OwnedFd, start_tick: Tick, buf: Vec<u8> },
}

/// Runtime state of a server's `agent-check`.
#[derive(Debug)]
pub struct AgentCheckState {
    pub proxy_idx: u32,
    pub server_idx: u32,
    pub srv_addr: SocketAddr,
    pub config: AgentCheckConfig,
    pub enabled: bool,
    pub health: u32,
    pub in_progress: bool,
    pub sub_state: AgentSubState,
    pub exp: Tick,
    pub next_check: Tick,
    pub last_status_code: &'static str,
    pub last_status_desc: &'static str,
    pub last_status_info: Option<Box<str>>,
    pub duration_ms: u32,
    pub task: TaskRef,
}

/// Snapshot of an agent check published for stats pages on any worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentView<'a> {
    pub enabled: bool,
    pub health: u32,
    pub in_progress: bool,
    pub last_status_code: &'static str,
    pub last_status_desc: &'static str,
    pub last_status_info: Option<Cow<'a, str>>,
    pub duration_ms: u32,
    pub addr: Option<IpAddr>,
    pub port: u16,
}

impl AgentView<'_> {
    /// Refreshes this view from `state`, reusing the info string when unchanged.
    pub fn refresh(&mut self, state: &AgentCheckState) {
        let prev = self.last_status_info.take();
        *self = AgentView {
            enabled: state.enabled,
            health: state.health,
            in_progress: state.in_progress,
            last_status_code: state.last_status_code,
            last_status_desc: state.last_status_desc,
            last_status_info: prev,
            duration_ms: state.duration_ms,
            addr: state.config.addr,
            port: state.config.port.unwrap_or(0),
        };
        if self.last_status_info.as_deref() != state.last_status_info.as_deref() {
            self.last_status_info = state
                .last_status_info
                .as_deref()
                .map(|s| Cow::Owned(s.to_string()));
        }
    }
}

impl AgentCheckState {
    /// Creates a new `AgentCheckState` for `(proxy_idx, server_idx)`.
    #[must_use]
    pub fn new(
        proxy_idx: usize,
        server_idx: usize,
        srv_addr: SocketAddr,
        config: AgentCheckConfig,
        now: Tick,
    ) -> Self {
        Self {
            proxy_idx: u32::try_from(proxy_idx).unwrap_or(u32::MAX),
            server_idx: u32::try_from(server_idx).unwrap_or(u32::MAX),
            srv_addr,
            enabled: config.enabled,
            config,
            health: 1,
            in_progress: false,
            sub_state: AgentSubState::Idle,
            exp: Tick(0),
            next_check: now,
            last_status_code: "INI",
            last_status_desc: "Initializing",
            last_status_info: None,
            duration_ms: 0,
            task: TaskRef::NONE,
        }
    }

    #[must_use]
    pub const fn proxy(&self) -> usize {
        self.proxy_idx as usize
    }

    #[must_use]
    pub const fn server(&self) -> usize {
        self.server_idx as usize
    }

    fn inter_ms(&self) -> u32 {
        let d = self.config.inter.unwrap_or(Duration::from_millis(2000));
        u32::try_from(d.as_millis()).unwrap_or(u32::MAX).max(1)
    }

    fn target(&self) -> SocketAddr {
        SocketAddr::new(
            self.config.addr.unwrap_or_else(|| self.srv_addr.ip()),
            self.config.port.unwrap_or_else(|| self.srv_addr.port()),
        )
    }

    fn finish_sock(
        &mut self,
        sock: OwnedFd,
        fdtab: &mut FdTab,
        poller: &mut Poller,
        now: Tick,
        start_tick: Tick,
        code: &'static str,
        desc: &'static str,
        info: Option<String>,
    ) {
        let raw_fd = sock.as_raw_fd();
        let _ = poller.delete(sock.as_fd());
        fdtab.remove(raw_fd);
        drop(sock);
        self.sub_state = AgentSubState::Idle;
        self.in_progress = false;
        self.duration_ms = now.0.saturating_sub(start_tick.0);
        self.last_status_code = code;
        self.last_status_desc = desc;
        self.last_status_info = info.map(String::into_boxed_str);
        self.next_check = now.add(self.inter_ms());
    }
}

fn start_agent_check(
    agent: &mut AgentCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
) -> Tick {
    let inter_ms = agent.inter_ms();
    let target = agent.target();
    match raw::connect(target) {
        Ok((sock, _immediate)) => {
            let raw_fd = sock.as_raw_fd();
            agent.exp = now.add(inter_ms);
            agent.in_progress = true;
            fdtab.insert(raw_fd, FdState::Conn { task: agent.task, conn: 0 }, Interest::WRITE);
            let _ = poller.add(sock.as_fd(), u64::try_from(raw_fd).unwrap_or(0), false, true);
            agent.sub_state = AgentSubState::Connecting { sock, start_tick: now };
            agent.exp
        }
        Err(e) => {
            // Failure to connect to the agent does not mark the server down.
            agent.duration_ms = 0;
            agent.last_status_code = "L4CON";
            agent.last_status_desc = "Layer4 connection problem";
            agent.last_status_info = Some(e.to_string().into_boxed_str());
            agent.next_check = now.add(inter_ms);
            agent.next_check
        }
    }
}

/// Advances one agent check state machine and returns the next wake tick.
pub fn step_agent_check(
    agent: &mut AgentCheckState,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    proxies: &crate::table::Table,
    checks: &mut [ServerCheckState],
) -> Tick {
    match std::mem::replace(&mut agent.sub_state, AgentSubState::Idle) {
        AgentSubState::Idle => start_agent_check(agent, fdtab, poller, now),
        AgentSubState::Connecting { sock, start_tick } if now.0 >= agent.exp.0 => {
            agent.finish_sock(sock, fdtab, poller, now, start_tick, "L4TOUT", "Layer4 timeout", None);
            agent.next_check
        }
        AgentSubState::Sending { sock, start_tick, .. }
        | AgentSubState::Reading { sock, start_tick, .. }
            if now.0 >= agent.exp.0 =>
        {
            agent.finish_sock(sock, fdtab, poller, now, start_tick, "L7TOUT", "Layer7 timeout", None);
            agent.next_check
        }
        AgentSubState::Connecting { sock, start_tick } => {
            let raw_fd = sock.as_raw_fd();
            let ready = fdtab.ready(raw_fd);
            if !ready.writable && !ready.readable {
                agent.sub_state = AgentSubState::Connecting { sock, start_tick };
                return agent.exp;
            }
            fdtab.clear_ready(raw_fd, true, true);
            match raw::check_connect_error(sock.as_fd()) {
                Ok(None) => on_connected(agent, sock, fdtab, poller, now, start_tick, proxies, checks),
                Ok(Some(e)) | Err(e) => {
                    agent.finish_sock(sock, fdtab, poller, now, start_tick, "L4CON", "Layer4 connection problem", Some(e.to_string()));
                    agent.next_check
                }
            }
        }
        AgentSubState::Sending { sock, start_tick, offset } => {
            drive_sending(agent, sock, start_tick, offset, fdtab, poller, now, proxies, checks)
        }
        AgentSubState::Reading { sock, start_tick, buf } => {
            drive_reading(agent, sock, start_tick, buf, fdtab, poller, now, proxies, checks)
        }
    }
}

fn on_connected(
    agent: &mut AgentCheckState,
    sock: OwnedFd,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    start_tick: Tick,
    proxies: &crate::table::Table,
    checks: &mut [ServerCheckState],
) -> Tick {
    let raw_fd = sock.as_raw_fd();
    if agent.config.send.as_deref().is_some_and(|s| !s.is_empty()) {
        fdtab.set_interest(raw_fd, Interest::WRITE);
        drive_sending(agent, sock, start_tick, 0, fdtab, poller, now, proxies, checks)
    } else {
        fdtab.set_interest(raw_fd, Interest::READ);
        drive_reading(agent, sock, start_tick, Vec::new(), fdtab, poller, now, proxies, checks)
    }
}

fn drive_sending(
    agent: &mut AgentCheckState,
    sock: OwnedFd,
    start_tick: Tick,
    mut offset: usize,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    proxies: &crate::table::Table,
    checks: &mut [ServerCheckState],
) -> Tick {
    let send_bytes = agent.config.send.as_deref().unwrap_or("").as_bytes();
    let raw_fd = sock.as_raw_fd();
    while offset < send_bytes.len() {
        match raw::send_uncounted(sock.as_fd(), &send_bytes[offset..]) {
            Ok(Io::Done(n)) => offset += n,
            Ok(Io::WouldBlock) => {
                fdtab.clear_ready(raw_fd, false, true);
                agent.sub_state = AgentSubState::Sending { sock, start_tick, offset };
                return agent.exp;
            }
            Ok(Io::Closed | Io::Eof) | Err(_) => {
                agent.finish_sock(sock, fdtab, poller, now, start_tick, "SOCKERR", "Socket error", None);
                return agent.next_check;
            }
        }
    }
    fdtab.set_interest(raw_fd, Interest::READ);
    drive_reading(agent, sock, start_tick, Vec::new(), fdtab, poller, now, proxies, checks)
}

fn drive_reading(
    agent: &mut AgentCheckState,
    sock: OwnedFd,
    start_tick: Tick,
    mut buf: Vec<u8>,
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    proxies: &crate::table::Table,
    checks: &mut [ServerCheckState],
) -> Tick {
    let raw_fd = sock.as_raw_fd();
    let mut last_read = false;
    let mut tmp = [0u8; 1024];

    while buf.len() < MAX_AGENT_REPLY {
        match raw::recv(sock.as_fd(), &mut tmp) {
            Ok(Io::Done(0) | Io::Eof) => {
                last_read = true;
                break;
            }
            Ok(Io::Done(n)) => {
                let take = (MAX_AGENT_REPLY - buf.len()).min(n);
                buf.extend_from_slice(&tmp[..take]);
                if buf.iter().any(|&b| b == b'\n' || b == b'\r') {
                    break;
                }
            }
            Ok(Io::WouldBlock) => {
                fdtab.clear_ready(raw_fd, true, false);
                agent.sub_state = AgentSubState::Reading { sock, start_tick, buf };
                return agent.exp;
            }
            Ok(Io::Closed) | Err(_) => {
                agent.finish_sock(sock, fdtab, poller, now, start_tick, "SOCKERR", "Socket error", None);
                return agent.next_check;
            }
        }
    }

    let (code, desc, info) = apply_agent_reply(agent, &buf, last_read, proxies, checks);
    agent.finish_sock(sock, fdtab, poller, now, start_tick, code, desc, info);
    agent.next_check
}

/// Parses and applies an agent-check reply, matching HAProxy's `tcpcheck_agent_expect_reply`.
fn apply_agent_reply(
    agent: &mut AgentCheckState,
    buf: &[u8],
    last_read: bool,
    proxies: &(impl crate::table::ProxyList + ?Sized),
    checks: &mut [ServerCheckState],
) -> (&'static str, &'static str, Option<String>) {
    let Some(eol) = buf.iter().position(|&b| b == b'\n' || b == b'\r') else {
        let msg = if buf.is_empty() && last_read {
            "TCPCHK got an empty response at step 2"
        } else {
            "Ignoring incomplete line from agent"
        };
        return ("L7RSP", "Layer7 invalid response", Some(msg.to_string()));
    };

    let line = String::from_utf8_lossy(&buf[..eol]);
    let mut hs: Option<&str> = None;
    let mut as_word: Option<&str> = None;
    let mut ps: Option<&str> = None;
    let mut sc: Option<&str> = None;
    let mut err: Option<&str> = None;
    let mut health_status: (&'static str, &'static str) = ("CHECKED", "Health check passed");
    let mut desc_tail = "";

    let bytes = line.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t' | b',') {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }
        if bytes[pos] == b'#' {
            pos += 1;
            while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t') {
                pos += 1;
            }
            desc_tail = line[pos..].trim_start_matches(' ');
            break;
        }
        let start = pos;
        while pos < bytes.len() && !matches!(bytes[pos], b' ' | b'\t' | b',') {
            pos += 1;
        }
        let word = &line[start..pos];

        if word.eq_ignore_ascii_case("up") {
            agent.health = 1;
            health_status = ("L7OKD", "Layer7 check passed");
            hs = Some(word);
        } else if word.eq_ignore_ascii_case("down")
            || word.eq_ignore_ascii_case("stopped")
            || word.eq_ignore_ascii_case("fail")
        {
            agent.health = 0;
            health_status = ("L7STS", "Layer7 wrong status");
            hs = Some(word);
        } else if word.eq_ignore_ascii_case("ready")
            || word.eq_ignore_ascii_case("drain")
            || word.eq_ignore_ascii_case("maint")
        {
            as_word = Some(word);
        } else if word.as_bytes()[0].is_ascii_digit() && word.contains('%') {
            ps = Some(word);
        } else if let Some(rest) = strip_prefix_ignore_case(word, "maxconn:") {
            sc = Some(rest);
        } else if let Some(rest) = strip_prefix_ignore_case(word, "weight:") {
            ps = Some(rest);
        } else if err.is_none() {
            err = Some(word);
        }
    }

    let p = agent.proxy();
    let s = agent.server();
    let mut wrn: Option<&str> = None;

    // 1. Admin status
    if let Some(as_w) = as_word {
        let to = if as_w.eq_ignore_ascii_case("drain") {
            crate::check::ServerStatus::Drain
        } else if as_w.eq_ignore_ascii_case("maint") {
            crate::check::ServerStatus::Maint
        } else {
            crate::check::ServerStatus::Up
        };
        crate::track::apply_admin(proxies, checks, p, s, to, crate::srvlog::Cause::Cli);
    }

    let px = proxies.get(p);

    // 2. Weight
    if let (Some(ps_w), Some(px)) = (ps, px) {
        let iw = px.initial_weight(s);
        match crate::applet::CliApplet::parse_weight_change(ps_w, iw) {
            Ok(w) => px.set_weight(s, w),
            Err(msg) => {
                if wrn.is_none() {
                    wrn = Some(msg);
                }
            }
        }
    }

    // 3. Maxconn
    if let (Some(sc_w), Some(px)) = (sc, px) {
        match sc_w.parse::<u32>() {
            Ok(mc) => {
                let _ = px.srv_set().set_maxconn(s, (mc > 0).then_some(mc));
            }
            Err(_) => {
                if wrn.is_none() {
                    wrn = Some("Invalid maxconn value");
                }
            }
        }
    }

    // 4. Health status
    if let Some(hs_w) = hs {
        if health_status.0 == "L7OKD" {
            let regular_down = checks
                .iter()
                .find(|c| c.proxy() == p && c.server() == s)
                .is_some_and(|c| c.enabled && c.health < c.config.rise);
            if !regular_down {
                crate::track::apply_health(proxies, checks, p, s, true, crate::srvlog::Cause::Cli);
            }
        } else {
            crate::track::apply_health(proxies, checks, p, s, false, crate::srvlog::Cause::Cli);
        }

        let mut msg = desc_tail;
        if msg.is_empty() || health_status.0 == "L7OKD" {
            if let Some(e) = err.filter(|s| !s.is_empty()) {
                msg = e;
            } else if let Some(w) = wrn.filter(|s| !s.is_empty()) {
                msg = w;
            }
        }
        let info = if msg.is_empty() {
            format!("via agent : {hs_w}")
        } else {
            format!("via agent : {hs_w} ({msg})")
        };
        return (health_status.0, health_status.1, Some(info));
    }

    if let Some(e) = err.filter(|s| !s.is_empty()) {
        return ("CHECKED", "Health check passed", Some(format!("agent reports an error : {e}")));
    }
    if let Some(w) = wrn.filter(|s| !s.is_empty()) {
        return ("CHECKED", "Health check passed", Some(format!("agent warns : {w}")));
    }
    ("CHECKED", "Health check passed", None)
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    // Compare bytes, not a `str` slice: a multibyte char straddling `prefix.len()` must not panic.
    let n = prefix.len();
    if s.as_bytes().get(..n)?.eq_ignore_ascii_case(prefix.as_bytes()) {
        s.get(n..)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent_and_proxies() -> (AgentCheckState, crate::engine::Proxies) {
        let cfg_str = "defaults\n    mode tcp\nbackend be1\n    server srv 127.0.0.1:1 weight 100 agent-check agent-port 2\n";
        let config = alcyon_config::parse_str(cfg_str).expect("config");
        let proxies = crate::engine::Engine::build_shared_state(&config).expect("proxies");
        let agent = AgentCheckState::new(
            0,
            0,
            "127.0.0.1:1".parse().unwrap(),
            AgentCheckConfig {
                enabled: true,
                addr: None,
                port: Some(2),
                send: None,
                inter: Some(Duration::from_millis(50)),
            },
            Tick(1),
        );
        (agent, proxies)
    }

    #[test]
    fn reply_edge_cases() {
        let (mut agent, proxies) = test_agent_and_proxies();
        let mut checks = Vec::new();

        // Empty response at EOF
        let (code, _, info) = apply_agent_reply(&mut agent, b"", true, &proxies, &mut checks);
        assert_eq!(code, "L7RSP");
        assert_eq!(info.as_deref(), Some("TCPCHK got an empty response at step 2"));

        // Incomplete line at EOF
        let (code, _, info) = apply_agent_reply(&mut agent, b"75%", true, &proxies, &mut checks);
        assert_eq!(code, "L7RSP");
        assert_eq!(info.as_deref(), Some("Ignoring incomplete line from agent"));

        // Whitespace-only line
        let (code, _, info) = apply_agent_reply(&mut agent, b"   \t \n", true, &proxies, &mut checks);
        assert_eq!(code, "CHECKED");
        assert_eq!(info, None);

        // Invalid weight -> warning
        let (code, _, info) = apply_agent_reply(&mut agent, b"weight:300\n", true, &proxies, &mut checks);
        assert_eq!(code, "CHECKED");
        assert!(info.as_deref().unwrap_or("").starts_with("agent warns : "));

        // Invalid maxconn -> warning
        let (code, _, info) = apply_agent_reply(&mut agent, b"maxconn:abc\n", true, &proxies, &mut checks);
        assert_eq!(code, "CHECKED");
        assert_eq!(info.as_deref(), Some("agent warns : Invalid maxconn value"));

        // Up with bogus token -> via agent : up (bogus)
        let (code, _, info) = apply_agent_reply(&mut agent, b"up bogus\n", true, &proxies, &mut checks);
        assert_eq!(code, "L7OKD");
        assert_eq!(info.as_deref(), Some("via agent : up (bogus)"));

        // Up with warning (invalid maxconn) -> via agent : up (Invalid maxconn value)
        let (code, _, info) = apply_agent_reply(&mut agent, b"up maxconn:abc\n", true, &proxies, &mut checks);
        assert_eq!(code, "L7OKD");
        assert_eq!(info.as_deref(), Some("via agent : up (Invalid maxconn value)"));

        // Out-of-range proxy index still returns cleanly without panicking
        agent.proxy_idx = 999;
        let (code, _, info) = apply_agent_reply(&mut agent, b"75% maxconn:10\n", true, &proxies, &mut checks);
        assert_eq!(code, "CHECKED");
        assert_eq!(info, None);
    }

    #[test]
    fn state_machine_edge_paths() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::os::unix::net::UnixStream;

        let (mut agent, proxies) = test_agent_and_proxies();
        let mut checks = Vec::new();
        let mut fdtab = FdTab::with_capacity(1024);
        let mut poller = Poller::new(64).expect("poller");

        // 1. Immediate raw::connect error (EACCES to 255.255.255.255:1 or EADDRNOTAVAIL to 0.0.0.0:0)
        agent.config.addr = Some("255.255.255.255".parse().unwrap());
        agent.config.port = Some(1);
        let next = step_agent_check(&mut agent, &mut fdtab, &mut poller, Tick(10), &proxies, &mut checks);
        assert_eq!(agent.last_status_code, "L4CON");
        assert_eq!(next, Tick(60));
        assert!(!agent.in_progress);

        // 2. Connecting: not ready yet -> stays Connecting; then L4TOUT on exp
        let (s1, _s2) = UnixStream::pair().expect("pair");
        s1.set_nonblocking(true).unwrap();
        let raw_fd = s1.as_raw_fd();
        fdtab.insert(raw_fd, FdState::Conn { task: TaskRef::NONE, conn: 0 }, Interest::WRITE);
        agent.in_progress = true;
        agent.exp = Tick(100);
        agent.sub_state = AgentSubState::Connecting { sock: OwnedFd::from(s1), start_tick: Tick(50) };
        let next = step_agent_check(&mut agent, &mut fdtab, &mut poller, Tick(60), &proxies, &mut checks);
        assert_eq!(next, Tick(100));
        assert!(matches!(agent.sub_state, AgentSubState::Connecting { .. }));
        let next = step_agent_check(&mut agent, &mut fdtab, &mut poller, Tick(100), &proxies, &mut checks);
        assert_eq!(agent.last_status_code, "L4TOUT");
        assert_eq!(next, Tick(150));

        // 3. Sending timeout -> L7TOUT
        let (s1, _s2) = UnixStream::pair().expect("pair");
        let raw_fd = s1.as_raw_fd();
        fdtab.insert(raw_fd, FdState::Conn { task: TaskRef::NONE, conn: 0 }, Interest::WRITE);
        agent.in_progress = true;
        agent.exp = Tick(200);
        agent.sub_state = AgentSubState::Sending { sock: OwnedFd::from(s1), start_tick: Tick(150), offset: 0 };
        let next = step_agent_check(&mut agent, &mut fdtab, &mut poller, Tick(200), &proxies, &mut checks);
        assert_eq!(agent.last_status_code, "L7TOUT");
        assert_eq!(next, Tick(250));

        // 4. Sending WouldBlock -> resumed in step_agent_check -> Reading multi-chunk without \n
        let (s1, mut s2) = UnixStream::pair().expect("pair");
        s1.set_nonblocking(true).unwrap();
        s2.set_nonblocking(true).unwrap();
        let raw_fd = s1.as_raw_fd();
        fdtab.insert(raw_fd, FdState::Conn { task: TaskRef::NONE, conn: 0 }, Interest::WRITE);
        agent.config.send = Some("A".repeat(1024 * 1024).into_boxed_str());
        agent.in_progress = true;
        agent.exp = Tick(500);
        let next = on_connected(&mut agent, OwnedFd::from(s1), &mut fdtab, &mut poller, Tick(300), Tick(300), &proxies, &mut checks);
        assert_eq!(next, Tick(500));
        assert!(matches!(agent.sub_state, AgentSubState::Sending { .. }));
        // Drain peer until Sending finishes and enters Reading
        let mut drain = [0u8; 65536];
        while matches!(agent.sub_state, AgentSubState::Sending { .. }) {
            while matches!(s2.read(&mut drain), Ok(n) if n > 0) {}
            let next = step_agent_check(&mut agent, &mut fdtab, &mut poller, Tick(310), &proxies, &mut checks);
            assert_eq!(next, Tick(500));
        }
        assert!(matches!(agent.sub_state, AgentSubState::Reading { .. }));
        // Partial reply without '\n' -> stays Reading
        s2.write_all(b"75%").unwrap();
        let next = step_agent_check(&mut agent, &mut fdtab, &mut poller, Tick(315), &proxies, &mut checks);
        assert_eq!(next, Tick(500));
        assert!(matches!(agent.sub_state, AgentSubState::Reading { .. }));
        // Complete reply with '\n'
        s2.write_all(b"\n").unwrap();
        let next = step_agent_check(&mut agent, &mut fdtab, &mut poller, Tick(320), &proxies, &mut checks);
        assert_eq!(agent.last_status_code, "CHECKED");
        assert_eq!(next, Tick(370));

        // 5. Sending to closed peer -> SOCKERR
        let (s1, s2) = UnixStream::pair().expect("pair");
        s1.set_nonblocking(true).unwrap();
        drop(s2);
        let raw_fd = s1.as_raw_fd();
        fdtab.insert(raw_fd, FdState::Conn { task: TaskRef::NONE, conn: 0 }, Interest::WRITE);
        agent.config.send = Some("ping".into());
        agent.in_progress = true;
        agent.exp = Tick(600);
        let _ = on_connected(&mut agent, OwnedFd::from(s1), &mut fdtab, &mut poller, Tick(400), Tick(400), &proxies, &mut checks);
        assert_eq!(agent.last_status_code, "SOCKERR");

        // 6. Reading clean EOF (empty) -> L7RSP
        let (s1, s2) = UnixStream::pair().expect("pair");
        s1.set_nonblocking(true).unwrap();
        drop(s2);
        let raw_fd = s1.as_raw_fd();
        fdtab.insert(raw_fd, FdState::Conn { task: TaskRef::NONE, conn: 0 }, Interest::READ);
        agent.config.send = None;
        agent.in_progress = true;
        agent.exp = Tick(700);
        let _ = on_connected(&mut agent, OwnedFd::from(s1), &mut fdtab, &mut poller, Tick(500), Tick(500), &proxies, &mut checks);
        assert_eq!(agent.last_status_code, "L7RSP");
        assert_eq!(agent.last_status_info.as_deref(), Some("TCPCHK got an empty response at step 2"));

        // 7. Reading > MAX_AGENT_REPLY without '\n' -> L7RSP (loop condition exits cleanly)
        let (s1, mut s2) = UnixStream::pair().expect("pair");
        s1.set_nonblocking(true).unwrap();
        s2.write_all(&vec![b'x'; MAX_AGENT_REPLY + 128]).unwrap();
        let raw_fd = s1.as_raw_fd();
        fdtab.insert(raw_fd, FdState::Conn { task: TaskRef::NONE, conn: 0 }, Interest::READ);
        agent.in_progress = true;
        agent.exp = Tick(800);
        let _ = on_connected(&mut agent, OwnedFd::from(s1), &mut fdtab, &mut poller, Tick(600), Tick(600), &proxies, &mut checks);
        assert_eq!(agent.last_status_code, "L7RSP");
        assert_eq!(agent.last_status_info.as_deref(), Some("Ignoring incomplete line from agent"));

        // 8. Reading from an unconnected socket -> ENOTCONN / EINVAL -> SOCKERR
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let raw_fd = listener.as_raw_fd();
        fdtab.insert(raw_fd, FdState::Conn { task: TaskRef::NONE, conn: 0 }, Interest::READ);
        agent.in_progress = true;
        agent.exp = Tick(900);
        let _ = on_connected(&mut agent, OwnedFd::from(listener), &mut fdtab, &mut poller, Tick(700), Tick(700), &proxies, &mut checks);
        assert_eq!(agent.last_status_code, "SOCKERR");
    }

    #[test]
    fn strip_prefix_ignore_case_multibyte_at_prefix_end() {
        // 'é' occupies bytes 7..9, so byte 8 (the length of "maxconn:") is not a char boundary.
        assert_eq!(strip_prefix_ignore_case("aaaaaaa\u{e9}", "maxconn:"), None);
        assert_eq!(strip_prefix_ignore_case("MAXCONN:\u{e9}", "maxconn:"), Some("\u{e9}"));
        assert_eq!(strip_prefix_ignore_case("weight", "weight:"), None);
    }
}
