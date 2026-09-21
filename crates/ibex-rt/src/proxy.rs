// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy 1.0.2 process_cli(), process_srv() and process_task()
// (haproxy.c), and from mainline's src/stream.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The stream engine for `mode tcp`.
//!
//! `HAProxy` 1.0.2's `process_cli()` and `process_srv()` are the specification. Each
//! inspects both sides, advances at most one state, and returns whether anything
//! changed; `process_task()` runs them until neither does. That "iterate to quiescence"
//! shape is preserved here, because it is what makes the two directions compose without
//! either needing to know the other's internals.
//!
//! The mux layer is absent by design, not by omission: in `mode tcp` `HAProxy` uses
//! `mux_pt`, the passthrough mux, which adds no framing. The seam is real ([`Mux`] in
//! `ibex-proto`), and an H1 mux slots in at exactly the point where this module moves
//! bytes between [`Buf`]s.
//!
//! [`Mux`]: ibex_proto::Mux

use crate::buf::Buf;
use crate::raw::{self, Io};
use ibex_config::{HttpAfterResAction, HttpResAction, Mode};
use ibex_proto::endpoint::ScState;
use ibex_proto::htx::{HttpVersion, Htx, HtxBlock, ResponseLine};
use ibex_proto::{extract_cookie, rewrite_header_block, CompiledExp};
use ibex_sample::{Expr, Registry, SampleContext};
use ibex_sched::Tick;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::time::Instant;

/// Default per-direction buffer. `HAProxy` 1.0 used `BUFSIZE` 8192.
pub const BUFSIZE: usize = 16 * 1024;

/// Why a session ended. Reported to logs and to `show sess`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Ending {
    /// Both directions completed normally.
    Complete,
    /// The client went away.
    ClientAbort,
    /// The server went away.
    ServerAbort,
    /// No server could be reached after exhausting retries.
    ConnectFailed,
    /// A timeout fired. Carries which one, for the log.
    Timeout(Which),
    /// An unexpected I/O error.
    Error,
}

/// Which side a timeout belongs to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Which {
    Client,
    Server,
    Connect,
}

/// What a side wants from the poller next.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Want {
    pub read: bool,
    pub write: bool,
}

/// Timeouts, in milliseconds. Zero means "not set", matching 1.0's config semantics.
#[derive(Copy, Clone, Debug, Default)]
pub struct Timeouts {
    pub client: u32,
    pub server: u32,
    pub connect: u32,
}

/// One TCP / HTTP session: two connections, two buffers, two state machines.
#[allow(clippy::struct_excessive_bools)]
pub struct TcpSession {
    pub cli: OwnedFd,
    pub srv: Option<OwnedFd>,
    pub mode: Mode,
    pub client_addr: Option<SocketAddr>,
    pub cookie_name: Option<String>,
    pub cookie_val: Option<String>,
    pub cliexp: Vec<CompiledExp>,
    pub srvexp: Vec<CompiledExp>,
    pub req_uri: Option<String>,
    pub req_method: Option<String>,
    pub req_headers: Option<Vec<(String, String)>>,
    pub cli_state: ScState,
    pub srv_state: ScState,
    /// Client to server.
    pub req: Buf,
    /// Server to client.
    pub rep: Buf,
    pub timeouts: Timeouts,
    /// Connect attempts left before giving up.
    pub conn_retries: u16,
    /// Deadline for the operation currently in flight on each side.
    pub cli_exp: Tick,
    pub srv_exp: Tick,
    pub conn_exp: Tick,
    /// Earliest tick at which a failed connect may be retried.
    ///
    /// HAProxy calls this the turn-around state (`SC_ST_TAR`). After an asynchronous
    /// connect failure it waits `MIN(1s, timeout connect)` before retrying the *same*
    /// server, because an instant retry almost always reproduces the same error and
    /// just burns the retry budget. See `src/backend.c:2890`.
    pub retry_after: Tick,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub ending: Option<Ending>,
    pub accept_proxy: bool,
    pub accept_proxy_v2: bool,
    pub proxy_handshake_done: bool,
    pub proxy_info: Option<ibex_proto::ProxyInfo>,
    pub server_addr: Option<SocketAddr>,
    pub send_proxy_prepended: bool,
    pub resp_headers_processed: bool,
    pub created_at: Instant,
    pub http_res_rules: Vec<ibex_config::HttpResRule>,
    pub http_after_res_rules: Vec<ibex_config::HttpAfterResRule>,
    pub acls: HashMap<String, Expr>,
    pub pending_resp: Option<(Vec<u8>, usize)>,
}

impl TcpSession {
    #[must_use]
    pub fn new(cli: OwnedFd, timeouts: Timeouts, retries: u16, now: Tick) -> Self {
        Self::new_with_mode(
            cli,
            Mode::Tcp,
            None,
            Vec::new(),
            Vec::new(),
            timeouts,
            retries,
            now,
        )
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_mode(
        cli: OwnedFd,
        mode: Mode,
        cookie_name: Option<String>,
        cliexp: Vec<CompiledExp>,
        srvexp: Vec<CompiledExp>,
        timeouts: Timeouts,
        retries: u16,
        now: Tick,
    ) -> Self {
        let cli_state = if mode == Mode::Http {
            ScState::Ready
        } else {
            ScState::Established
        };
        let mut s = TcpSession {
            cli,
            srv: None,
            mode,
            client_addr: None,
            cookie_name,
            cookie_val: None,
            cliexp,
            srvexp,
            req_uri: None,
            req_method: None,
            req_headers: None,
            cli_state,
            srv_state: ScState::Init,
            req: Buf::with_capacity(BUFSIZE),
            rep: Buf::with_capacity(BUFSIZE),
            timeouts,
            conn_retries: retries,
            retry_after: Tick::ETERNITY,
            cli_exp: Tick::ETERNITY,
            srv_exp: Tick::ETERNITY,
            conn_exp: Tick::ETERNITY,
            bytes_in: 0,
            bytes_out: 0,
            ending: None,
            accept_proxy: false,
            accept_proxy_v2: false,
            proxy_handshake_done: false,
            proxy_info: None,
            server_addr: None,
            send_proxy_prepended: false,
            resp_headers_processed: false,
            created_at: Instant::now(),
            http_res_rules: Vec::new(),
            http_after_res_rules: Vec::new(),
            acls: HashMap::new(),
            pending_resp: None,
        };
        s.arm_client(now);
        s
    }

    pub fn enable_accept_proxy(&mut self, require_v2: bool) {
        self.accept_proxy = true;
        self.accept_proxy_v2 = require_v2;
        self.proxy_handshake_done = false;
        self.cli_state = ScState::Ready;
    }

    fn arm_client(&mut self, now: Tick) {
        self.cli_exp = if self.timeouts.client == 0 {
            Tick::ETERNITY
        } else {
            now.add(self.timeouts.client)
        };
    }

    fn arm_server(&mut self, now: Tick) {
        self.srv_exp = if self.timeouts.server == 0 {
            Tick::ETERNITY
        } else {
            now.add(self.timeouts.server)
        };
    }

    /// Attaches a server-side connection that is still connecting.
    pub fn attach_server(&mut self, fd: OwnedFd, now: Tick) {
        self.srv = Some(fd);
        self.srv_state = ScState::Connecting;
        self.conn_exp = if self.timeouts.connect == 0 {
            Tick::ETERNITY
        } else {
            now.add(self.timeouts.connect)
        };
    }

    /// The server connection completed.
    pub fn server_connected(&mut self, now: Tick) {
        self.srv_state = if self.mode == Mode::Http {
            ScState::Ready
        } else {
            ScState::Established
        };
        self.conn_exp = Tick::ETERNITY;
        self.arm_server(now);
    }

    /// The server connection failed. Returns `true` if a retry remains.
    ///
    /// `same_server` says whether the next attempt will target the server that just
    /// failed. When it does, a turn-around delay is armed; on redispatch to a different
    /// server there is nothing to wait for, so the retry is immediate.
    pub fn server_failed_at(&mut self, now: Tick, same_server: bool) -> bool {
        self.srv = None;
        self.conn_exp = Tick::ETERNITY;
        if self.conn_retries > 0 {
            self.conn_retries -= 1;
            self.srv_state = ScState::Init;
            self.retry_after = if same_server {
                now.add(self.retry_delay_ms())
            } else {
                Tick::ETERNITY
            };
            true
        } else {
            self.srv_state = ScState::Error;
            self.retry_after = Tick::ETERNITY;
            self.ending.get_or_insert(Ending::ConnectFailed);
            false
        }
    }

    /// Turn-around delay: `MIN(1s, timeout connect)`, matching `src/backend.c:2898`.
    #[must_use]
    pub fn retry_delay_ms(&self) -> u32 {
        const DEFAULT_TURNAROUND_MS: u32 = 1000;
        if self.timeouts.connect != 0 && self.timeouts.connect < DEFAULT_TURNAROUND_MS {
            self.timeouts.connect
        } else {
            DEFAULT_TURNAROUND_MS
        }
    }

    /// Whether a retry is still waiting out its turn-around delay.
    ///
    /// The caller must not open a new server connection while this is true; doing so
    /// is exactly the back-to-back retry storm the delay exists to prevent.
    #[must_use]
    pub fn retry_pending(&self, now: Tick) -> bool {
        self.retry_after.is_set() && !self.retry_after.is_expired(now)
    }

    /// Backwards-compatible immediate-retry form. Prefer [`Self::server_failed_at`],
    /// which can arm the turn-around delay.
    pub fn server_failed(&mut self) -> bool {
        let now = Tick::ETERNITY;
        let _ = now;
        self.server_failed_at(Tick(1), false)
    }

    /// Injects or updates an HTTP header in the request buffer.
    pub fn inject_req_header(&mut self, name: &str, value: &str) -> bool {
        self.req.inject_http_header(name, value)
    }

    /// Removes all occurrences of an HTTP header from the request buffer.
    pub fn remove_req_header(&mut self, name: &str) -> bool {
        self.req.remove_http_header(name)
    }

    /// Injects or updates an HTTP header in the response buffer.
    pub fn inject_rep_header(&mut self, name: &str, value: &str) -> bool {
        self.rep.inject_http_header(name, value)
    }

    /// Removes all occurrences of an HTTP header from the response buffer.
    pub fn remove_rep_header(&mut self, name: &str) -> bool {
        self.rep.remove_http_header(name)
    }

    /// Writes an RFC-compliant synthetic HTTP response from raw bytes into `self.rep`.
    pub fn send_synthetic_bytes(&mut self, raw: &[u8]) {
        self.rep.clear();
        let w = self.rep.writable();
        let n = raw.len().min(w.len());
        w[..n].copy_from_slice(&raw[..n]);
        self.rep.commit(n);
        if n < raw.len() {
            self.pending_resp = Some((raw.to_vec(), n));
        } else {
            self.pending_resp = None;
        }
        self.cli_state = ScState::Established;
        self.srv_state = ScState::Closed;
    }

    /// Writes an RFC-compliant synthetic HTTP response into `self.rep` and closes the client read side.
    pub fn send_synthetic_response(
        &mut self,
        status: u16,
        content_type: Option<&str>,
        body: Option<&str>,
    ) {
        let resp = ibex_proto::build_synthetic_response(status, content_type, body);
        self.send_synthetic_bytes(&resp);
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        matches!(self.cli_state, ScState::Closed | ScState::Error)
            && matches!(self.srv_state, ScState::Closed | ScState::Error)
    }

    // ---- the two state machines --------------------------------------------------

    /// Advances the client side. Returns `true` if anything changed.
    fn process_cli(&mut self) -> io::Result<bool> {
        let changed_io = self.process_cli_io()?;
        let changed_trans = self.process_cli_transitions();
        Ok(changed_io || changed_trans)
    }

    #[allow(clippy::too_many_lines)]
    fn process_cli_io(&mut self) -> io::Result<bool> {
        let mut changed = false;

        // Read from the client into the request buffer while reading is permitted
        // and buffer space exists. Backpressure stops reads when full.
        if self.cli_state.can_read() && !self.req.is_full() {
            let dst = self.req.writable();
            match raw::recv(self.cli.as_fd(), dst)? {
                Io::Eof => {
                    raw::shutdown_read(self.cli.as_fd());
                    self.cli_state = match self.cli_state {
                        ScState::Ready | ScState::Established => ScState::ShutR,
                        ScState::ShutW => ScState::Closed,
                        other => other,
                    };
                    changed = true;
                }
                Io::Closed => {
                    self.cli_state = ScState::Closed;
                    self.ending.get_or_insert(Ending::ClientAbort);
                    changed = true;
                }
                Io::Done(n) if n > 0 => {
                    self.req.commit(n);
                    self.bytes_in += n as u64;
                    changed = true;
                }
                Io::Done(_) | Io::WouldBlock => {}
            }
        }

        // Parse PROXY protocol header if accept-proxy is configured
        if self.accept_proxy && !self.proxy_handshake_done {
            if !self.req.is_empty() {
                match ibex_proto::parse_proxy_header(self.req.readable()) {
                    Ok(Some((hdr, consumed))) => {
                        if self.accept_proxy_v2 && hdr.version != ibex_proto::ProxyVersion::V2 {
                            self.cli_state = ScState::Error;
                            self.ending = Some(Ending::Error);
                            return Ok(true);
                        }
                        if let Some(src) = hdr.src_sockaddr() {
                            self.client_addr = Some(src);
                        }
                        if let Some(dst) = hdr.dst_sockaddr() {
                            self.server_addr = Some(dst);
                        }
                        self.proxy_info = Some(hdr.to_owned());
                        self.req.consume(consumed);
                        self.proxy_handshake_done = true;
                        if self.mode == Mode::Http {
                            self.cli_state = ScState::Ready;
                        } else {
                            self.cli_state = ScState::Established;
                        }
                        changed = true;
                    }
                    Ok(None) => {
                        // Incomplete header in buffer, await more data from client
                    }
                    Err(_) => {
                        // Invalid signature, malformed header, or CRC mismatch: reject immediately
                        self.cli_state = ScState::Error;
                        self.ending = Some(Ending::Error);
                        return Ok(true);
                    }
                }
            }
            if !self.proxy_handshake_done {
                return Ok(changed);
            }
        }

        // Parse HTTP request headers if in Ready state
        if self.cli_state == ScState::Ready {
            if let Some((hdr_len, eoh_len)) = find_eoh(self.req.readable()) {
                let total_hdr_len = hdr_len + eoh_len;
                let hdr_bytes = &self.req.readable()[..total_hdr_len];
                let hdr_str = String::from_utf8_lossy(hdr_bytes);

                let (first_line, rest_headers) =
                    if let Some((fl, rest)) = hdr_str.split_once("\r\n") {
                        (fl, rest)
                    } else if let Some((fl, rest)) = hdr_str.split_once('\n') {
                        (fl, rest)
                    } else if let Some((fl, rest)) = hdr_str.split_once('\r') {
                        (fl, rest)
                    } else {
                        (hdr_str.as_ref(), "")
                    };

                let mut parts = first_line.split_whitespace();
                if let Some(m) = parts.next() {
                    self.req_method = Some(m.to_string());
                }
                if let Some(u) = parts.next() {
                    self.req_uri = Some(u.to_string());
                }
                let mut hdrs: Vec<(String, String)> = Vec::new();
                for line in rest_headers.lines() {
                    let trimmed = line.trim_end_matches(['\r', '\n']);
                    if trimmed.is_empty() {
                        continue;
                    }
                    if trimmed.starts_with(' ') || trimmed.starts_with('\t') {
                        if let Some(last) = hdrs.last_mut() {
                            last.1.push(' ');
                            last.1.push_str(trimmed.trim());
                        }
                    } else if let Some((k, v)) = trimmed.split_once(':') {
                        hdrs.push((k.trim().to_string(), v.trim().to_string()));
                    }
                }
                self.req_headers = Some(hdrs);

                if let Some(ref cname) = self.cookie_name {
                    self.cookie_val = extract_cookie(&hdr_str, cname);
                }

                if !self.cliexp.is_empty() {
                    let rewritten = rewrite_header_block(&hdr_str, &self.cliexp);
                    self.req.replace_prefix(total_hdr_len, rewritten.as_bytes());
                }

                self.cli_state = ScState::Established;
                changed = true;
            }
        }

        // Drain pending synthetic response into rep if space is available
        if let Some((ref data, ref mut offset)) = self.pending_resp {
            if self.rep.writable().is_empty() && self.rep.len() < self.rep.capacity() {
                self.rep.compact();
            }
            let space = self.rep.writable().len();
            if space > 0 && *offset < data.len() {
                let to_copy = space.min(data.len() - *offset);
                self.rep.writable()[..to_copy].copy_from_slice(&data[*offset..*offset + to_copy]);
                self.rep.commit(to_copy);
                *offset += to_copy;
                changed = true;
            }
            if *offset >= data.len() && self.rep.is_empty() {
                self.pending_resp = None;
            }
        }

        // Write any response data back to the client while writing is permitted.
        if self.cli_state.can_write() && !self.rep.is_empty() {
            match raw::send(self.cli.as_fd(), self.rep.readable())? {
                Io::Done(n) if n > 0 => {
                    self.rep.consume(n);
                    self.bytes_out += n as u64;
                    changed = true;
                }
                Io::Closed => {
                    self.cli_state = ScState::Closed;
                    self.ending.get_or_insert(Ending::ClientAbort);
                    changed = true;
                }
                Io::Done(_) | Io::WouldBlock | Io::Eof => {}
            }
        }

        Ok(changed)
    }

    fn process_cli_transitions(&mut self) -> bool {
        let mut changed = false;

        match self.cli_state {
            ScState::Ready | ScState::Established => {
                let srv_done_sending = matches!(
                    self.srv_state,
                    ScState::ShutR | ScState::Closed | ScState::Error
                );
                if srv_done_sending && self.rep.is_empty() && self.pending_resp.is_none() {
                    raw::shutdown_write(self.cli.as_fd());
                    self.cli_state = ScState::ShutW;
                    self.ending
                        .get_or_insert(if self.srv_state == ScState::Error {
                            Ending::ServerAbort
                        } else {
                            Ending::Complete
                        });
                    changed = true;
                } else {
                    let srv_done_receiving = matches!(
                        self.srv_state,
                        ScState::ShutW | ScState::Closed | ScState::Error
                    );
                    if srv_done_receiving {
                        raw::shutdown_read(self.cli.as_fd());
                        self.cli_state = ScState::ShutR;
                        changed = true;
                    }
                }
            }
            ScState::ShutR => {
                let srv_done_sending = matches!(
                    self.srv_state,
                    ScState::ShutR | ScState::Closed | ScState::Error
                );
                if srv_done_sending && self.rep.is_empty() && self.pending_resp.is_none() {
                    raw::shutdown_write(self.cli.as_fd());
                    self.cli_state = ScState::Closed;
                    self.ending
                        .get_or_insert(if self.srv_state == ScState::Error {
                            Ending::ServerAbort
                        } else {
                            Ending::Complete
                        });
                    changed = true;
                }
            }
            ScState::ShutW => {
                let srv_done_receiving = matches!(
                    self.srv_state,
                    ScState::ShutW | ScState::Closed | ScState::Error
                );
                if srv_done_receiving {
                    self.cli_state = ScState::Closed;
                    changed = true;
                }
            }
            _ => {}
        }

        changed
    }

    /// Advances the server side. Returns `true` if anything changed.
    ///
    /// Mirrors 1.0's `process_srv()`.
    fn process_srv(&mut self) -> io::Result<bool> {
        match self.srv_state {
            ScState::Init => {
                // 1.0: while idle, give up if the client is gone and has left nothing
                // behind. Connecting to a server for a client that has already
                // vanished is pure waste, and under a connection flood it is the
                // difference between absorbing the flood and amplifying it.
                let cli_done = matches!(
                    self.cli_state,
                    ScState::Closed | ScState::Error | ScState::ShutW
                ) || (self.cli_state == ScState::ShutR && self.req.is_empty());
                if cli_done {
                    self.srv_state = ScState::Closed;
                    return Ok(true);
                }
                Ok(false)
            }
            ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW => {
                if self.srv.is_none() {
                    self.srv_state = ScState::Error;
                    return Ok(true);
                }
                self.process_srv_active()
            }
            _ => Ok(false),
        }
    }

    fn process_srv_active(&mut self) -> io::Result<bool> {
        let mut changed_io = self.process_srv_io()?;

        // Parse HTTP response headers if in Ready state
        if self.srv_state == ScState::Ready {
            if let Some((hdr_len, eoh_len)) = find_eoh(self.rep.readable()) {
                let total_hdr_len = hdr_len + eoh_len;
                let hdr_bytes = &self.rep.readable()[..total_hdr_len];
                let mut hdr_str = String::from_utf8_lossy(hdr_bytes).to_string();

                if !self.srvexp.is_empty() {
                    hdr_str = rewrite_header_block(&hdr_str, &self.srvexp);
                }

                if !self.http_res_rules.is_empty() || !self.http_after_res_rules.is_empty() {
                    hdr_str = self.apply_response_rules(&hdr_str);
                }

                self.rep.replace_prefix(total_hdr_len, hdr_str.as_bytes());
                self.srv_state = ScState::Established;
                self.resp_headers_processed = true;
                changed_io = true;
            }
        }

        let changed_trans = self.process_srv_transitions();
        Ok(changed_io || changed_trans)
    }

    fn apply_response_rules(&self, hdr_str: &str) -> String {
        let mut out_hdr = hdr_str.to_string();

        let status = if let Some((first_line, _)) = out_hdr.split_once("\r\n") {
            let mut parts = first_line.split_whitespace();
            let _ver = parts.next();
            parts
                .next()
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(200)
        } else {
            200
        };

        let mut htx = Htx::new();
        htx.push(HtxBlock::ResLine(ResponseLine {
            version: HttpVersion::Http11,
            status,
            reason: ibex_proto::status_reason_phrase(status).to_string(),
        }));

        let ctx = SampleContext {
            client_addr: self.client_addr,
            server_addr: self.server_addr,
            htx: Some(&htx),
            req_uri: self.req_uri.as_deref(),
            req_method: self.req_method.as_deref(),
            req_headers: self.req_headers.as_deref(),
            ..Default::default()
        };

        let registry = Registry::new();
        #[allow(clippy::cast_possible_truncation)]
        let elapsed_ms = self.created_at.elapsed().as_millis() as u64;

        for rule in &self.http_res_rules {
            let matches = if let Some(ref cond) = rule.cond {
                eval_acl_condition(cond, &self.acls, &registry, &ctx)
            } else {
                true
            };

            if matches {
                match &rule.action {
                    HttpResAction::SetHeader { name, fmt } => {
                        let val =
                            ibex_proto::format_log_format_string(fmt, self.client_addr, elapsed_ms);
                        out_hdr = Self::apply_set_header(&out_hdr, name, &val);
                    }
                    HttpResAction::AddHeader { name, fmt } => {
                        let val =
                            ibex_proto::format_log_format_string(fmt, self.client_addr, elapsed_ms);
                        out_hdr = Self::apply_add_header(&out_hdr, name, &val);
                    }
                    HttpResAction::DelHeader { name } => {
                        out_hdr = Self::apply_del_header(&out_hdr, name);
                    }
                    HttpResAction::SetStatus { status: st } => {
                        out_hdr = Self::apply_set_status(&out_hdr, *st);
                    }
                }
            }
        }

        for rule in &self.http_after_res_rules {
            let matches = if let Some(ref cond) = rule.cond {
                eval_acl_condition(cond, &self.acls, &registry, &ctx)
            } else {
                true
            };

            if matches {
                match &rule.action {
                    HttpAfterResAction::SetHeader { name, fmt } => {
                        let val =
                            ibex_proto::format_log_format_string(fmt, self.client_addr, elapsed_ms);
                        out_hdr = Self::apply_set_header(&out_hdr, name, &val);
                    }
                    HttpAfterResAction::AddHeader { name, fmt } => {
                        let val =
                            ibex_proto::format_log_format_string(fmt, self.client_addr, elapsed_ms);
                        out_hdr = Self::apply_add_header(&out_hdr, name, &val);
                    }
                    HttpAfterResAction::DelHeader { name } => {
                        out_hdr = Self::apply_del_header(&out_hdr, name);
                    }
                }
            }
        }

        out_hdr
    }

    fn apply_set_header(raw_headers: &str, name: &str, value: &str) -> String {
        let mut vec = raw_headers.as_bytes().to_vec();
        vec.resize(vec.len() + name.len() + value.len() + 32, 0);
        if let Some(new_len) = ibex_proto::inject_http_header(&mut vec, name, value) {
            vec.truncate(new_len);
            String::from_utf8(vec).unwrap_or_else(|_| raw_headers.to_string())
        } else {
            raw_headers.to_string()
        }
    }

    fn apply_add_header(raw_headers: &str, name: &str, value: &str) -> String {
        if let Some((eoh_pos, _)) = find_eoh(raw_headers.as_bytes()) {
            let mut out = String::with_capacity(raw_headers.len() + name.len() + value.len() + 4);
            out.push_str(&raw_headers[..eoh_pos]);
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
            out.push_str(&raw_headers[eoh_pos..]);
            out
        } else {
            raw_headers.to_string()
        }
    }

    fn apply_del_header(raw_headers: &str, name: &str) -> String {
        let mut vec = raw_headers.as_bytes().to_vec();
        if let Some(new_len) = ibex_proto::remove_http_header(&mut vec, name) {
            vec.truncate(new_len);
            String::from_utf8(vec).unwrap_or_else(|_| raw_headers.to_string())
        } else {
            raw_headers.to_string()
        }
    }

    fn apply_set_status(raw_headers: &str, status: u16) -> String {
        if let Some((first_line, rest)) = raw_headers.split_once("\r\n") {
            let reason = ibex_proto::status_reason_phrase(status);
            let version = first_line.split_whitespace().next().unwrap_or("HTTP/1.1");
            format!("{version} {status} {reason}\r\n{rest}")
        } else {
            raw_headers.to_string()
        }
    }

    fn process_srv_io(&mut self) -> io::Result<bool> {
        let mut changed = false;

        if self.srv_state.can_write() && !self.req.is_empty() {
            let r = {
                let sfd = self
                    .srv
                    .as_ref()
                    .map(AsFd::as_fd)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
                raw::send(sfd, self.req.readable())?
            };
            match r {
                Io::Done(n) if n > 0 => {
                    self.req.consume(n);
                    changed = true;
                }
                Io::Closed => {
                    self.srv_state = ScState::Closed;
                    self.ending.get_or_insert(Ending::ServerAbort);
                    changed = true;
                }
                Io::Done(_) | Io::WouldBlock | Io::Eof => {}
            }
        }

        if self.srv_state.can_read() && !self.rep.is_full() {
            let r = {
                let sfd = self
                    .srv
                    .as_ref()
                    .map(AsFd::as_fd)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
                let dst = self.rep.writable();
                raw::recv(sfd, dst)?
            };
            match r {
                Io::Eof => {
                    if let Some(sfd) = self.srv.as_ref().map(AsFd::as_fd) {
                        raw::shutdown_read(sfd);
                    }
                    self.srv_state = match self.srv_state {
                        ScState::Ready | ScState::Established => ScState::ShutR,
                        ScState::ShutW => ScState::Closed,
                        other => other,
                    };
                    changed = true;
                }
                Io::Closed => {
                    self.srv_state = ScState::Closed;
                    self.ending.get_or_insert(Ending::ServerAbort);
                    changed = true;
                }
                Io::Done(n) if n > 0 => {
                    self.rep.commit(n);
                    changed = true;
                }
                Io::Done(_) | Io::WouldBlock => {}
            }
        }

        Ok(changed)
    }

    fn process_srv_transitions(&mut self) -> bool {
        let mut changed = false;

        match self.srv_state {
            ScState::Ready | ScState::Established => {
                let cli_done_sending = matches!(
                    self.cli_state,
                    ScState::ShutR | ScState::Closed | ScState::Error
                );
                if cli_done_sending && self.req.is_empty() {
                    if let Some(sfd) = self.srv.as_ref().map(AsFd::as_fd) {
                        raw::shutdown_write(sfd);
                    }
                    self.srv_state = ScState::ShutW;
                    changed = true;
                } else {
                    let cli_done_receiving = matches!(
                        self.cli_state,
                        ScState::ShutW | ScState::Closed | ScState::Error
                    );
                    if cli_done_receiving {
                        if let Some(sfd) = self.srv.as_ref().map(AsFd::as_fd) {
                            raw::shutdown_read(sfd);
                        }
                        self.srv_state = ScState::ShutR;
                        changed = true;
                    }
                }
            }
            ScState::ShutR => {
                let cli_done_sending = matches!(
                    self.cli_state,
                    ScState::ShutR | ScState::Closed | ScState::Error
                );
                if cli_done_sending && self.req.is_empty() {
                    if let Some(sfd) = self.srv.as_ref().map(AsFd::as_fd) {
                        raw::shutdown_write(sfd);
                    }
                    self.srv_state = ScState::Closed;
                    changed = true;
                }
            }
            ScState::ShutW => {
                let cli_done_receiving = matches!(
                    self.cli_state,
                    ScState::ShutW | ScState::Closed | ScState::Error
                );
                if cli_done_receiving {
                    self.srv_state = ScState::Closed;
                    changed = true;
                }
            }
            _ => {}
        }

        changed
    }

    /// Runs both sides until neither changes state.
    ///
    /// Mirrors 1.0's `process_task()`. The iteration bound is not decoration: each pass
    /// is driven by data the peer controls, so an unbounded loop here is a
    /// denial-of-service primitive. On exhaustion we return normally and the scheduler
    /// re-queues us, which costs a little latency and cannot hang the thread.
    ///
    /// # Errors
    /// Propagates unexpected I/O failures.
    pub fn process(&mut self, now: Tick) -> io::Result<()> {
        for _ in 0..16 {
            let a = self.process_cli()?;
            let b = self.process_srv()?;
            if !a && !b {
                break;
            }
            if matches!(
                self.cli_state,
                ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW
            ) {
                self.arm_client(now);
            }
            if matches!(
                self.srv_state,
                ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW
            ) {
                self.arm_server(now);
            }
        }
        Ok(())
    }

    /// Applies whichever timeout has fired, if any.
    pub fn check_timeouts(&mut self, now: Tick) -> bool {
        if self.conn_exp.is_expired(now) && self.srv_state == ScState::Connecting {
            self.conn_exp = Tick::ETERNITY;
            self.srv_state = ScState::Error;
            self.ending.get_or_insert(Ending::Timeout(Which::Connect));
            return true;
        }
        if self.cli_exp.is_expired(now)
            && matches!(
                self.cli_state,
                ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW
            )
        {
            self.cli_state = ScState::Error;
            self.ending.get_or_insert(Ending::Timeout(Which::Client));
            return true;
        }
        if self.srv_exp.is_expired(now)
            && matches!(
                self.srv_state,
                ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW
            )
        {
            self.srv_state = ScState::Error;
            self.ending.get_or_insert(Ending::Timeout(Which::Server));
            return true;
        }
        false
    }

    /// The earliest deadline across both sides, for the scheduler's wait queue.
    #[must_use]
    pub fn next_expiry(&self) -> Tick {
        self.cli_exp.earliest(self.srv_exp).earliest(self.conn_exp)
    }

    /// What each side needs from the poller.
    ///
    /// Derived from buffer occupancy, which is what makes backpressure work: a full
    /// request buffer stops us asking for client readability, the client's socket
    /// buffer fills, and TCP slows the sender.
    #[must_use]
    pub fn interests(&self) -> (Want, Want) {
        let has_pending = self
            .pending_resp
            .as_ref()
            .is_some_and(|(d, o)| *o < d.len());
        let cli = Want {
            read: self.cli_state.can_read() && !self.req.is_full(),
            write: self.cli_state.can_write() && (!self.rep.is_empty() || has_pending),
        };
        let srv = match self.srv_state {
            ScState::Connecting => Want {
                read: false,
                write: true,
            },
            ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW => Want {
                read: self.srv_state.can_read() && !self.rep.is_full(),
                write: self.srv_state.can_write() && !self.req.is_empty(),
            },
            _ => Want::default(),
        };
        (cli, srv)
    }
}

#[must_use]
pub fn find_eoh(buf: &[u8]) -> Option<(usize, usize)> {
    for i in 0..buf.len() {
        if i + 4 <= buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some((i, 4));
        }
        if i + 2 <= buf.len() && &buf[i..i + 2] == b"\n\n" {
            return Some((i, 2));
        }
        if i + 2 <= buf.len() && &buf[i..i + 2] == b"\r\r" {
            return Some((i, 2));
        }
    }
    None
}

#[must_use]
pub fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

#[must_use]
pub fn format_log_fmt(fmt: &str, client_addr: Option<SocketAddr>, elapsed_ms: u64) -> String {
    let mut out = String::with_capacity(fmt.len() + 16);
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            if let Some(&next) = chars.peek() {
                match next {
                    'c' => {
                        chars.next();
                        if let Some(&sub) = chars.peek() {
                            if sub == 'i' {
                                chars.next();
                                if let Some(sa) = client_addr {
                                    out.push_str(&sa.ip().to_string());
                                }
                            } else if sub == 'p' {
                                chars.next();
                                if let Some(sa) = client_addr {
                                    out.push_str(&sa.port().to_string());
                                }
                            } else {
                                out.push('%');
                                out.push('c');
                            }
                        } else {
                            out.push('%');
                            out.push('c');
                        }
                    }
                    'T' => {
                        chars.next();
                        if let Some(&sub) = chars.peek() {
                            if sub == 'r' {
                                chars.next();
                                out.push_str(&elapsed_ms.to_string());
                            } else {
                                out.push('%');
                                out.push('T');
                            }
                        } else {
                            out.push('%');
                            out.push('T');
                        }
                    }
                    '%' => {
                        chars.next();
                        out.push('%');
                    }
                    other => {
                        out.push('%');
                        chars.next();
                        out.push(other);
                    }
                }
            } else {
                out.push('%');
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn modify_http_headers<F>(hdr_str: &str, mut transform: F) -> String
where
    F: FnMut(&str, &mut Vec<(String, String)>),
{
    let use_crlf = hdr_str.contains("\r\n");
    let line_sep = if use_crlf { "\r\n" } else { "\n" };

    let (first_line, rest) = match hdr_str.split_once(line_sep) {
        Some((fl, r)) => (fl, r),
        None => (hdr_str, ""),
    };

    let mut headers = Vec::new();
    for line in rest.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    transform(first_line, &mut headers);

    let mut out = String::with_capacity(hdr_str.len() + 64);
    out.push_str(first_line);
    out.push_str("\r\n");
    for (k, v) in headers {
        out.push_str(&k);
        out.push_str(": ");
        out.push_str(&v);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

#[must_use]
pub fn apply_set_header(hdr_str: &str, name: &str, val: &str) -> String {
    modify_http_headers(hdr_str, |_first_line, headers| {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        headers.push((name.to_string(), val.to_string()));
    })
}

#[must_use]
pub fn apply_add_header(hdr_str: &str, name: &str, val: &str) -> String {
    modify_http_headers(hdr_str, |_first_line, headers| {
        headers.push((name.to_string(), val.to_string()));
    })
}

#[must_use]
pub fn apply_del_header(hdr_str: &str, name: &str) -> String {
    modify_http_headers(hdr_str, |_first_line, headers| {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    })
}

#[must_use]
pub fn update_http_response_status(raw: &str, status: u16) -> String {
    let Some((first_line, rest)) = raw.split_once("\r\n") else {
        return raw.to_string();
    };
    let version = first_line.split_whitespace().next().unwrap_or("HTTP/1.1");
    let reason = status_reason(status);
    let new_first_line = format!("{version} {status} {reason}");
    format!("{new_first_line}\r\n{rest}")
}

#[must_use]
pub fn eval_acl_term<S: ::std::hash::BuildHasher>(
    term: &ibex_config::AclTerm,
    acls: &HashMap<String, Expr, S>,
    registry: &Registry,
    ctx: &SampleContext,
) -> bool {
    let res = if let Some(expr) = acls.get(&term.name) {
        expr.eval(registry, ctx)
    } else if let Ok(expr) = Expr::parse(&term.name) {
        expr.eval(registry, ctx)
    } else {
        false
    };
    if term.negated {
        !res
    } else {
        res
    }
}

#[must_use]
pub fn eval_acl_condition<S: ::std::hash::BuildHasher>(
    cond: &ibex_config::AclCondition,
    acls: &HashMap<String, Expr, S>,
    registry: &Registry,
    ctx: &SampleContext,
) -> bool {
    let mut term_match = true;
    for term in &cond.terms {
        if !eval_acl_term(term, acls, registry, ctx) {
            term_match = false;
            break;
        }
    }
    if cond.is_if {
        term_match
    } else {
        !term_match
    }
}
