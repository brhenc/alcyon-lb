// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The messages `HAProxy` writes when a server changes state (`_srv_update_status_op` and
//! `_srv_update_status_adm` of src/server.c, `set_backend_down` of src/backend.c).
//!
//! They are written whatever `option log-health-checks` says: on stderr (`ha_warning`, or
//! `ha_alert` for a backend with no server left) and to the proxy's `log` targets (`send_log`).
//! `track::set_raw` is the one place a server's published state changes, so it calls
//! [`note`]; the engine writes what was noted once per scheduler pass ([`drain`]), because the
//! log targets belong to it and a CLI or stats-page handler cannot reach them.

use std::cell::RefCell;
use std::sync::atomic::Ordering;

use crate::check::{ServerCheckState, ServerStatus, DRAIN_DOWN};
use crate::engine::Proxy;
use ibex_config::LogLevel;

/// Why the state moved.
#[derive(Clone, Copy)]
pub enum Cause<'a> {
    /// A check's verdict.
    Check(&'a ServerCheckState),
    /// `enable`/`disable server`, `set server ... state`, `set server ... health`.
    Cli,
    /// The stats page: `ready`, `drain`, `maint`, `hrunn`, `hdown`.
    Web,
    /// The server-state file read at start (`changed from server-state after a reload`).
    StateFile,
    /// The stats page's `disable` (`'disable' on stats page`).
    WebDisable,
    /// The stats page's `stop` (`'stop' on stats page`).
    WebStop,
}

/// What `_srv_update_status_op` or `_srv_update_status_adm` looks at.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The operational state: a check, `set server health`.
    Op,
    /// The administrative state: `disable`, `set server state`, the stats page.
    Admin,
}

/// One line to write.
pub struct Event {
    /// Index of the proxy whose `log` targets get it.
    pub proxy: usize,
    /// Level of the log line.
    pub level: LogLevel,
    /// `ha_alert` (`[ALERT]`) rather than `ha_warning` (`[WARNING]`).
    pub alert: bool,
    /// The text of stderr line, without the final dot.
    pub stderr: String,
    /// The text of the log line, without the final dot.
    pub log: String,
}

thread_local! {
    static PENDING: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Adm {
    Ready,
    Drain,
    Maint,
}

fn adm_of(raw: u8) -> Adm {
    if raw == ServerStatus::Maint as u8 {
        Adm::Maint
    } else if raw == ServerStatus::Drain as u8 || raw == DRAIN_DOWN {
        Adm::Drain
    } else {
        Adm::Ready
    }
}

fn down_of(raw: u8) -> bool {
    raw == ServerStatus::Down as u8 || raw == DRAIN_DOWN
}

/// `srv_append_more`: the servers left (or online) and the sessions on this one.
fn more(px: &Proxy, s: usize, going_down: bool, out: &mut String) {
    use std::fmt::Write as _;
    let (mut act, mut bck) = (0, 0);
    for (i, st) in px.server_statuses.iter().enumerate() {
        if st.load(Ordering::Relaxed) != ServerStatus::Up as u8 {
            continue;
        }
        if px.server_backups.get(i).copied().unwrap_or(false) {
            bck += 1;
        } else {
            act += 1;
        }
    }
    let on_backup = if bck > 0 && act == 0 { " Running on backup." } else { "" };
    if going_down {
        let scur = px.server_actconn.get(s).map_or(0, |a| a.load(Ordering::Relaxed));
        let _ = write!(
            out,
            ". {act} active and {bck} backup servers left.{on_backup} {scur} sessions active, 0 requeued, 0 remaining in queue"
        );
    } else {
        let _ = write!(out, ". {act} active and {bck} backup servers online.{on_backup} 0 sessions requeued, 0 total in queue");
    }
}

/// The message for server `s` of `px` going from the published state `before` to `after`,
/// or `None` when `HAProxy` says nothing about it. The level is `Alert` for a server that was
/// serving and goes down, `Notice` otherwise.
#[must_use]
pub fn describe(px: &Proxy, s: usize, before: u8, after: u8, kind: Kind, cause: Cause<'_>) -> Option<(LogLevel, String)> {
    use std::fmt::Write as _;
    let name = px.server_ids.get(s)?;
    let backup = if px.server_backups.get(s).copied().unwrap_or(false) { "Backup " } else { "" };
    let head = format!("{backup}Server {}/{name}", px.name);
    let (b, a) = (adm_of(before), adm_of(after));
    let was_stopping = b == Adm::Drain;
    let leaving = |down: bool| if down { "DOWN" } else { "UP" };
    let mut out = head;
    match kind {
        Kind::Op => {
            if a == Adm::Maint || b == Adm::Maint || down_of(before) == down_of(after) {
                return None;
            }
            let down = down_of(after);
            let _ = write!(out, " is {}", leaving(down));
            match cause {
                Cause::Check(c) => c.append_info(&mut out),
                Cause::Cli => out.push_str(", changed from CLI"),
                Cause::StateFile => out.push_str(", changed from server-state after a reload"),
                Cause::Web | Cause::WebDisable | Cause::WebStop => out.push_str(", changed from Web interface"),
            }
            more(px, s, down, &mut out);
            Some((if down && !was_stopping { LogLevel::Alert } else { LogLevel::Notice }, out))
        }
        Kind::Admin => {
            let adm_cause = match cause {
                Cause::WebDisable => " ('disable' on stats page)",
                Cause::WebStop => " ('stop' on stats page)",
                _ => "",
            };
            let drain = if a == Adm::Drain { "DRAIN" } else { "READY" };
            match (b, a) {
                (x, Adm::Maint) if x != Adm::Maint => {
                    if down_of(before) {
                        let _ = write!(out, " was DOWN and now enters maintenance{adm_cause}");
                        Some((LogLevel::Notice, out))
                    } else {
                        let _ = write!(out, " is going DOWN for maintenance{adm_cause}");
                        more(px, s, true, &mut out);
                        Some((if was_stopping { LogLevel::Notice } else { LogLevel::Alert }, out))
                    }
                }
                (Adm::Maint, x) if x != Adm::Maint => {
                    let _ = write!(out, " is {}/{drain} (leaving forced maintenance)", leaving(down_of(after)));
                    Some((LogLevel::Notice, out))
                }
                (Adm::Ready, Adm::Drain) => {
                    let _ = write!(out, " enters drain state{adm_cause}");
                    more(px, s, false, &mut out);
                    Some((LogLevel::Notice, out))
                }
                (Adm::Drain, Adm::Ready) => {
                    let _ = write!(out, " is {} (leaving forced drain)", leaving(down_of(after)));
                    Some((LogLevel::Notice, out))
                }
                _ => None,
            }
        }
    }
}

/// Server `s` of proxy `p` went from `before` to `after`, and the backend went from having a
/// server to having none if `be_went_down`: queue the lines `HAProxy` writes for it.
pub fn note(proxies: &[Proxy], p: usize, s: usize, before: u8, after: u8, kind: Kind, cause: Cause<'_>, be_went_down: bool) {
    let Some(px) = proxies.get(p) else { return };
    if let Some((level, text)) = describe(px, s, before, after, kind, cause) {
        PENDING.with(|q| q.borrow_mut().push(Event { proxy: p, level, alert: false, stderr: text.clone(), log: format!("{text}.") }));
    }
    if be_went_down {
        let what = if px.has_frontend && px.has_backend { "proxy" } else { "backend" };
        PENDING.with(|q| {
            q.borrow_mut().push(Event {
                proxy: p,
                level: LogLevel::Emerg,
                alert: true,
                stderr: format!("{what} '{}' has no server available!", px.name),
                log: format!("{what} {} has no server available!", px.name),
            });
        });
    }
}

/// Writes the lines noted since the last call, through `send` (the log targets of the proxy).
/// Every line goes to stderr too.
pub fn drain(mut send: impl FnMut(usize, LogLevel, &str)) {
    let events = PENDING.with(|q| {
        let mut q = q.borrow_mut();
        if q.is_empty() {
            return Vec::new();
        }
        std::mem::take(&mut *q)
    });
    for e in events {
        stderr(e.alert, &e.stderr);
        send(e.proxy, e.level, &e.log);
    }
}

/// `ha_warning`/`ha_alert` format: `[WARNING]  (pid) : text.`.
pub fn stderr(alert: bool, text: &str) {
    let tag = if alert { "[ALERT]   " } else { "[WARNING] " };
    crate::stderr_line!("{tag} ({}) : {text}{}", std::process::id(), if alert { "" } else { "." });
}
