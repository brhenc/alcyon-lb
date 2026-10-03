// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::OnceLock;

static NOTIFY_ENV: OnceLock<Option<String>> = OnceLock::new();
static NOTIFY_ADDR: OnceLock<Option<SocketAddr>> = OnceLock::new();

/// Reads `NOTIFY_SOCKET` once and removes it from the environment, as `HAProxy` does
/// (`src/systemd.c:59`), so that unrelated children do not inherit it. The value is kept:
/// a reload hands it to the process that replaces this one, which becomes systemd's main
/// PID and must be able to notify in turn.
fn notify_env() -> Option<String> {
    NOTIFY_ENV
        .get_or_init(|| {
            let v = std::env::var("NOTIFY_SOCKET").ok();
            std::env::remove_var("NOTIFY_SOCKET");
            v
        })
        .clone()
}

/// Captures `NOTIFY_SOCKET` now, before anything spawns a child that would inherit it.
pub fn init() {
    let _ = notify_env();
}

/// The `NOTIFY_SOCKET` this process was started with, for the process a reload starts.
#[must_use]
pub fn notify_socket_env() -> Option<String> {
    notify_env()
}

fn get_notify_addr() -> Option<SocketAddr> {
    NOTIFY_ADDR
        .get_or_init(|| {
            let sock_str = notify_env()?;
            if let Some(name) = sock_str.strip_prefix('@') {
                SocketAddr::from_abstract_name(name.as_bytes()).ok()
            } else if sock_str.starts_with('/') {
                SocketAddr::from_pathname(&sock_str).ok()
            } else {
                None
            }
        })
        .clone()
}

/// Sends one `sd_notify` message; a no-op when not started by systemd.
///
/// # Errors
/// Propagates a failure to create the datagram socket or to send.
pub fn notify(message: &str) -> std::io::Result<()> {
    if let Some(addr) = get_notify_addr() {
        let sock = UnixDatagram::unbound()?;
        sock.send_to_addr(message.as_bytes(), &addr)?;
    }
    Ok(())
}

/// `READY=1` with this process as `MAINPID`.
///
/// # Errors
/// As [`notify`].
pub fn notify_ready() -> std::io::Result<()> {
    let pid = std::process::id();
    notify(&format!("READY=1\nMAINPID={pid}\nSTATUS=Ready.\n"))
}

/// `STOPPING=1`.
///
/// # Errors
/// As [`notify`].
pub fn notify_stopping() -> std::io::Result<()> {
    notify("STOPPING=1")
}

/// `READY=1` with a status saying the reload failed, as `HAProxy` sends
/// (`src/mworker.c:554`): the service is still up, on its previous configuration.
///
/// # Errors
/// As [`notify`].
pub fn notify_reload_failed() -> std::io::Result<()> {
    notify("READY=1\nSTATUS=Reload failed!\n")
}

static HANDING_OVER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Marks that this process is stopping *because* it is handing over to a new one. The soft
/// stop that follows must not send `STOPPING=1`: this process is still systemd's main PID
/// when it begins to drain, and systemd would take `STOPPING=1` from it as the whole service
/// going down, in the middle of a reload.
pub fn set_handing_over(on: bool) {
    HANDING_OVER.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Sends `STOPPING=1` once per process, however many workers begin a soft stop, unless the
/// stop is a reload handing over to a successor.
pub fn notify_stopping_once() {
    static SENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if HANDING_OVER.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    if !SENT.swap(true, std::sync::atomic::Ordering::Relaxed) {
        let _ = notify_stopping();
    }
}

/// `RELOADING=1`, with the `MONOTONIC_USEC` systemd 253 and later require alongside it, as
/// `HAProxy`'s master sends when a reload starts (`src/mworker.c:494`).
pub fn notify_reloading() {
    let ts = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let usec = u64::try_from(ts.tv_sec).unwrap_or(0) * 1_000_000
        + u64::try_from(ts.tv_nsec).unwrap_or(0) / 1_000;
    let _ = notify(&format!(
        "RELOADING=1\nSTATUS=Reloading Configuration.\nMONOTONIC_USEC={usec}\n"
    ));
}

/// Hands systemd's main PID to the process that has taken over from this one.
///
/// Sent by the *old* process, which is still the main PID when it sends this, so it is
/// accepted under the default `NotifyAccess=main`. The new process cannot say it itself
/// without the unit loosening that to `NotifyAccess=all`. It must arrive before this
/// process exits: a main PID that exits with no successor named is a failed service.
pub fn notify_handover(new_pid: u32) {
    let _ = notify(&format!("MAINPID={new_pid}\nREADY=1\nSTATUS=Ready.\n"));
}
