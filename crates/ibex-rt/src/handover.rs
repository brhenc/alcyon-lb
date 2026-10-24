// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Listening-socket handover, which is what makes a reload *hitless* rather than merely
//! graceful.
//!
//! Every worker binds its own `SO_REUSEPORT` socket, and the kernel spreads incoming SYNs
//! across them. A connection the kernel has already completed and queued on the *old*
//! process's socket is reset when that socket closes, however gracefully the old process
//! stops. The only way to keep it is for the new process to take over the same socket, and
//! with it the queue. That is what `HAProxy`'s `expose-fd listeners` / `_getsocks` / `-x` do
//! (`src/cli.c:2750`, `src/sock.c:469`), and what this module does for Ibex.
//!
//! The operator-facing names are `HAProxy`'s. The wire format is not: the peer is always
//! another Ibex, so there is nothing to be compatible with, and `HAProxy`'s format carries
//! namespace and interface fields Ibex has no use for. Ours is one `sendmsg` per batch,
//! text describing each socket plus the sockets themselves as `SCM_RIGHTS`:
//!
//! ```text
//! IBEXFD <n>\n            then n lines, one per descriptor, in the order they are attached:
//! tcp <address>\n         a listening stream socket (a proxy's or a log-forward's `bind`)
//! udp <address>\n         a log-forward `dgram-bind`
//! ...
//! END\n                   after the last batch
//! ```
//!
//! `log-forward` sockets go over too, as `HAProxy`'s do (the same socket inodes before and
//! after a `reload`, measured on 3.5-dev8): without them a new worker could not bind the
//! old one's addresses, and no configuration with a `log-forward` could be reloaded (T252).
//!
//! QUIC listeners are not handed over. A QUIC connection lives on the listening UDP socket,
//! so two processes sharing one would each receive datagrams for the other's connections.

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, IoSlice, IoSliceMut, Write};
use std::net::SocketAddr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The kernel accepts at most 253 descriptors in one `SCM_RIGHTS` message.
const BATCH: usize = 200;

/// How long `_getsocks` waits, in all, for a client to take what it is sent.
const SEND_BUDGET: Duration = Duration::from_secs(1);

static EXPOSE_ENABLED: AtomicBool = AtomicBool::new(false);
static EXPOSED: Mutex<Vec<(Kind, SocketAddr, OwnedFd)>> = Mutex::new(Vec::new());
/// `_getsocks` has sent this process's listeners to another process, which may serve on
/// them now: they are shared, and a pause must not disconnect them ([`handed_over`]).
static HANDED_OVER: AtomicBool = AtomicBool::new(false);
/// The sockets handed to one worker, by kind and address.
type PerWorker = HashMap<(Kind, SocketAddr), Vec<OwnedFd>>;
static INHERITED: Mutex<Vec<PerWorker>> = Mutex::new(Vec::new());

/// What a handed-over socket is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A listening stream socket.
    Tcp,
    /// A datagram socket (`log-forward` `dgram-bind`).
    Udp,
}

impl Kind {
    fn word(self) -> &'static str {
        match self {
            Kind::Tcp => "tcp",
            Kind::Udp => "udp",
        }
    }
}

/// Turns on `expose-fd listeners`: listeners register themselves and `_getsocks` answers.
pub fn enable_expose() {
    EXPOSE_ENABLED.store(true, Ordering::Relaxed);
}

/// Whether `expose-fd listeners` is on.
#[must_use]
pub fn expose_enabled() -> bool {
    EXPOSE_ENABLED.load(Ordering::Relaxed)
}

/// Registers a listening socket so `_getsocks` can hand it over. Keeps a duplicate, so the
/// registry holds the socket open; [`withdraw_all`] must run on soft stop, or the socket
/// would outlive the listener and keep queueing connections nobody accepts.
///
/// # Errors
/// Propagates a failure to duplicate the descriptor.
pub fn expose(addr: SocketAddr, fd: BorrowedFd<'_>) -> io::Result<()> {
    expose_kind(Kind::Tcp, addr, fd)
}

/// [`expose`] for a socket of any [`Kind`].
///
/// # Errors
/// Propagates a failure to duplicate the descriptor.
pub fn expose_kind(kind: Kind, addr: SocketAddr, fd: BorrowedFd<'_>) -> io::Result<()> {
    if !expose_enabled() {
        return Ok(());
    }
    let dup = fd.try_clone_to_owned()?;
    EXPOSED.lock().map_err(|_| io::Error::other("poisoned"))?.push((kind, addr, dup));
    Ok(())
}

/// Drops every registered listener. Called when a soft stop closes the listeners.
pub fn withdraw_all() {
    if let Ok(mut g) = EXPOSED.lock() {
        g.clear();
    }
}

/// Answers `_getsocks` on a CLI stream: sends every registered listener.
///
/// # Errors
/// Refuses when `expose-fd listeners` is off; propagates send failures.
pub fn serve_getsocks(stream: &UnixStream) -> io::Result<usize> {
    if !expose_enabled() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "_getsocks requires 'expose-fd listeners' on the stats socket",
        ));
    }
    // Duplicates, so that the registry is not held while a client that does not read keeps
    // the send waiting: listeners registering or withdrawing would wait with it.
    let exposed: Vec<(Kind, SocketAddr, OwnedFd)> = {
        let reg = EXPOSED.lock().map_err(|_| io::Error::other("poisoned"))?;
        reg.iter().map(|(k, a, fd)| fd.try_clone().map(|fd| (*k, *a, fd))).collect::<io::Result<_>>()?
    };
    // The whole answer gets this long, not each message.
    let deadline = Instant::now() + SEND_BUDGET;
    for chunk in exposed.chunks(BATCH) {
        let mut text = format!("IBEXFD {}\n", chunk.len());
        for (kind, addr, _) in chunk {
            let _ = writeln!(text, "{} {addr}", kind.word());
        }
        let fds: Vec<BorrowedFd<'_>> = chunk.iter().map(|(_, _, fd)| fd.as_fd()).collect();
        let mut space = vec![0u8; rustix::cmsg_space!(ScmRights(BATCH))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err(io::Error::other("ancillary buffer too small"));
        }
        send_all_with(stream, text.as_bytes(), &mut control, deadline)?;
    }
    let mut end = stream;
    end.write_all(b"END\n")?;
    if !exposed.is_empty() {
        HANDED_OVER.store(true, Ordering::Relaxed);
    }
    Ok(exposed.len())
}

/// Whether `_getsocks` has handed this process's listeners to another process. A `SIGTTOU`
/// then only stops polling them, as `HAProxy`'s `tcp_suspend_receiver` never disconnects a
/// shared socket (`RX_F_INHERITED_SOCK`): disconnecting it would take it from the successor
/// too.
#[must_use]
pub fn handed_over() -> bool {
    HANDED_OVER.load(Ordering::Relaxed)
}

/// `sendmsg` the whole of `data`, with `control` attached to the first byte.
fn send_all_with(
    stream: &UnixStream,
    data: &[u8],
    control: &mut SendAncillaryBuffer<'_, '_, '_>,
    deadline: Instant,
) -> io::Result<()> {
    let n = retry_eagain(deadline, || {
        rustix::net::sendmsg(stream, &[IoSlice::new(data)], control, SendFlags::empty())
    })?;
    // The descriptors went with the first byte; any remainder is plain data.
    let mut rest = stream;
    rest.write_all(&data[n..])
}

fn retry_eagain<T>(deadline: Instant, mut f: impl FnMut() -> rustix::io::Result<T>) -> io::Result<T> {
    while Instant::now() < deadline {
        match f() {
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            other => return other.map_err(io::Error::from),
        }
    }
    Err(io::Error::new(io::ErrorKind::WouldBlock, "socket stayed busy"))
}

/// `-x <socket>`: fetches the old process's listeners over its stats socket.
///
/// # Errors
/// Propagates connection, protocol, and descriptor-count failures. The caller treats any
/// error as "bind fresh", which is a graceful reload rather than a hitless one.
pub fn fetch(sock: &Path) -> io::Result<Vec<(Kind, SocketAddr, OwnedFd)>> {
    let mut stream = UnixStream::connect(sock)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"_getsocks\n")?;

    let mut text = Vec::new();
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let mut space = vec![0u8; rustix::cmsg_space!(ScmRights(BATCH))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let got = rustix::net::recvmsg(
            &stream,
            &mut [IoSliceMut::new(&mut buf)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        )?;
        for msg in control.drain() {
            if let RecvAncillaryMessage::ScmRights(rights) = msg {
                fds.extend(rights);
            }
        }
        if got.bytes == 0 {
            break;
        }
        text.extend_from_slice(&buf[..got.bytes]);
        if text.ends_with(b"END\n") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&text);
    if !text.ends_with("END\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("old process did not complete _getsocks: {}", text.trim()),
        ));
    }
    let addrs: Vec<(Kind, SocketAddr)> = text
        .lines()
        .filter_map(|l| {
            l.strip_prefix("tcp ").map(|a| (Kind::Tcp, a)).or_else(|| l.strip_prefix("udp ").map(|a| (Kind::Udp, a)))
        })
        .map(|(k, a)| a.parse().map(|a| (k, a)))
        .collect::<Result<_, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad address: {e}")))?;
    if addrs.len() != fds.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} addresses but {} descriptors", addrs.len(), fds.len()),
        ));
    }
    Ok(addrs.into_iter().zip(fds).map(|((k, a), fd)| (k, a, fd)).collect())
}

/// Spreads fetched sockets over `nbthread` workers: the i-th socket for an address goes to
/// worker `i % nbthread`. The old process may have run a different number of threads, so
/// a worker can end up with several sockets for one address, or none; every socket is
/// adopted by someone, because closing one would reset its queue.
pub fn distribute(sockets: Vec<(Kind, SocketAddr, OwnedFd)>, nbthread: usize) {
    let nbthread = nbthread.max(1);
    let mut per_worker: Vec<PerWorker> = (0..nbthread).map(|_| HashMap::new()).collect();
    let mut seen: HashMap<(Kind, SocketAddr), usize> = HashMap::new();
    for (kind, addr, fd) in sockets {
        let i = seen.entry((kind, addr)).or_insert(0);
        per_worker[*i % nbthread].entry((kind, addr)).or_default().push(fd);
        *i += 1;
    }
    if let Ok(mut g) = INHERITED.lock() {
        *g = per_worker;
    }
}

/// The inherited sockets for `addr` that belong to `worker`, if any.
#[must_use]
pub fn take_inherited(worker: usize, addr: SocketAddr) -> Vec<OwnedFd> {
    INHERITED
        .lock()
        .ok()
        .and_then(|mut g| g.get_mut(worker).and_then(|m| m.remove(&(Kind::Tcp, addr))))
        .unwrap_or_default()
}

/// Every inherited socket of `kind` for `addr`, whichever worker it was given to: a
/// `log-forward` listener is served by its own thread, not by the workers.
#[must_use]
pub fn take_inherited_all(kind: Kind, addr: SocketAddr) -> Vec<OwnedFd> {
    // A poisoned lock gives nothing (a panic aborts the process, so it is not seen).
    INHERITED.lock().map(|mut g| g.iter_mut().filter_map(|m| m.remove(&(kind, addr))).flatten().collect()).unwrap_or_default()
}

/// Closes inherited sockets no listener claimed -- an address the new config no longer
/// binds. `HAProxy` does the same (`sock_drop_unused_old_sockets`, `src/haproxy.c:3738`).
/// Returns how many were dropped.
pub fn drop_unused_inherited() -> usize {
    INHERITED.lock().map_or(0, |mut g| {
        let n = g.iter().map(|m| m.values().map(Vec::len).sum::<usize>()).sum();
        g.clear();
        n
    })
}
