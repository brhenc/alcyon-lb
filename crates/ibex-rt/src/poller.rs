// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/ev_epoll.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! epoll, wrapped so the rest of the runtime never sees a raw syscall.

use rustix::event::epoll;
use rustix::io::Errno;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use std::time::Duration;

/// A readiness notification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub fd: RawFd,
    pub readable: bool,
    pub writable: bool,
    /// Peer hung up, or an error was reported on the descriptor. Either way the fd is
    /// finished and the owner must be woken to observe it.
    pub closed: bool,
}

/// One thread's epoll instance.
///
/// Level-triggered, matching `HAProxy`. Edge-triggered would mean every reader must drain
/// to `EAGAIN` or lose a wakeup — which conflicts directly with the bounded-work
/// discipline in `design/003-scheduler.md`, where a reader is *supposed* to stop early
/// and let other work run.
pub struct Poller {
    epfd: OwnedFd,
    event_buf: epoll::EventVec,
}

impl Poller {
    /// # Errors
    /// Propagates `epoll_create1` failure.
    pub fn new(capacity: usize) -> io::Result<Self> {
        let epfd = epoll::create(epoll::CreateFlags::CLOEXEC)?;
        Ok(Poller {
            epfd,
            event_buf: epoll::EventVec::with_capacity(capacity),
        })
    }

    fn flags(readable: bool, writable: bool) -> epoll::EventFlags {
        let mut f = epoll::EventFlags::empty();
        if readable {
            f |= epoll::EventFlags::IN;
        }
        if writable {
            f |= epoll::EventFlags::OUT;
        }
        // RDHUP distinguishes "peer closed its write side" from a plain readable
        // event, which is what makes half-close detectable without a read syscall.
        f | epoll::EventFlags::RDHUP | epoll::EventFlags::ERR | epoll::EventFlags::HUP
    }

    /// Registers a descriptor. `data` is echoed back on every event for this fd.
    ///
    /// # Errors
    /// Propagates `epoll_ctl` failure.
    pub fn add(
        &self,
        fd: BorrowedFd<'_>,
        data: u64,
        readable: bool,
        writable: bool,
    ) -> io::Result<()> {
        epoll::add(
            self.epfd.as_fd(),
            fd,
            epoll::EventData::new_u64(data),
            Self::flags(readable, writable),
        )?;
        Ok(())
    }

    /// Changes what a descriptor is waiting for.
    ///
    /// # Errors
    /// Propagates `epoll_ctl` failure.
    pub fn modify(
        &self,
        fd: BorrowedFd<'_>,
        data: u64,
        readable: bool,
        writable: bool,
    ) -> io::Result<()> {
        epoll::modify(
            self.epfd.as_fd(),
            fd,
            epoll::EventData::new_u64(data),
            Self::flags(readable, writable),
        )?;
        Ok(())
    }

    /// Unregisters a descriptor.
    ///
    /// # Errors
    /// Propagates `epoll_ctl` failure.
    pub fn delete(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        epoll::delete(self.epfd.as_fd(), fd)?;
        Ok(())
    }

    /// Waits for readiness, calling `f` once per ready descriptor.
    ///
    /// `timeout` of `None` blocks indefinitely; `Some(Duration::ZERO)` polls. The
    /// scheduler derives this from its wait queue, so a thread sleeps exactly until its
    /// next timer is due.
    ///
    /// # Errors
    /// Propagates `epoll_wait` failure. `EINTR` is reported as zero events rather than
    /// an error, since a signal is not a failure.
    pub fn poll<F: FnMut(Event)>(
        &mut self,
        timeout: Option<Duration>,
        mut f: F,
    ) -> io::Result<usize> {
        self.event_buf.clear();

        // rustix 0.38 takes a millisecond timeout, with -1 meaning "block".
        let ms: i32 = match timeout {
            None => -1,
            Some(d) => i32::try_from(d.as_millis()).unwrap_or(i32::MAX),
        };

        match epoll::wait(self.epfd.as_fd(), &mut self.event_buf, ms) {
            Ok(()) => {}
            Err(Errno::INTR) => return Ok(0),
            Err(e) => return Err(e.into()),
        }

        let mut n = 0;
        for ev in &self.event_buf {
            let fl = ev.flags;
            f(Event {
                fd: RawFd::try_from(ev.data.u64()).unwrap_or(-1),
                readable: fl.contains(epoll::EventFlags::IN),
                writable: fl.contains(epoll::EventFlags::OUT),
                closed: fl.intersects(
                    epoll::EventFlags::HUP | epoll::EventFlags::ERR | epoll::EventFlags::RDHUP,
                ),
            });
            n += 1;
        }
        Ok(n)
    }
}
