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
    /// Shared with this worker's idle-connection slot ([`Poller::shared_epfd`]).
    epfd: std::sync::Arc<OwnedFd>,
    event_buf: epoll::EventVec,
    /// The `epoll_ctl` calls made through this poller: what the idle-pool tests count (T434).
    #[cfg(test)]
    ctls: std::cell::Cell<u64>,
    /// The `epoll_wait` calls (tests only).
    #[cfg(test)]
    waits: std::cell::Cell<u64>,
}

impl Poller {
    /// # Errors
    /// Propagates `epoll_create1` failure.
    pub fn new(capacity: usize) -> io::Result<Self> {
        let epfd = epoll::create(epoll::CreateFlags::CLOEXEC)?;
        Ok(Poller {
            epfd: std::sync::Arc::new(epfd),
            event_buf: epoll::EventVec::with_capacity(capacity),
            #[cfg(test)]
            ctls: std::cell::Cell::new(0),
            #[cfg(test)]
            waits: std::cell::Cell::new(0),
        })
    }

    /// Counts one `epoll_ctl` (tests only).
    #[inline]
    fn ctl(&self) {
        #[cfg(test)]
        self.ctls.set(self.ctls.get() + 1);
    }

    /// The `epoll_ctl` calls made so far.
    #[cfg(test)]
    pub(crate) fn ctl_calls(&self) -> u64 {
        self.ctls.get()
    }

    /// The `epoll_wait` calls made so far.
    #[cfg(test)]
    pub(crate) fn wait_calls(&self) -> u64 {
        self.waits.get()
    }

    /// Whether `fd` is in this epoll set (`EPOLL_CTL_ADD` answers `EEXIST`); one that was
    /// not is taken out again.
    #[cfg(test)]
    pub(crate) fn is_registered(&self, fd: BorrowedFd<'_>) -> bool {
        match epoll::add(self.epfd.as_fd(), fd, epoll::EventData::new_u64(0), epoll::EventFlags::empty()) {
            Err(Errno::EXIST) => true,
            Ok(()) => {
                let _ = epoll::delete(self.epfd.as_fd(), fd);
                false
            }
            Err(e) => panic!("epoll_ctl: {e}"),
        }
    }

    fn flags(readable: bool, writable: bool) -> epoll::EventFlags {
        let mut f = epoll::EventFlags::empty();
        // RDHUP distinguishes "peer closed its write side" from a plain readable
        // event, which is what makes half-close detectable without a read syscall.
        // It is asked for with IN only, as `HAProxy` does (`_do_poll`): the peer's FIN
        // stays pending, so on a descriptor we no longer read (a client that left while
        // its request is at the server) a level-triggered RDHUP wakes the thread on
        // every wait, and every worker spins (T226).
        if readable {
            f |= epoll::EventFlags::IN | epoll::EventFlags::RDHUP;
        }
        if writable {
            f |= epoll::EventFlags::OUT;
        }
        f | epoll::EventFlags::ERR | epoll::EventFlags::HUP
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
        self.ctl();
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
    ///
    /// A descriptor that waits for nothing leaves the epoll set, and one that waits for
    /// something again rejoins it, as `HAProxy`'s poller does (`_update_fd`: no active
    /// event is `EPOLL_CTL_DEL`). Kept in the set with an empty mask it is still reported
    /// for `EPOLLHUP` and `EPOLLERR`, which epoll always delivers: a client reset while
    /// nothing is read or written on its socket woke the thread on every wait, a core
    /// spinning until the session ended (T269).
    pub fn modify(
        &self,
        fd: BorrowedFd<'_>,
        data: u64,
        readable: bool,
        writable: bool,
    ) -> io::Result<()> {
        self.ctl();
        if !readable && !writable {
            return match epoll::delete(self.epfd.as_fd(), fd) {
                Ok(()) | Err(Errno::NOENT) => Ok(()),
                Err(e) => Err(e.into()),
            };
        }
        let flags = Self::flags(readable, writable);
        match epoll::modify(self.epfd.as_fd(), fd, epoll::EventData::new_u64(data), flags) {
            Ok(()) => Ok(()),
            Err(Errno::NOENT) => {
                self.ctl();
                epoll::add(self.epfd.as_fd(), fd, epoll::EventData::new_u64(data), flags)?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Unregisters a descriptor.
    ///
    /// # Errors
    /// Propagates `epoll_ctl` failure.
    /// One that waits for nothing is out of the set already ([`Self::modify`]).
    pub fn delete(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        self.ctl();
        match epoll::delete(self.epfd.as_fd(), fd) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// This poller's epoll descriptor, shared: what another worker that takes one of this
    /// worker's idle server connections removes it from ([`Poller::forget_in`]).
    #[must_use]
    pub fn shared_epfd(&self) -> std::sync::Arc<OwnedFd> {
        std::sync::Arc::clone(&self.epfd)
    }

    /// Takes `fd` out of the epoll set `epfd` (another worker's, from
    /// [`Poller::shared_epfd`]): `epoll_ctl` is safe from any thread. Not in it is fine.
    ///
    /// # Errors
    /// Propagates `epoll_ctl` failure other than `ENOENT`.
    pub fn forget_in(epfd: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> io::Result<()> {
        match epoll::delete(epfd, fd) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(e) => Err(e.into()),
        }
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

        #[cfg(test)]
        self.waits.set(self.waits.get() + 1);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    /// `epoll_ctl` refuses a descriptor that cannot be polled (a regular file, `/dev/null`)
    /// with `EPERM`; that error, unlike `ENOENT`, reaches the caller from every operation.
    #[test]
    fn epoll_errors_other_than_enoent_are_returned() {
        let poller = Poller::new(4).unwrap();
        let file = File::open("/dev/null").unwrap();
        let fd = file.as_fd();
        assert_eq!(poller.modify(fd, 1, true, false).unwrap_err().raw_os_error(), Some(Errno::PERM.raw_os_error()));
        assert_eq!(poller.modify(fd, 1, false, false).unwrap_err().raw_os_error(), Some(Errno::PERM.raw_os_error()));
        assert_eq!(poller.delete(fd).unwrap_err().raw_os_error(), Some(Errno::PERM.raw_os_error()));
    }

    /// A descriptor that is not registered: waiting for nothing and deleting are no-ops,
    /// and waiting for something again adds it.
    #[test]
    fn modify_and_delete_tolerate_a_descriptor_that_is_not_registered() {
        let poller = Poller::new(4).unwrap();
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        poller.modify(a.as_fd(), 1, false, false).unwrap();
        poller.delete(a.as_fd()).unwrap();
        poller.modify(a.as_fd(), 1, true, false).unwrap();
        poller.modify(a.as_fd(), 1, false, false).unwrap();
        poller.delete(a.as_fd()).unwrap();
    }
}
