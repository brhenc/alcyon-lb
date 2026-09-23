// SPDX-License-Identifier: GPL-2.0-or-later

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd, AsFd};
use rustix::net::{AddressFamily, SocketType, SocketFlags, bind_any};

use crate::raw::to_any;

pub use ibex_mmsg::RecvMsg as DgramBuf;
pub use ibex_mmsg::SendMsg as DgramOut;

pub struct DgramSocket {
    fd: OwnedFd,
}

impl DgramSocket {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let family = match addr {
            SocketAddr::V4(_) => AddressFamily::INET,
            SocketAddr::V6(_) => AddressFamily::INET6,
        };
        let fd = rustix::net::socket_with(
            family,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        
        let any = to_any(addr);
        bind_any(&fd, &any)?;

        // Request IP_PKTINFO for IPV4 and IPV6
        match addr {
            SocketAddr::V4(_) => {
                let _ = ibex_mmsg::set_ip_pktinfo(fd.as_fd(), true);
            }
            SocketAddr::V6(_) => {
                let _ = ibex_mmsg::set_ipv6_recvpktinfo(fd.as_fd(), true);
            }
        }
        
        Ok(Self { fd })
    }

    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let addr = rustix::net::getsockname(self.fd.as_fd())?;
        crate::raw::from_any(&addr).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid address"))
    }

    pub fn recv_batch(&self, bufs: &mut [DgramBuf]) -> io::Result<usize> {
        if bufs.is_empty() {
            return Ok(0);
        }

        ibex_mmsg::recvmmsg(self.fd.as_fd(), bufs)
    }

    pub fn send_batch(&self, out: &[DgramOut]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        ibex_mmsg::sendmmsg(self.fd.as_fd(), out)
    }
}
