// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// `cast_possible_truncation` is allowed because counts are bounded by `BATCH_MAX` (64), `AF_INET` fits in `sa_family_t`, and `size_of_val` returns small constants.
#![allow(clippy::cast_possible_truncation)]
#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, IpAddr};

pub struct RecvMsg<'a> {
    pub buf: &'a mut [u8],
    pub cmsg_buf: &'a mut [u8],
    /// Bytes actually present in `buf`. Never greater than `buf.len()`, so
    /// `&msg.buf[..msg.len]` is always in range.
    pub len: usize,
    /// The datagram's size on the wire, which `MSG_TRUNC` asks the kernel to report even
    /// when it did not fit. Equal to `len` unless `truncated` is set.
    pub wire_len: usize,
    pub src_addr: Option<SocketAddr>,
    pub dst_addr: Option<IpAddr>,
    pub truncated: bool,
}

impl<'a> RecvMsg<'a> {
    #[must_use]
    pub fn new(buf: &'a mut [u8], cmsg_buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            cmsg_buf,
            len: 0,
            wire_len: 0,
            src_addr: None,
            dst_addr: None,
            truncated: false,
        }
    }
}

pub struct SendMsg<'a> {
    pub buf: &'a [u8],
    pub dst_addr: Option<SocketAddr>,
    /// The source address the datagram leaves from, sent as an `IP_PKTINFO` (`ipi_spec_dst`) or
    /// `IPV6_PKTINFO` control message, as `HAProxy`'s `cmsg_set_saddr` (`quic_sock.c`). Set it
    /// only on a socket bound to the wildcard address (T552): a socket bound to one address
    /// needs none, and `None` sends no control message at all.
    pub src_addr: Option<IpAddr>,
}

impl<'a> SendMsg<'a> {
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            dst_addr: None,
            src_addr: None,
        }
    }
}

const BATCH_MAX: usize = 64;

/// One message's source-address control message: `CMSG_SPACE` of the larger of the two
/// payloads, in `u64`s so the buffer has `cmsghdr`'s alignment.
const SRC_CMSG_WORDS: usize = 6;
// SAFETY: `CMSG_SPACE` is arithmetic on its argument; it reads no memory.
const SRC_CMSG_SPACE_V6: usize = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as libc::c_uint) } as usize;
// SAFETY: as above.
const SRC_CMSG_SPACE_V4: usize = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as libc::c_uint) } as usize;
const _: () = assert!(SRC_CMSG_SPACE_V6 <= SRC_CMSG_WORDS * 8 && SRC_CMSG_SPACE_V4 <= SRC_CMSG_SPACE_V6);

/// Writes the control message that makes the kernel send from `src` into `space` (zeroed by
/// the caller), and points
/// `hdr` at it. The family follows the destination's, so an IPv4 source on an IPv6 socket
/// goes as its IPv4-mapped form and a mapped source on an IPv4 socket as plain IPv4.
fn set_src_cmsg(hdr: &mut libc::msghdr, space: &mut [u64; SRC_CMSG_WORDS], src: IpAddr, dst_v6: bool) {
    let src = match (src, dst_v6) {
        (IpAddr::V4(v4), true) => IpAddr::V6(v4.to_ipv6_mapped()),
        (IpAddr::V6(v6), false) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => return,
        },
        (src, _) => src,
    };
    hdr.msg_control = space.as_mut_ptr().cast::<libc::c_void>();
    // SAFETY: `space` is a zeroed, 8-byte aligned buffer of at least `CMSG_SPACE` of either
    // payload (the const assertion above), and `hdr.msg_control`/`msg_controllen` describe it,
    // so `CMSG_FIRSTHDR` returns its start and the header and payload written fit inside it.
    // The payload is written unaligned, as `CMSG_DATA` promises no alignment for it.
    unsafe {
        match src {
            IpAddr::V4(v4) => {
                hdr.msg_controllen = SRC_CMSG_SPACE_V4 as _;
                let cmsg = libc::CMSG_FIRSTHDR(hdr);
                (*cmsg).cmsg_level = libc::IPPROTO_IP;
                (*cmsg).cmsg_type = libc::IP_PKTINFO;
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as libc::c_uint) as _;
                let info = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr { s_addr: u32::to_be(u32::from(v4)) },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in_pktinfo>(), info);
            }
            IpAddr::V6(v6) => {
                hdr.msg_controllen = SRC_CMSG_SPACE_V6 as _;
                let cmsg = libc::CMSG_FIRSTHDR(hdr);
                (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as libc::c_uint) as _;
                let info = libc::in6_pktinfo { ipi6_addr: libc::in6_addr { s6_addr: v6.octets() }, ipi6_ifindex: 0 };
                std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in6_pktinfo>(), info);
            }
        }
    }
}

fn parse_sockaddr(storage: &libc::sockaddr_storage, len: usize) -> Option<SocketAddr> {
    if i32::from(storage.ss_family) == libc::AF_INET && len >= std::mem::size_of::<libc::sockaddr_in>() {
        // SAFETY: The cast is correctly aligned because `sockaddr_storage` carries `__ss_align`.
        let in_addr = unsafe { *std::ptr::addr_of!(*storage).cast::<libc::sockaddr_in>() };
        let ip = Ipv4Addr::from(u32::from_be(in_addr.sin_addr.s_addr));
        Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be(in_addr.sin_port)))
    } else if i32::from(storage.ss_family) == libc::AF_INET6 && len >= std::mem::size_of::<libc::sockaddr_in6>() {
        // SAFETY: The cast is correctly aligned because `sockaddr_storage` carries `__ss_align`.
        let in6_addr = unsafe { *std::ptr::addr_of!(*storage).cast::<libc::sockaddr_in6>() };
        let ip = Ipv6Addr::from(in6_addr.sin6_addr.s6_addr);
        Some(SocketAddr::new(IpAddr::V6(ip), u16::from_be(in6_addr.sin6_port)))
    } else {
        None
    }
}

/// The part of `buf` a control message can be written to: `cmsghdr` is read through a
/// pointer, which needs the alignment of the type, and a `&mut [u8]` has none.
#[doc(hidden)]
pub fn align_cmsg(buf: &mut [u8]) -> &mut [u8] {
    let skip = buf.as_ptr().align_offset(std::mem::align_of::<libc::cmsghdr>());
    if skip > buf.len() {
        return &mut [];
    }
    &mut buf[skip..]
}

fn extract_dst_addr(hdr: &libc::msghdr) -> Option<IpAddr> {
    if hdr.msg_control.is_null() || hdr.msg_controllen == 0 {
        return None;
    }
    // SAFETY: the kernel fills the cmsg buffer during recvmmsg, so CMSG_FIRSTHDR and CMSG_NXTHDR
    // traverse a well-formed list of control messages.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(hdr);
        while !cmsg.is_null() {
            // A message the kernel cut short (MSG_CTRUNC, a control buffer too small) has a
            // `cmsg_len` below the size of its data: reading the whole struct would read past it.
            let len = (*cmsg).cmsg_len as usize;
            if (*cmsg).cmsg_level == libc::IPPROTO_IP
                && (*cmsg).cmsg_type == libc::IP_PKTINFO
                && len >= libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize
            {
                let pktinfo = libc::CMSG_DATA(cmsg).cast::<libc::in_pktinfo>();
                let ip = Ipv4Addr::from(u32::from_be((*pktinfo).ipi_addr.s_addr));
                return Some(IpAddr::V4(ip));
            } else if (*cmsg).cmsg_level == libc::IPPROTO_IPV6
                && (*cmsg).cmsg_type == libc::IPV6_PKTINFO
                && len >= libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize
            {
                let pktinfo = libc::CMSG_DATA(cmsg).cast::<libc::in6_pktinfo>();
                let ip = Ipv6Addr::from((*pktinfo).ipi6_addr.s6_addr);
                return Some(IpAddr::V6(ip));
            }
            cmsg = libc::CMSG_NXTHDR(hdr, cmsg);
        }
    }
    None
}

/// Receives a batch of datagrams.
///
/// # Errors
///
/// Returns an error if the underlying `recvmmsg` syscall fails with an error other than `EAGAIN` or `EINTR`.
pub fn recvmmsg(fd: BorrowedFd<'_>, msgs: &mut [RecvMsg]) -> io::Result<usize> {
    if msgs.is_empty() {
        return Ok(0);
    }
    
    let count = msgs.len().min(BATCH_MAX);
    
    let mut mmsgs: [std::mem::MaybeUninit<libc::mmsghdr>; BATCH_MAX] =
        // SAFETY: std::mem::MaybeUninit array doesn't require initialization.
        unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    let mut iovecs: [std::mem::MaybeUninit<libc::iovec>; BATCH_MAX] =
        // SAFETY: std::mem::MaybeUninit array doesn't require initialization.
        unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    let mut addrs: [std::mem::MaybeUninit<libc::sockaddr_storage>; BATCH_MAX] =
        // SAFETY: std::mem::MaybeUninit array doesn't require initialization.
        unsafe { std::mem::MaybeUninit::uninit().assume_init() };

    for i in 0..count {
        // SAFETY: mem::zeroed() is sound for these types because an all-zero bit pattern is valid for every field.
        mmsgs[i].write(unsafe { std::mem::zeroed() });
        // SAFETY: mem::zeroed() is sound for these types because an all-zero bit pattern is valid for every field.
        iovecs[i].write(unsafe { std::mem::zeroed() });
        // SAFETY: mem::zeroed() is sound for these types because an all-zero bit pattern is valid for every field.
        addrs[i].write(unsafe { std::mem::zeroed() });

        let iov = unsafe { iovecs[i].assume_init_mut() };
        let msg = unsafe { mmsgs[i].assume_init_mut() };

        iov.iov_base = msgs[i].buf.as_mut_ptr().cast::<libc::c_void>();
        iov.iov_len = msgs[i].buf.len();

        msg.msg_hdr.msg_name = addrs[i].as_mut_ptr().cast::<libc::c_void>();
        #[allow(clippy::cast_possible_truncation)]
        {
            msg.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        }

        msg.msg_hdr.msg_iov = iov;
        msg.msg_hdr.msg_iovlen = 1;

        let cmsg_buf = align_cmsg(msgs[i].cmsg_buf);
        if !cmsg_buf.is_empty() {
            msg.msg_hdr.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
            msg.msg_hdr.msg_controllen = cmsg_buf.len() as libc::size_t;
        }
    }

    loop {
        // SAFETY: the `mmsghdr`/`iovec`/`sockaddr_storage`arrays are stack locals that outlive the syscall;
        // each `iov_base` points into a buffer the caller lent us for the duration of the call;
        // the kernel fills at most `count` entries, so the fill-back loop cannot run off.
        let ret = unsafe {
            libc::recvmmsg(
                fd.as_raw_fd(),
                mmsgs.as_mut_ptr().cast::<libc::mmsghdr>(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                std::ptr::null_mut(),
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == io::ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::EAGAIN) {
                return Ok(0);
            }
            return Err(err);
        }

        let ret = usize::try_from(ret).unwrap_or(0);
        for i in 0..ret {
            // SAFETY: Elements 0..ret were filled by the kernel and correctly initialized earlier.
            let mmsg = unsafe { mmsgs[i].assume_init_ref() };
            let addr = unsafe { addrs[i].assume_init_ref() };
            
            let wire = mmsg.msg_len as usize;
            msgs[i].wire_len = wire;
            msgs[i].len = wire.min(msgs[i].buf.len());
            msgs[i].truncated =
                wire > msgs[i].buf.len() || (mmsg.msg_hdr.msg_flags & libc::MSG_TRUNC) != 0;
            msgs[i].src_addr = parse_sockaddr(addr, mmsg.msg_hdr.msg_namelen as usize);
            msgs[i].dst_addr = extract_dst_addr(&mmsg.msg_hdr);
        }

        return Ok(ret);
    }
}

/// Sends a batch of datagrams.
///
/// # Errors
///
/// Returns an error if the underlying `sendmmsg` syscall fails with an error other than `EAGAIN` or `EINTR`.
pub fn sendmmsg(fd: BorrowedFd<'_>, msgs: &[SendMsg]) -> io::Result<usize> {
    if msgs.is_empty() {
        return Ok(0);
    }
    
    let count = msgs.len().min(BATCH_MAX);
    let mut mmsgs: [std::mem::MaybeUninit<libc::mmsghdr>; BATCH_MAX] =
        // SAFETY: std::mem::MaybeUninit array doesn't require initialization.
        unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    let mut iovecs: [std::mem::MaybeUninit<libc::iovec>; BATCH_MAX] =
        // SAFETY: std::mem::MaybeUninit array doesn't require initialization.
        unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    let mut addrs: [std::mem::MaybeUninit<libc::sockaddr_storage>; BATCH_MAX] =
        // SAFETY: std::mem::MaybeUninit array doesn't require initialization.
        unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    // Written only for a message with a `src_addr` (`set_src_cmsg`), so a socket bound to one
    // address pays nothing for it.
    let mut src_cmsgs: [std::mem::MaybeUninit<[u64; SRC_CMSG_WORDS]>; BATCH_MAX] =
        // SAFETY: std::mem::MaybeUninit array doesn't require initialization.
        unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    
    for i in 0..count {
        // SAFETY: mem::zeroed() is sound for these types because an all-zero bit pattern is valid for every field.
        mmsgs[i].write(unsafe { std::mem::zeroed() });
        // SAFETY: mem::zeroed() is sound for these types because an all-zero bit pattern is valid for every field.
        iovecs[i].write(unsafe { std::mem::zeroed() });
        // SAFETY: mem::zeroed() is sound for these types because an all-zero bit pattern is valid for every field.
        addrs[i].write(unsafe { std::mem::zeroed() });

        let iov = unsafe { iovecs[i].assume_init_mut() };
        let msg = unsafe { mmsgs[i].assume_init_mut() };

        iov.iov_base = msgs[i].buf.as_ptr() as *mut libc::c_void;
        iov.iov_len = msgs[i].buf.len();
        
        if let Some(addr) = msgs[i].dst_addr {
            match addr {
                SocketAddr::V4(v4) => {
                    let in_addr = libc::sockaddr_in {
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        sin_port: u16::to_be(v4.port()),
                        sin_addr: libc::in_addr { s_addr: u32::to_be(u32::from(*v4.ip())) },
                        sin_zero: [0; 8],
                    };
                    // SAFETY: `sockaddr_in` safely writes into the first 16 bytes of `sockaddr_storage`.
                    unsafe { std::ptr::write(addrs[i].as_mut_ptr().cast::<libc::sockaddr_in>(), in_addr) };
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        msg.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                    }
                }
                SocketAddr::V6(v6) => {
                    let in6_addr = libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: u16::to_be(v6.port()),
                        sin6_flowinfo: v6.flowinfo(),
                        sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                        sin6_scope_id: v6.scope_id(),
                    };
                    // SAFETY: `sockaddr_in6` safely writes into the first 28 bytes of `sockaddr_storage`.
                    unsafe { std::ptr::write(addrs[i].as_mut_ptr().cast::<libc::sockaddr_in6>(), in6_addr) };
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        msg.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
                    }
                }
            }
            msg.msg_hdr.msg_name = addrs[i].as_mut_ptr().cast::<libc::c_void>();
        } else {
            msg.msg_hdr.msg_name = std::ptr::null_mut();
            msg.msg_hdr.msg_namelen = 0;
        }
        
        msg.msg_hdr.msg_iov = iov;
        msg.msg_hdr.msg_iovlen = 1;
        
        msg.msg_hdr.msg_control = std::ptr::null_mut();
        msg.msg_hdr.msg_controllen = 0;
        if let Some(src) = msgs[i].src_addr {
            let dst_v6 = matches!(msgs[i].dst_addr, Some(SocketAddr::V6(_)));
            set_src_cmsg(&mut msg.msg_hdr, src_cmsgs[i].write([0; SRC_CMSG_WORDS]), src, dst_v6);
        }
    }

    loop {
        // SAFETY: the `mmsghdr`/`iovec`/`sockaddr_storage`/control-message arrays are stack locals that outlive the syscall;
        // each `iov_base` points into a buffer the caller lent us for the duration of the call;
        // the kernel fills at most `count` entries, so the fill-back loop cannot run off.
        let ret = unsafe {
            libc::sendmmsg(
                fd.as_raw_fd(),
                mmsgs.as_mut_ptr().cast::<libc::mmsghdr>(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == io::ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::EAGAIN) {
                return Ok(0);
            }
            return Err(err);
        }

        return Ok(usize::try_from(ret).unwrap_or(0));
    }
}

/// Sets or unsets the `IP_PKTINFO` socket option.
///
/// # Errors
///
/// Returns an error if the underlying `setsockopt` syscall fails.
pub fn set_ip_pktinfo(fd: BorrowedFd<'_>, value: bool) -> io::Result<()> {
    let val: libc::c_int = i32::from(value);
    // SAFETY: the pointer passed to setsockopt is valid for `size_of_val(&val)` bytes.
    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            std::ptr::addr_of!(val).cast::<libc::c_void>(),
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Sets or unsets the `IPV6_RECVPKTINFO` socket option.
///
/// # Errors
///
/// Returns an error if the underlying `setsockopt` syscall fails.
pub fn set_ipv6_recvpktinfo(fd: BorrowedFd<'_>, value: bool) -> io::Result<()> {
    let val: libc::c_int = i32::from(value);
    // SAFETY: the pointer passed to setsockopt is valid for `size_of_val(&val)` bytes.
    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            std::ptr::addr_of!(val).cast::<libc::c_void>(),
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsFd;

    #[test]
    fn test_recvmmsg_bounds() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        
        let server_addr = server.local_addr().unwrap();
        
        // send 3 datagrams
        client.send_to(b"msg1", server_addr).unwrap();
        client.send_to(b"msg2", server_addr).unwrap();
        client.send_to(b"msg3", server_addr).unwrap();
        
        let mut bufs = [[0u8; 10]; 10];
        let mut cmsgs = [[0u8; 128]; 10];
        
        let mut msgs: Vec<RecvMsg> = bufs.iter_mut().zip(cmsgs.iter_mut()).map(|(buf, cmsg_buf)| RecvMsg::new(buf, cmsg_buf)).collect();
        
        let fd = server.as_fd();
        let count = recvmmsg(fd, &mut msgs).unwrap();
        assert_eq!(count, 3);
        
        assert_eq!(&msgs[0].buf[..4], b"msg1");
        assert_eq!(msgs[0].len, 4);
        assert_eq!(&msgs[1].buf[..4], b"msg2");
        assert_eq!(msgs[1].len, 4);
        assert_eq!(&msgs[2].buf[..4], b"msg3");
        assert_eq!(msgs[2].len, 4);
        
        // Assert slots 3..10 are untouched
        for item in msgs.iter().take(10).skip(3) {
            assert_eq!(item.len, 0);
            assert_eq!(item.buf, &[0u8; 10]);
        }
    }
}
