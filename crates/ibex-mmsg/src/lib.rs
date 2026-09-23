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

pub struct SendMsg<'a> {
    pub buf: &'a [u8],
    pub dst_addr: Option<SocketAddr>,
    pub src_addr: Option<IpAddr>,
}

const BATCH_MAX: usize = 64;

fn parse_sockaddr(storage: &libc::sockaddr_storage, len: usize) -> Option<SocketAddr> {
    if storage.ss_family as i32 == libc::AF_INET && len >= std::mem::size_of::<libc::sockaddr_in>() {
        let in_addr = unsafe { *(storage as *const _ as *const libc::sockaddr_in) };
        let ip = Ipv4Addr::from(u32::from_be(in_addr.sin_addr.s_addr));
        Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be(in_addr.sin_port)))
    } else if storage.ss_family as i32 == libc::AF_INET6 && len >= std::mem::size_of::<libc::sockaddr_in6>() {
        let in6_addr = unsafe { *(storage as *const _ as *const libc::sockaddr_in6) };
        let ip = Ipv6Addr::from(in6_addr.sin6_addr.s6_addr);
        Some(SocketAddr::new(IpAddr::V6(ip), u16::from_be(in6_addr.sin6_port)))
    } else {
        None
    }
}

fn extract_dst_addr(hdr: &libc::msghdr) -> Option<IpAddr> {
    if hdr.msg_control.is_null() || hdr.msg_controllen == 0 {
        return None;
    }
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(hdr);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_PKTINFO {
                let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                let ip = Ipv4Addr::from(u32::from_be((*pktinfo).ipi_addr.s_addr));
                return Some(IpAddr::V4(ip));
            // IPV6_RECVPKTINFO (49) is what setsockopt takes; the kernel tags the
            // control message it then sends with IPV6_PKTINFO (50). Checking for the
            // former here meant this branch never fired and dst_addr was always None
            // on IPv6.
            } else if (*cmsg).cmsg_level == libc::IPPROTO_IPV6 && (*cmsg).cmsg_type == libc::IPV6_PKTINFO {
                let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
                let ip = Ipv6Addr::from((*pktinfo).ipi6_addr.s6_addr);
                return Some(IpAddr::V6(ip));
            }
            cmsg = libc::CMSG_NXTHDR(hdr, cmsg);
        }
    }
    None
}

pub fn recvmmsg(fd: BorrowedFd<'_>, msgs: &mut [RecvMsg]) -> io::Result<usize> {
    if msgs.is_empty() {
        return Ok(0);
    }
    
    let count = msgs.len().min(BATCH_MAX);
    let mut mmsgs: [libc::mmsghdr; BATCH_MAX] = unsafe { std::mem::zeroed() };
    let mut iovecs: [libc::iovec; BATCH_MAX] = unsafe { std::mem::zeroed() };
    let mut addrs: [libc::sockaddr_storage; BATCH_MAX] = unsafe { std::mem::zeroed() };

    for i in 0..count {
        iovecs[i].iov_base = msgs[i].buf.as_mut_ptr() as *mut libc::c_void;
        iovecs[i].iov_len = msgs[i].buf.len();

        mmsgs[i].msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut libc::c_void;
        mmsgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        mmsgs[i].msg_hdr.msg_iov = &mut iovecs[i];
        mmsgs[i].msg_hdr.msg_iovlen = 1;

        if !msgs[i].cmsg_buf.is_empty() {
            mmsgs[i].msg_hdr.msg_control = msgs[i].cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            mmsgs[i].msg_hdr.msg_controllen = msgs[i].cmsg_buf.len() as libc::size_t;
        }
    }

    let ret = unsafe {
        libc::recvmmsg(
            fd.as_raw_fd(),
            mmsgs.as_mut_ptr(),
            count as libc::c_uint,
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            std::ptr::null_mut(),
        )
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::EAGAIN) {
            return Ok(0);
        }
        return Err(err);
    }

    let ret = ret as usize;
    for i in 0..ret {
        // recvmmsg is called with MSG_TRUNC, so msg_len is the wire length and may be
        // larger than the buffer it was copied into. Handing that out as `len` makes
        // `&buf[..len]` a panic on any oversized datagram -- and on the QUIC ingress path
        // the sender chooses the size. Clamp, and keep the wire length separately.
        let wire = mmsgs[i].msg_len as usize;
        msgs[i].wire_len = wire;
        msgs[i].len = wire.min(msgs[i].buf.len());
        msgs[i].truncated =
            wire > msgs[i].buf.len() || (mmsgs[i].msg_hdr.msg_flags & libc::MSG_TRUNC) != 0;
        msgs[i].src_addr = parse_sockaddr(&addrs[i], mmsgs[i].msg_hdr.msg_namelen as usize);
        msgs[i].dst_addr = extract_dst_addr(&mmsgs[i].msg_hdr);
    }

    Ok(ret)
}

pub fn sendmmsg(fd: BorrowedFd<'_>, msgs: &[SendMsg]) -> io::Result<usize> {
    if msgs.is_empty() {
        return Ok(0);
    }
    
    let count = msgs.len().min(BATCH_MAX);
    let mut mmsgs: [libc::mmsghdr; BATCH_MAX] = unsafe { std::mem::zeroed() };
    let mut iovecs: [libc::iovec; BATCH_MAX] = unsafe { std::mem::zeroed() };
    let mut addrs: [libc::sockaddr_storage; BATCH_MAX] = unsafe { std::mem::zeroed() };
    
    for i in 0..count {
        iovecs[i].iov_base = msgs[i].buf.as_ptr() as *mut libc::c_void;
        iovecs[i].iov_len = msgs[i].buf.len();
        
        if let Some(addr) = msgs[i].dst_addr {
            match addr {
                SocketAddr::V4(v4) => {
                    let in_addr = libc::sockaddr_in {
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        sin_port: u16::to_be(v4.port()),
                        sin_addr: libc::in_addr { s_addr: u32::to_be(u32::from(*v4.ip())) },
                        sin_zero: [0; 8],
                    };
                    unsafe { std::ptr::write(&mut addrs[i] as *mut _ as *mut libc::sockaddr_in, in_addr) };
                    mmsgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                }
                SocketAddr::V6(v6) => {
                    let in6_addr = libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: u16::to_be(v6.port()),
                        sin6_flowinfo: v6.flowinfo(),
                        sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                        sin6_scope_id: v6.scope_id(),
                    };
                    unsafe { std::ptr::write(&mut addrs[i] as *mut _ as *mut libc::sockaddr_in6, in6_addr) };
                    mmsgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
                }
            }
            mmsgs[i].msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut libc::c_void;
        } else {
            mmsgs[i].msg_hdr.msg_name = std::ptr::null_mut();
            mmsgs[i].msg_hdr.msg_namelen = 0;
        }
        
        mmsgs[i].msg_hdr.msg_iov = &mut iovecs[i];
        mmsgs[i].msg_hdr.msg_iovlen = 1;
        
        mmsgs[i].msg_hdr.msg_control = std::ptr::null_mut();
        mmsgs[i].msg_hdr.msg_controllen = 0;
    }

    let ret = unsafe {
        libc::sendmmsg(
            fd.as_raw_fd(),
            mmsgs.as_mut_ptr(),
            count as libc::c_uint,
            libc::MSG_DONTWAIT,
        )
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::EAGAIN) {
            return Ok(0);
        }
        return Err(err);
    }

    Ok(ret as usize)
}

pub fn set_ip_pktinfo(fd: BorrowedFd<'_>, value: bool) -> io::Result<()> {
    let val: libc::c_int = if value { 1 } else { 0 };
    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn set_ipv6_recvpktinfo(fd: BorrowedFd<'_>, value: bool) -> io::Result<()> {
    let val: libc::c_int = if value { 1 } else { 0 };
    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &val as *const _ as *const libc::c_void,
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
        
        let mut bufs = vec![[0u8; 10]; 10];
        let mut cmsgs = vec![[0u8; 128]; 10];
        
        let mut msgs: Vec<RecvMsg> = bufs.iter_mut().zip(cmsgs.iter_mut()).map(|(buf, cmsg_buf)| RecvMsg {
            buf,
            cmsg_buf,
            len: 0,
            wire_len: 0,
            src_addr: None,
            dst_addr: None,
            truncated: false,
        }).collect();
        
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
        for i in 3..10 {
            assert_eq!(msgs[i].len, 0);
            assert_eq!(msgs[i].buf, &[0u8; 10]);
        }
    }
}
