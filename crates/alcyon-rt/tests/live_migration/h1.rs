// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A strict HTTP/1.1 client: one TCP connection, kept for the whole test.
//!
//! Strict, because a lenient reader can turn a broken response into a passing test: a
//! response head must parse completely, and a body is exactly its `Content-Length` or its
//! chunks. A byte too many is the start of the next response, and fails there.

use super::backend::is_gone;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Why a read or write did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The connection is gone: EOF, reset, broken pipe.
    Ended(String),
    /// Nothing within the time allowed.
    Timeout,
    /// The peer sent something that is not HTTP/1.1.
    Protocol(String),
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    /// The value of header `name`, case-insensitively; the first if repeated.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

pub struct H1 {
    pub s: TcpStream,
    pub local: SocketAddr,
    buf: Vec<u8>,
}

impl H1 {
    #[must_use]
    pub fn connect(fe: SocketAddr) -> Self {
        let s = TcpStream::connect(fe).expect("connect to the frontend");
        let local = s.local_addr().expect("local addr");
        let _ = s.set_nodelay(true);
        Self { s, local, buf: Vec::new() }
    }

    /// Writes all of `data`.
    ///
    /// # Errors
    /// The connection ended or the write timed out.
    pub fn send(&mut self, data: &[u8]) -> Result<(), Failure> {
        let _ = self.s.set_write_timeout(Some(Duration::from_secs(10)));
        self.s.write_all(data).map_err(|e| classify(&e))
    }

    /// Reads more into the buffer, waiting until `deadline`.
    fn fill(&mut self, deadline: Instant) -> Result<(), Failure> {
        let now = Instant::now();
        if now >= deadline {
            return Err(Failure::Timeout);
        }
        let _ = self.s.set_read_timeout(Some((deadline - now).max(Duration::from_millis(1))));
        let mut tmp = vec![0u8; 65536];
        match self.s.read(&mut tmp) {
            Ok(0) => Err(Failure::Ended("EOF".into())),
            Ok(n) => {
                self.buf.extend_from_slice(&tmp[..n]);
                Ok(())
            }
            Err(e) => Err(classify(&e)),
        }
    }

    /// Reads a response head.
    ///
    /// # Errors
    /// See [`Failure`].
    pub fn read_head(&mut self, within: Duration) -> Result<(u16, Vec<(String, String)>), Failure> {
        let deadline = Instant::now() + within;
        let end = loop {
            if let Some(p) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p;
            }
            self.fill(deadline)?;
        };
        let head: Vec<u8> = self.buf.drain(..end + 4).collect();
        let head = String::from_utf8(head[..end].to_vec()).map_err(|_| Failure::Protocol("non-UTF-8 head".into()))?;
        let mut lines = head.split("\r\n");
        let sl = lines.next().unwrap_or("");
        let status = sl
            .strip_prefix("HTTP/1.1 ")
            .and_then(|r| r.get(..3))
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| Failure::Protocol(format!("bad status line {sl:?} in head {head:?}")))?;
        let mut headers = Vec::new();
        for l in lines {
            let (n, v) = l.split_once(':').ok_or_else(|| Failure::Protocol(format!("bad header line {l:?} in head {head:?}")))?;
            if n.is_empty() || n.contains(' ') {
                return Err(Failure::Protocol(format!("bad header name {n:?} in head {head:?}")));
            }
            headers.push((n.to_string(), v.trim().to_string()));
        }
        Ok((status, headers))
    }

    /// Reads exactly `n` body bytes, handing them to `sink` as they arrive.
    fn read_exact_to(&mut self, mut n: u64, deadline: Instant, sink: &mut dyn FnMut(&[u8])) -> Result<(), Failure> {
        while n > 0 {
            if self.buf.is_empty() {
                self.fill(deadline)?;
            }
            let take = usize::try_from(n.min(self.buf.len() as u64)).unwrap_or(0);
            let part: Vec<u8> = self.buf.drain(..take).collect();
            sink(&part);
            n -= take as u64;
        }
        Ok(())
    }

    fn read_line(&mut self, deadline: Instant) -> Result<String, Failure> {
        loop {
            if let Some(p) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let l: Vec<u8> = self.buf.drain(..p + 2).collect();
                return Ok(String::from_utf8_lossy(&l[..p]).into_owned());
            }
            self.fill(deadline)?;
        }
    }

    /// Reads the body a head announced, handing it to `sink`; returns its length.
    ///
    /// # Errors
    /// See [`Failure`]. A head with neither `Content-Length` nor chunking is a protocol
    /// error here: every response these tests provoke has one or the other.
    pub fn read_body(&mut self, headers: &[(String, String)], within: Duration, sink: &mut dyn FnMut(&[u8])) -> Result<u64, Failure> {
        let deadline = Instant::now() + within;
        let get = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str());
        if get("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
            let mut total = 0;
            loop {
                let line = self.read_line(deadline)?;
                let size = u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                    .map_err(|_| Failure::Protocol(format!("bad chunk size line {line:?}")))?;
                if size == 0 {
                    loop {
                        if self.read_line(deadline)?.is_empty() {
                            return Ok(total);
                        }
                    }
                }
                self.read_exact_to(size, deadline, sink)?;
                total += size;
                let crlf = self.read_line(deadline)?;
                if !crlf.is_empty() {
                    return Err(Failure::Protocol(format!("chunk not followed by CRLF: {crlf:?}")));
                }
            }
        } else if let Some(cl) = get("content-length") {
            let n: u64 = cl.parse().map_err(|_| Failure::Protocol(format!("bad Content-Length {cl:?}")))?;
            self.read_exact_to(n, deadline, sink)?;
            Ok(n)
        } else {
            Err(Failure::Protocol(format!("response without Content-Length or chunking: {headers:?}")))
        }
    }

    /// Reads a whole response.
    ///
    /// # Errors
    /// See [`Failure`].
    pub fn response(&mut self, within: Duration) -> Result<Resp, Failure> {
        let deadline = Instant::now() + within;
        let (status, headers) = self.read_head(within)?;
        let mut body = Vec::new();
        self.read_body(&headers, deadline.saturating_duration_since(Instant::now()), &mut |b| body.extend_from_slice(b))?;
        Ok(Resp { status, headers, body })
    }

    /// Sends a keep-alive `GET path` with `extra` header lines and reads the response.
    ///
    /// # Errors
    /// See [`Failure`].
    pub fn get(&mut self, path: &str, extra: &str, within: Duration) -> Result<Resp, Failure> {
        self.send(format!("GET {path} HTTP/1.1\r\nHost: t96\r\n{extra}\r\n").as_bytes())?;
        self.response(within)
    }

    /// Waits up to `within` for the connection to end without sending anything. `Ok(())`
    /// if it ended; the bytes received instead, or `Timeout`, otherwise.
    ///
    /// # Errors
    /// `Protocol` with what arrived if data came instead of an end.
    pub fn wait_end(&mut self, within: Duration) -> Result<(), Failure> {
        let deadline = Instant::now() + within;
        loop {
            match self.fill(deadline) {
                Ok(()) => {}
                Err(Failure::Ended(_)) => return Ok(()),
                Err(e) => return Err(e),
            }
            if self.buf.len() > 1 << 20 {
                self.buf.clear();
            }
        }
    }
}

fn classify(e: &std::io::Error) -> Failure {
    match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => Failure::Timeout,
        k if is_gone(k) => Failure::Ended(e.to_string()),
        _ => Failure::Ended(format!("{e} ({:?})", e.kind())),
    }
}

/// An echo response's `X-Seen-Gen`: which configuration generation's `http-request` rules
/// processed the request -- and so which process served it.
#[must_use]
pub fn gen(r: &Resp) -> Option<&str> {
    r.header("X-Seen-Gen")
}
