// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A small HTTP/2 client (RFC 9113, cleartext with prior knowledge), written for this
//! harness and sharing nothing with `ibex_proto`.
//!
//! It is strict where a migration can go wrong: HPACK is decoded with a real dynamic
//! table (so an out-of-step table is an error, not a garbled value), the windows the
//! client advertised are enforced (DATA beyond them is recorded as a violation), and a
//! GOAWAY is recorded, never ignored.

use super::h1::Failure;
use super::hpack::{Decoder, Encoder};
use super::pattern::{self, Checker};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub const DATA: u8 = 0;
pub const HEADERS: u8 = 1;
pub const RST_STREAM: u8 = 3;
pub const SETTINGS: u8 = 4;
pub const PING: u8 = 6;
pub const GOAWAY: u8 = 7;
pub const WINDOW_UPDATE: u8 = 8;
pub const CONTINUATION: u8 = 9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

/// The client's initial windows (the protocol default) and header table size.
pub const WINDOW: i64 = 65_535;
pub const TABLE: usize = 4096;

/// One response stream, as received.
#[derive(Debug, Default)]
pub struct Stream {
    pub headers: Option<Vec<(String, String)>>,
    pub trailers: Option<Vec<(String, String)>>,
    /// Body bytes received (flow-controlled payload, padding excluded).
    pub data_len: u64,
    /// The body, kept when no pattern checker is set.
    pub body: Vec<u8>,
    /// Checks the body against a pattern stream, when the body is one.
    pub checker: Option<Checker>,
    pub ended: bool,
    pub reset: Option<u32>,
    /// Our receive window for this stream.
    recv_window: i64,
    /// Our send window for this stream.
    send_window: i64,
    /// Request body: (seed, total, sent).
    upload: Option<(u64, u64, u64)>,
}

impl Stream {
    #[must_use]
    pub fn header(&self, n: &str) -> Option<&str> {
        self.headers.as_ref()?.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str())
    }
}

pub struct H2 {
    pub s: TcpStream,
    pub local: SocketAddr,
    rbuf: Vec<u8>,
    pub dec: Decoder,
    pub enc: Encoder,
    pub streams: HashMap<u32, Stream>,
    next_sid: u32,
    /// (last stream id, error code) of a GOAWAY, if one arrived.
    pub goaway: Option<(u32, u32)>,
    /// Flow-control or protocol violations by the peer.
    pub violations: Vec<String>,
    send_conn_window: i64,
    peer_initial_window: i64,
    peer_max_frame: usize,
    recv_conn_window: i64,
    /// When set, every DATA frame is credited back at once, conn and stream.
    pub auto_window: bool,
    /// Header block being assembled: (stream, flags of the HEADERS frame, fragments).
    partial: Option<(u32, u8, Vec<u8>)>,
}

fn frame(ty: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame size");
    let mut v = Vec::with_capacity(9 + payload.len());
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.push(ty);
    v.push(flags);
    v.extend_from_slice(&sid.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

impl H2 {
    /// Connects, exchanges prefaces and SETTINGS.
    ///
    /// # Panics
    /// When the handshake fails: nothing a migration test can say anything about.
    #[must_use]
    pub fn connect(fe: SocketAddr) -> Self {
        let s = TcpStream::connect(fe).expect("connect to the h2 frontend");
        let _ = s.set_nodelay(true);
        let local = s.local_addr().expect("local addr");
        let mut c = Self {
            s,
            local,
            rbuf: Vec::new(),
            dec: Decoder::new(TABLE),
            enc: Encoder::new(TABLE),
            streams: HashMap::new(),
            next_sid: 1,
            goaway: None,
            violations: Vec::new(),
            send_conn_window: WINDOW,
            peer_initial_window: WINDOW,
            peer_max_frame: 16_384,
            recv_conn_window: WINDOW,
            auto_window: true,
            partial: None,
        };
        let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        // ENABLE_PUSH = 0; INITIAL_WINDOW_SIZE and HEADER_TABLE_SIZE stated explicitly.
        let mut settings = Vec::new();
        for (id, v) in [(2u16, 0u32), (4, u32::try_from(WINDOW).unwrap_or(0)), (1, u32::try_from(TABLE).unwrap_or(0))] {
            settings.extend_from_slice(&id.to_be_bytes());
            settings.extend_from_slice(&v.to_be_bytes());
        }
        hello.extend(frame(SETTINGS, 0, 0, &settings));
        c.raw_send(&hello).expect("send the h2 preface");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got_settings = false;
        while !got_settings {
            let f = c.pump(deadline).unwrap_or_else(|e| panic!("h2 handshake: {e:?}"));
            got_settings = f.0 == SETTINGS && f.1 & ACK == 0;
        }
        c
    }

    fn raw_send(&mut self, data: &[u8]) -> Result<(), Failure> {
        let _ = self.s.set_write_timeout(Some(Duration::from_secs(10)));
        self.s.write_all(data).map_err(|e| match e.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => Failure::Timeout,
            _ => Failure::Ended(e.to_string()),
        })
    }

    fn fill(&mut self, deadline: Instant) -> Result<(), Failure> {
        let now = Instant::now();
        if now >= deadline {
            return Err(Failure::Timeout);
        }
        let _ = self.s.set_read_timeout(Some((deadline - now).max(Duration::from_millis(1))));
        let mut tmp = vec![0u8; 65_536];
        match self.s.read(&mut tmp) {
            Ok(0) => Err(Failure::Ended("EOF".into())),
            Ok(n) => {
                self.rbuf.extend_from_slice(&tmp[..n]);
                Ok(())
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Err(Failure::Timeout),
            Err(e) => Err(Failure::Ended(e.to_string())),
        }
    }

    fn violation(&mut self, v: String) {
        self.violations.push(v);
    }

    /// Reads and handles one frame; returns its (type, flags, stream).
    ///
    /// # Errors
    /// The connection ended, timed out, or sent something undecodable.
    #[allow(clippy::too_many_lines)]
    pub fn pump(&mut self, deadline: Instant) -> Result<(u8, u8, u32), Failure> {
        while self.rbuf.len() < 9 || self.rbuf.len() < 9 + self.frame_len() {
            self.fill(deadline)?;
        }
        let len = self.frame_len();
        let ty = self.rbuf[3];
        let flags = self.rbuf[4];
        let sid = u32::from_be_bytes([self.rbuf[5] & 0x7f, self.rbuf[6], self.rbuf[7], self.rbuf[8]]);
        let payload: Vec<u8> = self.rbuf.drain(..9 + len).skip(9).collect();
        if let Some((psid, _, _)) = &self.partial {
            if ty != CONTINUATION || sid != *psid {
                return Err(Failure::Protocol(format!("frame type {ty} inside a header block of stream {psid}")));
            }
        }
        match ty {
            SETTINGS if flags & ACK == 0 => {
                for kv in payload.chunks(6) {
                    if kv.len() < 6 {
                        return Err(Failure::Protocol("short SETTINGS".into()));
                    }
                    let id = u16::from_be_bytes([kv[0], kv[1]]);
                    let v = i64::from(u32::from_be_bytes([kv[2], kv[3], kv[4], kv[5]]));
                    match id {
                        4 => {
                            let delta = v - self.peer_initial_window;
                            self.peer_initial_window = v;
                            for st in self.streams.values_mut() {
                                st.send_window += delta;
                            }
                        }
                        5 => self.peer_max_frame = usize::try_from(v).unwrap_or(16_384),
                        // Only a 4096-byte table is expected; anything else changes which
                        // references are valid and must be noticed.
                        1 if usize::try_from(v).unwrap_or(0) < TABLE => {
                            self.violation(format!("peer HEADER_TABLE_SIZE {v}"));
                        }
                        _ => {}
                    }
                }
                self.raw_send(&frame(SETTINGS, ACK, 0, &[]))?;
            }
            PING if flags & ACK == 0 => self.raw_send(&frame(PING, ACK, 0, &payload))?,
            WINDOW_UPDATE => {
                let inc = i64::from(u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]));
                if sid == 0 {
                    self.send_conn_window += inc;
                } else if let Some(st) = self.streams.get_mut(&sid) {
                    st.send_window += inc;
                }
            }
            GOAWAY => {
                let last = u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
                let code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                self.goaway = Some((last, code));
            }
            RST_STREAM => {
                let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                self.streams.entry(sid).or_default().reset = Some(code);
            }
            HEADERS => {
                let mut p = &payload[..];
                if flags & PADDED != 0 {
                    let pad = usize::from(p[0]);
                    p = &p[1..p.len() - pad];
                }
                if flags & PRIORITY != 0 {
                    p = &p[5..];
                }
                self.partial = Some((sid, flags, p.to_vec()));
                if flags & END_HEADERS != 0 {
                    self.finish_headers()?;
                }
            }
            CONTINUATION => {
                if let Some((_, _, ref mut block)) = self.partial {
                    block.extend_from_slice(&payload);
                } else {
                    return Err(Failure::Protocol("CONTINUATION without HEADERS".into()));
                }
                if flags & END_HEADERS != 0 {
                    self.finish_headers()?;
                }
            }
            DATA => {
                let flow = i64::try_from(payload.len()).unwrap_or(0);
                let mut p = &payload[..];
                if flags & PADDED != 0 {
                    let pad = usize::from(p[0]);
                    p = &p[1..p.len() - pad];
                }
                self.recv_conn_window -= flow;
                if self.recv_conn_window < 0 {
                    self.violation(format!("DATA on stream {sid} overran the connection window by {}", -self.recv_conn_window));
                }
                let auto = self.auto_window;
                let st = self.streams.entry(sid).or_default();
                st.recv_window -= flow;
                let overrun = st.recv_window;
                st.data_len += p.len() as u64;
                match st.checker.as_mut() {
                    Some(c) => {
                        c.feed(p);
                    }
                    None => st.body.extend_from_slice(p),
                }
                if flags & END_STREAM != 0 {
                    st.ended = true;
                }
                if overrun < 0 {
                    self.violation(format!("DATA on stream {sid} overran its window by {}", -overrun));
                }
                if auto && flow > 0 {
                    self.grant(sid, flow)?;
                }
            }
            _ => {}
        }
        if (ty == DATA || ty == HEADERS || ty == CONTINUATION) && flags & END_STREAM != 0 {
            self.check_length(sid);
        }
        Ok((ty, flags, sid))
    }

    /// A response that ends must have carried exactly its `content-length`, when it gave one.
    fn check_length(&mut self, sid: u32) {
        let Some(st) = self.streams.get(&sid) else { return };
        let cl = st.header("content-length").and_then(|v| v.parse::<u64>().ok());
        if let Some(cl) = cl.filter(|cl| *cl != st.data_len) {
            let got = st.data_len;
            self.violation(format!("stream {sid} ended after {got} body bytes; content-length is {cl}"));
        }
    }

    fn frame_len(&self) -> usize {
        (usize::from(self.rbuf[0]) << 16) | (usize::from(self.rbuf[1]) << 8) | usize::from(self.rbuf[2])
    }

    fn finish_headers(&mut self) -> Result<(), Failure> {
        let Some((sid, flags, block)) = self.partial.take() else { return Ok(()) };
        let fields = self
            .dec
            .decode(&block)
            .map_err(|e| Failure::Protocol(format!("HPACK decoding of stream {sid}'s headers failed: {e}")))?;
        let st = self.streams.entry(sid).or_default();
        if st.headers.is_none() {
            st.headers = Some(fields);
        } else {
            st.trailers = Some(fields);
        }
        if flags & END_STREAM != 0 {
            st.ended = true;
        }
        Ok(())
    }

    /// Credits `n` bytes back to the peer on the connection and on stream `sid`.
    ///
    /// # Errors
    /// The connection ended.
    pub fn grant(&mut self, sid: u32, n: i64) -> Result<(), Failure> {
        let inc = u32::try_from(n).unwrap_or(0).to_be_bytes();
        let mut out = frame(WINDOW_UPDATE, 0, 0, &inc);
        self.recv_conn_window += n;
        if let Some(st) = self.streams.get_mut(&sid) {
            if !st.ended {
                st.recv_window += n;
                out.extend(frame(WINDOW_UPDATE, 0, sid, &inc));
            }
        }
        self.raw_send(&out)
    }

    /// Opens a stream: `method path` with the extra header fields `fields` (already
    /// HPACK-encoded by the caller with [`Self::enc`]) and, for an upload, a body of
    /// `body = (seed, len)` announced by `content-length` and `x-body-seed`. The body is
    /// sent by [`Self::send_body`]. `checker_seed` makes the response body checked
    /// against that pattern stream as it arrives.
    ///
    /// # Errors
    /// The connection ended.
    pub fn open(&mut self, method: &str, path: &str, fields: &[Vec<u8>], body: Option<(u64, u64)>, checker_seed: Option<u64>) -> Result<u32, Failure> {
        let sid = self.next_sid;
        self.next_sid += 2;
        let mut block = vec![if method == "POST" { 0x83 } else { 0x82 }, 0x86];
        block.extend(Encoder::literal_plain(4, "", path));
        block.extend(Encoder::literal_plain(1, "", "t96"));
        if let Some((seed, len)) = body {
            block.extend(Encoder::literal_plain(28, "", &len.to_string()));
            block.extend(Encoder::literal_plain(0, "x-body-seed", &seed.to_string()));
        }
        for f in fields {
            block.extend_from_slice(f);
        }
        let flags = END_HEADERS | if body.is_none() { END_STREAM } else { 0 };
        self.streams.insert(
            sid,
            Stream {
                recv_window: WINDOW,
                send_window: self.peer_initial_window,
                checker: checker_seed.map(Checker::new),
                upload: body.map(|(s, l)| (s, l, 0)),
                ..Stream::default()
            },
        );
        self.raw_send(&frame(HEADERS, flags, sid, &block))?;
        Ok(sid)
    }

    /// Sends stream `sid`'s request body up to byte `upto` (or all of it), within the
    /// peer's windows, reading frames while it waits for window. Ends the stream after
    /// the last byte.
    ///
    /// # Errors
    /// The connection ended, or no window opened before `deadline`.
    pub fn send_body(&mut self, sid: u32, upto: Option<u64>, deadline: Instant) -> Result<(), Failure> {
        loop {
            let st = self.streams.get(&sid).ok_or_else(|| Failure::Protocol("no such stream".into()))?;
            let (seed, total, sent) = st.upload.ok_or_else(|| Failure::Protocol("no upload".into()))?;
            let target = upto.unwrap_or(total).min(total);
            if sent >= target {
                return Ok(());
            }
            let window = self.send_conn_window.min(st.send_window);
            if window <= 0 {
                self.pump(deadline)?;
                continue;
            }
            let n = (target - sent)
                .min(u64::try_from(window).unwrap_or(0))
                .min(self.peer_max_frame as u64)
                .min(16_384);
            let mut data = vec![0u8; usize::try_from(n).unwrap_or(0)];
            pattern::fill(seed, sent, &mut data);
            let last = sent + n == total;
            self.raw_send(&frame(DATA, if last { END_STREAM } else { 0 }, sid, &data))?;
            let ni = i64::try_from(n).unwrap_or(0);
            self.send_conn_window -= ni;
            let st = self.streams.get_mut(&sid).ok_or_else(|| Failure::Protocol("no such stream".into()))?;
            st.send_window -= ni;
            st.upload = Some((seed, total, sent + n));
        }
    }

    /// Makes the next [`Self::open`] use stream id `sid`, even one already used.
    pub fn reuse_id(&mut self, sid: u32) {
        self.next_sid = sid;
    }

    /// Bytes of stream `sid`'s request body sent so far.
    #[must_use]
    pub fn body_sent(&self, sid: u32) -> u64 {
        self.streams.get(&sid).and_then(|s| s.upload).map_or(0, |u| u.2)
    }

    /// Reads frames until `done` holds.
    ///
    /// # Errors
    /// The connection ended or `deadline` passed first.
    pub fn until(&mut self, deadline: Instant, mut done: impl FnMut(&Self) -> bool) -> Result<(), Failure> {
        while !done(self) {
            self.pump(deadline)?;
        }
        Ok(())
    }

    /// Reads frames for `d`, expecting nothing in particular: returns how it ended
    /// (`Timeout` meaning still open and quiet).
    pub fn idle(&mut self, d: Duration) -> Failure {
        let deadline = Instant::now() + d;
        loop {
            if let Err(e) = self.pump(deadline) {
                return e;
            }
        }
    }

    #[must_use]
    pub fn stream(&self, sid: u32) -> &Stream {
        self.streams.get(&sid).unwrap_or_else(|| panic!("no stream {sid}"))
    }
}
