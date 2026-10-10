// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Stick table entry definitions and tracked metrics.

use crate::rate::SlidingRate;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

/// Supported Stick Table key types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StickKey {
    Ip(IpAddr),
    Integer(u64),
    String(String),
    Binary(Vec<u8>),
}

impl From<IpAddr> for StickKey {
    fn from(ip: IpAddr) -> Self {
        StickKey::Ip(ip)
    }
}

impl From<Ipv4Addr> for StickKey {
    fn from(ip: Ipv4Addr) -> Self {
        StickKey::Ip(IpAddr::V4(ip))
    }
}

impl From<Ipv6Addr> for StickKey {
    fn from(ip: Ipv6Addr) -> Self {
        StickKey::Ip(IpAddr::V6(ip))
    }
}

impl From<u64> for StickKey {
    fn from(v: u64) -> Self {
        StickKey::Integer(v)
    }
}

impl From<&str> for StickKey {
    fn from(s: &str) -> Self {
        StickKey::String(s.to_string())
    }
}

impl StickKey {
    /// The key [`encode_bytes`](Self::encode_bytes) made `bytes` from; `None` if they are not
    /// the encoding of one.
    #[must_use]
    pub fn decode_bytes(bytes: &[u8]) -> Option<StickKey> {
        let (tag, rest) = bytes.split_first()?;
        Some(match tag {
            0x01 => StickKey::Ip(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(rest).ok()?))),
            0x02 => StickKey::Ip(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(rest).ok()?))),
            0x03 => StickKey::Integer(u64::from_be_bytes(<[u8; 8]>::try_from(rest).ok()?)),
            0x04 => StickKey::String(String::from_utf8(rest.to_vec()).ok()?),
            0x05 => StickKey::Binary(rest.to_vec()),
            _ => return None,
        })
    }

    /// Encodes key into bytes for indexing in `EbMbTree`.
    #[must_use]
    pub fn encode_bytes(&self) -> Vec<u8> {
        match self {
            StickKey::Ip(IpAddr::V4(v4)) => {
                let mut buf = Vec::with_capacity(5);
                buf.push(0x01);
                buf.extend_from_slice(&v4.octets());
                buf
            }
            StickKey::Ip(IpAddr::V6(v6)) => {
                let mut buf = Vec::with_capacity(17);
                buf.push(0x02);
                buf.extend_from_slice(&v6.octets());
                buf
            }
            StickKey::Integer(v) => {
                let mut buf = Vec::with_capacity(9);
                buf.push(0x03);
                buf.extend_from_slice(&v.to_be_bytes());
                buf
            }
            StickKey::String(s) => {
                let mut buf = Vec::with_capacity(1 + s.len());
                buf.push(0x04);
                buf.extend_from_slice(s.as_bytes());
                buf
            }
            StickKey::Binary(b) => {
                let mut buf = Vec::with_capacity(1 + b.len());
                buf.push(0x05);
                buf.extend_from_slice(b);
                buf
            }
        }
    }
}

/// Dynamic metrics tracked within a single stick table entry
#[derive(Debug, Clone)]
pub struct StickEntryData {
    pub server_id: Option<u32>,
    pub conn_cnt: u64,
    pub conn_cur: u32,
    pub conn_rate: Option<SlidingRate>,
    pub sess_cnt: u64,
    pub sess_rate: Option<SlidingRate>,
    pub http_req_cnt: u64,
    pub http_req_rate: Option<SlidingRate>,
    pub http_err_cnt: u64,
    pub http_err_rate: Option<SlidingRate>,
    pub bytes_in_cnt: u64,
    pub bytes_in_rate: Option<SlidingRate>,
    pub bytes_out_cnt: u64,
    pub bytes_out_rate: Option<SlidingRate>,
    pub http_fail_cnt: u64,
    pub http_fail_rate: Option<SlidingRate>,
    pub glitch_cnt: u64,
    pub glitch_rate: Option<SlidingRate>,
    pub gpc0: u64,
    pub gpc0_rate: Option<SlidingRate>,
    pub gpc1: u64,
    pub gpc1_rate: Option<SlidingRate>,
    pub gpt0: u32,
    /// The array form of the general purpose storage (`gpc(<n>)`, `gpc_rate(<n>,<period>)`,
    /// `gpt(<n>)`), empty where the table does not store it.
    pub gpc: Vec<u64>,
    pub gpc_rate: Vec<SlidingRate>,
    pub gpt: Vec<u32>,
    /// The streams that track this entry (`ref_cnt` in `HAProxy`).
    pub trackers: u32,
    pub last_updated: Instant,
}

impl Default for StickEntryData {
    fn default() -> Self {
        Self {
            server_id: None,
            conn_cnt: 0,
            conn_cur: 0,
            conn_rate: None,
            sess_cnt: 0,
            sess_rate: None,
            http_req_cnt: 0,
            http_req_rate: None,
            http_err_cnt: 0,
            http_err_rate: None,
            bytes_in_cnt: 0,
            bytes_in_rate: None,
            bytes_out_cnt: 0,
            bytes_out_rate: None,
            http_fail_cnt: 0,
            http_fail_rate: None,
            glitch_cnt: 0,
            glitch_rate: None,
            gpc0: 0,
            gpc0_rate: None,
            gpc1: 0,
            gpc1_rate: None,
            gpt0: 0,
            gpc: Vec::new(),
            gpc_rate: Vec::new(),
            gpt: Vec::new(),
            trackers: 0,
            last_updated: Instant::now(),
        }
    }
}

fn tick(rate: &mut Option<SlidingRate>, n: u64) {
    if let Some(r) = rate {
        r.tick(n);
    }
}

impl StickEntryData {
    /// A stream starts tracking the entry: a connection (`conn_cnt`, `conn_cur`, `conn_rate`),
    /// and a session when `session` (`sess_cnt`, `sess_rate`), the way the tracking rules of
    /// the connection and session sets count it; the `http-request` and `tcp-request content`
    /// ones track a stream that is already a session. It is one more tracker.
    pub fn track(&mut self, session: bool) {
        self.conn_cnt += 1;
        self.conn_cur += 1;
        tick(&mut self.conn_rate, 1);
        if session {
            self.sess_cnt += 1;
            tick(&mut self.sess_rate, 1);
        }
        self.trackers += 1;
    }

    /// `n` glitches of the connection (`glitch_cnt`, `glitch_rate`).
    pub fn add_glitches(&mut self, n: u64) {
        self.glitch_cnt += n;
        tick(&mut self.glitch_rate, n);
    }

    /// A stream stops tracking the entry.
    pub fn untrack(&mut self) {
        self.conn_cur = self.conn_cur.saturating_sub(1);
        self.trackers = self.trackers.saturating_sub(1);
    }

    /// `n` bytes the client sent, and `m` the server sent, accounted to the entry.
    pub fn add_bytes(&mut self, n: u64, m: u64) {
        self.bytes_in_cnt += n;
        self.bytes_out_cnt += m;
        tick(&mut self.bytes_in_rate, n);
        tick(&mut self.bytes_out_rate, m);
    }

    /// A request the stream sent: `http_req_cnt` and its rate.
    pub fn count_request(&mut self) {
        self.http_req_cnt += 1;
        tick(&mut self.http_req_rate, 1);
    }

    /// `stream_inc_http_err_ctr`: a request in error.
    pub fn count_err(&mut self) {
        self.http_err_cnt += 1;
        tick(&mut self.http_err_rate, 1);
    }

    /// `stream_inc_http_fail_ctr`: a request the server failed.
    pub fn count_fail(&mut self) {
        self.http_fail_cnt += 1;
        tick(&mut self.http_fail_rate, 1);
    }
}

#[cfg(test)]
mod key_codec_tests {
    use super::*;

    #[test]
    fn decode_undoes_encode() {
        let keys = [
            StickKey::Ip("10.0.0.1".parse().unwrap()),
            StickKey::Ip("::1".parse().unwrap()),
            StickKey::Integer(42),
            StickKey::String("abc".into()),
            StickKey::Binary(vec![0, 1, 255]),
        ];
        for k in keys {
            assert_eq!(StickKey::decode_bytes(&k.encode_bytes()), Some(k));
        }
        assert_eq!(StickKey::decode_bytes(&[]), None);
        assert_eq!(StickKey::decode_bytes(&[9, 1]), None);
        assert_eq!(StickKey::decode_bytes(&[1, 1, 2]), None);
        assert_eq!(StickKey::decode_bytes(&[4, 0xff]), None);
    }
}
