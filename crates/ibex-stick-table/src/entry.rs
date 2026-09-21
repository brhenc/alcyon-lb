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
    pub gpc0: u64,
    pub gpc1: u64,
    pub gpt0: u32,
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
            gpc0: 0,
            gpc1: 0,
            gpt0: 0,
            last_updated: Instant::now(),
        }
    }
}
