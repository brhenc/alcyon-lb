//! Stick Table storage engine backed by Elastic Binary Trees.

use crate::entry::{StickEntryData, StickKey};
use crate::rate::SlidingRate;
use ibex_core::error::{IbexError, IbexResult};
use ibex_ebtree::{Eb32Tree, Eb64Tree, EbMbTree, EbStTree};
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Key type specification for stick table configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ip,
    Ipv6,
    Integer,
    String,
    Binary,
}

/// Stick Table configuration options
#[derive(Debug, Clone)]
pub struct StickTableConfig {
    pub name: String,
    pub key_type: KeyType,
    pub max_size: usize,
    pub expire: Duration,
    pub track_conn_cnt: bool,
    pub track_conn_cur: bool,
    pub track_conn_rate_ms: Option<u64>,
    pub track_http_req_cnt: bool,
    pub track_http_req_rate_ms: Option<u64>,
    pub track_http_err_cnt: bool,
    pub track_http_err_rate_ms: Option<u64>,
    pub track_bytes_in_cnt: bool,
    pub track_bytes_out_cnt: bool,
    pub track_gpc0: bool,
}

impl Default for StickTableConfig {
    fn default() -> Self {
        Self {
            name: "default_table".to_string(),
            key_type: KeyType::Ip,
            max_size: 100_000,
            expire: Duration::from_secs(300),
            track_conn_cnt: true,
            track_conn_cur: true,
            track_conn_rate_ms: Some(10_000),
            track_http_req_cnt: true,
            track_http_req_rate_ms: Some(10_000),
            track_http_err_cnt: true,
            track_http_err_rate_ms: Some(10_000),
            track_bytes_in_cnt: true,
            track_bytes_out_cnt: true,
            track_gpc0: true,
        }
    }
}

/// High-performance Stick Table engine
pub struct StickTable {
    config: StickTableConfig,
    eb32: RwLock<Eb32Tree<StickEntryData>>,
    eb64: RwLock<Eb64Tree<StickEntryData>>,
    ebst: RwLock<EbStTree<StickEntryData>>,
    ebmb: RwLock<EbMbTree<StickEntryData>>,
}

impl StickTable {
    /// Creates a new stick table with configuration.
    pub fn new(config: StickTableConfig) -> Self {
        Self {
            config,
            eb32: RwLock::new(Eb32Tree::new()),
            eb64: RwLock::new(Eb64Tree::new()),
            ebst: RwLock::new(EbStTree::new()),
            ebmb: RwLock::new(EbMbTree::new()),
        }
    }

    /// Accesses or creates an entry for the given key and applies a mutation closure.
    pub fn update_entry<F>(&self, key: &StickKey, mut f: F) -> IbexResult<()>
    where
        F: FnMut(&mut StickEntryData),
    {
        match key {
            StickKey::Ip(IpAddr::V4(ipv4)) => {
                let mut tree = self
                    .eb32
                    .write()
                    .map_err(|e| IbexError::StickTable(e.to_string()))?;
                let k = u32::from(*ipv4);
                let entry = if let Some(existing) = tree.lookup_mut(k) {
                    existing
                } else {
                    let new_entry = self.create_default_entry();
                    tree.insert(k, new_entry);
                    tree.lookup_mut(k).expect("Inserted")
                };
                entry.last_updated = Instant::now();
                f(entry);
                Ok(())
            }
            StickKey::Ip(IpAddr::V6(ipv6)) => {
                let mut tree = self
                    .ebmb
                    .write()
                    .map_err(|e| IbexError::StickTable(e.to_string()))?;
                let octets = ipv6.octets();
                if let Some(existing) = tree.lookup(&octets) {
                    // clone & re-insert for ebmb
                    let mut mut_entry = existing.clone();
                    mut_entry.last_updated = Instant::now();
                    f(&mut mut_entry);
                    tree.insert(&octets, mut_entry);
                } else {
                    let mut new_entry = self.create_default_entry();
                    new_entry.last_updated = Instant::now();
                    f(&mut new_entry);
                    tree.insert(&octets, new_entry);
                }
                Ok(())
            }
            StickKey::Integer(val) => {
                let mut tree = self
                    .eb64
                    .write()
                    .map_err(|e| IbexError::StickTable(e.to_string()))?;
                let entry = if let Some(existing) = tree.lookup_mut(*val) {
                    existing
                } else {
                    let new_entry = self.create_default_entry();
                    tree.insert(*val, new_entry);
                    tree.lookup_mut(*val).expect("Inserted")
                };
                entry.last_updated = Instant::now();
                f(entry);
                Ok(())
            }
            StickKey::String(s) => {
                let mut tree = self
                    .ebst
                    .write()
                    .map_err(|e| IbexError::StickTable(e.to_string()))?;
                if let Some(existing) = tree.lookup(s) {
                    let mut mut_entry = existing.clone();
                    mut_entry.last_updated = Instant::now();
                    f(&mut mut_entry);
                    tree.insert(s, mut_entry);
                } else {
                    let mut new_entry = self.create_default_entry();
                    new_entry.last_updated = Instant::now();
                    f(&mut new_entry);
                    tree.insert(s, new_entry);
                }
                Ok(())
            }
            StickKey::Binary(bin) => {
                let mut tree = self
                    .ebmb
                    .write()
                    .map_err(|e| IbexError::StickTable(e.to_string()))?;
                if let Some(existing) = tree.lookup(bin) {
                    let mut mut_entry = existing.clone();
                    mut_entry.last_updated = Instant::now();
                    f(&mut mut_entry);
                    tree.insert(bin, mut_entry);
                } else {
                    let mut new_entry = self.create_default_entry();
                    new_entry.last_updated = Instant::now();
                    f(&mut new_entry);
                    tree.insert(bin, new_entry);
                }
                Ok(())
            }
        }
    }

    /// Reads an entry for a given key.
    pub fn get_entry(&self, key: &StickKey) -> IbexResult<Option<StickEntryData>> {
        match key {
            StickKey::Ip(IpAddr::V4(ipv4)) => {
                let tree = self
                    .eb32
                    .read()
                    .map_err(|e| IbexError::StickTable(e.to_string()))?;
                let k = u32::from(*ipv4);
                Ok(tree.lookup(k).cloned())
            }
            StickKey::Ip(IpAddr::V6(ipv6)) => {
                let tree = self
                    .ebmb
                    .read()
                    .map_err(|e| IbexError::StickTable(e.to_string()))?;
                Ok(tree.lookup(&ipv6.octets()).cloned())
            }
            StickKey::Integer(val) => {
                let tree = self
                    .eb64
                    .read()
                    .map_err(|e| IbexError::StickTable(e.to_string()))?;
                Ok(tree.lookup(*val).cloned())
            }
            StickKey::String(s) => {
                let tree = self
                    .ebst
                    .read()
                    .map_err(|e| IbexError::StickTable(e.to_string()))?;
                Ok(tree.lookup(s).cloned())
            }
            StickKey::Binary(bin) => {
                let tree = self
                    .ebmb
                    .read()
                    .map_err(|e| IbexError::StickTable(e.to_string()))?;
                Ok(tree.lookup(bin).cloned())
            }
        }
    }

    fn create_default_entry(&self) -> StickEntryData {
        let mut entry = StickEntryData::default();
        if let Some(period) = self.config.track_conn_rate_ms {
            entry.conn_rate = Some(SlidingRate::new(period));
        }
        if let Some(period) = self.config.track_http_req_rate_ms {
            entry.http_req_rate = Some(SlidingRate::new(period));
        }
        if let Some(period) = self.config.track_http_err_rate_ms {
            entry.http_err_rate = Some(SlidingRate::new(period));
        }
        entry
    }

    /// Table configuration.
    pub fn config(&self) -> &StickTableConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_stick_table_tracking() {
        let config = StickTableConfig {
            name: "test_ip_table".to_string(),
            key_type: KeyType::Ip,
            ..Default::default()
        };
        let table = StickTable::new(config);
        let key = StickKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));

        table
            .update_entry(&key, |entry| {
                entry.conn_cnt += 1;
                entry.conn_cur += 1;
                if let Some(ref mut rate) = entry.conn_rate {
                    rate.tick(1);
                }
            })
            .expect("update succeeds");

        let entry = table.get_entry(&key).expect("lookup succeeds").unwrap();
        assert_eq!(entry.conn_cnt, 1);
        assert_eq!(entry.conn_cur, 1);
        assert!(entry.conn_rate.unwrap().rate() >= 1);
    }
}
