use crate::protocol::{PeerCodec, PeerKey, PeerMessage};
use bytes::BytesMut;
use ibex_core::error::{IbexError, IbexResult};
use ibex_stick_table::{StickEntryData, StickKey, StickTable};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Peer node configuration
#[derive(Debug, Clone)]
pub struct PeerNodeConfig {
    pub name: String,
    pub address: SocketAddr,
    pub local_peer_name: String,
}

/// Peer Session State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Disconnected,
    Connecting,
    Handshaking,
    Synchronized,
}

/// Peer Synchronization Session
pub struct PeerSession {
    config: PeerNodeConfig,
    state: PeerState,
    table: Arc<StickTable>,
}

impl PeerSession {
    /// Creates a new peer session.
    pub fn new(config: PeerNodeConfig, table: Arc<StickTable>) -> Self {
        Self {
            config,
            state: PeerState::Disconnected,
            table,
        }
    }

    /// Current connection state.
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// Broadcasts a local stick-table update to the remote peer over TCP.
    pub async fn send_update(
        &mut self,
        stream: &mut TcpStream,
        key: &StickKey,
        data: &StickEntryData,
    ) -> IbexResult<()> {
        let peer_key = match key {
            StickKey::Ip(std::net::IpAddr::V4(v4)) => PeerKey::Ipv4(*v4),
            StickKey::Ip(std::net::IpAddr::V6(v6)) => PeerKey::Ipv6(*v6),
            StickKey::Integer(val) => PeerKey::Integer(*val),
            StickKey::String(s) => PeerKey::String(s.clone()),
            StickKey::Binary(_) => return Ok(()),
        };

        let msg = PeerMessage::TableUpdate {
            table_id: 1,
            key: peer_key,
            conn_cnt: Some(data.conn_cnt),
            conn_cur: Some(data.conn_cur),
            http_req_cnt: Some(data.http_req_cnt),
            server_id: data.server_id,
        };

        let mut buf = BytesMut::with_capacity(128);
        PeerCodec::encode(&msg, &mut buf)?;
        stream
            .write_all(&buf)
            .await
            .map_err(|e| IbexError::Peers(e.to_string()))?;
        Ok(())
    }
}
