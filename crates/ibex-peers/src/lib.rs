//! # `ibex-peers`
//!
//! HAProxy Peer Protocol (v2 / v2.1) implementation for real-time stick table
//! synchronization between Ibex and HAProxy nodes in hybrid clusters.

pub mod protocol;
pub mod sync;

pub use protocol::{PeerCodec, PeerKey, PeerMessage, VarintCodec};
pub use sync::{PeerNodeConfig, PeerSession, PeerState};
