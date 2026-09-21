//! HAProxy Configuration AST definitions.

use std::time::Duration;

/// Proxy Mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    Http,
    Tcp,
}

impl Default for ProxyMode {
    fn default() -> Self {
        ProxyMode::Http
    }
}

/// Load Balancing Algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceAlgorithm {
    RoundRobin,
    LeastConn,
    SourceIp,
}

impl Default for BalanceAlgorithm {
    fn default() -> Self {
        BalanceAlgorithm::RoundRobin
    }
}

/// Global configuration section
#[derive(Debug, Clone, Default)]
pub struct GlobalSection {
    pub maxconn: Option<usize>,
    pub nbthread: Option<usize>,
    pub stats_socket: Option<String>,
}

/// Backend Server definition
#[derive(Debug, Clone)]
pub struct ServerDef {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub check: bool,
    pub weight: u32,
}

/// ACL Match Criterion
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclCriterion {
    PathBeg(String),
    PathExact(String),
    HostExact(String),
    MethodExact(String),
    SrcIp(String),
    SslFc,
}

/// ACL Definition
#[derive(Debug, Clone)]
pub struct AclDef {
    pub name: String,
    pub criterion: AclCriterion,
}

/// Conditional Backend Routing Rule
#[derive(Debug, Clone)]
pub struct UseBackendRule {
    pub backend_name: String,
    pub condition_acl: String,
    pub is_if: bool, // true for `if`, false for `unless`
}

/// Frontend Section
#[derive(Debug, Clone)]
pub struct FrontendSection {
    pub name: String,
    pub bind_addr: Option<String>,
    pub mode: ProxyMode,
    pub default_backend: Option<String>,
    pub acls: Vec<AclDef>,
    pub use_backends: Vec<UseBackendRule>,
    pub timeout_client: Option<Duration>,
}

/// Backend Section
#[derive(Debug, Clone)]
pub struct BackendSection {
    pub name: String,
    pub mode: ProxyMode,
    pub balance: BalanceAlgorithm,
    pub servers: Vec<ServerDef>,
    pub timeout_server: Option<Duration>,
    pub timeout_connect: Option<Duration>,
}

/// Peers Peer Definition
#[derive(Debug, Clone)]
pub struct PeerEntry {
    pub name: String,
    pub address: String,
}

/// Peers Section
#[derive(Debug, Clone)]
pub struct PeersSection {
    pub name: String,
    pub peers: Vec<PeerEntry>,
}

/// Complete HAProxy / Ibex Configuration File AST
#[derive(Debug, Clone, Default)]
pub struct IbexConfigAst {
    pub global: GlobalSection,
    pub frontends: Vec<FrontendSection>,
    pub backends: Vec<BackendSection>,
    pub peers: Vec<PeersSection>,
}
