//! RCU-synchronized dynamic routing table without worker thread locking.

use arc_swap::ArcSwap;
use ibex_config::ast::{BackendSection, FrontendSection, IbexConfigAst};
use std::sync::Arc;

/// Immutable snapshot of the routing and configuration state
#[derive(Debug, Clone, Default)]
pub struct RoutingSnapshot {
    pub frontends: Vec<FrontendSection>,
    pub backends: Vec<BackendSection>,
}

/// RCU Routing Table using `ArcSwap` for lock-free read access on hot path
pub struct RcuRoutingTable {
    current: ArcSwap<RoutingSnapshot>,
}

impl RcuRoutingTable {
    /// Creates a new RCU table with initial snapshot.
    pub fn new(initial: RoutingSnapshot) -> Self {
        Self {
            current: ArcSwap::from_pointee(initial),
        }
    }

    /// Loads the current routing snapshot for reading (lock-free).
    #[inline(always)]
    pub fn load(&self) -> Arc<RoutingSnapshot> {
        self.current.load_full()
    }

    /// Replaces the routing table with a new configuration snapshot atomically.
    pub fn swap_config(&self, ast: &IbexConfigAst) {
        let snapshot = RoutingSnapshot {
            frontends: ast.frontends.clone(),
            backends: ast.backends.clone(),
        };
        self.current.store(Arc::new(snapshot));
    }
}

impl Default for RcuRoutingTable {
    fn default() -> Self {
        Self::new(RoutingSnapshot::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rcu_table_swap() {
        let table = RcuRoutingTable::default();
        assert_eq!(table.load().frontends.len(), 0);

        let mut ast = IbexConfigAst::default();
        ast.frontends.push(FrontendSection {
            name: "fe_test".to_string(),
            bind_addr: Some("127.0.0.1:8080".to_string()),
            mode: ibex_config::ast::ProxyMode::Http,
            default_backend: None,
            acls: Vec::new(),
            use_backends: Vec::new(),
            timeout_client: None,
        });

        table.swap_config(&ast);
        let current = table.load();
        assert_eq!(current.frontends.len(), 1);
        assert_eq!(current.frontends[0].name, "fe_test");
    }
}
