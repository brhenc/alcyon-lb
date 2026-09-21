use crate::rcu_table::RcuRoutingTable;
use ibex_config::acl::{evaluate_acl, RequestEvaluationContext};
use ibex_config::ast::FrontendSection;
use ibex_core::error::{IbexError, IbexResult};
use ibex_parser::{DynamicParserSwitcher, ParserEngineKind};
use ibex_stick_table::{StickKey, StickTable};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Server Load Balancer Engine
pub struct IbexEngine {
    rcu_table: Arc<RcuRoutingTable>,
    stick_table: Arc<StickTable>,
}

impl IbexEngine {
    /// Creates a new proxy engine.
    pub fn new(rcu_table: Arc<RcuRoutingTable>, stick_table: Arc<StickTable>) -> Self {
        Self {
            rcu_table,
            stick_table,
        }
    }

    /// Handles a single incoming TCP client connection.
    pub async fn handle_client(
        &self,
        mut client_stream: TcpStream,
        peer_addr: SocketAddr,
        frontend: &FrontendSection,
    ) -> IbexResult<()> {
        let mut buffer = [0u8; 8192];
        let bytes_read = client_stream
            .read(&mut buffer)
            .await
            .map_err(|e| IbexError::Io(e.to_string()))?;

        if bytes_read == 0 {
            return Ok(());
        }

        // 1. Update Stick Table metrics for client IP
        let key = StickKey::Ip(peer_addr.ip());
        self.stick_table.update_entry(&key, |entry| {
            entry.conn_cnt += 1;
            entry.conn_cur += 1;
            if let Some(ref mut r) = entry.conn_rate {
                r.tick(1);
            }
        })?;

        // 2. Parse request using Dynamic Parser (HTX by default, or Pingora)
        let mut switcher = DynamicParserSwitcher::new(ParserEngineKind::Htx);
        let (req, _consumed) = match switcher.parse_request(&buffer[..bytes_read])? {
            Some(res) => res,
            None => {
                return Err(IbexError::Parser("Incomplete request".into()));
            }
        };

        // 3. Evaluate ACLs and determine target backend
        let ctx = RequestEvaluationContext {
            path: &req.uri,
            host: req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.as_str()),
            method: &req.method,
            src_ip: &peer_addr.ip().to_string(),
            is_ssl: false,
        };

        let snapshot = self.rcu_table.load();
        let mut target_backend_name = frontend.default_backend.as_deref();

        for rule in &frontend.use_backends {
            if let Some(acl) = frontend.acls.iter().find(|a| a.name == rule.condition_acl) {
                let matches = evaluate_acl(acl, &ctx);
                if (rule.is_if && matches) || (!rule.is_if && !matches) {
                    target_backend_name = Some(&rule.backend_name);
                    break;
                }
            }
        }

        let target_backend = target_backend_name
            .and_then(|name| snapshot.backends.iter().find(|b| b.name == name));

        // 4. Forward to backend or send 503
        if let Some(backend) = target_backend {
            if let Some(server) = backend.servers.first() {
                let upstream_addr = format!("{}:{}", server.address, server.port);
                if let Ok(mut upstream) = TcpStream::connect(&upstream_addr).await {
                    upstream
                        .write_all(&buffer[..bytes_read])
                        .await
                        .map_err(|e| IbexError::Io(e.to_string()))?;
                    let mut up_buf = [0u8; 8192];
                    let up_read = upstream
                        .read(&mut up_buf)
                        .await
                        .map_err(|e| IbexError::Io(e.to_string()))?;
                    client_stream
                        .write_all(&up_buf[..up_read])
                        .await
                        .map_err(|e| IbexError::Io(e.to_string()))?;
                    return Ok(());
                }
            }
        }

        // Send 503 Service Unavailable if no upstream reached
        let resp_503 = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 21\r\nConnection: close\r\n\r\nService Unavailable\n";
        let _ = client_stream.write_all(resp_503).await;
        Ok(())
    }
}
