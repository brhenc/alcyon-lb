//! HAProxy configuration grammar parser.

use crate::ast::*;
use ibex_core::error::IbexResult;

/// Parser for HAProxy-compatible configuration syntax
pub struct ConfigParser;

impl ConfigParser {
    /// Parses an HAProxy configuration string into AST.
    pub fn parse_str(content: &str) -> IbexResult<IbexConfigAst> {
        let mut ast = IbexConfigAst::default();
        let mut current_frontend: Option<FrontendSection> = None;
        let mut current_backend: Option<BackendSection> = None;
        let mut current_peers: Option<PeersSection> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.is_empty() {
                continue;
            }

            match tokens[0] {
                "global" => {
                    Self::flush_sections(
                        &mut ast,
                        &mut current_frontend,
                        &mut current_backend,
                        &mut current_peers,
                    );
                }
                "frontend" => {
                    Self::flush_sections(
                        &mut ast,
                        &mut current_frontend,
                        &mut current_backend,
                        &mut current_peers,
                    );
                    let name = tokens.get(1).unwrap_or(&"default_fe").to_string();
                    current_frontend = Some(FrontendSection {
                        name,
                        bind_addr: None,
                        mode: ProxyMode::Http,
                        default_backend: None,
                        acls: Vec::new(),
                        use_backends: Vec::new(),
                        timeout_client: None,
                    });
                }
                "backend" => {
                    Self::flush_sections(
                        &mut ast,
                        &mut current_frontend,
                        &mut current_backend,
                        &mut current_peers,
                    );
                    let name = tokens.get(1).unwrap_or(&"default_be").to_string();
                    current_backend = Some(BackendSection {
                        name,
                        mode: ProxyMode::Http,
                        balance: BalanceAlgorithm::RoundRobin,
                        servers: Vec::new(),
                        timeout_server: None,
                        timeout_connect: None,
                    });
                }
                "peers" => {
                    Self::flush_sections(
                        &mut ast,
                        &mut current_frontend,
                        &mut current_backend,
                        &mut current_peers,
                    );
                    let name = tokens.get(1).unwrap_or(&"default_peers").to_string();
                    current_peers = Some(PeersSection {
                        name,
                        peers: Vec::new(),
                    });
                }
                "bind" => {
                    if let Some(ref mut fe) = current_frontend {
                        if let Some(addr) = tokens.get(1) {
                            fe.bind_addr = Some(addr.to_string());
                        }
                    }
                }
                "mode" => {
                    let mode = if tokens.get(1) == Some(&"tcp") {
                        ProxyMode::Tcp
                    } else {
                        ProxyMode::Http
                    };
                    if let Some(ref mut fe) = current_frontend {
                        fe.mode = mode;
                    } else if let Some(ref mut be) = current_backend {
                        be.mode = mode;
                    }
                }
                "default_backend" => {
                    if let Some(ref mut fe) = current_frontend {
                        if let Some(be) = tokens.get(1) {
                            fe.default_backend = Some(be.to_string());
                        }
                    }
                }
                "balance" => {
                    if let Some(ref mut be) = current_backend {
                        let algo = match tokens.get(1).copied() {
                            Some("leastconn") => BalanceAlgorithm::LeastConn,
                            Some("source") => BalanceAlgorithm::SourceIp,
                            _ => BalanceAlgorithm::RoundRobin,
                        };
                        be.balance = algo;
                    }
                }
                "server" => {
                    if let Some(ref mut be) = current_backend {
                        if tokens.len() >= 3 {
                            let name = tokens[1].to_string();
                            let addr_port = tokens[2];
                            let (addr, port) = if let Some(colon) = addr_port.rfind(':') {
                                let addr = addr_port[..colon].to_string();
                                let port = addr_port[colon + 1..].parse::<u16>().unwrap_or(80);
                                (addr, port)
                            } else {
                                (addr_port.to_string(), 80)
                            };
                            let check = tokens.contains(&"check");
                            be.servers.push(ServerDef {
                                name,
                                address: addr,
                                port,
                                check,
                                weight: 1,
                            });
                        }
                    }
                }
                "peer" => {
                    if let Some(ref mut pr) = current_peers {
                        if tokens.len() >= 3 {
                            pr.peers.push(PeerEntry {
                                name: tokens[1].to_string(),
                                address: tokens[2].to_string(),
                            });
                        }
                    }
                }
                "acl" => {
                    if let Some(ref mut fe) = current_frontend {
                        if tokens.len() >= 4 {
                            let name = tokens[1].to_string();
                            let match_type = tokens[2];
                            let pattern = tokens[3].to_string();
                            let criterion = match match_type {
                                "path_beg" => AclCriterion::PathBeg(pattern),
                                "path" => AclCriterion::PathExact(pattern),
                                "hdr(host)" | "hdr_dom(host)" => AclCriterion::HostExact(pattern),
                                "method" => AclCriterion::MethodExact(pattern),
                                "src" => AclCriterion::SrcIp(pattern),
                                _ => AclCriterion::PathBeg(pattern),
                            };
                            fe.acls.push(AclDef { name, criterion });
                        }
                    }
                }
                "use_backend" => {
                    if let Some(ref mut fe) = current_frontend {
                        if tokens.len() >= 4 {
                            let backend_name = tokens[1].to_string();
                            let is_if = tokens[2] == "if";
                            let condition_acl = tokens[3].to_string();
                            fe.use_backends.push(UseBackendRule {
                                backend_name,
                                condition_acl,
                                is_if,
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Self::flush_sections(
            &mut ast,
            &mut current_frontend,
            &mut current_backend,
            &mut current_peers,
        );
        Ok(ast)
    }

    fn flush_sections(
        ast: &mut IbexConfigAst,
        fe: &mut Option<FrontendSection>,
        be: &mut Option<BackendSection>,
        pr: &mut Option<PeersSection>,
    ) {
        if let Some(f) = fe.take() {
            ast.frontends.push(f);
        }
        if let Some(b) = be.take() {
            ast.backends.push(b);
        }
        if let Some(p) = pr.take() {
            ast.peers.push(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_haproxy_config() {
        let sample = r#"
global
    maxconn 50000

frontend http_in
    bind *:80
    mode http
    acl is_api path_beg /api/
    use_backend api_servers if is_api
    default_backend web_servers

backend api_servers
    mode http
    balance roundrobin
    server api1 10.0.0.1:8080 check
    server api2 10.0.0.2:8080 check

backend web_servers
    mode http
    balance roundrobin
    server web1 10.0.0.10:80 check

peers cluster_peers
    peer lb1 192.168.1.1:1024
    peer lb2 192.168.1.2:1024
"#;

        let ast = ConfigParser::parse_str(sample).expect("Parsed successfully");
        assert_eq!(ast.frontends.len(), 1);
        assert_eq!(ast.frontends[0].name, "http_in");
        assert_eq!(ast.frontends[0].bind_addr, Some("*:80".to_string()));
        assert_eq!(ast.frontends[0].acls.len(), 1);
        assert_eq!(ast.frontends[0].use_backends.len(), 1);

        assert_eq!(ast.backends.len(), 2);
        assert_eq!(ast.backends[0].name, "api_servers");
        assert_eq!(ast.backends[0].servers.len(), 2);

        assert_eq!(ast.peers.len(), 1);
        assert_eq!(ast.peers[0].peers.len(), 2);
    }
}
