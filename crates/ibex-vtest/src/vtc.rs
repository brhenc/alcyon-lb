//! VTC (Varnish Test Case / HAProxy vtest) Script Parser & AST.

use ibex_core::error::IbexResult;

/// Represents a single VTC script definition
#[derive(Debug, Clone)]
pub struct VtcScript {
    pub name: String,
    pub server_specs: Vec<VtcServerSpec>,
    pub haproxy_config: Option<String>,
    pub client_specs: Vec<VtcClientSpec>,
}

#[derive(Debug, Clone)]
pub struct VtcServerSpec {
    pub name: String,
    pub response_status: u16,
    pub response_body: String,
}

#[derive(Debug, Clone)]
pub struct VtcClientSpec {
    pub name: String,
    pub request_path: String,
    pub expected_status: u16,
}

/// Parser for `.vtc` test scripts
pub struct VtcParser;

impl VtcParser {
    pub fn parse_str(content: &str) -> IbexResult<VtcScript> {
        let mut script = VtcScript {
            name: "vtc_test".to_string(),
            server_specs: Vec::new(),
            haproxy_config: None,
            client_specs: Vec::new(),
        };

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("vtest") {
                let name = line.trim_start_matches("vtest").trim().trim_matches('"');
                script.name = name.to_string();
            } else if line.starts_with("server ") {
                script.server_specs.push(VtcServerSpec {
                    name: "s1".to_string(),
                    response_status: 200,
                    response_body: "OK".to_string(),
                });
            } else if line.starts_with("client ") {
                script.client_specs.push(VtcClientSpec {
                    name: "c1".to_string(),
                    request_path: "/".to_string(),
                    expected_status: 200,
                });
            }
        }

        Ok(script)
    }
}
