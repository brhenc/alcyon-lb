// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-request use-service prometheus-exporter` (T368). Messages measured on HAProxy
//! 3.5-dev8-885761-29 built with USE_PROMEX=1: a service other than the exporter is an
//! "unknown service name", a missing name "expects a service name".

use alcyon_config::{parse_config, HttpReqAction};

fn cfg(section: &str, rules: &str) -> String {
    let bind = if section.starts_with("backend") { "" } else { "    bind 127.0.0.1:8080\n" };
    format!("defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n{section}\n{bind}{rules}")
}

fn refused(section: &str, rules: &str) -> String {
    match parse_config(&cfg(section, rules)) {
        Ok(_) => panic!("accepted in {section}: {rules}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn the_exporter_is_accepted_in_frontend_listen_and_backend_with_a_condition() {
    for section in ["frontend f", "listen f", "backend f"] {
        let c = parse_config(&cfg(section, "    http-request use-service prometheus-exporter if { path /metrics }\n    http-request use-service prometheus-exporter unless { path /x }\n"))
            .unwrap_or_else(|e| panic!("{section}: {e}"));
        let rules = c.frontends.first().map(|f| &f.http_req_rules).or_else(|| c.backends.first().map(|b| &b.http_req_rules)).or_else(|| c.listens.first().map(|l| &l.http_req_rules)).expect("a section");
        assert_eq!(rules.len(), 2, "{section}");
        assert!(rules.iter().all(|r| r.action == HttpReqAction::UseServicePrometheus && r.cond.is_some()), "{section}");
    }
}

#[test]
fn another_service_or_none_is_refused_with_haproxys_message() {
    let e = refused("frontend f", "    http-request use-service foo\n");
    assert!(e.contains("error detected in frontend 'f' while parsing 'http-request use-service' rule : 'foo' unknown service name.."), "{e}");
    let e = refused("frontend f", "    http-request use-service\n");
    assert!(e.contains("error detected in frontend 'f' while parsing 'http-request use-service' rule : 'use-service' expects a service name.."), "{e}");
}
