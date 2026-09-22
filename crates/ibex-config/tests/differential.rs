// SPDX-License-Identifier: GPL-2.0-or-later
//
// HAProxy 1.0 configuration parser, ported to Rust.
// Derived from HAProxy 1.0.2 (haproxy.c) by Willy Tarreau <willy@meta-x.org>.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use ibex_config::parse_config;
use ibex_config::{
    AclCondition, AclTerm, TcpReqConnAction, TcpReqContentAction, TcpReqSessionAction,
};

const ORACLE_BIN: &str = "/home/bhenc/reference/haproxy/haproxy";

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    Reject,
}

fn run_oracle(config_path: &Path) -> (Verdict, String) {
    let output = match Command::new(ORACLE_BIN)
        .arg("-c")
        .arg("-f")
        .arg(config_path)
        .output()
    {
        Ok(out) => out,
        Err(e) => panic!("Failed to execute oracle binary at {ORACLE_BIN}: {e}"),
    };
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if output.status.success() {
        (Verdict::Accept, stderr)
    } else {
        (Verdict::Reject, stderr)
    }
}

#[test]
fn test_corpus_differential() {
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut entries: Vec<_> = fs::read_dir(&corpus_dir)
        .expect("Read corpus dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "cfg"))
        .collect();

    entries.sort();
    assert!(
        entries.len() >= 25,
        "Corpus must have at least 25 test configs, found {}",
        entries.len()
    );

    // Previously these four were expected to disagree, because HAProxy 1.0.2's C
    // `atol()` silently accepted non-numeric and out-of-range values where Ibex
    // rejected them. The oracle is now HAProxy 3.5, which validates properly and
    // rejects all four -- so they agree, and carrying the exception list would assert
    // a disagreement that no longer exists.
    let known_disagreements: [&str; 0] = [];

    let mut agreed_count = 0;
    let mut disagreement_count = 0;

    for path in &entries {
        let filename = path.file_name().unwrap().to_str().unwrap();
        let (oracle_verdict, oracle_msg) = run_oracle(path);
        let ibex_result = ibex_config::parse_file(path);
        let ibex_verdict = if ibex_result.is_ok() {
            Verdict::Accept
        } else {
            Verdict::Reject
        };

        let is_disagreement = known_disagreements.contains(&filename);

        if is_disagreement {
            disagreement_count += 1;
            assert_eq!(
                oracle_verdict,
                Verdict::Accept,
                "Case {filename} expected Oracle to accept due to 2001 C atol/overflow behavior"
            );
            assert_eq!(
                ibex_verdict,
                Verdict::Reject,
                "Case {filename} expected Ibex to reject invalid input"
            );
            println!(
                "[DISAGREEMENT] {filename}: Oracle={oracle_verdict:?}, Ibex={ibex_verdict:?} (Err: {})",
                ibex_result.unwrap_err()
            );
        } else {
            assert_eq!(
                oracle_verdict, ibex_verdict,
                "Mismatch on {filename}!\nOracle verdict: {oracle_verdict:?}\nOracle output: {oracle_msg}\nIbex verdict: {ibex_verdict:?}\nIbex result: {ibex_result:?}"
            );
            agreed_count += 1;
            println!("[AGREE] {filename}: {ibex_verdict:?}");
        }
    }

    println!(
        "\nCorpus verification complete: {} total cases, {} agreed, {} documented disagreements",
        entries.len(),
        agreed_count,
        disagreement_count
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_tcp_request_content_parsing() {
    let cfg_str = r"
frontend fe
    bind :8080
    tcp-request content sc-inc-gpc0
    tcp-request content sc-inc-gpc0(0)
    tcp-request content sc-inc-gpc0(1)
    tcp-request content sc-inc-gpc0(2)
    tcp-request content track-sc0 src
    tcp-request content track-sc1 src table t1
    tcp-request content track-sc2 src
    tcp-request content set-src src
    tcp-request content set-dst dst
    tcp-request content set-var(sess.foo) str(bar)
    tcp-request content set-var-fmt(sess.baz) %[src]
    tcp-request content unset-var(sess.foo)
    tcp-request content switch-mode http proto h2
    tcp-request content accept if is_ssl
    tcp-request content reject unless is_trusted
    tcp-request content silent-drop if is_bad !is_local

backend be
    tcp-request content track-sc0 src table t_backend if is_valid
    tcp-request content switch-mode http
";

    let cfg = parse_config(cfg_str).expect("Valid config with tcp-request content must parse");
    let fe_rules = &cfg.frontends[0].tcp_req_content_rules;
    assert_eq!(fe_rules.len(), 16);

    // sc-inc-gpc0 variants
    assert_eq!(fe_rules[0].action, TcpReqContentAction::ScIncGpc0 { sc: 0 });
    assert_eq!(fe_rules[0].cond, None);

    assert_eq!(fe_rules[1].action, TcpReqContentAction::ScIncGpc0 { sc: 0 });
    assert_eq!(fe_rules[1].cond, None);

    assert_eq!(fe_rules[2].action, TcpReqContentAction::ScIncGpc0 { sc: 1 });
    assert_eq!(fe_rules[2].cond, None);

    assert_eq!(fe_rules[3].action, TcpReqContentAction::ScIncGpc0 { sc: 2 });
    assert_eq!(fe_rules[3].cond, None);

    // track-sc variants
    assert_eq!(
        fe_rules[4].action,
        TcpReqContentAction::TrackSc0 {
            expr: "src".to_string(),
            table: None,
        }
    );
    assert_eq!(fe_rules[4].cond, None);

    assert_eq!(
        fe_rules[5].action,
        TcpReqContentAction::TrackSc1 {
            expr: "src".to_string(),
            table: Some("t1".to_string()),
        }
    );
    assert_eq!(fe_rules[5].cond, None);

    assert_eq!(
        fe_rules[6].action,
        TcpReqContentAction::TrackSc2 {
            expr: "src".to_string(),
            table: None,
        }
    );
    assert_eq!(fe_rules[6].cond, None);

    // set-src and set-dst
    assert_eq!(
        fe_rules[7].action,
        TcpReqContentAction::SetSrc {
            expr: "src".to_string(),
        }
    );
    assert_eq!(fe_rules[7].cond, None);

    assert_eq!(
        fe_rules[8].action,
        TcpReqContentAction::SetDst {
            expr: "dst".to_string(),
        }
    );
    assert_eq!(fe_rules[8].cond, None);

    // set-var, set-var-fmt, unset-var
    assert_eq!(
        fe_rules[9].action,
        TcpReqContentAction::SetVar {
            var_name: "sess.foo".to_string(),
            expr: "str(bar)".to_string(),
        }
    );
    assert_eq!(fe_rules[9].cond, None);

    assert_eq!(
        fe_rules[10].action,
        TcpReqContentAction::SetVarFmt {
            var_name: "sess.baz".to_string(),
            fmt: "%[src]".to_string(),
        }
    );
    assert_eq!(fe_rules[10].cond, None);

    assert_eq!(
        fe_rules[11].action,
        TcpReqContentAction::UnsetVar {
            var_name: "sess.foo".to_string(),
        }
    );
    assert_eq!(fe_rules[11].cond, None);

    // switch-mode http proto h2
    assert_eq!(
        fe_rules[12].action,
        TcpReqContentAction::SwitchModeHttp {
            proto: Some("h2".to_string()),
        }
    );
    assert_eq!(fe_rules[12].cond, None);

    // accept if is_ssl
    assert_eq!(fe_rules[13].action, TcpReqContentAction::Accept);
    assert_eq!(
        fe_rules[13].cond,
        Some(AclCondition {
            is_if: true,
            terms: vec![AclTerm {
                negated: false,
                name: "is_ssl".to_string(),
            }],
        })
    );

    // reject unless is_trusted
    assert_eq!(fe_rules[14].action, TcpReqContentAction::Reject);
    assert_eq!(
        fe_rules[14].cond,
        Some(AclCondition {
            is_if: false,
            terms: vec![AclTerm {
                negated: false,
                name: "is_trusted".to_string(),
            }],
        })
    );

    // silent-drop if is_bad !is_local
    assert_eq!(fe_rules[15].action, TcpReqContentAction::SilentDrop);
    assert_eq!(
        fe_rules[15].cond,
        Some(AclCondition {
            is_if: true,
            terms: vec![
                AclTerm {
                    negated: false,
                    name: "is_bad".to_string(),
                },
                AclTerm {
                    negated: true,
                    name: "is_local".to_string(),
                },
            ],
        })
    );

    // backend tcp-request content
    let be_rules = &cfg.backends[0].tcp_req_content_rules;
    assert_eq!(be_rules.len(), 2);
    assert_eq!(
        be_rules[0].action,
        TcpReqContentAction::TrackSc0 {
            expr: "src".to_string(),
            table: Some("t_backend".to_string()),
        }
    );
    assert_eq!(
        be_rules[0].cond,
        Some(AclCondition {
            is_if: true,
            terms: vec![AclTerm {
                negated: false,
                name: "is_valid".to_string(),
            }],
        })
    );
    assert_eq!(
        be_rules[1].action,
        TcpReqContentAction::SwitchModeHttp { proto: None }
    );
    assert_eq!(be_rules[1].cond, None);
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_tcp_request_session_parsing() {
    let cfg_str = r"
frontend fe
    bind :8080
    tcp-request session track-sc0 src
    tcp-request session track-sc1 src table t1
    tcp-request session track-sc2 src
    tcp-request session set-var(sess.foo) str(bar)
    tcp-request session set-var-fmt(sess.baz) %[src]
    tcp-request session unset-var(sess.foo)
    tcp-request session set-src src
    tcp-request session set-dst dst
    tcp-request session accept if is_local
    tcp-request session reject unless is_trusted
    tcp-request session silent-drop if is_bad

listen li
    bind :8081
    tcp-request session track-sc0 src table t_listen if is_allowed
    tcp-request session accept
";

    let cfg = parse_config(cfg_str).expect("Valid config with tcp-request session must parse");
    let fe_rules = &cfg.frontends[0].tcp_req_session_rules;
    assert_eq!(fe_rules.len(), 11);

    // track-sc variants
    assert_eq!(
        fe_rules[0].action,
        TcpReqSessionAction::TrackSc0 {
            expr: "src".to_string(),
            table: None,
        }
    );
    assert_eq!(fe_rules[0].cond, None);

    assert_eq!(
        fe_rules[1].action,
        TcpReqSessionAction::TrackSc1 {
            expr: "src".to_string(),
            table: Some("t1".to_string()),
        }
    );
    assert_eq!(fe_rules[1].cond, None);

    assert_eq!(
        fe_rules[2].action,
        TcpReqSessionAction::TrackSc2 {
            expr: "src".to_string(),
            table: None,
        }
    );
    assert_eq!(fe_rules[2].cond, None);

    // set-var, set-var-fmt, unset-var
    assert_eq!(
        fe_rules[3].action,
        TcpReqSessionAction::SetVar {
            var_name: "sess.foo".to_string(),
            expr: "str(bar)".to_string(),
        }
    );
    assert_eq!(fe_rules[3].cond, None);

    assert_eq!(
        fe_rules[4].action,
        TcpReqSessionAction::SetVarFmt {
            var_name: "sess.baz".to_string(),
            fmt: "%[src]".to_string(),
        }
    );
    assert_eq!(fe_rules[4].cond, None);

    assert_eq!(
        fe_rules[5].action,
        TcpReqSessionAction::UnsetVar {
            var_name: "sess.foo".to_string(),
        }
    );
    assert_eq!(fe_rules[5].cond, None);

    // set-src, set-dst
    assert_eq!(
        fe_rules[6].action,
        TcpReqSessionAction::SetSrc {
            expr: "src".to_string(),
        }
    );
    assert_eq!(fe_rules[6].cond, None);

    assert_eq!(
        fe_rules[7].action,
        TcpReqSessionAction::SetDst {
            expr: "dst".to_string(),
        }
    );
    assert_eq!(fe_rules[7].cond, None);

    // accept, reject, silent-drop
    assert_eq!(fe_rules[8].action, TcpReqSessionAction::Accept);
    assert_eq!(
        fe_rules[8].cond,
        Some(AclCondition {
            is_if: true,
            terms: vec![AclTerm {
                negated: false,
                name: "is_local".to_string(),
            }],
        })
    );

    assert_eq!(fe_rules[9].action, TcpReqSessionAction::Reject);
    assert_eq!(
        fe_rules[9].cond,
        Some(AclCondition {
            is_if: false,
            terms: vec![AclTerm {
                negated: false,
                name: "is_trusted".to_string(),
            }],
        })
    );

    assert_eq!(fe_rules[10].action, TcpReqSessionAction::SilentDrop);
    assert_eq!(
        fe_rules[10].cond,
        Some(AclCondition {
            is_if: true,
            terms: vec![AclTerm {
                negated: false,
                name: "is_bad".to_string(),
            }],
        })
    );

    // listen section
    let li_rules = &cfg.listens[0].tcp_req_session_rules;
    assert_eq!(li_rules.len(), 2);
    assert_eq!(
        li_rules[0].action,
        TcpReqSessionAction::TrackSc0 {
            expr: "src".to_string(),
            table: Some("t_listen".to_string()),
        }
    );
    assert_eq!(
        li_rules[0].cond,
        Some(AclCondition {
            is_if: true,
            terms: vec![AclTerm {
                negated: false,
                name: "is_allowed".to_string(),
            }],
        })
    );
    assert_eq!(li_rules[1].action, TcpReqSessionAction::Accept);
    assert_eq!(li_rules[1].cond, None);
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_tcp_request_connection_parsing() {
    let cfg_str = r"
frontend fe
    bind :8080
    tcp-request connection track-sc0 src
    tcp-request connection track-sc1 src table t1
    tcp-request connection track-sc2 src
    tcp-request connection set-src src
    tcp-request connection set-dst dst
    tcp-request connection accept if is_local
    tcp-request connection reject unless is_trusted
    tcp-request connection silent-drop if is_bad

listen li
    bind :8081
    tcp-request connection track-sc1 src table t_listen if is_allowed
    tcp-request connection accept
";

    let cfg = parse_config(cfg_str).expect("Valid config with tcp-request connection must parse");
    let fe_rules = &cfg.frontends[0].tcp_req_conn_rules;
    assert_eq!(fe_rules.len(), 8);

    // track-sc variants
    assert_eq!(
        fe_rules[0].action,
        TcpReqConnAction::TrackSc0 {
            expr: "src".to_string(),
            table: None,
        }
    );
    assert_eq!(fe_rules[0].cond, None);

    assert_eq!(
        fe_rules[1].action,
        TcpReqConnAction::TrackSc1 {
            expr: "src".to_string(),
            table: Some("t1".to_string()),
        }
    );
    assert_eq!(fe_rules[1].cond, None);

    assert_eq!(
        fe_rules[2].action,
        TcpReqConnAction::TrackSc2 {
            expr: "src".to_string(),
            table: None,
        }
    );
    assert_eq!(fe_rules[2].cond, None);

    // set-src, set-dst
    assert_eq!(
        fe_rules[3].action,
        TcpReqConnAction::SetSrc {
            expr: "src".to_string(),
        }
    );
    assert_eq!(fe_rules[3].cond, None);

    assert_eq!(
        fe_rules[4].action,
        TcpReqConnAction::SetDst {
            expr: "dst".to_string(),
        }
    );
    assert_eq!(fe_rules[4].cond, None);

    // accept, reject, silent-drop
    assert_eq!(fe_rules[5].action, TcpReqConnAction::Accept);
    assert_eq!(
        fe_rules[5].cond,
        Some(AclCondition {
            is_if: true,
            terms: vec![AclTerm {
                negated: false,
                name: "is_local".to_string(),
            }],
        })
    );

    assert_eq!(fe_rules[6].action, TcpReqConnAction::Reject);
    assert_eq!(
        fe_rules[6].cond,
        Some(AclCondition {
            is_if: false,
            terms: vec![AclTerm {
                negated: false,
                name: "is_trusted".to_string(),
            }],
        })
    );

    assert_eq!(fe_rules[7].action, TcpReqConnAction::SilentDrop);
    assert_eq!(
        fe_rules[7].cond,
        Some(AclCondition {
            is_if: true,
            terms: vec![AclTerm {
                negated: false,
                name: "is_bad".to_string(),
            }],
        })
    );

    // listen section
    let li_rules = &cfg.listens[0].tcp_req_conn_rules;
    assert_eq!(li_rules.len(), 2);
    assert_eq!(
        li_rules[0].action,
        TcpReqConnAction::TrackSc1 {
            expr: "src".to_string(),
            table: Some("t_listen".to_string()),
        }
    );
    assert_eq!(
        li_rules[0].cond,
        Some(AclCondition {
            is_if: true,
            terms: vec![AclTerm {
                negated: false,
                name: "is_allowed".to_string(),
            }],
        })
    );
    assert_eq!(li_rules[1].action, TcpReqConnAction::Accept);
    assert_eq!(li_rules[1].cond, None);
}

#[test]
fn test_tcp_request_inspect_delay_parsing() {
    let cfg_str = r"
defaults
    tcp-request inspect-delay 10s

frontend fe
    bind :8080
    tcp-request inspect-delay 5s

listen li
    bind :8081
    tcp-request inspect-delay 500ms

backend be
    tcp-request inspect-delay 1m
";

    let cfg = parse_config(cfg_str).expect("Valid config with inspect-delay must parse");
    assert_eq!(
        cfg.defaults.as_ref().unwrap().tcp_req_inspect_delay,
        Some(Duration::from_secs(10))
    );
    assert_eq!(
        cfg.frontends[0].tcp_req_inspect_delay,
        Some(Duration::from_secs(5))
    );
    assert_eq!(
        cfg.listens[0].tcp_req_inspect_delay,
        Some(Duration::from_millis(500))
    );
    assert_eq!(
        cfg.backends[0].tcp_req_inspect_delay,
        Some(Duration::from_secs(60))
    );
}

#[test]
fn test_unsupported_actions_refusal() {
    let cases = [
        (
            "frontend fe\n    bind :8080\n    tcp-request content lua.handler\n",
            "lua actions require Lua support",
        ),
        (
            "frontend fe\n    bind :8080\n    tcp-request content use-service s1\n",
            "use-service",
        ),
        (
            "frontend fe\n    bind :8080\n    tcp-request session attach-srv s1\n",
            "attach-srv",
        ),
        (
            "frontend fe\n    bind :8080\n    tcp-request content do-log\n",
            "do-log",
        ),
        (
            "frontend fe\n    bind :8080\n    tcp-request session do-log\n",
            "do-log",
        ),
        (
            "frontend fe\n    bind :8080\n    tcp-request connection do-log\n",
            "do-log",
        ),
        (
            "frontend fe\n    bind :8080\n    tcp-request content sc-inc-gpc0(99)\n",
            "stick counter index must be 0, 1, or 2",
        ),
        (
            "frontend fe\n    bind :8080\n    tcp-request content sc-inc-gpc0(abc)\n",
            "invalid stick counter index",
        ),
        (
            "frontend fe\n    bind :8080\n    tcp-request content sc-inc-gpc0(0\n",
            "missing closing parenthesis",
        ),
        (
            "backend be\n    tcp-request connection accept\n",
            "'tcp-request connection' is not allowed in a backend",
        ),
        (
            "backend be\n    tcp-request session accept\n",
            "'tcp-request session' is not allowed in a backend",
        ),
        (
            "frontend fe\n    bind :8080\n    tcp-request connection lua.handler\n",
            "lua actions require Lua support",
        ),
        (
            "frontend fe\n    bind :8080\n    tcp-request session lua.handler\n",
            "lua actions require Lua support",
        ),
    ];

    for (cfg_str, expected_err) in cases {
        let res = parse_config(cfg_str);
        assert!(
            res.is_err(),
            "Expected configuration to be rejected:\n{cfg_str}"
        );
        let err = res.unwrap_err();
        assert!(
            err.message.contains(expected_err),
            "Expected error message containing '{expected_err}', got: '{}'\nConfig:\n{cfg_str}",
            err.message
        );
    }
}

