// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// HAProxy 1.0 configuration parser, ported to Rust.
// Derived from HAProxy 1.0.2 (haproxy.c) by Willy Tarreau <willy@meta-x.org>.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use alcyon_config::parse_config;
use alcyon_config::{
    AclCondition, AclTerm, TcpReqConnAction, TcpReqContentAction, TcpReqSessionAction,
};

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    Reject,
}

fn run_oracle(oracle: &Path, config_path: &Path) -> (Verdict, String) {
    let output = match Command::new(oracle)
        .arg("-c")
        .arg("-f")
        .arg(config_path)
        .output()
    {
        Ok(out) => out,
        Err(e) => panic!("Failed to execute oracle binary at {}: {e}", oracle.display()),
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
    // The oracle is HAProxy 3.5 (`$ALCYON_REFERENCE/haproxy/haproxy`); without it there is
    // nothing to compare against.
    let Some(oracle) = crate::reference::reference("haproxy/haproxy") else { return };
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
    // `atol()` silently accepted non-numeric and out-of-range values where Alcyon
    // rejected them. The oracle is now HAProxy 3.5, which validates properly and
    // rejects all four -- so they agree, and carrying the exception list would assert
    // a disagreement that no longer exists.
    let known_disagreements: [&str; 0] = [];

    let mut agreed_count = 0;
    let mut disagreement_count = 0;

    for path in &entries {
        let filename = path.file_name().unwrap().to_str().unwrap();
        let (oracle_verdict, oracle_msg) = run_oracle(&oracle, path);
        let alcyon_result = alcyon_config::parse_file(path);
        let alcyon_verdict = if alcyon_result.is_ok() {
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
                alcyon_verdict,
                Verdict::Reject,
                "Case {filename} expected Alcyon to reject invalid input"
            );
            println!(
                "[DISAGREEMENT] {filename}: Oracle={oracle_verdict:?}, Alcyon={alcyon_verdict:?} (Err: {})",
                alcyon_result.unwrap_err()
            );
        } else {
            assert_eq!(
                oracle_verdict, alcyon_verdict,
                "Mismatch on {filename}!\nOracle verdict: {oracle_verdict:?}\nOracle output: {oracle_msg}\nAlcyon verdict: {alcyon_verdict:?}\nAlcyon result: {alcyon_result:?}"
            );
            agreed_count += 1;
            println!("[AGREE] {filename}: {alcyon_verdict:?}");
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
    acl is_ssl ssl_fc
    acl is_trusted src 10.0.0.0/8
    acl is_bad src 192.0.2.0/24
    acl is_local src 127.0.0.0/8
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
    acl is_valid src 10.0.0.0/8
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
    acl is_local src 127.0.0.0/8
    acl is_trusted src 10.0.0.0/8
    acl is_bad src 192.0.2.0/24
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
    acl is_allowed src 10.0.0.0/8
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
    acl is_local src 127.0.0.0/8
    acl is_trusted src 10.0.0.0/8
    acl is_bad src 192.0.2.0/24
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
    acl is_allowed src 10.0.0.0/8
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

#[test]
fn test_tune_bufsize_validation() {
    // 1. tune.bufsize >= 256 MB (268435456) must be refused
    let cfg_too_large = "global\n    tune.bufsize 268435456\n";
    let res = parse_config(cfg_too_large);
    assert!(res.is_err(), "tune.bufsize >= 256MB must be refused");
    assert!(
        res.unwrap_err().message.contains("268435456"),
        "error must name the 268435456 limit"
    );

    // 2. tune.bufsize below 16384 with HTTP/2 configured must be refused
    let cfg_h2_small_buf = "global\n    tune.bufsize 8192\nfrontend fe\n    bind :8080 proto h2\n";
    let res_h2 = parse_config(cfg_h2_small_buf);
    assert!(
        res_h2.is_err(),
        "tune.bufsize < 16384 with HTTP/2 must be refused"
    );
    assert!(
        res_h2.unwrap_err().message.contains("16384"),
        "error must name 16384 minimum limit when HTTP/2 is configured"
    );

    // 3. Rounding is applied: 16385 rounds up to next multiple of 16 (16400)
    let cfg_rounding = "global\n    tune.bufsize 16385\n    tune.bufsize.small 1025\n    tune.bufsize.large 65537\n";
    let parsed = parse_config(cfg_rounding).expect("parse valid tune.bufsize with rounding");
    let g = parsed.global.expect("global section present");
    assert_eq!(g.bufsize, Some(16400), "tune.bufsize must be rounded up to multiple of 16");
    assert_eq!(g.bufsize_small, Some(1040), "tune.bufsize.small must be rounded up to multiple of 16");
    assert_eq!(g.bufsize_large, Some(65552), "tune.bufsize.large must be rounded up to multiple of 16");
}

#[test]
fn test_http_reuse_parsing() {
    use alcyon_config::HttpReuse;

    let cfg_str = r"
defaults
    http-reuse safe

backend be_inherited
    server s1 127.0.0.1:8080

backend be_override
    http-reuse never
    server s1 127.0.0.1:8080

backend be_aggressive
    http-reuse aggressive
    server s1 127.0.0.1:8080

backend be_always
    http-reuse always
    server s1 127.0.0.1:8080

listen li_custom
    bind :8081
    http-reuse never
    server s1 127.0.0.1:8080
";

    let cfg = parse_config(cfg_str).expect("Valid config with http-reuse must parse");
    assert_eq!(
        cfg.defaults.as_ref().unwrap().http_reuse,
        Some(HttpReuse::Safe)
    );
    assert_eq!(cfg.backends[0].http_reuse, Some(HttpReuse::Safe));
    assert_eq!(cfg.backends[1].http_reuse, Some(HttpReuse::Never));
    assert_eq!(cfg.backends[2].http_reuse, Some(HttpReuse::Aggressive));
    assert_eq!(cfg.backends[3].http_reuse, Some(HttpReuse::Always));
    assert_eq!(cfg.listens[0].http_reuse, Some(HttpReuse::Never));

    // Invalid strategy rejected
    let invalid_cfg = "backend be\n    http-reuse invalid_strategy\n";
    let res = parse_config(invalid_cfg);
    assert!(res.is_err(), "Invalid http-reuse strategy must be rejected");
    assert!(res.unwrap_err().message.contains("unknown http-reuse strategy"));

    // Missing argument rejected
    let missing_arg_cfg = "backend be\n    http-reuse\n";
    let res2 = parse_config(missing_arg_cfg);
    assert!(res2.is_err(), "Missing http-reuse argument must be rejected");
}

#[test]
fn test_global_and_defaults_unknown_keywords_refusal() {
    let bad_global = "global\n\tthis-global-keyword-does-not-exist 42\n";
    let err_g = parse_config(bad_global).unwrap_err();
    assert!(
        err_g.message.contains("unknown keyword 'this-global-keyword-does-not-exist' in 'global' section"),
        "expected unknown global keyword error, got: {}",
        err_g.message
    );

    let bad_defaults = "defaults\n\tthis-keyword-does-not-exist 42\n";
    let err_d = parse_config(bad_defaults).unwrap_err();
    assert!(
        err_d.message.contains("unknown keyword 'this-keyword-does-not-exist' in 'defaults' section"),
        "expected unknown defaults keyword error, got: {}",
        err_d.message
    );
}

#[test]
fn test_unsupported_quic_dgram_prefixes_refusal() {
    for prefix in &["dgram+", "quic4+", "quic6+"] {
        let cfg = format!("frontend fe\n\tbind {prefix}127.0.0.1:8443\n");
        let err = parse_config(&cfg).unwrap_err();
        assert!(
            err.message.contains(prefix),
            "expected refusal naming prefix '{prefix}', got: {}",
            err.message
        );
    }
}

#[test]
fn test_tune_h2_flood_knobs_parsing() {
    let cfg_str = r"
global
    tune.h2.fe.max-total-streams 50
    tune.h2.fe.glitches-threshold 100

frontend fe
    bind 127.0.0.1:8080
";
    let cfg = parse_config(cfg_str).expect("Valid h2 flood knobs must parse");
    let global = cfg.global.as_ref().unwrap();
    assert_eq!(global.h2_max_total_streams, Some(50));
    assert_eq!(global.h2_glitches_threshold, Some(100));

    let unsupp_cpu = "global\n\ttune.glitches.kill.cpu-usage 80\n";
    let err_cpu = parse_config(unsupp_cpu).unwrap_err();
    assert!(
        err_cpu.message.contains("tune.glitches.kill.cpu-usage"),
        "expected cpu-usage refusal, got: {}",
        err_cpu.message
    );

    let unsupp_rst = "global\n\ttune.h2.fe.max-rst-at-once 20\n";
    let err_rst = parse_config(unsupp_rst).unwrap_err();
    assert!(
        err_rst.message.contains("tune.h2.fe.max-rst-at-once"),
        "expected max-rst-at-once refusal, got: {}",
        err_rst.message
    );
}

#[test]
fn test_thread_groups_semantics() {
    let ok_tg = "global\n\tthread-groups 1\n";
    assert!(
        parse_config(ok_tg).is_ok(),
        "thread-groups 1 must be accepted as inert (Alcyon single-group runtime)"
    );

    let err_zero = parse_config("global\n\tthread-groups 0\n").unwrap_err();
    assert!(
        err_zero.message.contains("between 1 and 32") || err_zero.message.contains("thread-groups"),
        "expected error for thread-groups 0, got: {}",
        err_zero.message
    );

    let err_multi = parse_config("global\n\tthread-groups 2\n").unwrap_err();
    assert!(
        err_multi.message.contains("thread-groups") && (err_multi.message.contains("> 1 is not supported") || err_multi.message.contains("not supported")),
        "expected refusal for thread-groups > 1, got: {}",
        err_multi.message
    );

    let err_missing = parse_config("global\n\tthread-groups\n").unwrap_err();
    assert!(
        err_missing.message.contains("thread-groups"),
        "expected error for missing thread-groups arg, got: {}",
        err_missing.message
    );

    let err_invalid = parse_config("global\n\tthread-groups abc\n").unwrap_err();
    assert!(
        err_invalid.message.contains("thread-groups"),
        "expected error for unparsable thread-groups arg, got: {}",
        err_invalid.message
    );
}

#[test]
fn test_keyword_buckets_classification() {
    // Bucket 1: Non-existent keywords are refused with section name
    let bad_g = parse_config("global\n\tthis-global-keyword-does-not-exist 42\n").unwrap_err();
    assert!(bad_g.message.contains("unknown keyword 'this-global-keyword-does-not-exist' in 'global' section"));

    let bad_d = parse_config("defaults\n\tthis-keyword-does-not-exist 42\n").unwrap_err();
    assert!(bad_d.message.contains("unknown keyword 'this-keyword-does-not-exist' in 'defaults' section"));

    // Bucket 2: Inert HAProxy keywords recorded in IGNORED tables are accepted
    let inert_cfg = r"
global
    thread-groups 1
    expose-experimental-directives
    insecure-fork-wanted
";
    assert!(
        parse_config(inert_cfg).is_ok(),
        "inert keywords in Bucket 2 must parse successfully"
    );

    // Bucket 3: Semantically load-bearing unimplemented keywords are refused by name
    let unsupp_cpu = parse_config("global\n\ttune.glitches.kill.cpu-usage 80\n").unwrap_err();
    assert!(unsupp_cpu.message.contains("tune.glitches.kill.cpu-usage"));

    let unsupp_rst = parse_config("global\n\ttune.h2.fe.max-rst-at-once 20\n").unwrap_err();
    assert!(unsupp_rst.message.contains("tune.h2.fe.max-rst-at-once"));

    // `log-format` is implemented since T53, `log-format-sd` since T303.
    let sd = parse_config("frontend fe\n\tbind 127.0.0.1:80\n\tlog-format-sd %ci:%cp\n").expect("log-format-sd loads");
    assert_eq!(sd.frontends[0].log_format_sd.as_deref(), Some("%ci:%cp"));
}



