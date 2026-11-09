// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T430 row 37: `sc-set-gpt0`, `sc-set-gpt` and `sc-add-gpc` with no value before `if` or
//! `unless`. HAProxy reads the next word as the value's sample fetch and refuses the line:
//! `unknown fetch method 'if'` (3.5-dev8, `haproxy -c`, rule inside a frontend). The same
//! rules with no word at all after them are accepted (the value is 0), and so is
//! `sc-inc-gpc*`, which takes no value.

use alcyon_config::parse_config;

fn load(rule_set: &str, action: &str) -> Result<(), String> {
    parse_config(&format!("frontend fe\n  mode http\n  bind 127.0.0.1:1\n  {rule_set} {action}\n")).map(|_| ()).map_err(|e| e.to_string())
}

#[test]
fn a_value_less_action_before_if_is_refused_as_haproxy_does() {
    let mut wrong = Vec::new();
    for rs in ["http-request", "tcp-request session", "tcp-request content"] {
        for act in ["sc-set-gpt0(0)", "sc-set-gpt0", "sc-set-gpt(0,0)", "sc-add-gpc(0,0)"] {
            for kw in ["if", "unless"] {
                let line = format!("{act} {kw} TRUE");
                match load(rs, &line) {
                    Ok(()) => wrong.push(format!("{rs} {line}: loaded")),
                    Err(e) if e.contains(&format!("unknown fetch method '{kw}'")) => {
                        if rs == "http-request" && !e.contains(&format!("while parsing 'http-request {act}' rule")) {
                            wrong.push(format!("{rs} {line}: {e:?} lacks the rule name"));
                        }
                    }
                    Err(e) => wrong.push(format!("{rs} {line}: {e:?}")),
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_accepted_forms_still_load() {
    for rs in ["http-request", "tcp-request session", "tcp-request content"] {
        for act in [
            "sc-set-gpt0(0)",
            "sc-set-gpt0(0) 1 if TRUE",
            "sc-set-gpt(0,0) 1 unless TRUE",
            "sc-add-gpc(0,0) 2 if TRUE",
            "sc-inc-gpc(0,0) if TRUE",
            "sc-inc-gpc0(0) if TRUE",
        ] {
            assert_eq!(load(rs, act), Ok(()), "{rs} {act}");
        }
    }
}
