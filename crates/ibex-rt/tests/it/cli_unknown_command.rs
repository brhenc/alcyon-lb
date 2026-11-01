// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! An unknown command on the stats socket gets HAProxy's list of the closest commands (T597,
//! left over by T588). Every expected answer below was measured on `HAProxy`
//! 3.5-dev8-885761-29 (`stats socket ... level admin`, 2026-11-01): the commands that match the
//! words typed so far, or else the five nearest by fingerprint distance (`cli_gen_usage_msg`,
//! `src/cli.c`), sorted, then `help`, `prompt` and `quit`.

use crate::common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CASES: &[(&str, &str)] = &[
    ("show schema", r#"Unknown command: 'show', but maybe one of the following ones is a better match:
  show schema json                        : report schema used for stats
  help [<command>]                        : list matching or all commands
  prompt [help | n | i | p | timed ]*     : toggle interactive mode with prompt
  quit                                    : disconnect

"#),
    ("bogus", r#"Unknown command: 'bogus', but maybe one of the following ones is a better match:
  echo <text>                             : print text to the output
  show libs                               : show loaded object files and libraries
  show sess [help|<id>|all] [opts...]     : report the list of current streams or dump this exact stream
  user                                    : lower the level of the current CLI session to user
  wait {-h|<delay_ms>} cond [args...]     : wait the specified delay or condition (-h to see list)
  help [<command>]                        : list matching or all commands
  prompt [help | n | i | p | timed ]*     : toggle interactive mode with prompt
  quit                                    : disconnect

"#),
    ("show foo", r#"Unknown command: 'show', but maybe one of the following ones is a better match:
  show anon                               : display the current state of anonymized mode
  show fd [-!plcfbs]* [num]               : dump list of file descriptors in use or a specific one
  show info [desc|json|typed|float]*      : report information about the running process
  show pools [by*] [match <pfx>] [nb]     : report information about the memory pools usage
  show sess [help|<id>|all] [opts...]     : report the list of current streams or dump this exact stream
  help [<command>]                        : list matching or all commands
  prompt [help | n | i | p | timed ]*     : toggle interactive mode with prompt
  quit                                    : disconnect

"#),
    ("set", r#"Unknown command: 'set', but maybe one of the following ones is a better match:
  set anon global-key <value>             : change the global anonymizing key
  set anon off                            : deactivate the anonymized mode
  set anon on [value]                     : activate the anonymized mode
  set dynamic-cookie-key backend <bk> <k> : change a backend secret key for dynamic cookies
  set map <map> [<key>|#<ref>] <value>    : modify a map entry
  set maxconn frontend <frontend> <value> : change a frontend's maxconn setting
  set maxconn global <value>              : change the per-process maxconn setting
  set maxconn server <bk>/<srv>           : change a server's maxconn setting
  set profiling <what> {auto|on|off}      : enable/disable resource profiling (tasks,memory)
  set rate-limit <setting> <value>        : change a rate limiting value
  set server <bk>/<srv> [opts]            : change a server's state, weight, address, name or ssl
  set severity-output [none|number|string]: set presence of severity level in feedback information
  set ssl ca-file <cafile> <payload>      : replace a CA file
  set ssl cert <certfile> <payload>       : replace a certificate file
  set ssl crl-file <crlfile> <payload>    : replace a CRL file
  set ssl ocsp-response <resp|payload>       : update a certificate's OCSP Response from a base64-encode DER
  set ssl tls-key [id|file] <key>         : set the next TLS key for the <id> or <file> listener to <key>
  set table <table> key <k> [data.* <v>]* : update or create a table entry's data
  set timeout [cli] <delay>               : change a timeout setting
  set weight <bk>/<srv>  (DEPRECATED)     : change a server's weight (use 'set server' instead)
  help [<command>]                        : list matching or all commands
  prompt [help | n | i | p | timed ]*     : toggle interactive mode with prompt
  quit                                    : disconnect

"#),
    ("hel", r#"Unknown command: 'hel', but maybe one of the following ones is a better match:
  add acl [@<ver>] <acl> <pattern>        : add an acl entry
  del acl <acl> [<key>|#<ref>]            : delete acl entries matching <key>
  del map <map> [<key>|#<ref>]            : delete map entries matching <key>
  echo <text>                             : print text to the output
  user                                    : lower the level of the current CLI session to user
  help [<command>]                        : list matching or all commands
  prompt [help | n | i | p | timed ]*     : toggle interactive mode with prompt
  quit                                    : disconnect

"#),
    ("show st", r#"Unknown command: 'show', but maybe one of the following ones is a better match:
  show stat [desc|json|no-maint|typed|up]*: report counters for each proxy and server
  help [<command>]                        : list matching or all commands
  prompt [help | n | i | p | timed ]*     : toggle interactive mode with prompt
  quit                                    : disconnect

"#),
    ("a b c d e f g", r#"Unknown command: 'a', but maybe one of the following ones is a better match:
  add acl [@<ver>] <acl> <pattern>        : add an acl entry
  add backend <backend>                   : add a new backend
  del acl <acl> [<key>|#<ref>]            : delete acl entries matching <key>
  echo <text>                             : print text to the output
  trace [<module>|0] [cmd [args...]]      : manage live tracing (empty to list, 0 to stop all)
  help [<command>]                        : list matching or all commands
  prompt [help | n | i | p | timed ]*     : toggle interactive mode with prompt
  quit                                    : disconnect

"#),
    ("abort", r#"Unknown command: 'abort', but maybe one of the following ones is a better match:
  abort ssl ca-file <cafile>              : abort a transaction for a CA file
  abort ssl cert <certfile>               : abort a transaction for a certificate file
  abort ssl crl-file <crlfile>            : abort a transaction for a CRL file
  help [<command>]                        : list matching or all commands
  prompt [help | n | i | p | timed ]*     : toggle interactive mode with prompt
  quit                                    : disconnect

"#),
    ("clear counters xx", r#"
"#),
    ("add map", r#"'add map' expects three parameters (map identifier, key and value) or one parameter (map identifier) and a payload

"#),
];

#[test]
fn an_unknown_command_lists_the_nearest_ones_as_haproxy() {
    let dir = tempfile::TempDir::new().expect("tmp");
    let sock = dir.path().join("stats.sock");
    let cfg = dir.path().join("ibex.cfg");
    std::fs::write(&cfg, format!("global\n  stats socket {} level admin\ndefaults\n  mode http\n  timeout client 5s\nfrontend f\n  bind 127.0.0.1:0\n", sock.display())).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Ibex).expect("spawn");
    let mut child = child;
    let start = Instant::now();
    while !sock.exists() && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut bad = Vec::new();
    for (cmd, want) in CASES {
        let mut s = UnixStream::connect(&sock).expect("connect");
        s.write_all(format!("{cmd}\n").as_bytes()).expect("write");
        let mut got = String::new();
        s.read_to_string(&mut got).expect("read");
        if got != *want {
            bad.push(format!("{cmd:?}: got {got:?}"));
        }
    }
    common::stop(&mut child);
    assert!(bad.is_empty(), "{} of {} differ: {}", bad.len(), CASES.len(), bad.iter().map(|b| b.chars().take(300).collect::<String>()).collect::<Vec<_>>().join("\n"));
}
