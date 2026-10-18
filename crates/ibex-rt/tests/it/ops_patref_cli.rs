// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Runtime map and ACL commands on the stats socket (T171 item 1).
//!
//! Every answer was measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-05 with a map file,
//! an `acl ... -f` file and `nbthread 4`:
//!
//! * `show map` / `show acl` list `<id> (<file>) pattern loaded from file '<file>' used by
//!   map|acl at file '<cfg>' line <n>. curr_ver=0 next_ver=0 entry_cnt=<k>`; an `acl` line
//!   also has a reference of its own for its inline patterns (`acl 'path' file ...`), which
//!   takes an id, so the first map after one `acl -f` line is `#2`;
//! * `show map <id|file>` prints `0x<id> <key> <value>` per entry, `show acl` `0x<id> <key>`;
//! * `add map <m> <k> <v>`, `set map <m> <k> <v>` (every entry of the key), `del map <m>
//!   <k>` (every entry; no error when there is none), `clear map <m>`: an empty answer;
//! * `set map` on a missing key: `entry not found.`; `show|add|clear map` on an unknown map:
//!   `Unknown map identifier. Please use #<id> or <file>.`; `clear map` alone: `Missing map
//!   identifier.`; `add map #2 d`: `'add map' expects three parameters (map identifier, key
//!   and value) or one parameter (map identifier) and a payload`; `del map #2`: `This
//!   command expects two parameters: map identifier and key.`;
//! * an integer map refuses `x` with `'x' is not a number.`, an ip map `foo` with `'foo' is
//!   not a valid IPv4 or IPv6 address.`;
//! * `add map #2 <<` takes `key value` lines up to an empty one;
//! * `add acl`, `del acl`, `clear acl` the same way, with `'add acl' expects two
//!   parameters: ACL identifier and pattern.`;
//! * the next request sees the change, on every thread.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Ibex {
    child: Child,
    sock: PathBuf,
    cfg: PathBuf,
    map: PathBuf,
    acl: PathBuf,
    ipmap: PathBuf,
    fe: SocketAddr,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        for p in [&self.sock, &self.cfg, &self.map, &self.acl, &self.ipmap] {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn start() -> Ibex {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = std::env::temp_dir();
    let tag = format!("ibex_t171_{}_{n}", std::process::id());
    let (sock, cfg, map, acl, ipmap) = (
        tmp.join(format!("{tag}.sock")),
        tmp.join(format!("{tag}.cfg")),
        tmp.join(format!("{tag}.map")),
        tmp.join(format!("{tag}.acl")),
        tmp.join(format!("{tag}.ipmap")),
    );
    std::fs::write(&map, "/a 1\n/b 2\n").expect("map");
    std::fs::write(&acl, "# comment\n/x\n/y\n").expect("acl");
    std::fs::write(&ipmap, "10.0.0.0/8 ten\n").expect("ipmap");
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  stats socket {sock} mode 600 level admin\n  nbthread 4\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {fe}\n\
         \x20 acl okpath path -f {acl}\n\
         \x20 http-request set-var(txn.m) path,map({map},none)\n\
         \x20 http-request set-var(txn.ip) src,map_ip({ipmap},none)\n\
         \x20 http-request return status 200 hdr x-m %[var(txn.m)] hdr x-a yes if okpath\n\
         \x20 http-request return status 200 hdr x-m %[var(txn.m)] hdr x-a no\n",
        sock = sock.display(),
        acl = acl.display(),
        map = map.display(),
        ipmap = ipmap.display(),
    );
    std::fs::write(&cfg, &text).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, sock, cfg, map, acl, ipmap, fe };
    assert!(common::wait_listening(fe), "ibex never listened with:\n{text}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    ibex
}

fn cli_raw(ibex: &Ibex, input: &str) -> String {
    let mut s = UnixStream::connect(&ibex.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(input.as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn cli(ibex: &Ibex, cmd: &str) -> String {
    cli_raw(ibex, &format!("{cmd}\n"))
}

/// Entries of a `show map|acl <ref>` answer with the addresses dropped: `key value` lines.
fn entries(out: &str) -> Vec<String> {
    out.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (id, rest) = l.split_once(' ').unwrap_or((l, ""));
            assert!(id.starts_with("0x") && id[2..].chars().all(|c| c.is_ascii_hexdigit()), "entry id in {l:?}");
            rest.to_string()
        })
        .collect()
}

/// The value of `header` in the answer to `GET <path>`.
fn get(ibex: &Ibex, path: &str, header: &str) -> String {
    let mut c = TcpStream::connect(ibex.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let text = String::from_utf8_lossy(&got).into_owned();
    let want = format!("{header}: ");
    text.split("\r\n")
        .find_map(|l| l.to_ascii_lowercase().starts_with(&want).then(|| l[want.len()..].to_string()))
        .unwrap_or_else(|| format!("<no {header} in {text:?}>"))
}

/// What every one of 40 fresh connections (spread over the four threads) answers.
fn all_threads(ibex: &Ibex, path: &str, header: &str) -> Vec<String> {
    let mut seen: Vec<String> = (0..40).map(|_| get(ibex, path, header)).collect();
    seen.sort();
    seen.dedup();
    seen
}

#[test]
fn show_lists_what_the_configuration_reads() {
    let ibex = start();
    let cfg = ibex.cfg.display().to_string();
    let (map, acl, ipmap) = (ibex.map.display().to_string(), ibex.acl.display().to_string(), ibex.ipmap.display().to_string());
    assert_eq!(
        cli(&ibex, "show map"),
        format!(
            "# id (file) description\n\
             2 ({map}) pattern loaded from file '{map}' used by map at file '{cfg}' line 12. curr_ver=0 next_ver=0 entry_cnt=2\n\
             3 ({ipmap}) pattern loaded from file '{ipmap}' used by map at file '{cfg}' line 13. curr_ver=0 next_ver=0 entry_cnt=1\n\n"
        )
    );
    assert_eq!(
        cli(&ibex, "show acl"),
        format!(
            "# id (file) description\n\
             0 ({acl}) pattern loaded from file '{acl}' used by acl at file '{cfg}' line 11. curr_ver=0 next_ver=0 entry_cnt=2\n\
             1 () acl 'path' file '{cfg}' line 11. curr_ver=0 next_ver=0 entry_cnt=0\n\n"
        )
    );
    assert_eq!(entries(&cli(&ibex, "show map #2")), ["/a 1", "/b 2"]);
    assert_eq!(cli(&ibex, "show map #2"), cli(&ibex, &format!("show map {map}")).replace(&map, "#2"));
    assert_eq!(entries(&cli(&ibex, "show acl #0")).len(), 2);
    assert!(entries(&cli(&ibex, &format!("show acl {acl}"))).iter().eq(["/x", "/y"].iter()));
    assert_eq!(cli(&ibex, "show map #0"), "Unknown map identifier. Please use #<id> or <file>.\n\n");
    assert_eq!(cli(&ibex, "show map /nonexistent"), "Unknown map identifier. Please use #<id> or <file>.\n\n");
    assert_eq!(cli(&ibex, "show acl #1"), "\n");
}

#[test]
fn map_changes_reach_the_data_path_on_every_thread() {
    let ibex = start();
    assert_eq!(all_threads(&ibex, "/c", "x-m"), ["none"]);
    assert_eq!(cli(&ibex, "add map #2 /c 3"), "\n");
    assert_eq!(all_threads(&ibex, "/c", "x-m"), ["3"], "after add map");
    assert_eq!(cli(&ibex, "set map #2 /c 9"), "\n");
    assert_eq!(all_threads(&ibex, "/c", "x-m"), ["9"], "after set map");
    assert_eq!(cli(&ibex, &format!("set map {} /a 7", ibex.map.display())), "\n");
    assert_eq!(all_threads(&ibex, "/a", "x-m"), ["7"], "set map by file");
    assert_eq!(cli(&ibex, "del map #2 /c"), "\n");
    assert_eq!(all_threads(&ibex, "/c", "x-m"), ["none"], "after del map");
    assert_eq!(cli(&ibex, "del map #2 /c"), "\n", "deleting what is not there is not an error");
    assert_eq!(cli(&ibex, "clear map #2"), "\n");
    assert_eq!(all_threads(&ibex, "/b", "x-m"), ["none"], "after clear map");
    assert_eq!(cli(&ibex, "show map #2"), "\n");
    assert_eq!(cli_raw(&ibex, "add map #2 <<\n/p 1\n/q 2\n\n"), "\n");
    assert_eq!(entries(&cli(&ibex, "show map #2")), ["/p 1", "/q 2"]);
    assert_eq!(all_threads(&ibex, "/q", "x-m"), ["2"], "after add map <<");
}

#[test]
fn map_command_errors() {
    let ibex = start();
    let usage = "'add map' expects three parameters (map identifier, key and value) or one parameter (map identifier) and a payload\n\n";
    for c in ["add map #2 d", "add map #2", "add map"] {
        assert_eq!(cli(&ibex, c), usage, "{c}");
    }
    assert_eq!(cli(&ibex, "set map #2 zz 9"), "entry not found.\n\n");
    assert_eq!(cli(&ibex, "set map #2 a"), "'set map' expects three parameters: map identifier, key and value.\n\n");
    assert_eq!(cli(&ibex, "del map #2"), "This command expects two parameters: map identifier and key.\n\n");
    assert_eq!(cli(&ibex, "clear map"), "Missing map identifier.\n\n");
    assert_eq!(cli(&ibex, "clear map #7"), "Unknown map identifier. Please use #<id> or <file>.\n\n");
    assert_eq!(cli(&ibex, "add map #9 a b"), "Unknown map identifier. Please use #<id> or <file>.\n\n");
    assert_eq!(cli_raw(&ibex, "add map #2 <<\nk3\n\n"), "Missing value for key 'k3'.\n\n");
    assert_eq!(cli(&ibex, "add map #3 foo x"), "'foo' is not a valid IPv4 or IPv6 address.\n\n");
    assert_eq!(cli(&ibex, "add map #3 1.2.3.0/24 x"), "\n");
    assert_eq!(entries(&cli(&ibex, "show map #3")), ["10.0.0.0/8 ten", "1.2.3.0/24 x"]);
}

#[test]
fn acl_changes_reach_the_data_path_on_every_thread() {
    let ibex = start();
    assert_eq!(all_threads(&ibex, "/x", "x-a"), ["yes"]);
    assert_eq!(all_threads(&ibex, "/z", "x-a"), ["no"]);
    assert_eq!(cli(&ibex, "add acl #0 /z"), "\n");
    assert_eq!(all_threads(&ibex, "/z", "x-a"), ["yes"], "after add acl");
    assert_eq!(cli(&ibex, "del acl #0 /x"), "\n");
    assert_eq!(all_threads(&ibex, "/x", "x-a"), ["no"], "after del acl");
    assert_eq!(all_threads(&ibex, "/y", "x-a"), ["yes"]);
    assert_eq!(entries(&cli(&ibex, "show acl #0")), ["/y", "/z"]);
    assert_eq!(cli(&ibex, &format!("add acl {} /k", ibex.acl.display())), "\n");
    assert_eq!(all_threads(&ibex, "/k", "x-a"), ["yes"], "add acl by file");
    assert_eq!(cli(&ibex, "clear acl #0"), "\n");
    assert_eq!(all_threads(&ibex, "/y", "x-a"), ["no"], "after clear acl");
    assert_eq!(cli(&ibex, "show acl #0"), "\n");
}

#[test]
fn acl_command_errors() {
    let ibex = start();
    let usage = "'add acl' expects two parameters: ACL identifier and pattern.\n\n";
    assert_eq!(cli(&ibex, "add acl #0"), usage);
    assert_eq!(cli(&ibex, "add acl"), usage);
    assert_eq!(cli(&ibex, "add acl #9 /q"), "Unknown ACL identifier. Please use #<id> or <file>.\n\n");
    assert_eq!(cli(&ibex, "del acl #0"), "This command expects two parameters: ACL identifier and key.\n\n");
    assert_eq!(cli(&ibex, "clear acl"), "Missing ACL identifier.\n\n");
    // Inline patterns are not changeable here: refused rather than accepted and ignored.
    assert!(cli(&ibex, "add acl #1 /q").contains("cannot be changed at runtime"));
}

/// T363h: a backslash protects the character after it from the command separator too
/// (`cli_parse_request` skips it when it looks for `;`), so `\;` and `\ ` reach the ACL as
/// `;` and a blank. Measured on HAProxy 3.5-dev8 (`add acl <f> Mon\ User\ Agent\;`, then
/// `show acl <f>`: `Mon User Agent;`); an unescaped `;` still ends the command.
#[test]
fn escaped_semicolon_and_blanks_stay_in_the_acl_value() {
    let ibex = start();
    let f = ibex.acl.display().to_string();
    assert_eq!(cli(&ibex, &format!("add acl {f} Mon\\ User\\ Agent\\;")), "\n");
    assert_eq!(entries(&cli(&ibex, &format!("show acl {f}"))), ["/x", "/y", "Mon User Agent;"]);
    assert_eq!(cli(&ibex, &format!("del acl {f} Mon\\ User\\ Agent\\;")), "\n");
    assert_eq!(entries(&cli(&ibex, &format!("show acl {f}"))), ["/x", "/y"]);
    // An unescaped `;` ends the command: the second one runs as well (prompt mode).
    assert_eq!(entries(&cli(&ibex, &format!("add acl {f} /m;show acl {f}"))), ["/x", "/y", "/m"]);
}
