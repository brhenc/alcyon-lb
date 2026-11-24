//! `stats scope <proxy>` limits the stats page to the named proxies.
//!
//! Measured on HAProxy 3.5-dev11 (the task's configuration, `GET /s;csv` and `GET /s` with
//! `Host: x`, `Connection: close`): the CSV's `pxname,svname` of every non-`#` line and the
//! names present anywhere in the HTML body follow the table in the task. The name matches
//! exactly (case-sensitive, no prefix), `.` names the proxy serving the page, several lines
//! add up, duplicates do not, the rows keep the configuration's order, and a scope that
//! names nothing leaves an empty page, not an error. A bare `stats scope` is a load error
//! whose message is `'scope' needs a proxy name.` on both binaries.
//!
//! The CLI is never scoped: HAProxy passes no `http_px` to the scope check, so `show stat`
//! prints everything; Alcyon's `format_show_stat*` does not consult the scope list either.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::common;

const NAMES: &[&str] = &["pxfront1", "pxback1", "pxback2", "pxstats", "srva1", "srva2", "srvb1"];

/// Every row: the scope lines, then the CSV `pxname,svname` pairs (configuration order) and
/// the names present in the HTML body.
const ROWS: &[(&str, &[&str], &[&str])] = &[
    ("",
     &["pxfront1,FRONTEND", "pxback1,srva1", "pxback1,srva2", "pxback1,BACKEND",
       "pxback2,srvb1", "pxback2,BACKEND", "pxstats,FRONTEND", "pxstats,BACKEND"],
     &["pxfront1", "pxback1", "pxback2", "pxstats", "srva1", "srva2", "srvb1"]),
    ("  stats scope pxback1\n",
     &["pxback1,srva1", "pxback1,srva2", "pxback1,BACKEND"],
     &["pxback1", "srva1", "srva2"]),
    ("  stats scope pxback1\n  stats scope pxfront1\n",
     &["pxfront1,FRONTEND", "pxback1,srva1", "pxback1,srva2", "pxback1,BACKEND"],
     &["pxfront1", "pxback1", "srva1", "srva2"]),
    ("  stats scope .\n",
     &["pxstats,FRONTEND", "pxstats,BACKEND"],
     &["pxstats"]),
    ("  stats scope nosuch\n", &[], &[]),
    ("  stats scope pxback1\n  stats scope pxback1\n",
     &["pxback1,srva1", "pxback1,srva2", "pxback1,BACKEND"],
     &["pxback1", "srva1", "srva2"]),
    ("  stats scope PXBACK1\n", &[], &[]),
    ("  stats scope pxback\n", &[], &[]),
];

fn binary() -> String {
    std::env::var("T281_ORACLE")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

struct Proc {
    child: Child,
    dir: PathBuf,
}

impl Drop for Proc {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Starts the proxy on the reserved ports with the task's configuration and the row's scope
/// lines in `listen pxstats`.
fn start(scope: &str) -> (Proc, SocketAddr) {
    let fe = common::reserve_addr();
    let stats = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!(
        "alcyon_statsscope_{}_{}",
        std::process::id(),
        stats.port()
    ));
    std::fs::create_dir_all(&dir).expect("mkdir the config directory");
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend pxfront1\n  bind {fe}\n  default_backend pxback1\n\
         backend pxback1\n  server srva1 127.0.0.1:1\n  server srva2 127.0.0.1:2\n\
         backend pxback2\n  server srvb1 127.0.0.1:3\n\
         listen pxstats\n  bind {stats}\n  stats enable\n  stats uri /s\n{scope}"
    );
    let path = dir.join("cfg");
    std::fs::write(&path, cfg).expect("write the config");
    let child = Command::new(binary())
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the proxy");
    let proc = Proc { child, dir };
    assert!(
        common::wait_listening(stats),
        "the proxy did not come up (a config error is printed on its stderr; the scope lines are {scope:?})"
    );
    (proc, stats)
}

/// Fetches `uri` from `addr` and returns the status line and the dechunked body.
fn get(addr: SocketAddr, uri: &str) -> (String, String) {
    let mut s = std::net::TcpStream::connect(addr).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("set the read timeout");
    s.write_all(format!("GET {uri} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
        .expect("send the request");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read the reply");
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((out.as_str(), ""));
    let status = head.lines().next().unwrap_or("").to_string();
    (status, dechunk(head, body))
}

/// Both binaries frame the stats page `transfer-encoding: chunked` for HTTP/1.1 clients.
fn dechunk(head: &str, body: &str) -> String {
    let lower: String = head.to_ascii_lowercase();
    if !lower.contains("transfer-encoding: chunked") {
        return body.to_string();
    }
    let mut out = String::new();
    let mut rest = body;
    while let Some(end) = rest.find("\r\n") {
        let size = usize::from_str_radix(&rest[..end], 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        let start = end + 2;
        let Some(chunk) = rest.get(start..start + size) else {
            break;
        };
        out.push_str(chunk);
        let after = start + size;
        if rest.get(after..after + 2) == Some("\r\n") {
            rest = &rest[after + 2..];
        } else {
            break;
        }
    }
    out
}

/// The `pxname,svname` of every CSV line that is not a comment.
fn csv_pairs(body: &str) -> Vec<String> {
    body.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let mut c = l.split(',');
            let a = c.next()?;
            let b = c.next()?;
            Some(format!("{a},{b}"))
        })
        .collect()
}

/// Which of the seven names appear anywhere in the body, in `NAMES` order.
fn html_names(body: &str) -> Vec<&'static str> {
    NAMES.iter().copied().filter(|n| body.contains(*n)).collect()
}

#[test]
fn stats_scope_limits_the_html_and_csv_pages() {
    for (scope, want_csv, want_names) in ROWS {
        let (proc, stats) = start(scope);
        let (st_csv, body_csv) = get(stats, "/s;csv");
        assert!(st_csv.starts_with("HTTP/1.1 200"), "the csv page answered {st_csv:?}");
        let (st_html, body_html) = get(stats, "/s");
        assert!(st_html.starts_with("HTTP/1.1 200"), "the html page answered {st_html:?}");
        let csv = csv_pairs(&body_csv);
        assert_eq!(&csv[..], *want_csv, "the csv rows for the scope {scope:?}");
        let names = html_names(&body_html);
        assert_eq!(&names[..], *want_names, "the names in the html page for the scope {scope:?}");
        drop(proc);
    }
}

/// HAProxy's load error for a bare `stats scope`, in the same words on both binaries.
#[test]
fn bare_stats_scope_check_mode_message() {
    let fe = common::reserve_addr();
    let stats = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!(
        "alcyon_statsscope_bare_{}_{}",
        std::process::id(),
        stats.port()
    ));
    std::fs::create_dir_all(&dir).expect("mkdir the config directory");
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend pxfront1\n  bind {fe}\n  default_backend pxback1\n\
         backend pxback1\n  server srva1 127.0.0.1:1\n  server srva2 127.0.0.1:2\n\
         backend pxback2\n  server srvb1 127.0.0.1:3\n\
         listen pxstats\n  bind {stats}\n  stats enable\n  stats uri /s\n  stats scope\n"
    );
    let path = dir.join("cfg");
    std::fs::write(&path, cfg).expect("write the config");
    let out = Command::new(binary())
        .arg("-c")
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run the check");
    std::fs::remove_dir_all(&dir).expect("rm the config directory");
    assert!(!out.status.success(), "the bare `stats scope` was accepted");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("'scope' needs a proxy name."),
        "the load error is {text:?}"
    );
}
