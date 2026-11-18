// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The run-time `add-acl`, `del-acl`, `set-map` and `del-map` actions (the reg-test
//! `http-rules/acl_map_updates.vtc`): one request changes a pattern file's entries, the
//! next one sees them. The file is named by its plain path, by `file@` (the very same
//! list), by `virt@` (no file at all) or by `opt@` (a file which does not exist).
//! `set-map` is also usable from `http-after-response`, and so are `del-map` and `del-acl`.
//! A rule whose file no registered reference answers is a no-op, as `HAProxy`'s
//! `pat_ref_lookup` finds none; a missing key (or value, for `set-map`) is refused at load.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev11 (the reg-test above, and the
//! wire bytes of an empty `set-header`). Set `T281_ORACLE=/path/to/haproxy` to run these
//! tests against `HAProxy`: it passes them all.

use crate::common;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

/// The files and the proxy that serves the reg-test's scenario.
struct P {
    child: std::process::Child,
    fe: SocketAddr,
    sock: std::path::PathBuf,
    cfg: std::path::PathBuf,
    dir: tempfile::TempDir,
}

impl Drop for P {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn start() -> P {
    let dir = tempfile::tempdir().expect("dir");
    let acl = dir.path().join("a.acl");
    let map = dir.path().join("m.map");
    let missing = dir.path().join("missing.map");
    std::fs::write(&acl, "/initial\n").expect("acl");
    std::fs::write(&map, "/initial\tinitial\n").expect("map");
    let fe = common::reserve_addr();
    // One unique tag per proxy: the tests run in the same process, so the
    // process id alone would let them overwrite each other's config and socket.
    let tag = format!("alcyon_map_actions_{}_{}", std::process::id(), fe.port());
    let sock = std::env::temp_dir().join(format!("{tag}.sock"));
    let cfg = std::env::temp_dir().join(format!("{tag}.cfg"));
    let text = format!(
        "global\n  stats socket {sock} mode 600 level admin\n\
         defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n\
         acl known url_param(q) -f {acl}\n\
         acl vknown url_param(vk) -f virt@vlist\n\
         http-request add-acl({acl}) %[url_param(add)] if {{ url_param(add) -m found }}\n\
         http-request del-acl({acl}) %[url_param(del)] if {{ url_param(del) -m found }}\n\
         http-request add-acl(virt@vlist) %[url_param(vadd)] if {{ url_param(vadd) -m found }}\n\
         http-request set-map(virt@vmap) %[url_param(key)] \"v-%[url_param(val)]\" if {{ url_param(key) -m found }}\n\
         http-request del-map(virt@vmap) %[url_param(unkey)] if {{ url_param(unkey) -m found }}\n\
         http-request set-map(opt@{missing}) %[url_param(key)] \"o-%[url_param(val)]\" if {{ url_param(key) -m found }}\n\
         http-request set-map(file@{map}) %[url_param(key)] \"f-%[url_param(val)]\" if {{ url_param(key) -m found }}\n\
         http-request add-acl(/no/such/ma-ghost.acl) /ghost if {{ url_param(add) -m found }}\n\
         http-request set-var(txn.acl) str(yes) if known\n\
         http-request set-var(txn.vlist) str(yes) if vknown\n\
         http-request set-var(txn.vmap) url_param(q),map(virt@vmap)\n\
         http-request set-var(txn.omap) url_param(q),map(opt@{missing})\n\
         http-request set-var(txn.fmap) url_param(q),map(file@{map})\n\
         http-request set-var(txn.pmap) url_param(q),map({map})\n\
         http-request return status 200\n\
         http-after-response set-map(virt@vmap) /aft aft-value if {{ status 200 }}\n\
         http-after-response del-map(/no/such/ma-ghost.map) /ghost if {{ status 200 }}\n\
         http-after-response del-map(virt@vmap) /zz if {{ status 599 }}\n\
         http-after-response del-acl(virt@vlist) /zz if {{ status 599 }}\n\
         http-after-response set-header x-acl \"%[var(txn.acl)]\"\n\
         http-after-response set-header x-vlist \"%[var(txn.vlist)]\"\n\
         http-after-response set-header x-vmap \"%[var(txn.vmap)]\"\n\
         http-after-response set-header x-omap \"%[var(txn.omap)]\"\n\
         http-after-response set-header x-fmap \"%[var(txn.fmap)]\"\n\
         http-after-response set-header x-pmap \"%[var(txn.pmap)]\"\n",
        sock = sock.display(),
        acl = acl.display(),
        map = map.display(),
        missing = missing.display(),
    );
    std::fs::write(&cfg, &text).expect("cfg");
    let errf = std::env::temp_dir().join(format!("{tag}.err"));
    let err = std::fs::File::create(&errf).expect("err file");
    let child = common::alcyon_command(bin())
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(std::process::Stdio::from(err))
        .spawn()
        .expect("spawn proxy");
    let mut p = P { child, fe, sock: sock.clone(), cfg, dir };
    assert!(
        common::wait_listening(fe),
        "proxy never listened (config:\n{text}\nstderr:\n{})",
        std::fs::read_to_string(&errf).unwrap_or_default()
    );
    p
}

/// One request; the status line and the observed headers, in order.
fn hit(p: &P, url: &str) -> (String, Vec<(String, String)>) {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(format!("GET {url} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
        .expect("send");
    let mut got = Vec::new();
    c.read_to_end(&mut got).expect("read");
    let text = String::from_utf8_lossy(&got).into_owned();
    let mut lines = text.lines();
    let status = lines.next().unwrap_or("<no status line>").to_string();
    let hdrs = lines
        .map_while(|l| {
            let l = l.strip_suffix("\r").unwrap_or(l);
            if l.is_empty() {
                None
            } else {
                l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            }
        })
        .collect();
    (status, hdrs)
}

fn check(p: &P, url: &str, status: &str, want: &[(&str, &str)]) {
    let (st, hdrs) = hit(p, url);
    assert!(st.starts_with(status), "for {url}: status line {st:?}, wanted {status}");
    let get = |n: &str| {
        hdrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    for (name, val) in want {
        assert_eq!(get(name), *val, "for {url}: header {name}");
    }
}

/// The stats-socket answer of `cmd`.
fn cli(p: &P, cmd: &str) -> String {
    let mut s = std::os::unix::net::UnixStream::connect(&p.sock).expect("stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// The whole reg-test: the initial state, an add in every list (file, `virt@`, `opt@` and
/// `file@`), the after-response feed, an update of an existing key, a removal, the untouched
/// file entries, and the CLI view. The two rules whose file no registered reference answers
/// fire on the same requests and change nothing.
#[test]
fn the_actions_change_the_lists_at_run_time() {
    let p = start();

    // initial state: only the entries loaded from the files are present
    check(
        &p,
        "/?q=/initial",
        "HTTP/1.1 200",
        &[("x-acl", "yes"), ("x-vlist", ""), ("x-vmap", ""), ("x-omap", ""), ("x-fmap", "initial"), ("x-pmap", "initial")],
    );
    check(
        &p,
        "/?q=/added",
        "HTTP/1.1 200",
        &[("x-acl", ""), ("x-vmap", ""), ("x-omap", ""), ("x-fmap", ""), ("x-pmap", "")],
    );

    // add one ACL entry and one entry in each of the three maps
    check(&p, "/?add=/added&key=/added&val=1", "HTTP/1.1 200", &[]);
    check(
        &p,
        "/?q=/added",
        "HTTP/1.1 200",
        &[("x-acl", "yes"), ("x-vmap", "v-1"), ("x-omap", "o-1"), ("x-fmap", "f-1"), ("x-pmap", "f-1")],
    );

    // the http-after-response rule fed the virtual map as well
    check(&p, "/?q=/aft", "HTTP/1.1 200", &[("x-vmap", "aft-value")]);

    // a virtual ACL starts empty; an add-acl fills it, and the next request matches it
    check(&p, "/?vk=/v", "HTTP/1.1 200", &[("x-vlist", "")]);
    check(&p, "/?vk=/v&vadd=/v", "HTTP/1.1 200", &[]);
    check(&p, "/?vk=/v", "HTTP/1.1 200", &[("x-vlist", "yes")]);

    // adding an existing key does not duplicate it, it updates its value
    check(&p, "/?add=/added&key=/added&val=2", "HTTP/1.1 200", &[]);
    check(
        &p,
        "/?q=/added",
        "HTTP/1.1 200",
        &[("x-acl", "yes"), ("x-vmap", "v-2"), ("x-fmap", "f-2")],
    );

    // now remove them again: the virtual map entry and the ACL entry
    check(&p, "/?del=/added&unkey=/added", "HTTP/1.1 200", &[]);
    check(
        &p,
        "/?q=/added",
        "HTTP/1.1 200",
        &[("x-acl", ""), ("x-vmap", ""), ("x-omap", "o-2"), ("x-fmap", "f-2")],
    );

    // the entries loaded from the files are untouched
    check(&p, "/?q=/initial", "HTTP/1.1 200", &[("x-acl", "yes"), ("x-fmap", "initial")]);

    // the run-time updates are visible from the CLI, and the virtual map
    // is listed under its full name
    let dir = p.dir.path().display().to_string();
    let vmap = cli(&p, "show map virt@vmap");
    assert!(vmap.lines().any(|l| l.trim_end().ends_with("/aft aft-value")), "show map virt@vmap:\n{vmap}");
    let acl = cli(&p, &format!("show acl {}", dir + "/a.acl"));
    assert!(acl.lines().any(|l| l.trim_end().ends_with("/initial")), "show acl:\n{acl}");
}

/// `del-map` with a key that is not there changes nothing, and neither does an
/// `add-acl` of a pattern the file already holds (the file keeps one entry per line).
#[test]
fn a_del_of_a_missing_key_is_a_noop() {
    let p = start();
    check(&p, "/?q=/initial", "HTTP/1.1 200", &[("x-acl", "yes"), ("x-fmap", "initial")]);
    // removing a key that was never added leaves every list as it was
    check(&p, "/?del=/never&unkey=/never", "HTTP/1.1 200", &[]);
    check(
        &p,
        "/?q=/initial",
        "HTTP/1.1 200",
        &[("x-acl", "yes"), ("x-vmap", ""), ("x-omap", ""), ("x-fmap", "initial"), ("x-pmap", "initial")],
    );
    // the CLI shows the one entry that was loaded
    let dir = p.dir.path().display().to_string();
    let acl = cli(&p, &format!("show acl {}", dir + "/a.acl"));
    let n = acl.lines().filter(|l| l.starts_with("0x")).count();
    assert_eq!(n, 1, "show acl:\n{acl}");
}

/// An action without its key (`add-acl`, `del-acl`) or, for `set-map`, without its value is
/// refused at load, with the `HAProxy` arity message: silently ignored, a misspelt key would
/// change nothing and the mistake would be invisible. The substring asserted below is the
/// one `HAProxy` 3.5-dev11 prints too (it prefixes it with `error detected in frontend 'f'`).
#[test]
fn a_missing_key_or_value_is_refused_at_load() {
    for (rule, want) in [
        (
            "http-request add-acl(virt@a)",
            "while parsing 'http-request add-acl(virt@a)' rule : expects exactly 1 arguments.",
        ),
        (
            "http-request del-acl(virt@d)",
            "while parsing 'http-request del-acl(virt@d)' rule : expects exactly 1 arguments.",
        ),
        (
            "http-request set-map(virt@v) /k",
            "while parsing 'http-request set-map(virt@v)' rule : expects exactly 2 arguments.",
        ),
        (
            "http-after-response set-map(virt@v) /k",
            "while parsing 'http-after-response set-map(virt@v)' rule : expects exactly 2 arguments.",
        ),
    ] {
        let cfg = format!(
            "global\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nfrontend f\n  bind 127.0.0.1:1\n  {rule}\n"
        );
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write cfg");
        let out = Command::new(bin()).arg("-c").arg("-f").arg(f.path()).output().expect("run -c");
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!out.status.success(), "{rule} should be refused, said: {text}");
        assert!(text.contains(want), "{rule}: {text}");
    }
}
