// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! VV-18: the stats page's admin POST answers `303 See Other` to `<uri>;st=<CODE>` (POST,
//! redirect, GET), as `stats_process_http_post` and `stats_send_http_redirect` do in
//! HAProxy 3.5-dev8, and the next GET shows the banner for the code. Every expected value
//! below was measured on the reference binary with the same configuration. A POST without
//! `stats admin` (or whose condition is false) is refused with `st=DENY` and changes nothing.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};

const AUTH: &str = "Authorization: Basic dTpw\r\n";

struct Stats {
    addr: SocketAddr,
    child: Child,
}

impl Stats {
    fn start(admin: &str) -> Stats {
        let addr = common::reserve_addr();
        let dir = std::path::PathBuf::from(format!("/tmp/vv18-post-{}-{}", std::process::id(), addr.port()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("c.cfg");
        std::fs::write(
            &cfg,
            format!(
                "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 3s\n  timeout server 3s\n\
                 frontend f\n  bind {addr}\n  stats enable\n  stats uri /st\n  stats auth u:p\n  {admin}\n  default_backend app\n\
                 backend app\n  server s1 127.0.0.1:1\n  server s2 127.0.0.1:1\n"
            ),
        )
        .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        assert!(common::wait_listening(addr));
        Stats { addr, child }
    }

    fn send(&self, req: &[u8]) -> Vec<u8> {
        let mut c = TcpStream::connect(self.addr).expect("connect");
        c.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
        c.write_all(req).unwrap();
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        out
    }

    fn post_with(&self, path: &str, extra: &str, body: &str) -> String {
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\n{AUTH}Content-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\n{extra}Connection: close\r\n\r\n{body}",
            body.len()
        );
        String::from_utf8_lossy(&self.send(req.as_bytes())).into_owned()
    }

    fn post(&self, body: &str) -> String {
        self.post_with("/st", "", body)
    }

    fn get(&self, uri: &str) -> String {
        let req = format!("GET {uri} HTTP/1.1\r\nHost: x\r\n{AUTH}Connection: close\r\n\r\n");
        String::from_utf8_lossy(&self.send(req.as_bytes())).into_owned()
    }

    /// The status column of a server in `;csv`.
    fn status(&self, sv: &str) -> String {
        let csv = self.get("/st;csv");
        csv.lines().find(|l| l.starts_with(&format!("app,{sv},"))).and_then(|l| l.split(',').nth(17)).unwrap_or("?").to_string()
    }
}

impl Drop for Stats {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn see_other(code: &str) -> String {
    format!(
        "HTTP/1.1 303 See Other\r\ncache-control: no-cache\r\ncontent-type: text/plain\r\ncontent-length: 0\r\nlocation: /st;st={code}\r\nconnection: close\r\n\r\n"
    )
}

#[test]
fn admin_post_answers_303_with_the_result_code() {
    let s = Stats::start("stats admin if TRUE");
    // (body, code) measured on the reference binary.
    let cases = [
        ("s=s1&action=maint&b=app", "DONE"),
        ("s=s1&s=nope&action=maint&b=app", "PART"),
        ("s=nope&action=maint&b=app", "ERRP"),
        ("s=s1&action=maint&b=nobe", "ERRP"),
        ("s=s1&action=bogus&b=app", "ERRP"),
        ("s=s1&action=maint", "NONE"),
        ("b=app", "NONE"),
        ("", "NONE"),
        ("garbage", "NONE"),
        ("action=ready&b=app&s=s1&s=s2", "DONE"),
        ("s=s1&&action=maint&b=app", "DONE"),
        ("s=s1&action=maint&b=ap%zz", "NONE"),
        // A verb that leaves the server as it is (not in maintenance, no check) changes and counts nothing.
        ("s=s1&s=s2&b=app&action=ready", "DONE"),
        ("s=s1&b=app&action=enable", "NONE"),
        ("s=s1&b=app&action=dhlth", "NONE"),
    ];
    for (body, code) in cases {
        assert_eq!(s.post(body), see_other(code), "body {body:?}");
    }
}

#[test]
fn admin_post_applies_the_action_once_and_the_redirect_target_does_not_repeat_it() {
    let s = Stats::start("stats admin if TRUE");
    assert_eq!(s.status("s1"), "no check");
    assert_eq!(s.post("s=s1&action=maint&b=app"), see_other("DONE"));
    assert_eq!(s.status("s1"), "MAINT");
    assert_eq!(s.status("s2"), "no check");
    // The page the redirect leads to is a GET: it changes nothing.
    assert_eq!(s.post("s=s1&action=ready&b=app"), see_other("DONE"));
    let page = s.get("/st;st=DONE");
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert_eq!(s.status("s1"), "no check");
    // `action=drain` on one server only.
    assert_eq!(s.post("s=s2&action=drain&b=app"), see_other("DONE"));
    assert_eq!(s.status("s2"), "DRAIN");
    assert_eq!(s.status("s1"), "no check");
}

#[test]
fn admin_post_is_denied_without_admin_or_with_a_false_condition() {
    for admin in ["", "stats admin if FALSE"] {
        let s = Stats::start(admin);
        assert_eq!(s.post("s=s1&action=maint&b=app"), see_other("DENY"), "admin line {admin:?}");
        assert_eq!(s.status("s1"), "no check", "admin line {admin:?}: the action must not apply");
    }
}

#[test]
fn admin_post_from_another_origin_is_denied() {
    let s = Stats::start("stats admin if TRUE");
    assert_eq!(s.post_with("/st", "Origin: http://evil\r\n", "s=s1&action=maint&b=app"), see_other("DENY"));
    assert_eq!(s.status("s1"), "no check");
    assert_eq!(s.post_with("/st", "Origin: http://x\r\n", "s=s1&action=maint&b=app"), see_other("DONE"));
    assert_eq!(s.status("s1"), "MAINT");
    // A bare authority names the host as well as a URL does.
    assert_eq!(s.post_with("/st", "Origin: x\r\n", "s=s1&action=ready&b=app"), see_other("DONE"));
}

#[test]
fn admin_post_with_a_too_long_key_or_too_large_body() {
    let s = Stats::start("stats admin if TRUE");
    let long = format!("s=s1&action=maint&b=app&{}=1", "k".repeat(3000));
    assert_eq!(s.post(&long), see_other("ERRP"));
    assert_eq!(s.status("s1"), "no check");
    let big = format!("s=s1&action=maint&b=app{}", "&x".repeat(8100));
    assert_eq!(s.post(&big), see_other("EXCD"));
    assert_eq!(s.status("s1"), "no check");
}

#[test]
fn redirect_keeps_the_page_flags_of_the_post_uri() {
    let s = Stats::start("stats admin if TRUE");
    let r = s.post_with("/st;up", "", "s=s1&action=ready&b=app");
    assert!(r.contains("location: /st;st=DONE;up\r\n"), "{r}");
}

#[test]
fn get_with_a_status_code_shows_its_banner() {
    let s = Stats::start("stats admin if TRUE");
    let banners = [
        ("DONE", "<p><div class=active_up><a class=lfsb href=\"/st\" title=\"Remove this message\">[X]</a> Action processed successfully.</div>"),
        ("NONE", "<p><div class=active_going_down><a class=lfsb href=\"/st\" title=\"Remove this message\">[X]</a> Nothing has changed.</div>"),
        ("PART", "<p><div class=active_going_down><a class=lfsb href=\"/st\" title=\"Remove this message\">[X]</a> Action partially processed.<br>Some server names are probably unknown or ambiguous (duplicated names in the backend).</div>"),
        ("ERRP", "<p><div class=active_down><a class=lfsb href=\"/st\" title=\"Remove this message\">[X]</a> Action not processed because of invalid parameters.<ul><li>The action is maybe unknown.</li><li>Invalid key parameter (empty or too long).</li><li>The backend name is probably unknown or ambiguous (duplicated names).</li><li>Some server names are probably unknown or ambiguous (duplicated names in the backend).</li></ul></div>"),
        ("EXCD", "<p><div class=active_down><a class=lfsb href=\"/st\" title=\"Remove this message\">[X]</a> <b>Action not processed : the buffer couldn't store all the data.<br>You should retry with less servers at a time.</b></div>"),
        ("DENY", "<p><div class=active_down><a class=lfsb href=\"/st\" title=\"Remove this message\">[X]</a> <b>Action denied.</b></div>"),
        ("IVAL", "<p><div class=active_down><a class=lfsb href=\"/st\" title=\"Remove this message\">[X]</a> <b>Invalid requests (unsupported method or chunked encoded request).</b></div>"),
        ("UNKN", "<p><div class=active_no_check><a class=lfsb href=\"/st\" title=\"Remove this message\">[X]</a> Unexpected result.</div>"),
        ("BOGU", "<p><div class=active_no_check><a class=lfsb href=\"/st\" title=\"Remove this message\">[X]</a> Unexpected result.</div>"),
    ];
    for (code, banner) in banners {
        let page = s.get(&format!("/st;st={code}"));
        assert!(page.contains(banner), "st={code}: banner missing");
    }
    let plain = s.get("/st");
    assert!(!plain.contains("Remove this message"));
    let up = s.get("/st;st=DONE;up");
    assert!(up.contains("href=\"/st;up\" title=\"Remove this message\""));
}

#[test]
fn admin_post_waits_for_the_whole_body_and_applies_once() {
    let s = Stats::start("stats admin if TRUE");
    let body = "s=s1&action=maint&b=app";
    let head = format!(
        "POST /st HTTP/1.1\r\nHost: x\r\n{AUTH}Content-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut c = TcpStream::connect(s.addr).unwrap();
    c.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
    c.write_all(head.as_bytes()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    c.write_all(&body.as_bytes()[..10]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    c.write_all(&body.as_bytes()[10..]).unwrap();
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    assert_eq!(String::from_utf8_lossy(&out), see_other("DONE"));
    assert_eq!(s.status("s1"), "MAINT");
}

#[test]
fn admin_get_with_an_action_is_ignored_without_admin() {
    let s = Stats::start("stats admin if FALSE");
    let page = s.get("/st?action=maint&backend=app&server=s1");
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert_eq!(s.status("s1"), "no check");
}

#[test]
fn any_stats_admin_line_that_holds_allows_the_post() {
    let addr = common::reserve_addr();
    let dir = std::path::PathBuf::from(format!("/tmp/vv18-post-multi-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("c.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 3s\n  timeout server 3s\n\
             frontend f\n  bind {addr}\n  stats enable\n  stats uri /st\n  stats auth u:p\n  stats admin if TRUE\n  stats admin if FALSE\n  default_backend app\n\
             backend app\n  server s1 127.0.0.1:1\n"
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    assert!(common::wait_listening(addr));
    let s = Stats { addr, child };
    assert_eq!(s.post("s=s1&action=maint&b=app"), see_other("DONE"));
}
