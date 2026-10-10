// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `chroot`, `group`/`gid` and `user`/`uid` are applied once every listener is bound, in
//! HAProxy's order (`main` and `set_identity`, src/haproxy.c): chroot and chdir("/"), then
//! setgroups(0) and setgid, then setuid; a failure is an alert and exit 1, never a process
//! that goes on as the user it was started as (T240 item 3). Ibex used to parse the
//! keywords and drop them, so `user haproxy` ran as root.
//!
//! The suite runs unprivileged: a switch to our own ids must work, and a switch to
//! anyone else's, or a chroot, must fail the start before a single request is answered.
//! Texts measured on HAProxy 3.5-dev8 started unprivileged the same way. One difference:
//! HAProxy retries an unprivileged chroot inside a new user namespace (`unshare
//! (CLONE_NEWUSER)`), which a process that already runs threads cannot do; Ibex's
//! listeners are bound by its worker threads, so an unprivileged chroot to a directory
//! that exists fails here where HAProxy's succeeds.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ibex");

fn status_field(pid: u32, key: &str) -> Vec<u32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with(key))
        .map(|l| l[key.len()..].split_whitespace().filter_map(|v| v.parse().ok()).collect())
        .unwrap_or_default()
}

fn my_uid() -> u32 {
    status_field(std::process::id(), "Uid:")[1]
}

fn my_gid() -> u32 {
    status_field(std::process::id(), "Gid:")[1]
}

fn name_of(file: &str, id: u32) -> String {
    let text = std::fs::read_to_string(file).expect(file);
    let line = text.lines().find(|l| l.split(':').nth(2) == Some(&id.to_string())).expect("entry");
    line.split(':').next().unwrap_or_default().to_string()
}

fn write_cfg(global: &str, port: u16, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ibex-t240-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ibex.cfg");
    std::fs::write(
        &path,
        format!(
            "global\n{global}\ndefaults\n mode http\n timeout client 5s\n timeout server 5s\n timeout connect 5s\n\
             frontend fe\n bind 127.0.0.1:{port}\n http-request return status 200 content-type text/plain string {body}\n"
        ),
    )
    .unwrap();
    path
}

/// Ibex with its stderr in a file next to `cfg` (a pipe would keep a test waiting on any
/// process that inherited it) and its pidfile there too, for [`reap`].
fn spawn(args: &[&str], cfg: &Path) -> Child {
    let dir = cfg.parent().expect("dir");
    let err = std::fs::File::create(dir.join("stderr")).expect("stderr file");
    Command::new(BIN)
        .args(args)
        .arg("-p")
        .arg(dir.join("pid"))
        .arg("-f")
        .arg(cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(err)
        .spawn()
        .expect("spawn ibex")
}

/// Stops `child`, and whatever process its pidfile names now (one a reload started).
fn reap(child: &mut Child, cfg: &Path) -> String {
    common::stop(child);
    let dir = cfg.parent().expect("dir");
    let other = std::fs::read_to_string(dir.join("pid")).ok().and_then(|p| p.trim().parse::<i32>().ok());
    if let Some(pid) = other.filter(|p| u32::try_from(*p).ok() != Some(child.id())).and_then(rustix::process::Pid::from_raw) {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::Usr1);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && rustix::process::test_kill_process(pid).is_ok() {
            std::thread::sleep(Duration::from_millis(20));
        }
        if rustix::process::test_kill_process(pid).is_ok() {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::Kill);
        }
    }
    let err = std::fs::read_to_string(dir.join("stderr")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(dir);
    err
}

fn get(port: u16) -> Option<String> {
    let mut s = TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(200)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(500))).ok()?;
    s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").ok()?;
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.starts_with("HTTP/1.1 200").then(|| out.rsplit("\r\n\r\n").next().unwrap_or("").to_string())
}

fn served(port: u16, want: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if get(port).as_deref() == Some(want) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Starts ibex with `global`, which must make it refuse to start: it exits 1 within a few
/// seconds, with `alert` on stderr, and no request sent meanwhile is ever answered.
fn refuses_to_start(args: &[&str], global: &str, alert: &str) {
    let port = common::reserve_port();
    let cfg = write_cfg(global, port, "served");
    let mut child = spawn(args, &cfg);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut answered = false;
    let status = loop {
        answered |= get(port).is_some();
        if let Ok(Some(st)) = child.try_wait() {
            break Some(st);
        }
        if Instant::now() > deadline {
            break None;
        }
    };
    let err = reap(&mut child, &cfg);
    assert_eq!(status.and_then(|s| s.code()), Some(1), "did not exit 1 ({global}); stderr:\n{err}");
    assert!(!answered, "answered a request before refusing ({global})");
    assert!(err.contains(alert), "no '{alert}' in:\n{err}");
    assert!(err.contains("[ALERT]"), "{err}");
}

fn serves_as(args: &[&str], global: &str, uid: u32, gid: u32) -> String {
    let port = common::reserve_port();
    let cfg = write_cfg(global, port, "served");
    let mut child = spawn(args, &cfg);
    let ok = served(port, "served");
    let ids = (status_field(child.id(), "Uid:"), status_field(child.id(), "Gid:"));
    let err = reap(&mut child, &cfg);
    assert!(ok, "never served ({global}):\n{err}");
    if args.is_empty() {
        assert_eq!(ids, (vec![uid; 4], vec![gid; 4]), "{err}");
    }
    err
}

fn root() -> bool {
    my_uid() == 0
}

#[test]
fn user_and_group_naming_ourselves_start_and_serve() {
    let (uid, gid) = (my_uid(), my_gid());
    let (user, group) = (name_of("/etc/passwd", uid), name_of("/etc/group", gid));
    let err = serves_as(&[], &format!(" user {user}\n group {group}"), uid, gid);
    // `setgroups(0, NULL)` needs CAP_SETGID: HAProxy warns and goes on (setgid to our own
    // gid works).
    if !root() && status_field(std::process::id(), "Groups:").iter().any(|g| *g != gid) {
        assert!(
            err.contains(
                ".main()] Failed to drop supplementary groups. Using 'gid'/'group' without 'uid'/'user' is generally useless."
            ),
            "{err}"
        );
    }
}

#[test]
fn numeric_uid_and_gid_naming_ourselves_start_and_serve() {
    let (uid, gid) = (my_uid(), my_gid());
    serves_as(&[], &format!(" uid {uid}\n gid {gid}"), uid, gid);
}

#[test]
fn chroot_slash_is_no_chroot_and_serves() {
    serves_as(&[], " chroot /", my_uid(), my_gid());
}

#[test]
fn a_uid_we_cannot_take_refuses_to_start() {
    if root() {
        return;
    }
    refuses_to_start(&[], " uid 65534", ".main()] Cannot set uid 65534.");
}

#[test]
fn a_gid_we_cannot_take_refuses_to_start() {
    if root() {
        return;
    }
    refuses_to_start(&[], " gid 65534", ".main()] Cannot set gid 65534.");
}

#[test]
fn a_missing_chroot_directory_refuses_to_start() {
    refuses_to_start(&[], " chroot /nonexistent-ibex-t240", ".main()] Cannot chroot(/nonexistent-ibex-t240).");
}

#[test]
fn an_unprivileged_chroot_refuses_to_start() {
    if root() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("ibex-t240-jail-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let global = format!(" chroot {}", dir.display());
    refuses_to_start(&[], &global, &format!(".main()] Cannot chroot({}).", dir.display()));
}

#[test]
fn chroot_is_tried_before_the_uid() {
    // HAProxy's order: the chroot fails first, so its alert is the one printed.
    refuses_to_start(&[], " uid 65534\n chroot /nonexistent-ibex-t240", "Cannot chroot(/nonexistent-ibex-t240).");
}

#[test]
fn a_master_worker_whose_worker_cannot_switch_refuses_to_start() {
    if root() {
        return;
    }
    let sock = std::env::temp_dir().join(format!("ibex-t240-m-{}.sock", std::process::id()));
    let s = sock.display().to_string();
    refuses_to_start(&["-W", "-S", &s], " uid 65534", ".main()] Cannot set uid 65534.");
    let _ = std::fs::remove_file(&sock);
}

/// Under `-W` the master keeps the privileges it was started with, as HAProxy's does, so a
/// reload can bind and switch again; only the worker switches. Before this, a `-W` process
/// was its own master and would have reloaded as the user it had dropped to.
#[test]
fn master_worker_reloads_after_the_worker_switched() {
    let (uid, gid) = (my_uid(), my_gid());
    let user = name_of("/etc/passwd", uid);
    let port = common::reserve_port();
    let cfg = write_cfg(&format!(" user {user}\n gid {gid}"), port, "one");
    let mut child = spawn(&["-W"], &cfg);
    let first = served(port, "one");
    let _ = write_cfg(&format!(" user {user}\n gid {gid}"), port, "two");
    if let Some(pid) = i32::try_from(child.id()).ok().and_then(rustix::process::Pid::from_raw) {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::Usr2);
    }
    let second = served(port, "two");
    let err = reap(&mut child, &cfg);
    assert!(first && second, "first {first}, after reload {second}:\n{err}");
}

#[test]
fn the_cli_flags_haproxy_does_not_have_are_refused() {
    let cfg = write_cfg("", common::reserve_port(), "x");
    for flags in [&["-u", "nobody"][..], &["-g", "nobody"], &["-U", "65534"], &["-G", "65534"], &["-ch", "/"]] {
        let mut args = flags.to_vec();
        args.push("-c");
        let out = Command::new(BIN).args(&args).arg("-f").arg(&cfg).output().expect("run");
        assert_eq!(out.status.code(), Some(1), "{flags:?}");
    }
}

#[test]
fn an_unprivileged_chroot_auto_refuses_to_start() {
    // `chroot auto`: an empty directory under /tmp, entered then removed. Unprivileged, the
    // chroot itself fails, and the alert names the directory.
    if root() {
        return;
    }
    refuses_to_start(&[], " chroot auto", ".main()] Cannot chroot(/tmp/haproxy.");
}
