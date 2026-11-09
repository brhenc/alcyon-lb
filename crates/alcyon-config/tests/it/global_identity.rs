// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `user`, `group`, `uid`, `gid` and `chroot` in `global` (T240 item 3). HAProxy resolves
//! the names while it parses (`cfg_parse_global`, src/cfgparse-global.c: `getpwnam`,
//! `getgrnam`), so an unknown one fails the load, `-c` included. Alcyon used to keep the
//! strings and never look at them, and refused `uid`/`gid` as unknown keywords. The texts
//! are those of `haproxy -c` (3.5-dev8), less the `parsing [file:line] :` prefix; the
//! process side (chroot, setgid, setuid after the listeners are bound) is in `alcyon-rt`
//! `tests/privilege_drop.rs`.

use alcyon_config::{parse_str, GlobalSection};

fn global(cfg: &str) -> GlobalSection {
    parse_str(cfg).unwrap_or_else(|e| panic!("refused: {}", e.message)).global.expect("global")
}

fn refusal(cfg: &str) -> String {
    match parse_str(cfg) {
        Ok(_) => panic!("accepted:\n{cfg}"),
        Err(e) => e.message,
    }
}

fn me() -> (String, u32, String, u32) {
    let passwd = std::fs::read_to_string("/etc/passwd").expect("/etc/passwd");
    let uid = rustix_uid();
    let line = passwd.lines().find(|l| l.split(':').nth(2) == Some(&uid.to_string())).expect("my passwd entry");
    let f: Vec<&str> = line.split(':').collect();
    let gid: u32 = f[3].parse().expect("gid");
    let group = std::fs::read_to_string("/etc/group").expect("/etc/group");
    let gname = group
        .lines()
        .find(|l| l.split(':').nth(2) == Some(&gid.to_string()))
        .map(|l| l.split(':').next().unwrap_or_default().to_string())
        .expect("my group entry");
    (f[0].to_string(), uid, gname, gid)
}

fn rustix_uid() -> u32 {
    // /proc/self/status: "Uid:\t<real>\t<effective>..."
    let status = std::fs::read_to_string("/proc/self/status").expect("status");
    let line = status.lines().find(|l| l.starts_with("Uid:")).expect("Uid line");
    line.split_whitespace().nth(2).expect("euid").parse().expect("uid")
}

#[test]
fn user_and_group_are_resolved_while_parsing() {
    let (user, uid, group, gid) = me();
    let g = global(&format!("global\n user {user}\n group {group}\n"));
    assert_eq!((g.uid, g.gid), (i32::try_from(uid).ok(), i32::try_from(gid).ok()));
}

#[test]
fn numeric_uid_and_gid_are_taken_as_written() {
    let g = global("global\n uid 1234\n gid 5678\n");
    assert_eq!((g.uid, g.gid), (Some(1234), Some(5678)));
    // `strl2irc` takes a sign; a negative id is never applied (`global.uid > 0`).
    assert_eq!(global("global\n uid -5\n").uid, Some(-5));
}

#[test]
fn an_unknown_user_or_group_fails_the_load() {
    assert_eq!(
        refusal("global\n user alcyon-no-such-user-t240\n"),
        "cannot find user id for 'alcyon-no-such-user-t240' (0:Success)"
    );
    assert_eq!(
        refusal("global\n group alcyon-no-such-group-t240\n"),
        "cannot find group id for 'alcyon-no-such-group-t240' (0:Success)"
    );
    assert_eq!(refusal("global\n user\n"), "cannot find user id for '' (0:Success)");
}

#[test]
fn missing_and_extra_arguments_are_refused() {
    assert_eq!(refusal("global\n uid\n"), "'uid' expects an integer argument.");
    assert_eq!(refusal("global\n gid\n"), "'gid' expects an integer argument.");
    assert_eq!(refusal("global\n chroot\n"), "'chroot' expects a directory as an argument.");
    assert_eq!(refusal("global\n chroot /a /b\n"), "'chroot' cannot handle unexpected argument '/b'.");
    assert_eq!(refusal("global\n uid 1 2\n"), "'uid' cannot handle unexpected argument '2'.");
}

#[test]
fn a_uid_that_is_not_a_number_is_a_warning_and_no_uid() {
    let g = global("global\n uid abc\n gid 99999999999\n");
    assert_eq!((g.uid, g.gid), (None, None));
    let texts: Vec<&str> = g.load_warnings.iter().map(|w| w.text.as_str()).collect();
    assert_eq!(
        texts,
        [
            " uid: string 'abc' is not a number.\n   | You might want to use the 'user' parameter to use a system user name.",
            " gid: string '99999999999' is not a number.\n   | You might want to use the 'group' parameter to use a system group name.",
        ]
    );
}

#[test]
fn a_second_user_or_group_keeps_the_first_with_an_alert() {
    let g = global("global\n uid 10\n uid 20\n gid 30\n gid 40\n chroot /a\n chroot /b\n");
    assert_eq!((g.uid, g.gid, g.chroot.as_deref()), (Some(10), Some(30), Some("/a")));
    let texts: Vec<(&str, bool)> = g.load_warnings.iter().map(|w| (w.text.as_str(), w.alert)).collect();
    assert_eq!(
        texts,
        [
            ("user/uid already specified. Continuing.", true),
            ("group/gid already specified. Continuing.", true),
            ("'chroot' is already specified. Continuing.", false),
        ]
    );
}

#[test]
fn chroot_is_kept() {
    assert_eq!(global("global\n chroot /var/empty\n").chroot.as_deref(), Some("/var/empty"));
}
