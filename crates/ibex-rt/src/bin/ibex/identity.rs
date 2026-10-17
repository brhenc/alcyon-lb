// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `chroot`, `group`/`gid` and `user`/`uid` (T240), applied as `HAProxy`'s `main` does
//! once every listener is bound (src/haproxy.c, `do_chroot` and `set_identity`):
//!
//! 1. chroot, then chdir("/") -- `/` means no chroot, `auto` an empty directory that is
//!    removed once entered;
//! 2. the old processes are told to go (`-sf` / `-st`), while this one may still signal
//!    them;
//! 3. setgroups(0) (a warning if it fails) and setgid, when the gid is above 0;
//! 4. setuid, when the uid is above 0.
//!
//! A failure in 1, 3 or 4 is an alert and exit 1: the process never serves as the user it
//! was started as when the configuration said otherwise. The workers wait for this before
//! they accept anything (see `main`).
//!
//! Not done, as in `HAProxy` built without them or on purpose:
//! - the user-namespace retry of an unprivileged chroot (`unshare(CLONE_NEWUSER)`), which
//!   needs a process with one thread, and Ibex's listeners are bound by its worker threads;
//! - the automatic `chroot auto` of a process started as root without a `chroot` line;
//! - Linux capabilities kept across setuid (`setcap`).
//!
//! `setgid`/`setuid` are glibc's, which apply to every thread of the process.

use std::process;

use nix::unistd::{getgroups, setgid, setgroups, setuid, Gid, Uid};

/// What the `global` section asked for.
#[derive(Debug, Default, Clone)]
pub struct Identity {
    pub chroot: Option<String>,
    pub uid: Option<i32>,
    pub gid: Option<i32>,
}

impl Identity {
    pub fn from_config(config: &ibex_config::Config) -> Self {
        config.global.as_ref().map_or_else(Self::default, |g| Self { chroot: g.chroot.clone(), uid: g.uid, gid: g.gid })
    }

    /// Whether this start changes anything about the process.
    pub fn any(&self) -> bool {
        self.chroot.is_some() || self.uid.is_some_and(|u| u > 0) || self.gid.is_some_and(|g| g > 0)
    }
}

fn alert(text: &str) {
    ibex_rt::stderr_line!("[ALERT]    ({}) : {text}", process::id());
}

fn warning(text: &str) {
    ibex_rt::stderr_line!("[WARNING]  ({}) : {text}", process::id());
}

/// `do_chroot`. Exits 1 when it fails.
pub fn chroot(prog: &str, id: &Identity) {
    let Some(path) = id.chroot.as_deref() else { return };
    let (dir, entered) = match path {
        "auto" => {
            let tmp = empty_dir().unwrap_or_else(|t| fail(&format!("[{prog}.main()] Cannot create({t}) for chroot auto.")));
            // The directory is gone once we are in it: nothing can be put in it.
            let inside = std::env::set_current_dir(&tmp).is_ok();
            let _ = std::fs::remove_dir(&tmp);
            (tmp, inside && rustix::process::chroot(".").is_ok())
        }
        "/" => (path.to_string(), true),
        _ => (path.to_string(), rustix::process::chroot(path).is_ok()),
    };
    if !entered || std::env::set_current_dir("/").is_err() {
        fail(&format!("[{prog}.main()] Cannot chroot({dir})."));
    }
}

fn fail(text: &str) -> ! {
    alert(text);
    process::exit(1);
}

/// `mkdtemp("/tmp/haproxy.XXXXXX")`: a new 0700 directory, or the template.
fn empty_dir() -> Result<String, &'static str> {
    use std::os::unix::fs::DirBuilderExt;
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    let name = format!("/tmp/haproxy.{:06x}", (nanos ^ process::id().rotate_left(12)) & 0xff_ffff);
    std::fs::DirBuilder::new().mode(0o700).create(&name).map(|()| name).map_err(|_| "/tmp/haproxy.XXXXXX")
}

/// `set_identity`. Exits 1 when the gid or the uid cannot be taken.
pub fn set_identity(prog: &str, id: &Identity) {
    if let Some(gid) = id.gid.filter(|g| *g > 0) {
        if getgroups().is_ok_and(|g| !g.is_empty()) && setgroups(&[]).is_err() {
            warning(&format!(
                "[{prog}.main()] Failed to drop supplementary groups. Using 'gid'/'group' without 'uid'/'user' is generally useless."
            ));
        }
        #[allow(clippy::cast_sign_loss)]
        if setgid(Gid::from_raw(gid as u32)).is_err() {
            fail(&format!("[{prog}.main()] Cannot set gid {gid}."));
        }
    }
    if let Some(uid) = id.uid.filter(|u| *u > 0) {
        #[allow(clippy::cast_sign_loss)]
        if setuid(Uid::from_raw(uid as u32)).is_err() {
            fail(&format!("[{prog}.main()] Cannot set uid {uid}."));
        }
    }
}
