// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The operator interface to live connection migration, in one place.
//!
//! The interface is provisional. Everything a test knows about how an operator asks for
//! migration -- the stats-socket keyword, the command-line flag, how a reload is started --
//! lives here, so renaming any of it is a one-line change.
//!
//! As decided for T96: the configuration is plain `HAProxy` syntax (`expose-fd
//! listeners`, today's hitless reload). Migration is asked for on the command line of the
//! *new* process only: `-x <sock> --migrate-conns -sf <oldpid>`. Under `-W`, the master is
//! started with `-W --migrate-conns` and the flag carries over to `SIGUSR2` reloads. The
//! control (spec item 11) is the same reload without the flag.

use std::path::Path;

/// The stats-socket option the *old* process needs so that it can hand anything over.
pub const EXPOSE: &str = "expose-fd listeners";

/// The flag the *new* process is given to fetch established connections.
pub const MIGRATE_FLAG: &str = "--migrate-conns";

/// Which kind of reload a scenario performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reload {
    /// A reload that migrates established connections (T96).
    Migrate,
    /// Today's hitless reload: listeners only. Connections stay in the old process and end
    /// with it. This is the control of spec item 11.
    Control,
}

impl Reload {
    /// The reload actually performed.
    ///
    /// `IBEX_T96_FORCE_CONTROL=1` turns every `Migrate` into a `Control` while leaving
    /// the assertions those tests make unchanged. It exists for one purpose: showing,
    /// on a build that does not accept `--migrate-conns`, that the migration tests fail
    /// because the connection is lost and not merely because the flag is unknown.
    #[must_use]
    pub fn effective(self) -> Self {
        if self == Self::Migrate && std::env::var_os("IBEX_T96_FORCE_CONTROL").is_some() {
            eprintln!("IBEX_T96_FORCE_CONTROL is set: performing a reload WITHOUT {MIGRATE_FLAG}");
            return Self::Control;
        }
        self
    }
}

/// The `global` line that declares the stats socket, with the exposure the reload needs.
#[must_use]
pub fn stats_socket_line(sock: &Path) -> String {
    format!("  stats socket {} mode 600 level admin {EXPOSE}\n", sock.display())
}

/// The arguments, after `-f <cfg>`, of the process that replaces `old_pid`.
#[must_use]
pub fn reload_args(sock: &Path, old_pid: u32, reload: Reload) -> Vec<String> {
    let mut v = vec!["-x".to_string(), sock.display().to_string()];
    if reload.effective() == Reload::Migrate {
        v.push(MIGRATE_FLAG.to_string());
    }
    v.extend(["-sf".to_string(), old_pid.to_string()]);
    v
}

/// The arguments, after `-f <cfg>`, of a master-worker process whose `SIGUSR2` reloads
/// perform `reload`.
#[must_use]
pub fn master_args(reload: Reload) -> Vec<String> {
    let mut v = vec!["-W".to_string()];
    if reload.effective() == Reload::Migrate {
        v.push(MIGRATE_FLAG.to_string());
    }
    v
}

/// What a master-worker reload is triggered with.
pub const MASTER_RELOAD_SIGNAL: rustix::process::Signal = rustix::process::Signal::Usr2;
