// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Support for `live_migration.rs`: processes, servers, clients and configurations.

pub mod backend;
pub mod h1;
pub mod h2;
pub mod hpack;
pub mod iface;
pub mod pattern;
pub mod procs;

use procs::TempPath;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;

/// One generation of the configuration. Reloads go from generation N to N+1 with only
/// the generation number changed, so every response can say which process's rules
/// produced it: `http-request set-header X-Gen <gen>` reaches the backend, which echoes
/// it back as `X-Seen-Gen`. A request answered with the new generation's number was
/// processed by the new process; nothing the old process does can produce it.
#[derive(Clone, Debug)]
pub struct Cfg {
    pub sock: std::path::PathBuf,
    pub fe: SocketAddr,
    pub be: SocketAddr,
    pub gen: u32,
    /// `mode tcp` instead of `mode http`.
    pub tcp: bool,
    /// `bind ... proto h2`.
    pub h2: bool,
    pub nbthread: Option<u32>,
    pub timeout_client: &'static str,
    /// `hard-stop-after`. Two seconds by default: the old process is then gone, with
    /// whatever it still held, two seconds after it is told to stop -- so a connection
    /// that did not migrate is observably cut, and no test waits on a drain that never
    /// ends.
    pub hard_stop_after: &'static str,
    /// Add `http-response set-header X-Resp-Gen <gen>` (spec item 7).
    pub response_rule: bool,
    /// Extra lines for the frontend (more binds).
    pub fe_extra: String,
    /// Extra sections after the backend.
    pub extra_sections: String,
}

impl Cfg {
    #[must_use]
    pub fn http(sock: &Path, fe: SocketAddr, be: SocketAddr) -> Self {
        Self {
            sock: sock.to_path_buf(),
            fe,
            be,
            gen: 1,
            tcp: false,
            h2: false,
            nbthread: Some(1), // T208: the default is now every CPU
            timeout_client: "30s",
            hard_stop_after: "2s",
            response_rule: false,
            fe_extra: String::new(),
            extra_sections: String::new(),
        }
    }

    #[must_use]
    pub fn gen(&self, gen: u32) -> Self {
        Self { gen, ..self.clone() }
    }

    #[must_use]
    pub fn render(&self) -> String {
        let mut g = String::from("global\n");
        g.push_str(&iface::stats_socket_line(&self.sock));
        let _ = writeln!(g, "  hard-stop-after {}", self.hard_stop_after);
        if let Some(n) = self.nbthread {
            let _ = writeln!(g, "  nbthread {n}");
        }
        let mode = if self.tcp { "tcp" } else { "http" };
        if self.tcp {
            // A `listen` section, not `frontend` + `default_backend`: at 9512e76 a TCP-mode
            // frontend never connects to its default backend (the client is closed at
            // once), a defect outside T96 that `tests/tcp_frontend_backend.rs` in the main
            // checkout already covers. The listen section is still named `fe`.
            return format!(
                "{g}defaults\n  mode tcp\n  timeout connect 2s\n  timeout client {}\n  timeout server 30s\n\
                 listen fe\n  bind {}\n{}  server s1 {}\n{}",
                self.timeout_client, self.fe, self.fe_extra, self.be, self.extra_sections
            );
        }
        let proto = if self.h2 { " proto h2" } else { "" };
        let mut fe = format!("frontend fe\n  bind {}{proto}\n{}", self.fe, self.fe_extra);
        if !self.tcp {
            let _ = writeln!(fe, "  http-request set-header X-Gen {}", self.gen);
            if self.response_rule {
                let _ = writeln!(fe, "  http-response set-header X-Resp-Gen {}", self.gen);
            }
        }
        fe.push_str("  default_backend be\n");
        format!(
            "{g}defaults\n  mode {mode}\n  timeout connect 2s\n  timeout client {}\n  timeout server 30s\n\
             {fe}backend be\n  server s1 {}\n{}",
            self.timeout_client, self.be, self.extra_sections
        )
    }

    /// Writes this generation to a fresh file.
    #[must_use]
    pub fn file(&self) -> TempPath {
        let f = TempPath::new(&format!("g{}", self.gen), "cfg");
        f.write(&self.render());
        f
    }
}
