// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The server-state file keywords (T490): `server-state-file` and `server-state-base` in
//! `global`, `load-server-state-from-file` in `defaults`/`backend`/`listen`,
//! `server-state-file-name` in `backend`/`listen`. The texts were measured with
//! `haproxy -c` on 3.5-dev8-885761-29 (2026-10-25), less the `parsing [file:line] :`
//! prefix (`cfg_parse_global`, `cfg_parse_listen`). What the file does at start is in
//! `ibex-rt` `tests/it/server_state_file.rs`.

use ibex_config::ast::LoadServerState;
use ibex_config::{parse_str, Config};

const D: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";

fn ok(cfg: &str) -> Config {
    parse_str(cfg).unwrap_or_else(|e| panic!("refused {cfg:?}: {}", e.message))
}

fn refusal(cfg: &str) -> String {
    match parse_str(cfg) {
        Ok(_) => panic!("accepted:\n{cfg}"),
        Err(e) => e.message,
    }
}

#[test]
fn the_global_keywords_keep_their_path() {
    let c = ok("global\n  server-state-file st\n  server-state-base /var/lib/st\n");
    let g = c.global.expect("global");
    assert_eq!(g.server_state_file.as_deref(), Some("st"));
    assert_eq!(g.server_state_base.as_deref(), Some("/var/lib/st"));
    // A second argument is not looked at (HAProxy: no message, the first is kept).
    let g = ok("global\n  server-state-file /a /b\n").global.expect("global");
    assert_eq!(g.server_state_file.as_deref(), Some("/a"));
}

#[test]
fn the_global_keywords_need_their_argument() {
    assert_eq!(refusal("global\n  server-state-file\n"), "'server-state-file' expect one argument: a file path.");
    assert_eq!(refusal("global\n  server-state-base\n"), "'server-state-base' expects one argument: a directory path.");
}

#[test]
fn a_second_global_keyword_keeps_the_first_with_an_alert() {
    let g = ok("global\n  server-state-file /a\n  server-state-file /b\n  server-state-base /x\n  server-state-base /y\n")
        .global
        .expect("global");
    assert_eq!((g.server_state_file.as_deref(), g.server_state_base.as_deref()), (Some("/a"), Some("/x")));
    let w: Vec<(usize, &str, bool)> = g.load_warnings.iter().map(|w| (w.line, w.text.as_str(), w.alert)).collect();
    assert_eq!(
        w,
        [
            (3, "'server-state-file' already specified. Continuing.", true),
            (5, "'server-state-base' already specified. Continuing.", true),
        ]
    );
}

#[test]
fn load_server_state_from_file_takes_one_of_three_words() {
    for (word, want) in [("global", LoadServerState::Global), ("local", LoadServerState::Local), ("none", LoadServerState::None)] {
        let c = ok(&format!("{D}backend b\n  load-server-state-from-file {word}\n"));
        assert_eq!(c.backends[0].load_server_state, want, "{word}");
        let c = ok(&format!("{D}listen l\n  bind 127.0.0.1:19899\n  load-server-state-from-file {word}\n"));
        assert_eq!(c.listens[0].load_server_state, want, "{word}");
    }
    // Words after the first are not looked at.
    assert_eq!(ok(&format!("{D}backend b\n  load-server-state-from-file global x\n")).backends[0].load_server_state, LoadServerState::Global);
    assert_eq!(
        refusal(&format!("{D}backend b\n  load-server-state-from-file foo\n")),
        "'load-server-state-from-file' expects 'global', 'local' or 'none'. Got 'foo'"
    );
    assert_eq!(
        refusal(&format!("{D}backend b\n  load-server-state-from-file\n")),
        "'load-server-state-from-file' expects 'global', 'local' or 'none'. Got ''"
    );
}

#[test]
fn load_server_state_from_file_is_inherited_from_defaults() {
    let c = ok(&format!("{D}  load-server-state-from-file global\nbackend b\nbackend c\n  load-server-state-from-file none\nlisten l\n  bind 127.0.0.1:19899\n"));
    assert_eq!(c.backends[0].load_server_state, LoadServerState::Global);
    assert_eq!(c.backends[1].load_server_state, LoadServerState::None);
    assert_eq!(c.listens[0].load_server_state, LoadServerState::Global);
    // Nothing anywhere: no file is read.
    assert_eq!(ok(&format!("{D}backend b\n")).backends[0].load_server_state, LoadServerState::None);
}

#[test]
fn server_state_file_name_defaults_to_the_backend_name() {
    let c = ok(&format!("{D}backend b\n  server-state-file-name x\nbackend c\n  server-state-file-name use-backend-name\nbackend d\n  server-state-file-name x\n  server-state-file-name\nbackend e\n"));
    let names: Vec<Option<&str>> = c.backends.iter().map(|b| b.server_state_file_name.as_deref()).collect();
    assert_eq!(names, [Some("x"), Some("c"), Some("d"), None]);
    let c = ok(&format!("{D}listen l\n  bind 127.0.0.1:19899\n  server-state-file-name\nlisten m\n  bind 127.0.0.1:19898\n  server-state-file-name /st/m\n"));
    let names: Vec<Option<&str>> = c.listens.iter().map(|l| l.server_state_file_name.as_deref()).collect();
    assert_eq!(names, [Some("l"), Some("/st/m")]);
    assert_eq!(
        refusal(&format!("{D}backend b\n  server-state-file-name x y\n")),
        "'server-state-file-name' cannot handle unexpected argument 'y'."
    );
}

#[test]
fn a_frontend_warns_and_ignores_both() {
    let c = ok(&format!("{D}frontend f\n  bind 127.0.0.1:19899\n  load-server-state-from-file none\n  server-state-file-name x\n"));
    let w: Vec<(usize, &str)> = c.proxy_warnings.iter().map(|w| (w.line, w.text.as_str())).collect();
    assert_eq!(
        w,
        [
            (8, "'load-server-state-from-file' ignored because frontend 'f' has no backend capability."),
            (9, "'server-state-file-name' ignored because frontend 'f' has no backend capability."),
        ]
    );
}

/// `HAProxy` accepts `server-state-file-name` in `defaults` and never copies it to a backend
/// (measured: the backend reads `<base>/<backend name>`). Ibex says so instead of dropping it
/// in silence (AGENTS.md §5); the text is Ibex's own.
#[test]
fn server_state_file_name_in_defaults_warns_that_it_does_nothing() {
    let c = ok(&format!("{D}  server-state-file-name x\nbackend b\n"));
    assert_eq!(c.backends[0].server_state_file_name, None);
    let w: Vec<(usize, &str)> = c.proxy_warnings.iter().map(|w| (w.line, w.text.as_str())).collect();
    assert_eq!(
        w,
        [(6, "'server-state-file-name' is ignored in a 'defaults' section (as HAProxy does): set it in the backend.")]
    );
}

/// A server-state file with `lines` (after the version and the header) in a fresh
/// directory, and the configuration that reads it as the global file, `servers` in
/// backend `b`.
struct StateFile {
    dir: std::path::PathBuf,
}

impl StateFile {
    fn new(lines: &[&str]) -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ibex-t490b-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut text = String::from("1\n# be_id be_name srv_id srv_name srv_addr ...\n");
        for l in lines {
            text.push_str(l);
            text.push('\n');
        }
        std::fs::write(dir.join("st"), text).expect("write");
        StateFile { dir }
    }

    fn cfg(&self, servers: &str) -> String {
        format!(
            "global\n  server-state-file {}/st\nresolvers r\n  nameserver ns1 127.0.0.1:53\n{D}  load-server-state-from-file global\nbackend b\n{servers}",
            self.dir.display()
        )
    }
}

impl Drop for StateFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A file line for `b/<srv>` with `addr`, `admin` and `fqdn`.
fn line(srv: &str, addr: &str, admin: u32, fqdn: &str) -> String {
    format!("3 b 1 {srv} {addr} 2 {admin} 1 1 50 1 0 0 0 0 0 0 {fqdn} 80 - 0 0 - - 0")
}

fn addr(cfg: &Config, i: usize) -> String {
    cfg.backends[0].servers[i].addr.ip().to_string()
}

/// `init-addr last` and the default `last,libc`: the file's `srv_addr` for a server written
/// as a name (`srv->lastaddr`, `srv_apply_lastaddr`). `HAProxy` 3.5-dev8, same file: s1
/// `10.0.0.7` (`localhost`, `init-addr last`), s2 `10.0.0.8` (no `init-addr`: `last` first),
/// s3 `10.1.1.1` with the notice (the file's `foo` is no address), s4 `-` in maintenance
/// (`-` in the file: `last` skipped, then `none`), s5 the configuration's address (written as
/// one: the file's is not read).
#[test]
fn init_addr_last_takes_the_files_address() {
    let f = StateFile::new(&[
        &line("s1", "10.0.0.7", 0, "localhost"),
        &line("s2", "10.0.0.8", 0, "nosuch.invalid"),
        &line("s3", "foo", 0, "nosuch.invalid"),
        &line("s4", "-", 0, "nosuch.invalid"),
        &line("s5", "10.0.0.9", 0, "-"),
    ]);
    let cfg = ok(&f.cfg(
        "  server s1 localhost:80 init-addr last\n  server s2 nosuch.invalid:80\n  server s3 nosuch.invalid:80 init-addr last,10.1.1.1\n\
         \x20 server s4 nosuch.invalid:80 init-addr last,none\n  server s5 127.0.0.1:80\n",
    ));
    assert_eq!([addr(&cfg, 0), addr(&cfg, 1), addr(&cfg, 2), addr(&cfg, 4)], ["10.0.0.7", "10.0.0.8", "10.1.1.1", "127.0.0.1"]);
    let extras = &cfg.backends[0].server_extras;
    assert_eq!((extras.unresolved(1), extras.unresolved(3)), (false, true));
    let notices: Vec<&str> = cfg.proxy_warnings.iter().map(|w| w.text.as_str()).collect();
    assert_eq!(notices, ["{at} : 'server b/s3' : could not resolve address 'nosuch.invalid', falling back to configured address."]);
}

/// `HAProxy`: an address `last` cannot parse is an error of that method, so with nothing
/// after it the load fails with "could not resolve" (not "no method found").
#[test]
fn a_file_address_that_is_no_address_fails_last() {
    let f = StateFile::new(&[&line("s1", "foo", 0, "nosuch.invalid")]);
    let e = parse_str(&f.cfg("  server s1 nosuch.invalid:80 init-addr last\n")).expect_err("refused");
    let alerts: Vec<&str> = e.alerts.iter().map(|(_, t)| t.as_str()).collect();
    assert_eq!(alerts, ["{at} : 'server b/s1' : could not resolve address 'nosuch.invalid'.", "Failed to initialize server(s) addr."]);
}

/// Only a line that is applied gives its address: the first line of the server, with valid
/// values, in a file whose every line has the right shape, of the backend's own file.
#[test]
fn only_an_applied_line_gives_its_address() {
    let last = |lines: &[&str], extra: &str| {
        let f = StateFile::new(lines);
        let cfg = ok(&f.cfg(&format!("{extra}  server s1 nosuch.invalid:80 init-addr last,10.1.1.1\n")));
        addr(&cfg, 0)
    };
    let good = line("s1", "10.0.0.7", 0, "nosuch.invalid");
    assert_eq!(last(&[&good], ""), "10.0.0.7");
    // The first line wins, also when it is the bad one.
    assert_eq!(last(&[&good, &line("s1", "10.0.0.8", 0, "x")], ""), "10.0.0.7");
    assert_eq!(last(&[&line("s1", "10.0.0.8", 9, "x"), &good], ""), "10.1.1.1");
    // A bad value voids the line; a line of the wrong shape voids the file.
    assert_eq!(last(&[&good.replace(" 50 ", " x ")], ""), "10.1.1.1");
    assert_eq!(last(&[&good, "1 2 3"], ""), "10.1.1.1");
    // Another backend's line, a file of another version, a missing file, no file read.
    assert_eq!(last(&[&good.replace(" b ", " c ")], ""), "10.1.1.1");
    let f = StateFile::new(&[&good]);
    std::fs::write(f.dir.join("st"), format!("2\n{good}\n")).expect("write");
    assert_eq!(addr(&ok(&f.cfg("  server s1 nosuch.invalid:80 init-addr last,10.1.1.1\n")), 0), "10.1.1.1");
    std::fs::remove_file(f.dir.join("st")).expect("rm");
    assert_eq!(addr(&ok(&f.cfg("  server s1 nosuch.invalid:80 init-addr last,10.1.1.1\n")), 0), "10.1.1.1");
    assert_eq!(last(&[&good], "  load-server-state-from-file none\n"), "10.1.1.1");
    // A local file: `<base>/<backend>`, its lines naming the backend.
    let f = StateFile::new(&[&good]);
    std::fs::rename(f.dir.join("st"), f.dir.join("b")).expect("rename");
    let local = f.cfg("  load-server-state-from-file local\n  server s1 nosuch.invalid:80 init-addr last,10.1.1.1\n");
    let local = local.replace("server-state-file ", &format!("server-state-base {}\n  server-state-file ", f.dir.display()));
    assert_eq!(addr(&ok(&local), 0), "10.0.0.7");
    std::fs::write(f.dir.join("b"), format!("1\n{}\n", good.replace(" b ", " c "))).expect("write");
    assert_eq!(addr(&ok(&local), 0), "10.1.1.1");
    std::fs::remove_file(f.dir.join("b")).expect("rm");
    assert_eq!(addr(&ok(&local), 0), "10.1.1.1");
}

/// `srv_fqdn` with `SRV_ADMF_FQDN_CHANGED` (64): `HAProxy` keeps the flag when the file's
/// name differs from the configuration's, and resolves the file's name when the server has
/// `resolvers` (`srv_set_fqdn` needs them); the same name or no flag: nothing. Measured:
/// `localhost` + file `other.invalid` 64 -> `localhost`, admin 64; file `localhost` 64 ->
/// admin 0; with `resolvers r`, `a1.test` + file `a2.test` 64 -> `a2.test` (resolved).
#[test]
fn a_changed_fqdn_is_kept_with_resolvers() {
    let f = StateFile::new(&[
        &line("s1", "10.0.0.7", 64, "other.invalid"),
        &line("s2", "10.0.0.7", 0, "other.invalid"),
        &line("s3", "10.0.0.7", 64, "localhost"),
        &line("s4", "10.0.0.7", 64, "a2.test"),
    ]);
    let cfg = ok(&f.cfg(
        "  server s1 localhost:80\n  server s2 localhost:80\n  server s3 localhost:80\n  server s4 a1.test:80 resolvers r\n",
    ));
    let names: Vec<(&str, bool)> = cfg.backends[0].server_extras.names.iter().map(|n| (&*n.fqdn, n.fqdn_changed)).collect();
    assert_eq!(names, [("localhost", true), ("localhost", false), ("localhost", false), ("a2.test", true)]);
    assert_eq!(addr(&cfg, 3), "10.0.0.7");
}
