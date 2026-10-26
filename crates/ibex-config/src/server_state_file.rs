// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The server-state file's format (T490, version 1 of `src/server_state.c`): its lines, its
//! fields and their checks. `ibex-rt` `server_state` applies a file when the proxies are
//! built; [`crate::parser`] reads the address and `srv_fqdn` of the servers written as a
//! name before they are resolved (`init-addr last`, `srv->lastaddr`).

use std::fmt::Write as _;
use std::io::{BufRead, Read};

/// `SRV_STATE_LINE_MAXLEN` less the terminating NUL: the most `fgets` reads at once.
pub const LINE_MAX: u64 = 1999;
/// `SRV_STATE_FILE_MAX_FIELDS`, and the fewest fields of a version 1 line.
pub const MAX_FIELDS: usize = 25;
pub const MIN_FIELDS: usize = 20;

/// `srv_state_get_filepath`: `name` under `server-state-base` unless it is absolute.
pub fn file_path(base: Option<&str>, name: &str) -> String {
    match base {
        Some(b) if !name.starts_with('/') => {
            let sep = if b.ends_with('/') { "" } else { "/" };
            format!("{b}{sep}{name}")
        }
        _ => name.to_string(),
    }
}

/// Reads the next line of at most [`LINE_MAX`] bytes into `buf`; `false` at the end.
pub fn next_line(r: &mut impl BufRead, buf: &mut Vec<u8>) -> bool {
    buf.clear();
    matches!(r.by_ref().take(LINE_MAX).read_until(b'\n', buf), Ok(n) if n > 0)
}

/// What a line holds (`srv_state_parse_line`). The fields borrow the line: no allocation.
#[allow(clippy::large_enum_variant)]
pub enum Line<'a> {
    /// Empty or a comment.
    Skip,
    /// Truncated (no end of line) or a field count out of 20..=25.
    Bad,
    Fields([&'a str; MAX_FIELDS]),
}

pub fn parse_line(buf: &[u8]) -> Line<'_> {
    let Some(text) = buf.strip_suffix(b"\n") else { return Line::Bad };
    let Ok(text) = std::str::from_utf8(text) else { return Line::Bad };
    let t = text.trim_start_matches([' ', '\t']);
    if t.is_empty() || t.starts_with('#') {
        return Line::Skip;
    }
    let mut f = [""; MAX_FIELDS];
    let mut n = 0;
    // HAProxy stops at 25 fields and does not count the rest.
    for word in t.split([' ', '\t']).filter(|w| !w.is_empty()).take(MAX_FIELDS) {
        f[n] = word;
        n += 1;
    }
    if n < MIN_FIELDS { Line::Bad } else { Line::Fields(f) }
}

/// `srv_state_get_version`: `Some(1)`, `Some(0)` for a version line that is not `1`, `None`
/// for an empty file.
pub fn version(r: &mut impl BufRead, buf: &mut Vec<u8>) -> Option<u8> {
    if !next_line(r, buf) {
        return None;
    }
    // `strtol` and then the end of the line: leading blanks and a sign are taken.
    let line = std::str::from_utf8(buf).unwrap_or("");
    let ok = line.strip_suffix('\n').and_then(strtol_all) == Some(1);
    Some(u8::from(ok))
}

/// `strtol` of a whole field: a number and nothing after it.
pub fn strtol_all(s: &str) -> Option<i64> {
    let t = s.trim_start_matches([' ', '\t']);
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then(|| t.parse().ok()).flatten()
}

/// `strtol` as `HAProxy` calls it: leading digits (after blanks and a sign), the rest ignored;
/// `None` when there is no digit or the value overflows.
pub fn strtol(s: &str) -> Option<i64> {
    let t = s.trim_start_matches([' ', '\t']);
    let (neg, rest) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let end = rest.bytes().position(|b| !b.is_ascii_digit()).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    let v: i64 = rest[..end].parse().ok()?;
    Some(if neg { -v } else { v })
}

/// `strl2uic`: the leading digits, 0 when there are none; saturates instead of wrapping.
pub fn strl2uic(s: &str) -> u64 {
    s.bytes().take_while(u8::is_ascii_digit).fold(0u64, |acc, b| acc.saturating_mul(10).saturating_add(u64::from(b - b'0')))
}

/// `invalid_domainchar`: only `[A-Za-z0-9_.-]`.
pub fn invalid_domain(s: &str) -> bool {
    !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// The file's view of one server, checked (`srv_state_srv_update`).
pub struct Fields {
    pub op: i64,
    pub admin: i64,
    pub uweight: u32,
    pub iweight: u32,
    pub age: i64,
    pub check_status: i64,
    pub health: i64,
    pub check_state: i64,
    pub port: u16,
    pub use_ssl: Option<bool>,
    pub check_port: Option<String>,
    pub check_addr: Option<String>,
    pub agent_addr: Option<String>,
    pub agent_port: Option<String>,
}

/// The values of a line, checked as `srv_state_srv_update` checks them.
///
/// # Errors
///
/// `HAProxy`'s list of the invalid values (", invalid <field> value '<v>'" each).
pub fn check_fields(f: &[&str; MAX_FIELDS]) -> Result<Fields, String> {
    let mut msg = String::new();
    let mut num = |i: usize, name: &str, ok: &dyn Fn(i64) -> bool| -> i64 {
        match strtol(f[i]) {
            Some(v) if ok(v) => v,
            _ => {
                let _ = write!(msg, ", invalid {name} value '{}'", f[i]);
                0
            }
        }
    };
    let op = num(5, "srv_op_state", &|v| (0..=3).contains(&v));
    // The inherited states are worked out again, `SRV_ADMF_FQDN_CHANGED` is dropped.
    let admin = num(6, "srv_admin_state", &|v| [0, 1, 4, 5, 12, 8].contains(&(v & !(0x10 | 0x02 | 0x20 | 0x40))));
    let admin = admin & !(0x10 | 0x02 | 0x20 | 0x40);
    let uweight = num(7, "srv_uweight", &|v| (0..=256).contains(&v));
    let iweight = num(8, "srv_iweight", &|v| (0..=256).contains(&v));
    let age = num(9, "srv_last_time_change", &|_| true);
    let check_status = num(10, "srv_check_status", &|v| v < 21);
    num(11, "srv_check_result", &|v| (0..=4).contains(&v));
    let health = num(12, "srv_check_health", &|_| true);
    let check_state = num(13, "srv_check_state", &|v| v & !0x1F == 0);
    num(14, "srv_agent_state", &|v| v & !0x1F == 0);
    num(15, "bk_f_forced_id", &|v| v == 0 || v == 1);
    num(16, "srv_f_forced_id", &|v| v == 0 || v == 1);
    let fqdn = f[17];
    if !fqdn.starts_with('-') && (fqdn.len() > 255 || invalid_domain(fqdn)) {
        let _ = write!(msg, ", invalid srv_fqdn value '{fqdn}'");
    }
    let port = u16::try_from(strl2uic(f[18]));
    if port.is_err() {
        let _ = write!(msg, ", invalid srv_port value '{}'", f[18]);
    }
    if !msg.is_empty() {
        return Err(msg);
    }
    let opt = |i: usize, none: &str| Some(f[i]).filter(|v| !v.is_empty() && *v != none).map(str::to_string);
    Ok(Fields {
        op,
        admin,
        uweight: u32::try_from(uweight).unwrap_or(0),
        iweight: u32::try_from(iweight).unwrap_or(0),
        age,
        check_status,
        health,
        check_state,
        port: port.unwrap_or(0),
        use_ssl: Some(f[20]).filter(|v| !v.is_empty()).map(|v| strtol(v).unwrap_or(0) != 0),
        check_port: opt(21, "0"),
        check_addr: opt(22, "-"),
        agent_addr: opt(23, "-"),
        agent_port: opt(24, "0"),
    })
}

/// A section whose servers written as a name can take their address from a file.
struct NameSection<'a> {
    name: &'a str,
    servers: &'a [crate::ast::Server],
    names: &'a mut [crate::ast::ServerName],
    load: crate::ast::LoadServerState,
    file_name: Option<&'a str>,
}

/// Opens `path` if it is a version 1 file whose lines all have the right shape, silently:
/// `ibex-rt` `server_state::open` says why a file is not read when it applies it.
fn open_checked(path: &str) -> Option<std::io::BufReader<std::fs::File>> {
    let mut r = std::io::BufReader::new(std::fs::File::open(path).ok()?);
    let mut buf = Vec::with_capacity(256);
    if version(&mut r, &mut buf) != Some(1) {
        return None;
    }
    while next_line(&mut r, &mut buf) {
        if matches!(parse_line(&buf), Line::Bad) {
            return None;
        }
    }
    let mut f = r.into_inner();
    std::io::Seek::rewind(&mut f).ok()?;
    let mut r = std::io::BufReader::new(f);
    next_line(&mut r, &mut buf);
    Some(r)
}

/// The first line of each server written as a name in `secs` (a local file when `local`):
/// its `srv_addr` into [`crate::ast::ServerName::last_addr`] and its `srv_fqdn`
/// (`srv_state_srv_update`), when the line's values are valid.
#[allow(clippy::many_single_char_names)] // f(ields), u(ser), s(ection), k, n(ame)
fn read_file(mut r: std::io::BufReader<std::fs::File>, secs: &mut [&mut NameSection<'_>], local: bool) {
    let mut seen: Vec<Vec<bool>> = secs.iter().map(|s| vec![false; s.names.len()]).collect();
    let mut buf = Vec::with_capacity(256);
    while next_line(&mut r, &mut buf) {
        let Line::Fields(f) = parse_line(&buf) else { continue };
        // A local file's lines must name its backend too (see `server_state::apply_file`).
        let Some(u) = secs.iter().position(|s| s.name == f[1]).filter(|_| !local || secs[0].name == f[1]) else { continue };
        let s = &mut *secs[u];
        let Some(k) = s.names.iter().position(|n| s.servers.get(n.index as usize).is_some_and(|srv| srv.id == f[3])) else { continue };
        if std::mem::replace(&mut seen[u][k], true) || check_fields(&f).is_err() {
            continue;
        }
        let n = &mut s.names[k];
        if f[4] != "-" {
            n.last_addr = Some(f[4].into());
        }
        let fqdn = Some(f[17]).filter(|v| !v.starts_with('-'));
        if let Some(fqdn) = fqdn.filter(|v| **v != *n.fqdn) {
            // Set from the CLI before the reload (`SRV_ADMF_FQDN_CHANGED`): kept, and with
            // resolvers the name to resolve (`srv_set_fqdn` needs them).
            if strtol(f[6]).is_some_and(|a| a & 0x40 != 0) {
                n.fqdn_changed = true;
                if n.resolvers.is_some() {
                    n.fqdn = fqdn.into();
                }
            }
        }
    }
}

/// Before the servers written as a name are resolved (`apply_server_state` runs before
/// `srv_init_addr`): what their server-state file has for them. Reads only the files of the
/// sections that have such servers; memory is a line and a flag per such server.
pub(crate) fn read_names(global: Option<&crate::ast::GlobalSection>, listens: &mut [crate::ast::ListenSection], backends: &mut [crate::ast::BackendSection]) {
    use crate::ast::LoadServerState as L;
    let base = global.and_then(|g| g.server_state_base.as_deref());
    let listens = listens.iter_mut().filter(|l| !l.disabled).map(|l| NameSection {
        name: &l.name,
        servers: &l.servers,
        names: &mut l.server_extras.names,
        load: l.load_server_state,
        file_name: l.server_state_file_name.as_deref(),
    });
    let backends = backends.iter_mut().filter(|b| !b.disabled).map(|b| NameSection {
        name: &b.name,
        servers: &b.servers,
        names: &mut b.server_extras.names,
        load: b.load_server_state,
        file_name: b.server_state_file_name.as_deref(),
    });
    let mut secs: Vec<NameSection<'_>> = listens.chain(backends).filter(|s| s.load != L::None && !s.names.is_empty()).collect();
    if let Some(name) = global.and_then(|g| g.server_state_file.as_deref()) {
        let mut users: Vec<&mut NameSection<'_>> = secs.iter_mut().filter(|s| s.load == L::Global).collect();
        if !users.is_empty() {
            if let Some(r) = open_checked(&file_path(base, name)) {
                read_file(r, &mut users, false);
            }
        }
    }
    for s in secs.iter_mut().filter(|s| s.load == L::Local) {
        let path = file_path(base, s.file_name.unwrap_or(s.name));
        if let Some(r) = open_checked(&path) {
            read_file(r, &mut [s], true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strtol_takes_the_leading_number() {
        assert_eq!(strtol("12x"), Some(12));
        assert_eq!(strtol("-3"), Some(-3));
        assert_eq!(strtol("+4"), Some(4));
        assert_eq!(strtol("x"), None);
        assert_eq!(strtol("-"), None);
        assert_eq!(strtol("99999999999999999999"), None);
        assert_eq!(strtol_all("1"), Some(1));
        assert_eq!(strtol_all("1x"), None);
        assert_eq!(strl2uic("80x"), 80);
        assert_eq!(strl2uic("-"), 0);
        assert_eq!(strl2uic("99999999999999999999999"), u64::MAX);
    }

    #[test]
    fn paths_join_the_base() {
        assert_eq!(file_path(Some("/a"), "b"), "/a/b");
        assert_eq!(file_path(Some("/a/"), "b"), "/a/b");
        assert_eq!(file_path(Some("/a"), "/c"), "/c");
        assert_eq!(file_path(None, "b"), "b");
    }

    #[test]
    fn a_line_is_skipped_bad_or_fields() {
        assert!(matches!(parse_line(b"  # x\n"), Line::Skip));
        assert!(matches!(parse_line(b"\t\n"), Line::Skip));
        assert!(matches!(parse_line(b"1 2 3\n"), Line::Bad));
        assert!(matches!(parse_line(b"1 b 1 s 1 2 0 1 1 0 1 0 0 0 0 0 0 - 80 -"), Line::Bad));
        assert!(matches!(parse_line(b"\xff\n"), Line::Bad));
        let Line::Fields(f) = parse_line(b"1\tb 1 s 1 2 0 1 1 0 1 0 0 0 0 0 0 - 80 -\n") else { panic!("fields") };
        assert_eq!((f[1], f[18], f[20]), ("b", "80", ""));
    }

    #[test]
    fn every_bad_value_is_named() {
        let line = "1 b 1 s 1.2.3.4 7 9 300 -1 x 21 5 x 64 64 2 2 a/b 70000 - 0 0 - - 0\n";
        let Line::Fields(f) = parse_line(line.as_bytes()) else { panic!("fields") };
        let Err(msg) = check_fields(&f) else { panic!("accepted") };
        assert_eq!(
            msg,
            ", invalid srv_op_state value '7', invalid srv_admin_state value '9', invalid srv_uweight value '300', \
             invalid srv_iweight value '-1', invalid srv_last_time_change value 'x', invalid srv_check_status value '21', \
             invalid srv_check_result value '5', invalid srv_check_health value 'x', invalid srv_check_state value '64', \
             invalid srv_agent_state value '64', invalid bk_f_forced_id value '2', invalid srv_f_forced_id value '2', \
             invalid srv_fqdn value 'a/b', invalid srv_port value '70000'"
        );
    }
}
