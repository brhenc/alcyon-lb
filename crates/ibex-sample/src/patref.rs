// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/pattern.c (`pat_ref`) and src/map.c (the `show/add/set/del/clear
// map|acl` CLI commands).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Pattern references: the files an ACL (`-f`) or a map converter reads, as objects the
//! runtime CLI can list and change while requests are being served.
//!
//! One process-wide registry holds them, so a change made on the stats socket by one thread
//! is what every worker thread matches against on its next request:
//!
//! * a map file's entries live here, indexed for each way a converter matches them
//!   ([`PatTable`]), and [`crate::registry::match_map`] reads them in place;
//! * an ACL file's patterns are compiled once per `(method, -i)` in the same table and read
//!   by [`Matcher::File`].
//!
//! A change on the CLI changes one entry and its indexes, never the whole file (T251).
//!
//! The CLI answers are those measured on `HAProxy 3.5-dev8-885761-29` (see
//! `tests/ops_patref_cli.rs`).

use crate::matcher::Matcher;
use crate::pattable::PatTable;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Whether a reference backs an ACL or a map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefKind {
    Acl,
    Map,
}

impl RefKind {
    const fn word(self) -> &'static str {
        match self {
            Self::Acl => "acl",
            Self::Map => "map",
        }
    }
}

/// What a map's keys are, from the converter that reads it: it decides what `add map`
/// accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapKeys {
    Str,
    Int,
    Ip,
    Reg,
}

/// One entry: what `show map` prints is `<id> <key> <value>`.
#[derive(Clone, Debug)]
pub struct PatEntry {
    pub id: u64,
    pub key: String,
    pub val: String,
}

/// A pattern file, as loaded and as changed since.
#[derive(Debug)]
pub struct PatRef {
    pub id: usize,
    pub kind: RefKind,
    pub file: String,
    users: Mutex<Vec<String>>,
    /// Modification time and size of the file when it was read.
    stamp: Mutex<Option<(Option<std::time::SystemTime>, u64)>>,
    map_keys: Mutex<MapKeys>,
    /// The entries, their indexes, and the patterns compiled for every ACL reader.
    entries: RwLock<PatTable>,
    version: AtomicU64,
}

/// Locks, taking the data of a lock a panicking thread poisoned: the registry holds plain
/// lists that a panic cannot leave half-written.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(std::sync::PoisonError::into_inner)
}

static REFS: Mutex<Vec<Arc<PatRef>>> = Mutex::new(Vec::new());
static NEXT_ENTRY: AtomicU64 = AtomicU64::new(0x5581_0000);

fn table_of(pairs: Vec<(String, String)>) -> PatTable {
    let mut t = PatTable::new();
    for (key, val) in pairs {
        t.insert(next_entry_id(), &key, &val);
    }
    t
}

fn next_entry_id() -> u64 {
    NEXT_ENTRY.fetch_add(0x40, Ordering::Relaxed)
}

/// The lines of a map file as `(key, value)`: `#` comments and blank lines skipped, the
/// value is what follows the first blank (blanks inside it kept as one space).
fn parse_lines(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            (parts[0].to_string(), parts[1..].join(" "))
        })
        .collect()
}

impl PatRef {
    fn new(id: usize, kind: RefKind, file: &str, pairs: Vec<(String, String)>) -> Self {
        Self {
            id,
            kind,
            file: file.to_string(),
            users: Mutex::new(Vec::new()),
            stamp: Mutex::new(None),
            map_keys: Mutex::new(MapKeys::Str),
            entries: RwLock::new(table_of(pairs)),
            version: AtomicU64::new(1),
        }
    }

    /// The version of the entries; it moves on every change.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// A copy of the entries, in the order they were added.
    #[must_use]
    pub fn entries(&self) -> Vec<PatEntry> {
        read(&self.entries).iter().map(|(id, e)| PatEntry { id, key: e.key.to_string(), val: e.val.to_string() }).collect()
    }

    /// The entries and their indexes, for a lookup.
    pub fn table(&self) -> std::sync::RwLockReadGuard<'_, PatTable> {
        read(&self.entries)
    }

    /// Records a reader of this file: what `show` says it is "used by".
    pub fn add_user(&self, text: String) {
        let mut u = lock(&self.users);
        if !u.contains(&text) {
            u.push(text);
        }
    }

    fn changed(&self) {
        self.version.fetch_add(1, Ordering::AcqRel);
    }

    fn writable(&self) -> Result<(), String> {
        if self.file.is_empty() {
            return Err("the inline patterns of an ACL cannot be changed at runtime (not supported); use an ACL file with -f".to_string());
        }
        Ok(())
    }

    fn check_key(&self, key: &str) -> Result<(), String> {
        self.writable()?;
        match self.kind {
            RefKind::Map => match *lock(&self.map_keys) {
                MapKeys::Str => Ok(()),
                MapKeys::Int => {
                    let ok = |s: &str| s.parse::<i64>().is_ok();
                    let range = key.split_once(['-', ':']).is_some_and(|(a, b)| ok(a) && ok(b));
                    if ok(key) || range { Ok(()) } else { Err(format!("'{key}' is not a number.")) }
                }
                MapKeys::Ip => {
                    let net = key.split_once('/').map_or(key, |(n, _)| n);
                    if net.parse::<std::net::IpAddr>().is_ok() {
                        Ok(())
                    } else {
                        Err(format!("'{key}' is not a valid IPv4 or IPv6 address."))
                    }
                }
                MapKeys::Reg => ibex_regex::UserRegex::new(key)
                    .map(|_| ())
                    .map_err(|e| format!("regex '{key}' is invalid (error={e}).")),
            },
            RefKind::Acl => {
                let readers = read(&self.entries).reader_methods();
                for (method, ci) in readers {
                    Matcher::compile_with_flags(&method, key, ci)?;
                }
                Ok(())
            }
        }
    }

    fn add(&self, key: &str, val: &str) -> Result<(), String> {
        self.check_key(key)?;
        write(&self.entries).insert(next_entry_id(), key, val);
        self.changed();
        Ok(())
    }
}

/// The reference of ACL file `path`, created (and read) when none is registered.
///
/// # Errors
/// The file cannot be read.
pub fn acl_file(path: &str) -> Result<Arc<PatRef>, String> {
    let failed = || format!("failed to open pattern file <{path}>");
    let mut refs = lock(&REFS);
    let stamp = std::fs::metadata(path).map_err(|_| failed()).map(|m| (m.modified().ok(), m.len()))?;
    if let Some(r) = refs.iter().find(|r| r.kind == RefKind::Acl && r.file == path) {
        // A file that changed on disk since it was read, and that the CLI has not touched,
        // is read again: parsing an ACL reads its file, as it always did.
        let stale = *lock(&r.stamp) != Some(stamp);
        if stale && r.version() == 1 {
            let pairs = read_acl_file(path).ok_or_else(failed)?;
            let mut t = write(&r.entries);
            t.clear();
            for (key, val) in pairs {
                t.insert(next_entry_id(), &key, &val);
            }
            drop(t);
            *lock(&r.stamp) = Some(stamp);
        }
        return Ok(Arc::clone(r));
    }
    let pairs = read_acl_file(path).ok_or_else(failed)?;
    let r = Arc::new(PatRef::new(refs.len(), RefKind::Acl, path, pairs));
    *lock(&r.stamp) = Some(stamp);
    refs.push(Arc::clone(&r));
    Ok(r)
}

/// The patterns of an ACL file (`pat_ref_read_from_file`): leading and trailing blanks
/// dropped, a CR ends the line, empty lines and `#` lines skipped.
fn read_acl_file(path: &str) -> Option<Vec<(String, String)>> {
    let text = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&text);
    Some(
        text.split('\n')
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.trim_start_matches([' ', '\t']))
            .map(|l| l.split('\r').next().unwrap_or(l))
            .map(|l| l.trim_end_matches([' ', '\t']))
            .filter(|l| !l.is_empty())
            .map(|l| (l.to_string(), String::new()))
            .collect(),
    )
}

/// A reference for an ACL expression's inline patterns (it has no file). It is listed so
/// that ids are numbered as `HAProxy` numbers them, but its entries cannot be changed at
/// runtime.
fn acl_expr(desc: String) {
    let mut refs = lock(&REFS);
    let r = Arc::new(PatRef::new(refs.len(), RefKind::Acl, "", Vec::new()));
    r.add_user(desc);
    refs.push(r);
}

/// The reference of map file `path`, created (and read) when none is registered; `keys` and
/// `user` describe the converter that reads it. `None` when the file cannot be read.
#[must_use]
pub fn map_file(path: &str, keys: MapKeys, user: Option<String>) -> Option<Arc<PatRef>> {
    let mut refs = lock(&REFS);
    let found = refs.iter().find(|r| r.kind == RefKind::Map && r.file == path).cloned();
    let r = if let Some(r) = found {
        r
    } else {
        let text = std::fs::read_to_string(path).ok()?;
        let r = Arc::new(PatRef::new(refs.len(), RefKind::Map, path, parse_lines(&text)));
        *lock(&r.map_keys) = keys;
        refs.push(Arc::clone(&r));
        r
    };
    drop(refs);
    if let Some(u) = user {
        r.add_user(u);
    }
    Some(r)
}

/// Every registered reference of `kind`, in id order.
#[must_use]
pub fn list(kind: RefKind) -> Vec<Arc<PatRef>> {
    lock(&REFS).iter().filter(|x| x.kind == kind).cloned().collect()
}

fn find(kind: RefKind, ident: &str) -> Result<Arc<PatRef>, String> {
    let unknown = || format!("Unknown {} identifier. Please use #<id> or <file>.", if kind == RefKind::Map { "map" } else { "ACL" });
    let refs = list(kind);
    if let Some(id) = ident.strip_prefix('#') {
        let id: usize = id.parse().map_err(|_| unknown())?;
        refs.into_iter().find(|r| r.id == id).ok_or_else(unknown)
    } else {
        refs.into_iter().find(|r| r.file == ident).ok_or_else(unknown)
    }
}

/// Scans the configuration text for the files its ACLs and maps read, so that they are
/// registered in the order they are written, with where they are used. `locate` turns a
/// line of `text` into the file and line it came from.
pub fn scan_config(text: &str, locate: &dyn Fn(usize) -> (String, usize)) {
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split(" #").next().unwrap_or(raw);
        let line = if line.trim_start().starts_with('#') { "" } else { line };
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        let (file, fline) = locate(n + 1);
        // Each ACL expression is a reference of its own (patterns written inline), after the
        // references of the files its `-f` options name: `acl <name> <expr>` and `{ <expr> }`.
        let mut groups: Vec<&[&str]> = Vec::new();
        if tokens[0] == "acl" && tokens.len() > 2 {
            groups.push(&tokens[2..]);
        } else {
            for (i, t) in tokens.iter().enumerate() {
                if *t == "{" {
                    let end = tokens[i..].iter().position(|t| *t == "}").map_or(tokens.len(), |e| i + e);
                    groups.push(&tokens[i + 1..end]);
                }
            }
        }
        for group in groups {
            let Some(fetch) = group.first() else { continue };
            for w in group.windows(2) {
                if w[0] == "-f" {
                    if let Ok(r) = acl_file(w[1]) {
                        r.add_user(format!("acl at file '{file}' line {fline}"));
                    }
                }
            }
            let name = fetch.split('(').next().unwrap_or(fetch);
            acl_expr(format!("acl '{name}' file '{file}' line {fline}"));
        }
        // `map(<file>,...)`, `map_beg(<file>,...)`, `set-map(<file>)`, `del-map(<file>)`.
        let mut from = 0;
        while let Some(at) = line[from..].find("map") {
            let start = from + at;
            from = start + 3;
            let before = line[..start].chars().next_back();
            if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            let rest = &line[start..];
            let name_len = rest.find('(').unwrap_or(0);
            let name = &rest[..name_len];
            let keys = match name {
                "map_int" => MapKeys::Int,
                "map_ip" => MapKeys::Ip,
                "map_reg" | "map_regm" => MapKeys::Reg,
                "map" | "map_str" | "map_beg" | "map_end" | "map_sub" | "map_dir" | "map_dom" => MapKeys::Str,
                _ => continue,
            };
            let args = &rest[name_len + 1..];
            let end = args.find([',', ')']).unwrap_or(args.len());
            let path = args[..end].trim_matches(['"', '\'']);
            if !path.is_empty() {
                let _ = map_file(path, keys, Some(format!("map at file '{file}' line {fline}")));
            }
        }
    }
}

/// `# id (file) description` and one line per reference.
fn show_list(kind: RefKind) -> String {
    let mut out = String::from("# id (file) description\n");
    for r in list(kind) {
        let users = lock(&r.users).join(", ");
        let n = read(&r.entries).len();
        let what = if r.file.is_empty() { users } else { format!("pattern loaded from file '{}' used by {users}", r.file) };
        let _ = writeln!(out, "{} ({}) {what}. curr_ver=0 next_ver=0 entry_cnt={n}", r.id, r.file);
    }
    out
}

fn show_entries(r: &PatRef) -> String {
    let mut out = String::new();
    for e in r.entries() {
        match r.kind {
            RefKind::Map => {
                let _ = writeln!(out, "0x{:x} {} {}", e.id, e.key, e.val);
            }
            RefKind::Acl => {
                let _ = writeln!(out, "0x{:x} {}", e.id, e.key);
            }
        }
    }
    out
}

/// Runs `show|add|set|del|clear map|acl <args>` (`verb` and `kind` already split off).
/// `payload` carries the lines of an `add map <id> <<` command. The answer is what the CLI
/// prints, without the closing empty line.
#[must_use]
pub fn command(verb: &str, kind: RefKind, args: &[&str], payload: Option<&str>) -> String {
    match run(verb, kind, args, payload) {
        Ok(s) => s,
        Err(e) => format!("{e}\n"),
    }
}

#[allow(clippy::too_many_lines)]
fn run(verb: &str, kind: RefKind, args: &[&str], payload: Option<&str>) -> Result<String, String> {
    let word = kind.word();
    let ident_or = |missing: String| args.first().copied().ok_or(missing);
    match verb {
        "show" => match args.first() {
            None => Ok(show_list(kind)),
            Some(id) => {
                let r = find(kind, id)?;
                Ok(show_entries(&r))
            }
        },
        "clear" => {
            let id = ident_or(format!("Missing {} identifier.", if kind == RefKind::Map { "map" } else { "ACL" }))?;
            let r = find(kind, id)?;
            r.writable()?;
            write(&r.entries).clear();
            r.changed();
            Ok(String::new())
        }
        "add" => {
            if let Some(body) = payload.filter(|_| kind == RefKind::Map && args.len() == 1) {
                let r = find(kind, args[0])?;
                for line in body.lines() {
                    let mut it = line.split_whitespace();
                    let Some(key) = it.next() else { continue };
                    let Some(val) = it.next() else { return Err(format!("Missing value for key '{key}'.")) };
                    r.add(key, val)?;
                }
                return Ok(String::new());
            }
            let usage = if kind == RefKind::Map {
                "'add map' expects three parameters (map identifier, key and value) or one parameter (map identifier) and a payload".to_string()
            } else {
                "'add acl' expects two parameters: ACL identifier and pattern.".to_string()
            };
            let want = if kind == RefKind::Map { 3 } else { 2 };
            if args.len() < want {
                return Err(usage);
            }
            let r = find(kind, args[0])?;
            r.add(args[1], if kind == RefKind::Map { args[2] } else { "" })?;
            Ok(String::new())
        }
        "set" => {
            if kind != RefKind::Map || args.len() < 3 {
                return Err("'set map' expects three parameters: map identifier, key and value.".to_string());
            }
            let r = find(kind, args[0])?;
            let hit = {
                let mut t = write(&r.entries);
                let ids = t.ids(args[1]);
                for id in &ids {
                    t.set_val(*id, args[2]);
                }
                !ids.is_empty()
            };
            if !hit {
                return Err(if args[1].starts_with('#') { "key or pattern not found." } else { "entry not found." }.to_string());
            }
            r.changed();
            Ok(String::new())
        }
        "del" => {
            if args.len() < 2 {
                return Err(format!(
                    "This command expects two parameters: {} identifier and key.",
                    if kind == RefKind::Map { "map" } else { "ACL" }
                ));
            }
            let r = find(kind, args[0])?;
            r.writable()?;
            let by_ref = args[1].starts_with('#');
            let removed = {
                let mut t = write(&r.entries);
                t.ids(args[1]).into_iter().filter(|id| t.remove(*id)).count()
            };
            if removed == 0 && by_ref {
                return Err("Key not found.".to_string());
            }
            r.changed();
            Ok(String::new())
        }
        _ => Err(format!("Unknown {word} command.")),
    }
}

/// An ACL's `-f` file as a matcher: the patterns of the file, compiled once per method in
/// the file's table and kept up to date entry by entry when the CLI changes the file.
#[derive(Debug)]
pub struct FileMatcher {
    pat: Arc<PatRef>,
    /// The reader's index in the table.
    reader: usize,
}

impl FileMatcher {
    /// # Errors
    /// A pattern of the file does not compile with `method`.
    pub fn new(pat: Arc<PatRef>, method: &str, case_insensitive: bool) -> Result<Self, String> {
        let reader = write(&pat.entries).reader(method, case_insensitive)?;
        Ok(Self { pat, reader })
    }

    /// Whether any pattern of the file matches `sample`, as the file is now.
    #[must_use]
    pub fn matches(&self, sample: &crate::sample::Sample) -> bool {
        read(&self.pat.entries).compiled(self.reader).any(|m| m.matches(sample))
    }

    /// Whether the file has no pattern now.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        read(&self.pat.entries).is_empty()
    }

    /// The shortest pattern (for payload waiting decisions).
    #[must_use]
    pub fn min_pattern_len(&self) -> usize {
        read(&self.pat.entries).compiled(self.reader).map(Matcher::min_pattern_len).min().unwrap_or(1)
    }

    /// Whether a miss may become a hit with more payload.
    #[must_use]
    pub fn may_match_later(&self, ends_with_newline: bool) -> bool {
        read(&self.pat.entries).compiled(self.reader).any(|m| m.may_match_later(ends_with_newline))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::Sample;

    fn tmp(name: &str, text: &str) -> String {
        let p = std::env::temp_dir().join(format!("ibex-t171-{}-{name}", std::process::id()));
        std::fs::write(&p, text).expect("write");
        p.display().to_string()
    }

    #[test]
    fn a_file_matcher_follows_the_commands() {
        let path = tmp("a.acl", "/x\n");
        let r = acl_file(&path).expect("file");
        let m = Matcher::File(Arc::new(FileMatcher::new(Arc::clone(&r), "beg", false).expect("matcher")));
        let s = |t: &str| Sample::Str(t.to_string());
        assert!(m.matches(&s("/x1")) && !m.matches(&s("/z")));
        assert_eq!(m.min_pattern_len(), 2);
        assert!(!m.may_match_later(false));
        assert_eq!(command("add", RefKind::Acl, &[&path, "/z"], None), "");
        assert!(m.matches(&s("/z1")));
        r.add_user("acl at file 'c' line 1".to_string());
        r.add_user("acl at file 'c' line 1".to_string());
        assert_eq!(command("frob", RefKind::Acl, &[&path], None), "Unknown acl command.\n");
        // A pattern no reader can compile is refused, and the file is unchanged.
        let ints = tmp("i.acl", "5\n");
        let ri = acl_file(&ints).expect("file");
        let mi = FileMatcher::new(Arc::clone(&ri), "int", false).expect("matcher");
        assert!(command("add", RefKind::Acl, &[&ints, "x"], None).contains('x'));
        assert_eq!(ri.entries().len(), 1);
        assert!(!mi.is_empty());
        // `del` by the id `show` prints.
        let id = format!("#0x{:x}", r.entries()[0].id);
        assert_eq!(command("del", RefKind::Acl, &[&path, &id], None), "");
        assert!(!m.matches(&s("/x1")));
        assert_eq!(command("del", RefKind::Acl, &[&path, "#0xdead"], None), "Key not found.\n");
        // A reload of the file on disk is picked up by a new parse until the CLI has edited it.
        let reread = tmp("r.acl", "/a\n");
        let rr = acl_file(&reread).expect("file");
        std::fs::write(&reread, "/a\n/bb\n").expect("write");
        assert_eq!(acl_file(&reread).expect("file").entries().len(), 2);
        assert_eq!(rr.entries().len(), 2);
        assert_eq!(command("clear", RefKind::Acl, &[&reread], None), "");
        std::fs::write(&reread, "/a\n/bb\n/ccc\n").expect("write");
        assert!(acl_file(&reread).expect("file").entries().is_empty(), "edited by the CLI: kept");
    }

    #[test]
    fn map_keys_are_checked_by_the_converter_that_reads_them() {
        let ints = tmp("i.map", "1 one\n");
        let ips = tmp("ip.map", "10.0.0.0/8 ten\n");
        let regs = tmp("r.map", "^/a x\n");
        let ri = map_file(&ints, MapKeys::Int, None).expect("map");
        let rp = map_file(&ips, MapKeys::Ip, Some("map at file 'c' line 1".to_string())).expect("map");
        let rr = map_file(&regs, MapKeys::Reg, None).expect("map");
        let run = |r: &PatRef, key: &str| command("add", RefKind::Map, &[&format!("#{}", r.id), key, "v"], None);
        assert_eq!(run(&ri, "7"), "");
        assert_eq!(run(&ri, "5-9"), "");
        assert_eq!(run(&ri, "x"), "'x' is not a number.\n");
        assert_eq!(run(&rp, "1.2.3.0/24"), "");
        assert_eq!(run(&rp, "foo"), "'foo' is not a valid IPv4 or IPv6 address.\n");
        assert_eq!(run(&rr, "^/b.*"), "");
        assert!(run(&rr, "[").starts_with("regex '[' is invalid"));
        let sel = |r: &PatRef| format!("#{}", r.id);
        let id = format!("#0x{:x}", ri.entries()[0].id);
        assert_eq!(command("set", RefKind::Map, &[&sel(&ri), &id, "uno"], None), "");
        assert_eq!(command("set", RefKind::Map, &[&sel(&ri), "#0xdead", "x"], None), "key or pattern not found.\n");
        assert_eq!(command("del", RefKind::Map, &[&sel(&ri), &id], None), "");
        assert_eq!(command("show", RefKind::Map, &[&sel(&ri)], None).lines().count(), 2);
    }

    #[test]
    fn the_scan_registers_acl_and_map_files_in_the_order_written() {
        let acl = tmp("s.acl", "/s\n");
        let map = tmp("s.map", "k v\n");
        let (mi, mp, mr) = (tmp("s_i.map", "1 a\n"), tmp("s_p.map", "1.1.1.1 a\n"), tmp("s_r.map", "^a b\n"));
        let text = format!("frontend f\n  acl a path -f {acl}\n  http-request set-var(txn.x) path,map_beg({map},d)\n  use_backend b if {{ path -f {acl} }} # c\n  http-request set-var(txn.y) path,map_int({mi},0),map_ip({mp},0),map_reg({mr},0)\n");
        scan_config(&text, &|l| ("c.cfg".to_string(), l));
        let shown = command("show", RefKind::Acl, &[], None);
        assert!(shown.contains("used by acl at file 'c.cfg' line 2, acl at file 'c.cfg' line 4"), "{shown}");
        assert!(shown.contains("acl 'path' file 'c.cfg' line 2."), "{shown}");
        let maps = command("show", RefKind::Map, &[], None);
        for f in [&mi, &mp, &mr] {
            assert!(maps.contains(&format!("({f}) pattern loaded from file '{f}' used by map at file 'c.cfg' line 5")), "{maps}");
        }
        assert!(maps.contains(&format!("({map}) pattern loaded from file '{map}' used by map at file 'c.cfg' line 3")), "{maps}");
        // The inline patterns of an expression are not changeable: refused, not ignored.
        let expr = list(RefKind::Acl).into_iter().find(|r| r.file.is_empty()).expect("an expression ref");
        let out = command("add", RefKind::Acl, &[&format!("#{}", expr.id), "/q"], None);
        assert!(out.contains("cannot be changed at runtime"), "{out}");
    }
}
