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
    /// `map_reg`: compiled without auto-capture, as an ACL regex.
    Reg,
    /// `map_regm`: every group captures.
    Regm,
}

/// What a map's values must be, from the converter's output type (`map_str_int`, `_ip`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapVals {
    Str,
    Int,
    Ip,
}

/// The key and value types of converter `name` (`map`, `map_<in>`, `map_<in>_<out>`), or
/// `None` when it is no map converter.
#[must_use]
pub fn converter_map(name: &str) -> Option<(MapKeys, MapVals)> {
    let rest = if name == "map" { "str" } else { name.strip_prefix("map_")? };
    let (inp, out) = rest.split_once('_').map_or((rest, ""), |(i, o)| (i, o));
    let keys = match inp {
        "str" | "beg" | "end" | "sub" | "dir" | "dom" => MapKeys::Str,
        "int" => MapKeys::Int,
        "ip" => MapKeys::Ip,
        "reg" => MapKeys::Reg,
        "regm" => MapKeys::Regm,
        _ => return None,
    };
    let vals = match out {
        "" | "key" | "str" => MapVals::Str,
        "int" => MapVals::Int,
        "ip" => MapVals::Ip,
        _ => return None,
    };
    Some((keys, vals))
}

/// The refusal (without the period) of value `val` for a map of values `vals`.
fn map_val_error(vals: MapVals, val: &str) -> Option<String> {
    let ok = match vals {
        MapVals::Str => true,
        MapVals::Int => pat_number(val).is_some(),
        MapVals::Ip => val.parse::<std::net::IpAddr>().is_ok(),
    };
    (!ok).then(|| format!("unable to parse '{val}'"))
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
    map_vals: Mutex<MapVals>,
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
            map_vals: Mutex::new(MapVals::Str),
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
            RefKind::Map => match map_key_error(*lock(&self.map_keys), key, false) {
                Some(e) => Err(format!("{e}.")),
                None => Ok(()),
            },
            RefKind::Acl => {
                let readers = read(&self.entries).reader_methods();
                for (method, ci) in readers {
                    if method == "reg" {
                        // `HAProxy`'s answer to `add acl` with a regex PCRE2 refuses.
                        ibex_regex::UserRegex::with_case_nocapture(key, ci).map_err(|e| format!("{}.", regex_refusal(key, &e)))?;
                    } else {
                        Matcher::compile_with_flags(&method, key, ci)?;
                    }
                }
                Ok(())
            }
        }
    }

    fn check_val(&self, val: &str) -> Result<(), String> {
        map_val_error(*lock(&self.map_vals), val).map_or(Ok(()), |e| Err(format!("{e}.")))
    }

    fn add(&self, key: &str, val: &str) -> Result<(), String> {
        self.check_key(key)?;
        if self.kind == RefKind::Map {
            self.check_val(val)?;
        }
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

/// `regex '<key>' is invalid (error=<why>, erroffset=<n>)`, as `HAProxy` words a regex PCRE2
/// refuses; the offset is left out when the parser did not say where it stopped.
fn regex_refusal(key: &str, e: &ibex_regex::Error) -> String {
    match e.offset() {
        Some(at) => format!("regex '{key}' is invalid (error={e}, erroffset={at})"),
        None => format!("regex '{key}' is invalid (error={e})"),
    }
}

/// `HAProxy`'s `strl2llrc`: optional `-`, then decimal digits, within `i64`; no `+`, no
/// blanks, no digits is an error (a lone `-` is 0).
fn pat_number(s: &str) -> Option<i64> {
    let (neg, digits) = s.strip_prefix('-').map_or((false, s), |d| (true, d));
    if (!neg && digits.is_empty()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut v: i128 = 0;
    for b in digits.bytes() {
        v = v * 10 + i128::from(b - b'0');
        if v > i128::from(i64::MAX) + 1 {
            return None;
        }
    }
    let v = if neg { -v } else { v };
    // the positive form stops at `i64::MAX`
    i64::try_from(v).ok()
}

/// `HAProxy`'s `pat_parse_int`: a number, or a range `a-b`, `a:b`, `-b` (up to), `a-` (from).
fn int_key_error(key: &str) -> Option<String> {
    let range = || Some(format!("'{key}' is not a valid number range"));
    if key.is_empty() {
        return range();
    }
    let Some(at) = key.find([':', '-']) else {
        return pat_number(key).is_none().then(|| format!("'{key}' is not a number"));
    };
    let (lo, hi) = (&key[..at], &key[at + 1..]);
    if at == 0 && !hi.is_empty() {
        return if pat_number(hi).is_none() { range() } else { None };
    }
    if hi.is_empty() {
        return if pat_number(lo).is_none() { range() } else { None };
    }
    match (pat_number(lo), pat_number(hi)) {
        (Some(a), Some(b)) if a <= b => None,
        _ => range(),
    }
}

/// `HAProxy`'s `str2net` / `str62net`: an IPv4 or IPv6 address with an optional `/<bits>` or
/// (IPv4) `/<dotted mask>`. `resolve`: at load `HAProxy` also resolves a name that is not an
/// address; so does this, for a name with a letter in it.
fn ip_key_error(key: &str, resolve: bool) -> Option<String> {
    let bad = || Some(format!("'{key}' is not a valid IPv4 or IPv6 address"));
    let (addr, mask) = key.rsplit_once('/').map_or((key, None), |(a, m)| (a, Some(m)));
    let bits = |m: &str, max: u32| !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()) && m.parse::<u32>().is_ok_and(|n| n <= max);
    let v4_mask = mask.is_none_or(|m| if m.contains('.') { m.parse::<std::net::Ipv4Addr>().is_ok() } else { bits(m, 32) });
    if v4_mask && addr.parse::<std::net::Ipv4Addr>().is_ok() {
        return None;
    }
    if mask.is_none_or(|m| bits(m, 128)) && addr.parse::<std::net::Ipv6Addr>().is_ok() {
        return None;
    }
    if resolve && v4_mask && addr.bytes().any(|b| b.is_ascii_alphabetic()) {
        use std::net::ToSocketAddrs as _;
        if (addr, 0).to_socket_addrs().is_ok_and(|mut a| a.any(|a| a.is_ipv4())) {
            return None;
        }
    }
    bad()
}

/// Why `key` cannot be a key of a map read by a converter of kind `keys`, as `HAProxy` words
/// it (without the closing period). `resolve`: the map is being loaded, not changed at
/// runtime.
fn map_key_error(keys: MapKeys, key: &str, resolve: bool) -> Option<String> {
    match keys {
        MapKeys::Str => None,
        MapKeys::Int => int_key_error(key),
        MapKeys::Ip => ip_key_error(key, resolve),
        MapKeys::Reg => ibex_regex::UserRegex::new_nocapture(key).err().map(|e| regex_refusal(key, &e)),
        MapKeys::Regm => ibex_regex::UserRegex::new(key).err().map(|e| regex_refusal(key, &e)),
    }
}

/// The first key of map file `path` that a converter of kind `keys` refuses, as `HAProxy`
/// words it when it loads the file: `<why> at line <n> of file '<path>'.` `None` when every
/// key is fine, or the file cannot be read (reported elsewhere). A key of a regex map is
/// otherwise compiled only when a lookup first reaches it, and one that does not compile
/// then never matches (T277).
#[must_use]
pub fn map_file_error(path: &str, keys: MapKeys, vals: MapVals) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().enumerate().find_map(|(n, l)| {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            return None;
        }
        let mut it = l.split_whitespace();
        let key = it.next()?;
        map_key_error(keys, key, true)
            .or_else(|| it.next().and_then(|v| map_val_error(vals, v)))
            .map(|e| format!("{e} at line {} of file '{path}'.", n + 1))
    })
}

/// The reference of map file `path`, created (and read) when none is registered; `keys` and
/// `user` describe the converter that reads it. `None` when the file cannot be read.
#[must_use]
pub fn map_file(path: &str, keys: MapKeys, user: Option<String>) -> Option<Arc<PatRef>> {
    map_file_typed(path, keys, MapVals::Str, user)
}

/// [`map_file`] for a converter whose output is of type `vals`.
#[must_use]
pub fn map_file_typed(path: &str, keys: MapKeys, vals: MapVals, user: Option<String>) -> Option<Arc<PatRef>> {
    let mut refs = lock(&REFS);
    let found = refs.iter().find(|r| r.kind == RefKind::Map && r.file == path).cloned();
    let r = if let Some(r) = found {
        r
    } else {
        let text = std::fs::read_to_string(path).ok()?;
        let r = Arc::new(PatRef::new(refs.len(), RefKind::Map, path, parse_lines(&text)));
        *lock(&r.map_keys) = keys;
        *lock(&r.map_vals) = vals;
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
            let Some((keys, vals)) = converter_map(name) else { continue };
            let args = &rest[name_len + 1..];
            let end = args.find([',', ')']).unwrap_or(args.len());
            let path = args[..end].trim_matches(['"', '\'']);
            if !path.is_empty() {
                let _ = map_file_typed(path, keys, vals, Some(format!("map at file '{file}' line {fline}")));
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
            r.check_val(args[2])?;
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
    fn key_parsers_follow_haproxy_at_the_edges() {
        // strl2llrc rejects what overflows, however many digits
        assert_eq!(int_key_error("99999999999999999999999999999999999999999"), Some("'99999999999999999999999999999999999999999' is not a number".to_string()));
        // an empty key is "not a valid number range" (pat_parse_int)
        assert_eq!(int_key_error(""), Some("'' is not a valid number range".to_string()));
        // at load a name is resolved, as HAProxy does; at runtime it is not
        assert_eq!(ip_key_error("localhost", true), None);
        assert!(ip_key_error("localhost", false).is_some());
        assert!(ip_key_error("no-such-host.invalid", true).is_some());
    }

    #[test]
    fn converters_that_read_no_key_file_check_nothing() {
        let args = ["/nonexistent".to_string()];
        assert_eq!(crate::registry::check_converter_args("map_str_int", &args), None);
        assert_eq!(crate::registry::check_converter_args("map_int", &args), None);
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

    /// Map values are checked by the converter's output type (T287 item 5). Measured on
    /// HAProxy 3.5-dev8-885761-29: `map_str_int` over a file with `b xx` is refused at load
    /// with `unable to parse 'xx' at line 2 of file '<f>'`, `map_str_ip` the same with
    /// `notip`; `add map` and `set map` answer `unable to parse 'xx'.`, and so does a
    /// payload line (the lines before it stay added).
    #[test]
    fn map_values_are_checked_by_the_converters_output_type() {
        let f = tmp("vi.map", "a 1\nb xx\n");
        let args = [f.clone()];
        let why = |n: &str| crate::registry::check_converter_args(n, &args);
        assert_eq!(why("map_str_int"), Some(format!("invalid args in converter 'map_str_int' : unable to parse 'xx' at line 2 of file '{f}'.")));
        assert!(why("map_str_ip").is_some_and(|e| e.contains("unable to parse '1' at line 1")));
        assert!(why("map_int_int").is_some());
        assert_eq!(why("map_str"), None);
        assert_eq!(why("map_str_key"), None);
        let ok = tmp("vok.map", "a 1\n");
        let ri = map_file_typed(&ok, MapKeys::Str, MapVals::Int, None).expect("map");
        let id = format!("#{}", ri.id);
        assert_eq!(command("add", RefKind::Map, &[&id, "k", "xx"], None), "unable to parse 'xx'.\n");
        assert_eq!(command("add", RefKind::Map, &[&id, "k", "-5"], None), "");
        assert_eq!(command("set", RefKind::Map, &[&id, "k", "yy"], None), "unable to parse 'yy'.\n");
        assert_eq!(command("add", RefKind::Map, &[&id], Some("p1 7\np2 zz\np3 8\n")), "unable to parse 'zz'.\n");
        let shown = command("show", RefKind::Map, &[&id], None);
        assert!(shown.contains(" p1 7") && !shown.contains("p2") && !shown.contains("p3"), "{shown}");
        let ip = tmp("vip.map", "a 1.2.3.4\n");
        let rp = map_file_typed(&ip, MapKeys::Str, MapVals::Ip, None).expect("map");
        let id = format!("#{}", rp.id);
        assert_eq!(command("add", RefKind::Map, &[&id, "k", "zz"], None), "unable to parse 'zz'.\n");
        assert_eq!(command("add", RefKind::Map, &[&id, "k", "::1"], None), "");
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
