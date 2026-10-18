// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/vars.c and src/sample.c (`sample_conv_var2smp`).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The variable store: what `set-var` keeps and `var()` gives back (T364).
//!
//! A variable holds a whole [`Sample`], its type included, as `HAProxy`'s `struct var` holds a
//! `struct sample` (`var_set` / `smp_fetch_var`, src/vars.c). Whatever reads it casts from that
//! type with the cast table (`cast.rs`), as it would straight from the fetch: a `bin` variable
//! into a string converter stops at its first NUL, an `int` into `hex` is its 8 bytes.
//!
//! Every read and write of a variable goes through this module. Storage today is a map keyed
//! by the full name (`txn.x`), one per thread for the running stream ([`CURRENT_VARS`]) and one
//! per process for `proc.` ([`GLOBAL_PROC_VARS`]); T364 S6 replaces it underneath this API.
//!
//! The thread map is a `RefCell`. Every borrow is a `try_borrow*` held inside one function of
//! this module: a nested borrow reads as "no variable" or writes nothing, never a panic.

use crate::cast::cast;
use crate::sample::{Sample, SampleType};

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

/// The variables of one stream (`sess.`, `txn.`, `req.`, `res.`) or of the process (`proc.`),
/// keyed by the full name.
pub type VarMap = HashMap<String, Sample>;

thread_local! {
    /// The variables of the stream running on this thread, for the fetches and converters,
    /// which get no stream. The engine moves a stream's variables in for each run and back out
    /// after (`with_stream_vars`, ibex-rt engine.rs).
    pub static CURRENT_VARS: RefCell<VarMap> = RefCell::new(HashMap::new());
}

/// The `proc.` variables, shared by every thread.
pub static GLOBAL_PROC_VARS: LazyLock<RwLock<VarMap>> = LazyLock::new(|| RwLock::new(HashMap::new()));

fn is_proc(name: &str) -> bool {
    name.starts_with("proc.")
}

/// Runs `f` on the thread's stream variables; `None` when they are already borrowed.
pub fn with_current<R>(f: impl FnOnce(&VarMap) -> R) -> Option<R> {
    CURRENT_VARS.try_with(|v| v.try_borrow().ok().map(|m| f(&m))).ok().flatten()
}

/// Runs `f` on the thread's stream variables, to change them; `None` when they are borrowed.
pub fn with_current_mut<R>(f: impl FnOnce(&mut VarMap) -> R) -> Option<R> {
    CURRENT_VARS.try_with(|v| v.try_borrow_mut().ok().map(|mut m| f(&mut m))).ok().flatten()
}

/// The value of `proc.<name>`.
#[must_use]
pub fn get_proc(name: &str) -> Option<Sample> {
    GLOBAL_PROC_VARS.read().ok()?.get(name).cloned()
}

/// Sets `proc.<name>`.
pub fn set_proc(name: &str, smp: Sample) {
    if let Ok(mut lock) = GLOBAL_PROC_VARS.write() {
        lock.insert(name.to_string(), smp);
    }
}

/// The `proc.` variables, copied out (for `dump_all_vars`).
#[must_use]
pub fn proc_snapshot() -> Vec<(String, Sample)> {
    GLOBAL_PROC_VARS.read().map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default()
}

/// The value of the variable `name` (scope prefix included): `vars_get_by_desc`. A `proc.`
/// name reads the process's, any other the running stream's.
#[must_use]
pub fn get(name: &str) -> Option<Sample> {
    if is_proc(name) {
        return get_proc(name);
    }
    with_current(|m| m.get(name).cloned()).flatten()
}

/// Whether the variable `name` has a value.
#[must_use]
pub fn is_set(name: &str) -> bool {
    if is_proc(name) {
        return GLOBAL_PROC_VARS.read().is_ok_and(|m| m.contains_key(name));
    }
    with_current(|m| m.contains_key(name)).unwrap_or(false)
}

/// Sets the variable `name` to `smp`, with no condition.
pub fn set(name: &str, smp: Sample) {
    if is_proc(name) {
        set_proc(name, smp);
        return;
    }
    with_current_mut(|m| m.insert(name.to_string(), smp));
}

/// Removes the variable `name` (`var_unset`). A `proc.` variable stays declared, with no value.
pub fn unset(name: &str) {
    if is_proc(name) {
        if let Ok(mut lock) = GLOBAL_PROC_VARS.write() {
            lock.remove(name);
        }
        return;
    }
    with_current_mut(|m| m.remove(name));
}

/// Whether a sample is empty for `ifempty`/`ifnotempty` (`var_set`, src/vars.c): only a
/// string or a binary of no bytes is; an integer, a boolean or an address never is.
#[must_use]
pub fn is_empty(smp: &Sample) -> bool {
    match smp {
        Sample::Str(s) => s.is_empty(),
        Sample::Bin(b) => b.is_empty(),
        _ => false,
    }
}

/// The conditions of `set-var(<name>,<cond>...)` against what is known of the variable and the
/// sample (`var_set`, src/vars.c): `exists`/`is_set` describe the variable, `empty` the new
/// sample. `ifgt` and `iflt` are refused when the configuration loads.
#[must_use]
pub fn conds_hold(spec: &str, exists: bool, is_set: bool, empty: bool) -> bool {
    spec.split(',').skip(1).all(|c| {
        (c != "ifexists" || exists)
            && (c != "ifnotexists" || !exists)
            && (c != "ifset" || is_set)
            && (c != "ifnotset" || !is_set)
            && (c != "ifempty" || empty)
            && (c != "ifnotempty" || !empty)
    })
}

/// `set-var(<name>[,<cond>...])` from a converter, where only the thread's variables are at
/// hand: sets the variable when the conditions hold, and says whether it did. A `proc.`
/// variable always exists (the configuration declares it) and is set once it has a value.
#[allow(clippy::must_use_candidate)] // the rule form ignores it; S3 may not
pub fn set_cond(spec: &str, smp: Sample) -> bool {
    let name = spec.split(',').next().unwrap_or("");
    let set_now = is_set(name);
    if !conds_hold(spec, is_proc(name) || set_now, set_now, is_empty(&smp)) {
        return false;
    }
    set(name, smp);
    true
}

/// A converter argument naming a variable, cast to `ty`: `sample_conv_var2smp` (src/sample.c).
/// No variable, or no cast from its type to `ty`, is no sample; `str -> sint` is the lenient
/// `c_str2int` (`Abc` is 0, an empty string fails).
#[must_use]
pub fn var_arg(name: &str, ty: SampleType) -> Option<Sample> {
    cast(get(name)?, ty)
}

/// [`var_arg`] to `sint`, as the integer.
#[must_use]
pub fn var_arg_int(name: &str) -> Option<i64> {
    match var_arg(name, SampleType::Sint)? {
        Sample::Sint(n) => Some(n),
        _ => None,
    }
}

/// [`var_arg`] to `str`, as the text (bytetext: a byte from 0x80 is the char of that value).
#[must_use]
pub fn var_arg_str(name: &str) -> Option<String> {
    match var_arg(name, SampleType::Str)? {
        Sample::Str(s) => Some(s),
        _ => None,
    }
}

/// [`var_arg`] to `bin`, as the bytes.
#[must_use]
pub fn var_arg_bin(name: &str) -> Option<Vec<u8>> {
    match var_arg(name, SampleType::Bin)? {
        Sample::Bin(b) => Some(b),
        _ => None,
    }
}

// The `String` shims, for the CLI and the tests written against the untyped store
// (crates/ibex-sample/tests/sample_semantics.rs is frozen).

/// The text of `proc.<name>`, as a log-format prints it.
#[must_use]
pub fn get_proc_var(name: &str) -> Option<String> {
    get_proc(name).map(|s| crate::registry::sample_to_string(&s))
}

/// Sets `proc.<name>` to the string `val`.
pub fn set_proc_var(name: &str, val: String) {
    set_proc(name, Sample::Str(val));
}

/// `unset-var` of a process variable: it stays declared but has no value.
pub fn unset_proc_var(name: &str) {
    unset(name);
}

/// Replaces the thread's stream variables with `vars`, each a string (a test adapter).
// Not generalised over the hasher: the map is converted anyway.
#[allow(clippy::implicit_hasher)]
pub fn set_current_vars(vars: HashMap<String, String>) {
    with_current_mut(|m| *m = vars.into_iter().map(|(k, v)| (k, Sample::Str(v))).collect());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_variable_keeps_its_type_and_an_argument_casts_from_it() {
        set("txn.t364i", Sample::Ipv4(std::net::Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(get("txn.t364i"), Some(Sample::Ipv4(std::net::Ipv4Addr::new(10, 1, 2, 3))));
        assert_eq!(var_arg_int("txn.t364i"), Some(167_838_211));
        set("txn.t364s", Sample::Str("Abc".to_string()));
        assert_eq!(var_arg_int("txn.t364s"), Some(0));
        set("txn.t364e", Sample::Str(String::new()));
        assert_eq!(var_arg_int("txn.t364e"), None);
        set("txn.t364b", Sample::Bin(vec![b'A', 0, b'B']));
        assert_eq!(var_arg_str("txn.t364b").as_deref(), Some("A"));
        assert_eq!(var_arg_int("txn.t364b"), None);
        unset("txn.t364b");
        assert!(!is_set("txn.t364b"));
    }

    #[test]
    fn a_nested_borrow_reads_no_variable_rather_than_panicking() {
        set("txn.t364n", Sample::Sint(1));
        let inner = with_current_mut(|_| get("txn.t364n"));
        assert_eq!(inner, Some(None));
        let inner = with_current(|_| with_current_mut(VarMap::clear));
        assert_eq!(inner, Some(None));
        assert_eq!(get("txn.t364n"), Some(Sample::Sint(1)));
    }
}
