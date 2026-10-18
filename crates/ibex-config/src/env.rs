// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The environment as the configuration sees it while it is being read.
//!
//! `HAProxy` changes its own process environment on `setenv`, `presetenv`, `unsetenv` and
//! `resetenv`, and a `${VAR}` further down reads the result. Ibex reads the configuration
//! in a library that tests call from several threads, and changing the real environment
//! under them is not sound, so the changes are kept here as an overlay on top of it: [`get`]
//! answers what `getenv` would have. The same changes are kept as an ordered list of
//! [`EnvOp`], handed out in `Config::env_ops`, for the binary to replay on the real
//! environment before it starts a thread (children such as an `external-check` command
//! inherit it).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

/// One change a `global` environment keyword makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvOp {
    /// `setenv` (`overwrite`) and `presetenv` (not).
    Set { name: String, value: String, overwrite: bool },
    /// `unsetenv`.
    Unset(Vec<String>),
    /// `resetenv`: every variable but those listed is removed.
    Reset(Vec<String>),
}

#[derive(Default)]
struct Overlay {
    set: HashMap<String, String>,
    unset: HashSet<String>,
    /// After a `resetenv`: what the real environment holds is gone, but for `set`.
    reset: bool,
    ops: Vec<EnvOp>,
    /// What `${.FILE}` is.
    file: String,
}

thread_local! {
    static OVERLAY: RefCell<Overlay> = RefCell::new(Overlay::default());
}

/// Forgets the changes of a previous read of a configuration.
pub fn begin() {
    OVERLAY.with(|o| {
        let mut o = o.borrow_mut();
        o.set.clear();
        o.unset.clear();
        o.reset = false;
        o.ops.clear();
    });
}

/// Names the configuration file, for `${.FILE}`.
pub fn set_file(name: &str) {
    OVERLAY.with(|o| name.clone_into(&mut o.borrow_mut().file));
}

/// `${.FILE}`.
#[must_use]
pub fn file() -> String {
    OVERLAY.with(|o| o.borrow().file.clone())
}

/// `getenv`, as the configuration read so far would see it.
#[must_use]
pub fn get(name: &str) -> Option<String> {
    OVERLAY.with(|o| {
        let o = o.borrow();
        if let Some(v) = o.set.get(name) {
            return Some(v.clone());
        }
        if o.reset || o.unset.contains(name) {
            return None;
        }
        std::env::var(name).ok()
    })
}

/// Whether a name can be put in the environment (`setenv` fails with `EINVAL` otherwise).
#[must_use]
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('=') && !name.contains('\0')
}

/// Applies one change to the overlay and records it. A name or value `setenv` would refuse
/// is left out (the keyword's parser reports it).
pub fn apply_to_overlay(op: EnvOp) {
    match &op {
        EnvOp::Set { name, value, overwrite } => {
            if !valid_name(name) || value.contains('\0') {
                return;
            }
            if *overwrite || get(name).is_none() {
                OVERLAY.with(|o| {
                    let mut o = o.borrow_mut();
                    o.unset.remove(name);
                    o.set.insert(name.clone(), value.clone());
                });
            }
        }
        EnvOp::Unset(names) => {
            for n in names.iter().filter(|n| valid_name(n)) {
                OVERLAY.with(|o| {
                    let mut o = o.borrow_mut();
                    o.set.remove(n);
                    o.unset.insert(n.clone());
                });
            }
        }
        EnvOp::Reset(keep) => {
            let kept: Vec<(String, String)> = keep.iter().filter_map(|k| get(k).map(|v| (k.clone(), v))).collect();
            OVERLAY.with(|o| {
                let mut o = o.borrow_mut();
                o.set = kept.into_iter().collect();
                o.unset.clear();
                o.reset = true;
            });
        }
    }
    OVERLAY.with(|o| o.borrow_mut().ops.push(op));
}

/// The changes recorded since [`begin`].
#[must_use]
pub fn take_ops() -> Vec<EnvOp> {
    OVERLAY.with(|o| std::mem::take(&mut o.borrow_mut().ops))
}

/// Replays changes on the real process environment. The caller must be single-threaded
/// (`std::env::set_var` is not sound otherwise): the binary does it right after reading the
/// configuration, before any worker exists.
pub fn apply_to_process(ops: &[EnvOp]) {
    for op in ops {
        match op {
            EnvOp::Set { name, value, overwrite } => {
                if valid_name(name) && !value.contains('\0') && (*overwrite || std::env::var_os(name).is_none()) {
                    std::env::set_var(name, value);
                }
            }
            EnvOp::Unset(names) => {
                for n in names.iter().filter(|n| valid_name(n)) {
                    std::env::remove_var(n);
                }
            }
            EnvOp::Reset(keep) => {
                for (k, _) in std::env::vars_os() {
                    if !keep.iter().any(|n| k == n.as_str()) {
                        std::env::remove_var(k);
                    }
                }
            }
        }
    }
}
