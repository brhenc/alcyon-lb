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
//! Every read and write of a variable goes through this module.
//!
//! # Storage, and why a request allocates nothing for it (T364 S6)
//!
//! - **Names are interned** once per process ([`intern`]): `vars_check` interns every name the
//!   configuration checks at load, and a name first seen at run time is interned on its first
//!   set (warm-up). A name is a `u32` index from then on.
//! - **A [`VarStore`] is a slot vector** indexed by that number. A slot holds a scalar inline,
//!   or the bytes of a `str`/`bin`/unusual method in its own buffer. Clearing a slot keeps the
//!   buffer's capacity, so the next transaction's value of the same variable is copied into it:
//!   a keep-alive connection sets its variables with no allocation once the first request has
//!   sized the buffers. A value bigger than the buffer adopts the sample's own allocation (a
//!   move, no copy); a value copied from a constant reserves with `try_reserve`, and a failed
//!   reservation is `HAProxy`'s failed `malloc` in `var_set`: the variable becomes a `bool`.
//! - **One store per stream** holds its `sess.`, `txn.`, `req.` and `res.` variables. While the
//!   stream runs, the store is swapped into the thread's [`CURRENT_VARS`] ([`enter`]/[`leave`],
//!   a `mem::swap`: nothing is copied or allocated) so the fetches and converters, which get no
//!   stream, read it. The end of a transaction clears the `txn`/`req`/`res` slots.
//! - **Spare stores** of ended sessions are kept per thread ([`VarStore::new`] takes one, `Drop`
//!   gives it back), so a new connection reuses the slots and buffers of an old one. This is the
//!   only cache of stores in the tree; T372 P0 replaces it with `ibex_alloc::Pool<T>`
//!   (docs/design/pools-2026-10-18.md §4.1): see [`SPARE`].
//! - Reading a `str`/`bin` variable still copies it into an owned [`Sample`] (one allocation):
//!   a borrowed sample in the evaluator is tradeoff.md §6.13 work, not this store's.
//!
//! `proc.` variables are one store per process ([`GLOBAL_PROC_VARS`]), a health check's run has
//! its own (`check.`).
//!
//! The thread store is a `RefCell`. Every borrow is a `try_borrow*` held inside one function of
//! this module: a nested borrow reads as "no variable" or writes nothing, never a panic.

use crate::cast::cast;
use crate::sample::{Sample, SampleType};
use ibex_proto::htx::HttpMethod;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{LazyLock, RwLock};

// ---------------------------------------------------------------------------------------------
// Names

/// The scope a variable name starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    Proc,
    Sess,
    Txn,
    Req,
    Res,
    Check,
    /// `psess.`/`ptxn.`/... (no sub-streams in Ibex) or anything else.
    #[default]
    Other,
}

impl Scope {
    /// The scope of the full name `name`.
    #[must_use]
    pub fn of(name: &str) -> Self {
        match name.split('.').next() {
            Some("proc") => Self::Proc,
            Some("sess") => Self::Sess,
            Some("txn") => Self::Txn,
            Some("req") => Self::Req,
            Some("res") => Self::Res,
            Some("check") => Self::Check,
            _ => Self::Other,
        }
    }

    /// The scopes a transaction owns: they end with it.
    const fn of_txn(self) -> bool {
        matches!(self, Self::Txn | Self::Req | Self::Res)
    }
}

/// Every variable name the process has seen, and its number.
#[derive(Default)]
struct Names {
    ids: HashMap<Box<str>, u32>,
    names: Vec<Box<str>>,
}

/// The names only grow; a configuration has a few dozen. The cap keeps a runaway (a name built
/// at run time) from growing every store without bound.
const MAX_NAMES: usize = 1 << 16;

static NAMES: LazyLock<RwLock<Names>> = LazyLock::new(|| RwLock::new(Names::default()));

/// The number of `name`, if it has one.
fn lookup(name: &str) -> Option<u32> {
    NAMES.read().ok()?.ids.get(name).copied()
}

/// The number of `name`, given it on first sight: at load for the names the configuration
/// checks (`vars_check`), else on the first set. `None` past [`MAX_NAMES`].
pub fn intern(name: &str) -> Option<u32> {
    if let Some(id) = lookup(name) {
        return Some(id);
    }
    let mut w = NAMES.write().ok()?;
    intern_locked(&mut w, name)
}

/// [`intern`] under the write lock: another thread may have given `name` its number between
/// the read that missed and the write lock.
fn intern_locked(w: &mut Names, name: &str) -> Option<u32> {
    if let Some(&id) = w.ids.get(name) {
        return Some(id);
    }
    if w.names.len() >= MAX_NAMES {
        return None;
    }
    let id = u32::try_from(w.names.len()).ok()?;
    w.names.push(name.into());
    w.ids.insert(name.into(), id);
    Some(id)
}

/// Makes `slots` at least `len` long; `None` (and `slots` as it was) when the memory is not there.
fn grow_to(slots: &mut Vec<Slot>, len: usize) -> Option<()> {
    if slots.len() < len {
        reserve_more(slots, len - slots.len())?;
        slots.resize_with(len, Slot::default);
    }
    Some(())
}

/// What runs when a reservation is refused, before it is tried once more: the runtime's
/// `pool_gc` (T445), which empties the caches and trims the heap.
static ALLOC_FAILURE_HOOK: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

/// Sets the collector a refused reservation runs before its one retry (the first call wins).
pub fn set_alloc_failure_hook(f: fn()) {
    let _ = ALLOC_FAILURE_HOOK.set(f);
}

/// Room for `extra` more elements in `v`; `None` when the memory is not there (the allocator
/// refuses, or the size cannot be addressed). A refusal runs the collector and is tried once
/// more, as `HAProxy` retries `SSL_new` after `pool_gc` (`src/ssl_sock.c:6074`).
fn reserve_more<T>(v: &mut Vec<T>, extra: usize) -> Option<()> {
    if v.try_reserve(extra).is_ok() {
        return Some(());
    }
    (ALLOC_FAILURE_HOOK.get()?)();
    v.try_reserve(extra).ok()
}

// ---------------------------------------------------------------------------------------------
// Slots

/// The known methods, as a slot keeps them (an unusual one is its bytes).
const METHODS: [HttpMethod; 9] = [
    HttpMethod::Get,
    HttpMethod::Head,
    HttpMethod::Post,
    HttpMethod::Put,
    HttpMethod::Delete,
    HttpMethod::Connect,
    HttpMethod::Options,
    HttpMethod::Trace,
    HttpMethod::Patch,
];

/// What a slot holds; the bytes of `Str`/`Bin`/`MethOther` are in the slot's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Val {
    #[default]
    Absent,
    Bool(bool),
    Sint(i64),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Meth(u8),
    Str,
    Bin,
    MethOther,
}

#[derive(Debug, Clone, Default)]
struct Slot {
    val: Val,
    scope: Scope,
    /// The value's bytes for a `Str` (its UTF-8: bytetext), `Bin` or `MethOther`; empty
    /// otherwise. Its capacity outlives the value.
    buf: Vec<u8>,
}

impl Slot {
    fn clear(&mut self) {
        self.val = Val::Absent;
        self.buf.clear();
    }

    fn sample(&self) -> Option<Sample> {
        Some(match self.val {
            Val::Absent => return None,
            Val::Bool(b) => Sample::Bool(b),
            Val::Sint(n) => Sample::Sint(n),
            Val::Ipv4(a) => Sample::Ipv4(a),
            Val::Ipv6(a) => Sample::Ipv6(a),
            Val::Meth(m) => Sample::Meth(METHODS.get(usize::from(m))?.clone()),
            // The one copy of a read (module doc): borrowed samples are §6.13 work.
            Val::Str => Sample::Str(String::from_utf8(self.buf.clone()).ok()?),
            Val::Bin => Sample::Bin(self.buf.clone()),
            Val::MethOther => Sample::Meth(HttpMethod::Other(String::from_utf8(self.buf.clone()).ok()?)),
        })
    }

    /// The bytes the value holds beyond its `struct var` (accounting): a `str` counts a
    /// character per byte of bytetext.
    fn extra_bytes(&self) -> u64 {
        let n = match self.val {
            Val::Str => self.buf.iter().filter(|&&b| b & 0xC0 != 0x80).count(),
            Val::Bin | Val::MethOther => self.buf.len(),
            _ => 0,
        };
        n as u64
    }

    fn same_value(&self, other: &Slot) -> bool {
        self.val == other.val && self.buf == other.buf
    }

    /// What a failed allocation leaves (`var_set`): a `bool` of what the variable held.
    fn as_bool(&self) -> bool {
        match self.val {
            Val::Sint(n) => n != 0,
            Val::Bool(b) => b,
            Val::Ipv4(a) => !a.is_unspecified(),
            _ => false,
        }
    }

    /// Sets the value from `v`. Bytes go into the buffer when it has the room; else an owned
    /// sample's own allocation becomes the buffer, and a borrowed one is copied after a
    /// `try_reserve` (on failure the variable becomes a `bool`).
    fn set(&mut self, v: In<'_>) {
        // A text sample is copied in like a borrowed one, and its string given back for the
        // next fetch (T437): the buffer keeps its capacity from one value to the next.
        if let In::Owned(smp @ Sample::Str(_)) = v {
            self.set(In::Ref(&smp));
            crate::spare::give_sample(smp);
            return;
        }
        let (val, bytes): (Val, Bytes<'_>) = match v {
            In::Owned(s) => match s {
                Sample::Bool(b) => (Val::Bool(b), Bytes::None),
                Sample::Sint(n) => (Val::Sint(n), Bytes::None),
                Sample::Ipv4(a) => (Val::Ipv4(a), Bytes::None),
                Sample::Ipv6(a) => (Val::Ipv6(a), Bytes::None),
                Sample::Str(t) => (Val::Str, Bytes::Owned(t.into_bytes())),
                Sample::Bin(b) => (Val::Bin, Bytes::Owned(b)),
                Sample::Meth(HttpMethod::Other(m)) => (Val::MethOther, Bytes::Owned(m.into_bytes())),
                Sample::Meth(m) => (Val::Meth(meth_code(&m)), Bytes::None),
            },
            In::Ref(s) => match s {
                Sample::Bool(b) => (Val::Bool(*b), Bytes::None),
                Sample::Sint(n) => (Val::Sint(*n), Bytes::None),
                Sample::Ipv4(a) => (Val::Ipv4(*a), Bytes::None),
                Sample::Ipv6(a) => (Val::Ipv6(*a), Bytes::None),
                Sample::Str(t) => (Val::Str, Bytes::Ref(t.as_bytes())),
                Sample::Bin(b) => (Val::Bin, Bytes::Ref(b)),
                Sample::Meth(HttpMethod::Other(m)) => (Val::MethOther, Bytes::Ref(m.as_bytes())),
                Sample::Meth(m) => (Val::Meth(meth_code(m)), Bytes::None),
            },
        };
        match bytes {
            Bytes::None => self.buf.clear(),
            Bytes::Owned(b) if b.len() > self.buf.capacity() => self.buf = b,
            Bytes::Owned(b) => {
                self.buf.clear();
                self.buf.extend_from_slice(&b);
            }
            Bytes::Ref(b) => {
                self.buf.clear();
                let Some(()) = reserve_more(&mut self.buf, b.len()) else { return self.val = Val::Bool(self.as_bool()) };
                self.buf.extend_from_slice(b);
            }
        }
        self.val = val;
    }
}

fn meth_code(m: &HttpMethod) -> u8 {
    METHODS.iter().position(|k| k == m).and_then(|i| u8::try_from(i).ok()).unwrap_or(0)
}

enum Bytes<'a> {
    None,
    Owned(Vec<u8>),
    Ref(&'a [u8]),
}

/// A value to store: a sample that is the store's to keep, or one it copies (a constant of the
/// configuration, which then costs no allocation at all).
pub enum In<'a> {
    Owned(Sample),
    Ref(&'a Sample),
}

impl In<'_> {
    fn is_bytes(&self) -> bool {
        let s = match self {
            In::Owned(s) => s,
            In::Ref(s) => *s,
        };
        matches!(s, Sample::Str(_) | Sample::Bin(_) | Sample::Meth(HttpMethod::Other(_)))
    }

    fn extra_bytes(&self) -> u64 {
        let s = match self {
            In::Owned(s) => s,
            In::Ref(s) => *s,
        };
        let n = match s {
            Sample::Str(t) => t.chars().count(),
            Sample::Bin(b) => b.len(),
            Sample::Meth(HttpMethod::Other(m)) => m.len(),
            _ => 0,
        };
        n as u64
    }
}

// ---------------------------------------------------------------------------------------------
// The store

/// The variables of one owner: a stream (all its `sess.`/`txn.`/`req.`/`res.` ones), the
/// process (`proc.`) or a health check's run (`check.`). See the module doc.
#[derive(Debug, Default)]
pub struct VarStore {
    slots: Vec<Slot>,
}

/// The spare stores of this thread (module doc), at most [`SPARE_MAX`].
///
/// T372 P0 slots in here: this list and [`VarStore::new`]/`Drop` become
/// `declare_pool!(static VAR_STORES: Pool<Vec<Slot>>, "vars")`, `VarStore` a `PoolBox` of it and
/// [`VarStore::recycle`] its `Reset`. Nothing else in the tree caches stores.
const SPARE_MAX: usize = 256;
/// The bytes of value buffers a spare store keeps; past it, its buffers are freed on return.
const SPARE_KEEP_BYTES: usize = 4096;

thread_local! {
    /// [`SPARE_MAX`] spare stores' slots.
    static SPARE: RefCell<Vec<Vec<Slot>>> = const { RefCell::new(Vec::new()) };
    /// Whether a stream runs on this thread ([`enter`]/[`leave`]): its store is then in
    /// [`CURRENT_VARS`], and the session's own is empty.
    static RUNNING: Cell<bool> = const { Cell::new(false) };
}

/// `pool_gc` (T445): frees this thread's spare variable stores. `wipe` is given each value
/// buffer first (the runtime's `tune.ibex.zero-buffers` wipe: this crate has no allocator
/// policy of its own). Returns how many stores were freed.
pub fn drain_spare(mut wipe: impl FnMut(&mut Vec<u8>)) -> usize {
    let taken = SPARE.try_with(|s| s.try_borrow_mut().map(|mut s| std::mem::take(&mut *s)).unwrap_or_default()).unwrap_or_default();
    let n = taken.len();
    for slots in taken {
        for mut slot in slots {
            wipe(&mut slot.buf);
        }
    }
    n
}

impl VarStore {
    /// An empty store, with nothing allocated.
    #[must_use]
    pub const fn empty() -> Self {
        Self { slots: Vec::new() }
    }

    /// An empty store, the slots and buffers of a spare one if this thread has one.
    #[must_use]
    pub fn new() -> Self {
        let slots = SPARE.try_with(|s| s.try_borrow_mut().ok().and_then(|mut s| s.pop())).ok().flatten();
        Self { slots: slots.unwrap_or_default() }
    }

    /// Empties the store for the spare list: values gone, buffers kept up to
    /// [`SPARE_KEEP_BYTES`] in all.
    fn recycle(slots: &mut [Slot]) {
        let mut kept = 0;
        for s in slots {
            s.clear();
            kept += s.buf.capacity();
            if kept > SPARE_KEEP_BYTES {
                s.buf = Vec::new();
            }
        }
    }

    fn slot(&self, name: &str) -> Option<&Slot> {
        let s = self.slots.get(lookup(name)? as usize)?;
        (s.val != Val::Absent).then_some(s)
    }

    /// The value of `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Sample> {
        self.slot(name)?.sample()
    }

    /// The value of `name` when it is an integer (`ifgt`/`iflt` compare only those).
    #[must_use]
    pub fn int(&self, name: &str) -> Option<i64> {
        match self.slot(name)?.val {
            Val::Sint(n) => Some(n),
            _ => None,
        }
    }

    /// Whether `name` has a value.
    #[must_use]
    pub fn contains_key(&self, name: &str) -> bool {
        self.slot(name).is_some()
    }

    /// Whether no variable has a value.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|s| s.val == Val::Absent)
    }

    /// Sets `name` with no accounting (a test, or a value already admitted). Nothing is stored
    /// past [`MAX_NAMES`] names or when the slots cannot grow.
    pub fn insert(&mut self, name: impl AsRef<str>, smp: Sample) {
        let name = name.as_ref();
        if let Some(id) = intern(name) {
            self.write(id, Scope::of(name), In::Owned(smp));
        }
    }

    fn write(&mut self, id: u32, scope: Scope, v: In<'_>) -> bool {
        let i = id as usize;
        // Grows only for a name this store has not held yet: on warm-up.
        let Some(()) = grow_to(&mut self.slots, i + 1) else { return false };
        let slot = &mut self.slots[i];
        slot.scope = scope;
        slot.set(v);
        true
    }

    /// Removes `name` (its buffer stays for the next value).
    pub fn remove(&mut self, name: &str) {
        if let Some(s) = lookup(name).and_then(|id| self.slots.get_mut(id as usize)) {
            s.clear();
        }
    }

    /// Removes every variable.
    pub fn clear(&mut self) {
        self.slots.iter_mut().for_each(Slot::clear);
    }

    /// Removes the variables of `scope`.
    pub fn clear_scope(&mut self, scope: Scope) {
        self.slots.iter_mut().filter(|s| s.scope == scope).for_each(Slot::clear);
    }

    /// Removes the variables of the transaction (`txn.`, `req.`, `res.`): the session's stay.
    pub fn clear_txn(&mut self) {
        self.slots.iter_mut().filter(|s| s.scope.of_txn()).for_each(Slot::clear);
    }

    /// Every variable, named, sorted by number (for `dump_all_vars`, which sorts by name).
    #[must_use]
    pub fn entries(&self) -> Vec<(String, Sample)> {
        let Ok(names) = NAMES.read() else { return Vec::new() };
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| Some((names.names.get(i)?.to_string(), s.sample()?)))
            .collect()
    }

    /// Makes this store's `scope` variables those of `from` (an H2 stream starts with its
    /// connection's `sess.` variables).
    pub fn copy_scope_from(&mut self, from: &VarStore, scope: Scope) {
        self.clear_scope(scope);
        for (i, s) in from.slots.iter().enumerate() {
            if s.scope == scope && s.val != Val::Absent {
                let Some(()) = grow_to(&mut self.slots, i + 1) else { return };
                self.slots[i].clone_from(s);
            }
        }
    }

    /// What an H2 stream `child` changed of its connection's `sess.` variables (from
    /// `at_start`, which it was given) comes back to this, the connection's store: a variable
    /// it removed is removed, one it set differently is set. The others stay as other
    /// streams made them.
    pub fn merge_sess_from(&mut self, child: &VarStore, at_start: &VarStore) {
        let n = child.slots.len().max(at_start.slots.len());
        for i in 0..n {
            let c = child.slots.get(i).filter(|s| s.scope == Scope::Sess && s.val != Val::Absent);
            let a = at_start.slots.get(i).filter(|s| s.scope == Scope::Sess && s.val != Val::Absent);
            match (c, a) {
                (None, Some(_)) => {
                    if let Some(s) = self.slots.get_mut(i) {
                        s.clear();
                    }
                }
                (Some(c), a) if !a.is_some_and(|a| a.same_value(c)) => {
                    let Some(()) = grow_to(&mut self.slots, i + 1) else { return };
                    self.slots[i].clone_from(c);
                }
                _ => {}
            }
        }
    }

    /// The accounting sizes of the variables held.
    fn sizes(&self) -> Sizes {
        let mut z = Sizes::default();
        for s in self.slots.iter().filter(|s| s.val != Val::Absent) {
            let c = VAR_STRUCT_COST + s.extra_bytes();
            z.all += c;
            match s.scope {
                Scope::Req | Scope::Res => {
                    z.reqres += c;
                    z.txn += c;
                    z.sess += c;
                }
                Scope::Txn => {
                    z.txn += c;
                    z.sess += c;
                }
                Scope::Sess => z.sess += c,
                Scope::Check => {
                    z.check += c;
                    z.sess += c;
                }
                Scope::Proc | Scope::Other => {}
            }
        }
        z
    }
}

impl Clone for VarStore {
    fn clone(&self) -> Self {
        let mut c = Self::new();
        c.clone_from(self);
        c
    }

    fn clone_from(&mut self, from: &Self) {
        self.clear();
        let Some(()) = grow_to(&mut self.slots, from.slots.len()) else { return };
        for (d, s) in self.slots.iter_mut().zip(&from.slots) {
            if s.val != Val::Absent {
                d.clone_from(s);
            }
        }
    }
}

impl Drop for VarStore {
    fn drop(&mut self) {
        if self.slots.capacity() == 0 {
            return;
        }
        let mut slots = std::mem::take(&mut self.slots);
        Self::recycle(&mut slots);
        let _ = SPARE.try_with(|s| {
            let Ok(mut s) = s.try_borrow_mut() else { return };
            // The list is sized once, on the first return: no allocation after that.
            if s.len() < SPARE_MAX && (s.len() < s.capacity() || s.try_reserve_exact(SPARE_MAX).is_ok()) {
                s.push(slots);
            }
        });
    }
}

// ---------------------------------------------------------------------------------------------
// The thread's store and the process's

thread_local! {
    /// The variables of the stream running on this thread, for the fetches and converters,
    /// which get no stream. [`enter`] swaps a stream's store in for each run, [`leave`] back.
    pub static CURRENT_VARS: RefCell<VarStore> = const { RefCell::new(VarStore::empty()) };
}

/// The `proc.` variables, shared by every thread.
pub static GLOBAL_PROC_VARS: LazyLock<RwLock<VarStore>> = LazyLock::new(|| RwLock::new(VarStore::empty()));

/// A stream's run starts: its store `vars` becomes the thread's (a swap), and `vars` holds the
/// thread's empty one until [`leave`].
pub fn enter(vars: &mut VarStore) {
    let _ = CURRENT_VARS.try_with(|c| {
        if let Ok(mut c) = c.try_borrow_mut() {
            std::mem::swap(&mut *c, vars);
            vars.clear();
        }
    });
    let _ = RUNNING.try_with(|r| r.set(true));
}

/// A stream's run ends: the thread's store goes back to `vars`, or, for a stream that is
/// gone (`None`), is emptied.
pub fn leave(vars: Option<&mut VarStore>) {
    let _ = CURRENT_VARS.try_with(|c| {
        if let Ok(mut c) = c.try_borrow_mut() {
            if let Some(vars) = vars {
                std::mem::swap(&mut *c, vars);
            }
            c.clear();
        }
    });
    let _ = RUNNING.try_with(|r| r.set(false));
}

/// Runs `f` on the store of the stream whose own is `own`: the thread's while the stream runs
/// ([`enter`]), `own` otherwise. `None` when the thread's is already borrowed.
pub fn with_stream<R>(own: &mut VarStore, f: impl FnOnce(&mut VarStore) -> R) -> Option<R> {
    if RUNNING.try_with(Cell::get).unwrap_or(false) {
        with_current_mut(f)
    } else {
        Some(f(own))
    }
}

fn is_proc(name: &str) -> bool {
    name.starts_with("proc.")
}

/// Runs `f` on the thread's stream variables; `None` when they are already borrowed.
pub fn with_current<R>(f: impl FnOnce(&VarStore) -> R) -> Option<R> {
    CURRENT_VARS.try_with(|v| v.try_borrow().ok().map(|m| f(&m))).ok().flatten()
}

/// Runs `f` on the thread's stream variables, to change them; `None` when they are borrowed.
pub fn with_current_mut<R>(f: impl FnOnce(&mut VarStore) -> R) -> Option<R> {
    CURRENT_VARS.try_with(|v| v.try_borrow_mut().ok().map(|mut m| f(&mut m))).ok().flatten()
}

/// The value of `proc.<name>`.
#[must_use]
pub fn get_proc(name: &str) -> Option<Sample> {
    GLOBAL_PROC_VARS.read().ok()?.get(name)
}

/// Sets `proc.<name>`, unless it does not fit `tune.vars.proc-max-size` / `global-max-size`.
pub fn set_proc(name: &str, smp: Sample) {
    set_proc_in(name, In::Owned(smp));
}

fn set_proc_in(name: &str, v: In<'_>) {
    // The running stream's variables count in the process total too (see [`admit`]).
    let stream = if limits_set() { with_current(|m| m.sizes().sess).unwrap_or(0) } else { 0 };
    if let Ok(mut lock) = GLOBAL_PROC_VARS.write() {
        put(&mut lock, name, v, stream);
    }
}

/// The `proc.` variables, copied out (for `dump_all_vars`).
#[must_use]
pub fn proc_snapshot() -> Vec<(String, Sample)> {
    GLOBAL_PROC_VARS.read().map(|m| m.entries()).unwrap_or_default()
}

/// The value of the variable `name` (scope prefix included): `vars_get_by_desc`. A `proc.`
/// name reads the process's, any other the running stream's.
#[must_use]
pub fn get(name: &str) -> Option<Sample> {
    if is_proc(name) {
        return get_proc(name);
    }
    with_current(|m| m.get(name)).flatten()
}

/// Whether the variable `name` has a value.
#[must_use]
pub fn is_set(name: &str) -> bool {
    if is_proc(name) {
        return GLOBAL_PROC_VARS.read().is_ok_and(|m| m.contains_key(name));
    }
    with_current(|m| m.contains_key(name)).unwrap_or(false)
}

/// Sets the variable `name` to `smp`, with no condition, in the running stream's store.
pub fn set(name: &str, smp: Sample) {
    if is_proc(name) {
        set_proc(name, smp);
        return;
    }
    let procs = if limits_set() { proc_size() } else { 0 };
    with_current_mut(|m| put(m, name, In::Owned(smp), procs));
}

/// Sets the variable `name` of the stream store `vars` (or of the process, for `proc.`),
/// with the accounting of `tune.vars.*`. Says whether it set it.
pub fn set_in(vars: &mut VarStore, name: &str, v: In<'_>) -> bool {
    if is_proc(name) {
        set_proc_in(name, v);
        return true;
    }
    let procs = if limits_set() { proc_size() } else { 0 };
    put(vars, name, v, procs)
}

/// Stores `v` in `store` if it fits the limits: `var_set`.
fn put(store: &mut VarStore, name: &str, v: In<'_>, procs: u64) -> bool {
    let Some(id) = intern(name) else { return false };
    let scope = Scope::of(name);
    let v = match admit(store, procs, id, scope, &v) {
        Admit::Refuse => return false,
        Admit::Bool(b) => In::Owned(Sample::Bool(b)),
        Admit::Store => v,
    };
    store.write(id, scope, v)
}

// Accounting: `var_accounting_add` / `var_accounting_diff` (src/vars.c).

/// What `sizeof(struct var)` is in the x86-64 build of `HAProxy` 3.5-dev8 (measured: a limit of 87
/// refuses one `int` variable, 88 takes it). Ibex's own entries are smaller (design §2.5); the
/// accounting uses `HAProxy`'s number so that a limit means the same.
pub const VAR_STRUCT_COST: u64 = 88;

/// The limits, in the order global, proc, sess, txn, reqres, check; 0 is none.
static LIMITS: [AtomicU32; 6] = [const { AtomicU32::new(0) }; 6];

/// Sets `tune.vars.{global,proc,sess,txn,reqres,check}-max-size`.
pub fn set_limits(global: u32, proc_: u32, sess: u32, txn: u32, reqres: u32, check: u32) {
    for (a, v) in LIMITS.iter().zip([global, proc_, sess, txn, reqres, check]) {
        a.store(v, Ordering::Relaxed);
    }
}

fn limit(i: usize) -> u64 {
    u64::from(LIMITS[i].load(Ordering::Relaxed))
}

fn limits_set() -> bool {
    (0..6).any(|i| limit(i) != 0)
}

#[derive(Default, Clone, Copy)]
struct Sizes {
    /// `sess.`, `txn.`, `req.`, `res.` and `check.`: what a session's counter holds.
    sess: u64,
    txn: u64,
    reqres: u64,
    check: u64,
    /// Every variable of the store (the `proc.` store's total).
    all: u64,
}

/// The size of the `proc.` variables.
fn proc_size() -> u64 {
    GLOBAL_PROC_VARS.read().map_or(0, |m| m.sizes().all)
}

enum Admit {
    Refuse,
    Store,
    Bool(bool),
}

/// Whether setting the variable `id` (of `scope`) to `new` fits the limits: `var_set` with its
/// two `var_accounting_add` calls. `store` holds the variables of the scope's owner (the
/// stream, the check run, or the `proc.` store), `procs` the bytes of the rest of the process
/// that the `proc` and `global` limits also count.
///
/// - The variable does not exist: its `struct var` must fit, or nothing is created (`Refuse`).
/// - A `str`, `bin` or unusual method replaces what the variable held (its bytes are given back)
///   and must fit its bytes too; if not the variable stays, as a `bool` that takes no memory.
///   `HAProxy`'s keeps the integer it held in the union, so that `int(7)` then a string that does
///   not fit still prints `7`; Ibex stores `Bool(old != 0)` (T364 Q1, tradeoff.md).
///
/// Counted per scope as `HAProxy` does: `req`/`res` in `reqres`, `txn` and `sess`, `txn` in `sess`,
/// `check` in `check` and `sess`, and every one in `proc`. Not counted: sessions other than
/// this one (a process total is this process's `proc.` variables and the running stream's; S7
/// brings the rest) and the 88 bytes `HAProxy` charges for each `proc.` name the configuration only
/// mentions (it creates them at load).
fn admit(store: &VarStore, procs: u64, id: u32, scope: Scope, new: &In<'_>) -> Admit {
    if !limits_set() {
        return Admit::Store;
    }
    let old = store.slots.get(id as usize).filter(|s| s.val != Val::Absent);
    let z = store.sizes();
    let proc_total = procs + if scope == Scope::Proc { z.all } else { z.sess };
    // Whether `size - minus + add` fits every limit `scope` counts in.
    let fits = |add: u64, minus: u64| {
        let over = |size: u64, lim: u64| lim != 0 && (size + add).saturating_sub(minus) > lim;
        let (reqres, txn, sess, check) = (z.reqres, z.txn, z.sess, z.check);
        match scope {
            Scope::Req | Scope::Res if over(reqres, limit(4)) || over(txn, limit(3)) => return false,
            Scope::Txn if over(txn, limit(3)) => return false,
            Scope::Check if over(check, limit(5)) => return false,
            Scope::Req | Scope::Res | Scope::Txn | Scope::Sess | Scope::Check if over(sess, limit(2)) => {
                return false
            }
            _ => {}
        }
        !(over(proc_total, limit(1)) || over(proc_total, limit(0)))
    };
    let created = old.is_none();
    if created && !fits(VAR_STRUCT_COST, 0) {
        return Admit::Refuse;
    }
    let held = old.map_or(0, Slot::extra_bytes);
    if new.is_bytes() && !fits(if created { VAR_STRUCT_COST } else { 0 } + new.extra_bytes(), held) {
        return Admit::Bool(old.is_some_and(Slot::as_bool));
    }
    Admit::Store
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
/// sample (`var_set`, src/vars.c): `exists`/`is_set` describe the variable, `stored` is its
/// value, `new` the sample. `ifgt` holds when the stored value is greater than the sample's,
/// `iflt` when it is less, but only when both are `sint`; with any other pair of types (or no
/// stored value) the comparison is ignored, as in `HAProxy`.
#[must_use]
pub fn conds_hold(spec: &str, exists: bool, is_set: bool, stored: Option<&Sample>, new: &Sample) -> bool {
    let empty = is_empty(new);
    let ints = match (stored, new) {
        (Some(Sample::Sint(a)), Sample::Sint(b)) => Some((*a, *b)),
        _ => None,
    };
    spec.split(',').skip(1).all(|c| {
        (c != "ifexists" || exists)
            && (c != "ifnotexists" || !exists)
            && (c != "ifset" || is_set)
            && (c != "ifnotset" || !is_set)
            && (c != "ifempty" || empty)
            && (c != "ifnotempty" || !empty)
            && (c != "ifgt" || ints.is_none_or(|(a, b)| a > b))
            && (c != "iflt" || ints.is_none_or(|(a, b)| a < b))
    })
}


/// `set-var(<name>[,<cond>...])` from a converter, where only the thread's variables are at
/// hand: sets the variable when the conditions hold, and says whether it did. A `proc.`
/// variable always exists (the configuration declares it) and is set once it has a value.
#[allow(clippy::must_use_candidate)] // the rule form ignores it; S3 may not
pub fn set_cond(spec: &str, smp: Sample) -> bool {
    let name = spec.split(',').next().unwrap_or("");
    let set_now = is_set(name);
    // Only an integer is compared (`ifgt`/`iflt`): no copy of a string to look at it.
    let stored = if is_proc(name) {
        GLOBAL_PROC_VARS.read().ok().and_then(|m| m.int(name))
    } else {
        with_current(|m| m.int(name)).flatten()
    }
    .map(Sample::Sint);
    if !conds_hold(spec, is_proc(name) || set_now, set_now, stored.as_ref(), &smp) {
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
    let Sample::Sint(n) = var_arg(name, SampleType::Sint)? else { return None };
    Some(n)
}

/// [`var_arg`] to `str`, as the text (bytetext: a byte from 0x80 is the char of that value).
#[must_use]
pub fn var_arg_str(name: &str) -> Option<String> {
    let Sample::Str(s) = var_arg(name, SampleType::Str)? else { return None };
    Some(s)
}

/// [`var_arg`] to `bin`, as the bytes.
#[must_use]
pub fn var_arg_bin(name: &str) -> Option<Vec<u8>> {
    let Sample::Bin(b) = var_arg(name, SampleType::Bin)? else { return None };
    Some(b)
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
    with_current_mut(|m| {
        m.clear();
        for (k, v) in vars {
            m.insert(k, Sample::Str(v));
        }
    });
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
        let inner = with_current(|_| with_current_mut(VarStore::clear));
        assert_eq!(inner, Some(None));
        assert_eq!(get("txn.t364n"), Some(Sample::Sint(1)));
    }

    /// S6: a slot keeps its buffer when cleared, so the next value of the same variable is
    /// copied into it; every type comes back as it went in.
    #[test]
    fn a_slot_reuses_its_buffer_and_keeps_every_type() {
        let mut s = VarStore::new();
        let meth = Sample::Meth(HttpMethod::Other("PURGE".to_string()));
        for v in [
            Sample::Bool(true),
            Sample::Sint(-3),
            Sample::Ipv6(std::net::Ipv6Addr::LOCALHOST),
            Sample::Meth(HttpMethod::Patch),
            meth.clone(),
            Sample::Bin(vec![0, 0xff]),
            Sample::Str("h\u{e9}llo".to_string()),
        ] {
            s.insert("txn.t364r", v.clone());
            assert_eq!(s.get("txn.t364r"), Some(v));
        }
        let cap = s.slot("txn.t364r").map(|x| x.buf.capacity());
        s.clear_txn();
        assert!(!s.contains_key("txn.t364r"));
        assert!(set_in(&mut s, "txn.t364r", In::Ref(&Sample::Str("abc".to_string()))));
        assert_eq!(s.slots[lookup("txn.t364r").unwrap() as usize].buf.capacity(), cap.unwrap());
        assert_eq!(s.get("txn.t364r"), Some(Sample::Str("abc".to_string())));
        s.insert("sess.t364r", Sample::Sint(1));
        s.clear_txn();
        assert_eq!(s.get("sess.t364r"), Some(Sample::Sint(1)));
        assert!(s.get("txn.t364r").is_none());
    }

    /// S6: a store given back is taken again by the next session of the thread.
    #[test]
    fn a_dropped_store_is_reused_by_the_next() {
        let mut a = VarStore::new();
        a.insert("txn.t364d", Sample::Str("x".repeat(100)));
        let ptr = a.slots.as_ptr();
        drop(a);
        let b = VarStore::new();
        assert_eq!(b.slots.as_ptr(), ptr);
        assert!(b.is_empty());
    }
    /// T445: `pool_gc` frees the spare stores, each kept value buffer handed to the wipe
    /// first, and leaves none for the next store.
    #[test]
    fn draining_the_spare_stores_wipes_each_kept_buffer() {
        let _ = drain_spare(|_| {});
        let mut a = VarStore::new();
        a.insert("txn.t445", Sample::Str("secret".repeat(10)));
        let ptr = a.slots.as_ptr();
        drop(a);
        let mut wiped = Vec::new();
        assert_eq!(drain_spare(|b| wiped.push(b.capacity())), 1, "one spare store");
        assert!(!wiped.is_empty() && wiped.iter().any(|&c| c >= 60), "the value's buffer was wiped: {wiped:?}");
        assert_eq!(drain_spare(|_| {}), 0);
        assert_ne!(VarStore::new().slots.as_ptr(), ptr, "the store was freed, not kept");
    }

    /// T445: a reservation the allocator refuses runs the runtime's `pool_gc` and is tried
    /// once more, as `ssl_sock.c` retries `SSL_new` (the hook is process-wide: set once).
    #[test]
    fn a_refused_reservation_collects_and_retries_once() {
        // Counted per thread: another test's refusals run the same hook on its own thread.
        thread_local! {
            static RUNS: Cell<u32> = const { Cell::new(0) };
        }
        fn hook() {
            RUNS.with(|r| r.set(r.get() + 1));
        }
        set_alloc_failure_hook(hook);
        let mut v: Vec<u8> = Vec::new();
        assert_eq!(reserve_more(&mut v, usize::MAX), None);
        assert_eq!(RUNS.with(Cell::get), 1, "one collection for one failure");
        assert_eq!(reserve_more(&mut v, 8), Some(()));
        assert_eq!(RUNS.with(Cell::get), 1, "no collection when it succeeds");
    }

    /// The paths of the stores that cannot grow: no memory, or a size nothing can address.
    #[test]
    fn a_store_that_cannot_grow_is_left_as_it_is() {
        let mut v: Vec<u8> = Vec::new();
        assert_eq!(reserve_more(&mut v, usize::MAX), None);
        assert_eq!(reserve_more(&mut v, 8), Some(()));
        let mut slots: Vec<Slot> = Vec::new();
        assert_eq!(grow_to(&mut slots, usize::MAX / 2), None);
        assert!(slots.is_empty());
        assert_eq!(grow_to(&mut slots, 3), Some(()));
        assert_eq!(slots.len(), 3);
        assert_eq!(grow_to(&mut slots, 2), Some(()));
        assert_eq!(slots.len(), 3);
    }

    /// The thread's store is borrowed while a stream's run ends: `leave` empties nothing and
    /// goes on; with no stream running, `with_stream` runs on the store it is given.
    #[test]
    fn leave_while_borrowed_and_a_stream_not_running() {
        assert_eq!(with_current(|_| leave(None)), Some(()));
        let mut own = VarStore::new();
        assert_eq!(with_stream(&mut own, |s| s.is_empty()), Some(true));
        assert_eq!(In::Owned(Sample::Sint(1)).extra_bytes(), 0);
        assert_eq!(In::Ref(&Sample::Str("h\u{e9}".into())).extra_bytes(), 2);
    }

    /// Another thread may name a variable between the read that missed and the write lock;
    /// the names stop at `MAX_NAMES`.
    #[test]
    fn a_name_is_numbered_once_and_the_table_is_capped() {
        let mut w = Names::default();
        assert_eq!(intern_locked(&mut w, "txn.a"), Some(0));
        assert_eq!(intern_locked(&mut w, "txn.a"), Some(0));
        for i in 1..MAX_NAMES {
            assert_eq!(intern_locked(&mut w, &format!("txn.n{i}")), u32::try_from(i).ok());
        }
        assert_eq!(intern_locked(&mut w, "txn.one-too-many"), None);
        assert_eq!(intern_locked(&mut w, "txn.a"), Some(0));
    }

    /// A value set by reference keeps its type for every kind, an unusual method included,
    /// and is counted by its bytes.
    #[test]
    fn a_value_set_by_reference_keeps_every_type() {
        let mut s = VarStore::new();
        for v in [
            Sample::Bin(vec![1, 2, 3]),
            Sample::Meth(HttpMethod::Other("PURGE".to_string())),
            Sample::Meth(HttpMethod::Patch),
        ] {
            assert!(set_in(&mut s, "txn.t363ref", In::Ref(&v)));
            assert_eq!(s.get("txn.t363ref"), Some(v.clone()));
        }
        assert!(set_in(&mut s, "txn.t363ref2", In::Ref(&Sample::Meth(HttpMethod::Other("PURGE".to_string())))));
        let z = s.sizes();
        assert_eq!(z.all, 2 * VAR_STRUCT_COST + 5);
    }
}
