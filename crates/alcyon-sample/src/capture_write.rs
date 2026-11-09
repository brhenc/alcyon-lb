// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T331: the writes of the `capture-req(<id>)` and `capture-res(<id>)` converters.
//!
//! A converter gets a read-only [`crate::SampleContext`], and the stream's capture slots
//! (`sess.log.req_captures`, `res_captures`) are borrowed by it. `HAProxy` stores into a slot at
//! the moment the converter runs, so a fetch that follows in the same expression, or a later
//! rule, reads the new value. This module keeps the writes of the stream that is running on
//! the thread, the way `CURRENT_VARS` keeps its variables: the engine hands over the slots'
//! lengths when a run starts ([`enter`]), the `capture.*.hdr` fetches read what has been
//! written ([`pending`]) before the slots, and the engine takes the writes back when the run
//! ends ([`leave`]) and puts them in the slots.

use std::cell::RefCell;
use std::sync::Arc;

/// The capture slots of a frontend, as `(header name, length)`; the length is what the slot
/// cuts a value at.
pub type SlotLens = Arc<[(String, usize)]>;

/// One write: the response's slots (not the request's), the slot, the value as cut.
pub type CaptureWrite = (bool, usize, Vec<u8>);

#[derive(Default)]
struct State {
    req: Option<SlotLens>,
    res: Option<SlotLens>,
    writes: Vec<CaptureWrite>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// A run of a stream starts: its slots' lengths are the thread's, and nothing is written yet.
pub fn enter(req: SlotLens, res: SlotLens) {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.req = Some(req);
        s.res = Some(res);
        s.writes.clear();
    });
}

/// [`enter`] without a clone a run (L3, Q6): the thread keeps the tables of the frontend
/// that ran last, and takes another's only when it changes. [`leave_kept`] ends the run.
/// Returns whether the tables were taken (cloned).
#[must_use]
pub fn enter_shared(req: &SlotLens, res: &SlotLens) -> bool {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.writes.clear();
        let same = s.req.as_ref().is_some_and(|r| Arc::ptr_eq(r, req)) && s.res.as_ref().is_some_and(|r| Arc::ptr_eq(r, res));
        if !same {
            s.req = Some(Arc::clone(req));
            s.res = Some(Arc::clone(res));
        }
        !same
    })
}

/// The end of a run [`enter_shared`] began: what its converters wrote, if anything (no
/// allocation when nothing was). The tables stay for the next run.
#[must_use]
pub fn leave_kept() -> Vec<CaptureWrite> {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        if s.writes.is_empty() {
            Vec::new()
        } else {
            std::mem::take(&mut s.writes)
        }
    })
}

/// The run ends: what its converters wrote, to be put in the stream's slots.
#[must_use]
pub fn leave() -> Vec<CaptureWrite> {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.req = None;
        s.res = None;
        std::mem::take(&mut s.writes)
    })
}

/// Stores `value` in slot `id`, cut at the slot's length. A slot that does not exist captures
/// nothing (the converter fails silently, `sample_conv_req_capture`).
pub fn store(res: bool, id: usize, value: &[u8]) {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let lens = if res { s.res.as_ref() } else { s.req.as_ref() };
        let Some(&(_, len)) = lens.and_then(|l| l.get(id)) else { return };
        let cut = value.get(..len).unwrap_or(value).to_vec();
        s.writes.retain(|w| (w.0, w.1) != (res, id));
        s.writes.push((res, id, cut));
    });
}

/// The engine wrote slot `id` itself (`http-request capture`): an earlier write of a
/// converter is not the slot's value any more.
pub fn discard(res: bool, id: usize) {
    STATE.with(|s| s.borrow_mut().writes.retain(|w| (w.0, w.1) != (res, id)));
}

/// What a converter wrote to slot `id` in this run, if it did.
#[must_use]
pub fn pending(res: bool, id: usize) -> Option<Vec<u8>> {
    STATE.with(|s| s.borrow().writes.iter().find(|w| (w.0, w.1) == (res, id)).map(|w| w.2.clone()))
}
