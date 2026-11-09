// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Warnings the proxy keywords raise while the configuration is read.
//!
//! The keyword parsers return `Result<(), ConfigError>` and have nowhere to put a warning
//! that does not stop the load, so they hand it to [`push`]; `parse_str` starts the list
//! empty and moves it into `Config::proxy_warnings`, which `alcyon -c` prints as `HAProxy`
//! does.

use crate::ast::global::{LoadWarning, WarnStyle};
use std::cell::RefCell;

thread_local! {
    static STATE: RefCell<(Vec<LoadWarning>, String)> = const { RefCell::new((Vec::new(), String::new())) };
}

/// Starts a new configuration: no warnings, no current proxy.
pub(crate) fn reset() {
    STATE.with(|s| *s.borrow_mut() = (Vec::new(), String::new()));
}

/// The name of the proxy section being read, for `{px}` in a message.
pub(crate) fn set_proxy(name: &str) {
    STATE.with(|s| s.borrow_mut().1 = name.to_string());
}

/// Records a `[WARNING]` of `line`; `{px}` in `text` is the current proxy's name.
pub(crate) fn push(line: usize, style: WarnStyle, text: &str) {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let text = text.replace("{px}", &s.1);
        s.0.push(LoadWarning { line, alert: false, text, style });
    });
}

/// Records an `[ALERT]` that does not fail the load.
pub(crate) fn push_alert(line: usize, style: WarnStyle, text: &str) {
    STATE.with(|s| s.borrow_mut().0.push(LoadWarning { line, alert: true, text: text.to_string(), style }));
}

/// Takes what was recorded since [`reset`].
pub(crate) fn take() -> Vec<LoadWarning> {
    STATE.with(|s| std::mem::take(&mut s.borrow_mut().0))
}
