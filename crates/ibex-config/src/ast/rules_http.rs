// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;
use std::cell::RefCell;

/// Modern HTTP-request action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpReqAction {
    TrackSc0 {
        expr: String,
        table: Option<String>,
    },
    TrackSc1 {
        expr: String,
        table: Option<String>,
    },
    TrackSc2 {
        expr: String,
        table: Option<String>,
    },
    Return {
        status: u16,
        content_type: Option<String>,
        lf_string: Option<String>,
        /// `default-errorfiles`/`errorfile`/`errorfiles`: use the proxy's configured
        /// error page for `status` instead of the dummy/templated body above.
        error_page: Option<ErrorPageSource>,
    },
    Deny {
        deny_status: Option<u16>,
        /// Templated response payload, same encoding as `Return::content_type`.
        content_type: Option<String>,
        /// Templated response payload, same encoding as `Return::lf_string`.
        lf_string: Option<String>,
        /// `default-errorfiles`/`errorfile`/`errorfiles`: use the proxy's configured
        /// error page for the deny status instead of the templated body above. `HAProxy`
        /// implies this when `deny` carries no body argument at all (or only
        /// `deny_status`), so the parser sets it in that case too.
        error_page: Option<ErrorPageSource>,
    },
    /// Holds the request for `timeout tarpit` (`timeout connect` when unset), then answers
    /// as `Deny` does, with status 500 unless given.
    Tarpit {
        deny_status: Option<u16>,
        content_type: Option<String>,
        lf_string: Option<String>,
        error_page: Option<ErrorPageSource>,
    },
    Allow,
    SetHeader {
        name: String,
        fmt: String,
    },
    AddHeader {
        name: String,
        fmt: String,
    },
    DelHeader {
        name: String,
    },
    ReplaceHeader {
        name: String,
        regex: String,
        repl: String,
    },
    ReplaceValue {
        name: String,
        regex: String,
        repl: String,
    },
    SetPath {
        fmt: String,
    },
    ReplacePath {
        regex: String,
        repl: String,
    },
    SetPathq {
        fmt: String,
    },
    ReplacePathq {
        regex: String,
        repl: String,
    },
    ReplaceUri {
        regex: String,
        repl: String,
    },
    SetQuery {
        fmt: String,
    },
    SetUri {
        fmt: String,
    },
    SetMethod {
        fmt: String,
    },
    SetSrc {
        expr: String,
    },
    SetDst {
        expr: String,
    },
    /// Rewrites the port of the stream's source (`src`).
    SetSrcPort {
        expr: String,
    },
    /// Rewrites the port of the stream's destination (`dst`), which a server without a
    /// port connects to.
    SetDstPort {
        expr: String,
    },
    /// `set-priority-class <expr>`: the stream's queue class, clamped to +-2047.
    SetPriorityClass {
        expr: String,
    },
    /// `set-priority-offset <expr>`: the stream's queue offset, clamped to +-524287.
    SetPriorityOffset {
        expr: String,
    },
    /// Replaces the stream's retry budget.
    SetRetries {
        value: RetriesValue,
    },
    /// `http-request redirect location|prefix|scheme <fmt> [options]`.
    Redirect(RedirectRule),
    StrictMode {
        on: bool,
    },
    SetVar {
        var_name: String,
        expr: String,
    },
    SetVarFmt {
        var_name: String,
        fmt: String,
    },
    UnsetVar {
        var_name: String,
    },
    NormalizeUri {
        normalizer: String,
        full: bool,
        strict: bool,
    },
    SetTimeout {
        timeout_type: String,
        timeout_val: String,
    },
    /// `auth [realm <realm>]`: the 401 that asks for credentials; no realm is the proxy's name.
    Auth {
        realm: Option<String>,
    },
    Capture {
        expr: String,
        len: Option<usize>,
        id: Option<usize>,
    },
    ScIncGpc0 {
        sc: u8,
    },
    ScIncGpc1 {
        sc: u8,
    },
    ScSetGpt0 {
        sc: u8,
        expr: String,
    },
    /// `sc-inc-gpc(<idx>,<sc>)`, `sc-add-gpc(<idx>,<sc>) <value>`, `sc-set-gpt(<idx>,<sc>) <value>`:
    /// the array form of the general purpose storage.
    ScIncGpc {
        idx: usize,
        sc: u8,
    },
    ScAddGpc {
        idx: usize,
        sc: u8,
        expr: String,
    },
    ScSetGpt {
        idx: usize,
        sc: u8,
        expr: String,
    },
    /// `http-request wait-for-body time <t> [at-least <bytes>]`: the rules after this one
    /// run once the request body is complete, or `at_least` bytes of it are here, or the
    /// buffer is full; `time_ms` after the rule is reached, the client gets a 408. `None`
    /// is the wait `option http-buffer-request` stands for: `timeout http-request`, else
    /// `timeout client`.
    WaitForBody {
        time_ms: Option<u32>,
        at_least: u32,
    },
}

/// The argument of `set-retries`: an integer from 0 to 100, or an expression evaluated per
/// request whose result is used only when it falls in that range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetriesValue {
    Fixed(u16),
    Expr(String),
}

/// Rule pairing an HTTP-request action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReqRule {
    pub action: HttpReqAction,
    pub cond: Option<AclCondition>,
    /// The configuration line the rule was written on, for `last_rule_line`.
    pub line: u32,
}

/// Modern HTTP-response action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpResAction {
    SetHeader { name: String, fmt: String },
    AddHeader { name: String, fmt: String },
    DelHeader { name: String },
    /// `set-status <code> [reason <text>]`; the reason is literal (measured: no log-format).
    SetStatus { status: u16, reason: Option<String> },
    /// `http-response capture <sample> id <id>`: the sample into the frontend's response
    /// capture slot `id` (a `declare capture response`, or a `capture response header`),
    /// cut to that slot's length.
    Capture { expr: String, id: usize },
    /// `http-response wait-for-body time <t> [at-least <bytes>]`: the rules after this one
    /// run once the response body is complete, or `at_least` bytes of it are here, or the
    /// buffer is full; after `time_ms` the client gets a 504.
    WaitForBody { time_ms: u32, at_least: u32 },
    /// `http-response redirect location <fmt> [code <c>] [set-cookie <c>|clear-cookie <n>]`:
    /// the response is replaced by an empty redirect to `location` (a log-format string).
    /// `HAProxy` refuses the `prefix` and `scheme` types in a response.
    Redirect { location: String, code: u16, cookie: Option<RedirectCookie> },
}

/// The three kinds of `http-request redirect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectKind {
    /// `location <fmt>`: the location is the formatted text.
    Location,
    /// `prefix <fmt>`: the formatted text, then the request's path and query.
    Prefix,
    /// `scheme <fmt>`: `<scheme>://<host>` then the request's path and query.
    Scheme,
}

/// An `http-request redirect` rule (`http_parse_redirect_rule`, `src/http_act.c`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectRule {
    pub kind: RedirectKind,
    /// The log-format text of the location, prefix or scheme.
    pub target: String,
    pub code: u16,
    pub cookie: Option<RedirectCookie>,
    /// `drop-query`: a prefix or scheme redirect leaves the query out.
    pub drop_query: bool,
    /// `keep-query`: a location redirect appends the request's query.
    pub keep_query: bool,
    /// `append-slash`: a prefix or scheme redirect ends with a `/`.
    pub append_slash: bool,
    /// `ignore-empty`: an empty location skips the rule.
    pub ignore_empty: bool,
}

/// The cookie a redirect sets or clears: of `set-cookie` and `clear-cookie` the last one
/// on the line stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectCookie {
    /// `set-cookie NAME[=VALUE]`: `set-cookie: NAME[=VALUE]; path=/;`.
    Set(String),
    /// `set-cookie-fmt <log-format>`: as `Set`, the text being formatted for the request.
    SetFmt(String),
    /// `clear-cookie NAME`: `set-cookie: NAME; path=/; Max-Age=0;`.
    Clear(String),
}

/// Rule pairing an HTTP-response action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResRule {
    pub action: HttpResAction,
    pub cond: Option<AclCondition>,
    /// The configuration line the rule was written on, for `last_rule_line`.
    pub line: u32,
}

/// Modern HTTP-after-response action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpAfterResAction {
    SetHeader { name: String, fmt: String },
    AddHeader { name: String, fmt: String },
    DelHeader { name: String },
    /// `capture <sample> id <idx>`: a frontend response slot, as `http-response capture`.
    Capture { expr: String, id: usize },
}

/// Rule pairing an HTTP-after-response action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAfterResRule {
    pub action: HttpAfterResAction,
    pub cond: Option<AclCondition>,
}

/// Source of a custom error page, as selected by `default-errorfiles`, `errorfile
/// <file>`, or `errorfiles <name>` on `http-request return`/`deny`, or by `http-error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorPageSource {
    /// `default-errorfiles`: use the proxy's own configured error page for this status
    /// (an `http-error` override if any, else an `errorfile`/`errorfiles` entry, else
    /// `HAProxy`'s built-in page for the code), rather than a page named by this rule.
    DefaultErrorfiles,
    /// A full raw HTTP response, loaded verbatim from a file at config time (`errorfile
    /// <file>`, or a status code resolved out of an `errorfiles <name>` / `http-errors`
    /// section).
    Raw(Vec<u8>),
    /// `http-error`'s inline templated body (`content-type`/`hdr`/`string`/`lf-string`),
    /// built at request/response time against the denying request -- the same encoding
    /// `http-request return`'s own `content_type`/`lf_string` fields use.
    ///
    /// On `deny`/`return`, `Custom { None, None }` is also what `errorfiles <name>` names
    /// when the section has no page for the status: `HAProxy` then sends the status line
    /// with `content-length: 0`, which is what an empty template builds.
    Custom {
        content_type: Option<String>,
        lf_string: Option<String>,
    },
}

/// One `http-errors <name>` section: status code to the raw response `errorfile` loaded.
type HttpErrorsTable = HashMap<u16, Vec<u8>>;

thread_local! {
    /// Named `http-errors <name>` sections from the parse in progress on this thread.
    ///
    /// `errorfiles <name> [<code>...]` (a proxy directive or an `http-request`
    /// `return`/`deny`/`http-error` argument) looks entries up here by name. HAProxy
    /// requires a section to be declared before it is used, so the lookup is resolved at
    /// parse time. Thread-local, not process-global: `parse_str` clears it on entry, and
    /// two parses on different threads (tests, a reload beside a running check) must not
    /// clear or read each other's sections.
    static HTTP_ERRORS_SECTIONS: RefCell<HashMap<String, HttpErrorsTable>> =
        RefCell::new(HashMap::new());
}

/// Clears this thread's `http-errors` sections. Called at the start of `parse_str`.
pub fn clear_http_errors_sections() {
    HTTP_ERRORS_SECTIONS.with_borrow_mut(HashMap::clear);
}

/// Registers a parsed `http-errors <name>` section's `errorfile` table under its name.
pub fn register_http_errors_section(name: String, table: HttpErrorsTable) {
    HTTP_ERRORS_SECTIONS.with_borrow_mut(|m| {
        m.insert(name, table);
    });
}

/// Every `errorfile` entry declared in the named `http-errors` section.
#[must_use]
pub fn http_errors_section(name: &str) -> Option<HttpErrorsTable> {
    HTTP_ERRORS_SECTIONS.with_borrow(|m| m.get(name).cloned())
}

/// One status code's `errorfile` entry in the named `http-errors` section.
#[must_use]
pub fn http_errors_section_code(name: &str, code: u16) -> Option<Vec<u8>> {
    HTTP_ERRORS_SECTIONS.with_borrow(|m| m.get(name).and_then(|t| t.get(&code).cloned()))
}

