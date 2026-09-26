// SPDX-License-Identifier: GPL-2.0-or-later
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;

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
        /// error page for the deny status instead of the templated body above. HAProxy
        /// implies this when `deny` carries no body argument at all (or only
        /// `deny_status`), so the parser sets it in that case too.
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
    Redirect {
        location: Option<String>,
        scheme: Option<String>,
        prefix: Option<String>,
        code: Option<u16>,
    },
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
    Auth,
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
}

/// Rule pairing an HTTP-request action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReqRule {
    pub action: HttpReqAction,
    pub cond: Option<AclCondition>,
}

/// Modern HTTP-response action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpResAction {
    SetHeader { name: String, fmt: String },
    AddHeader { name: String, fmt: String },
    DelHeader { name: String },
    SetStatus { status: u16 },
}

/// Rule pairing an HTTP-response action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResRule {
    pub action: HttpResAction,
    pub cond: Option<AclCondition>,
}

/// Modern HTTP-after-response action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpAfterResAction {
    SetHeader { name: String, fmt: String },
    AddHeader { name: String, fmt: String },
    DelHeader { name: String },
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
    /// HAProxy's built-in page for the code), rather than a page named by this rule.
    DefaultErrorfiles,
    /// A full raw HTTP response, loaded verbatim from a file at config time (`errorfile
    /// <file>`, or a status code resolved out of an `errorfiles <name>` / `http-errors`
    /// section).
    Raw(Vec<u8>),
    /// `http-error`'s inline templated body (`content-type`/`hdr`/`string`/`lf-string`),
    /// built at request/response time against the denying request -- the same encoding
    /// `http-request return`'s own `content_type`/`lf_string` fields use.
    Custom {
        content_type: Option<String>,
        lf_string: Option<String>,
    },
}

/// Registry of named `http-errors <name>` sections, keyed by section name and then by
/// HTTP status code, holding the raw bytes `errorfile <code> <file>` loaded for each.
///
/// `errorfiles <name> [<code>...]` (a proxy directive or an `http-request`
/// return`/`deny`/`http-error` argument) looks entries up here by name. Sections are
/// declared textually before they are used in every configuration this crate parses
/// (HAProxy requires the same ordering), so resolving eagerly at parse time, the same way
/// `crate::ast::checks` resolves checks, avoids threading the registry through every
/// proxy-section parser.
static HTTP_ERRORS_SECTIONS: LazyLock<RwLock<HashMap<String, HashMap<u16, Vec<u8>>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Clears the `http-errors` section registry. Called once at the start of `parse_str` so
/// that sections from a previous parse in the same process (tests parse many configs)
/// cannot leak into the next one.
pub fn clear_http_errors_sections() {
    if let Ok(mut map) = HTTP_ERRORS_SECTIONS.write() {
        map.clear();
    }
}

/// Registers a parsed `http-errors <name>` section's `errorfile` table under its name.
pub fn register_http_errors_section(name: String, table: HashMap<u16, Vec<u8>>) {
    if let Ok(mut map) = HTTP_ERRORS_SECTIONS.write() {
        map.insert(name, table);
    }
}

/// Looks up every `errorfile` entry declared in the named `http-errors` section.
#[must_use]
pub fn http_errors_section(name: &str) -> Option<HashMap<u16, Vec<u8>>> {
    HTTP_ERRORS_SECTIONS.read().ok().and_then(|map| map.get(name).cloned())
}

/// Looks up a single status code's `errorfile` entry in the named `http-errors` section.
#[must_use]
pub fn http_errors_section_code(name: &str, code: u16) -> Option<Vec<u8>> {
    HTTP_ERRORS_SECTIONS
        .read()
        .ok()
        .and_then(|map| map.get(name).and_then(|table| table.get(&code).cloned()))
}

