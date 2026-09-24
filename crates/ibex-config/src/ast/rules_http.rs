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
    },
    Deny {
        deny_status: Option<u16>,
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

