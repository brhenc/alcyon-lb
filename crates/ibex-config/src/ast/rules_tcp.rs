// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;

/// Modern TCP-request connection action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpReqConnAction {
    TrackSc0 { expr: String, table: Option<String> },
    TrackSc1 { expr: String, table: Option<String> },
    TrackSc2 { expr: String, table: Option<String> },
    SilentDrop,
    /// `silent-drop rst-ttl <1-255>`: the RST is sent with that TTL (`SilentDrop` is a TTL of 1).
    SilentDropTtl(u8),
    Reject,
    Accept,
    SetSrc { expr: String },
    SetDst { expr: String },
    SetSrcPort { expr: String },
    SetDstPort { expr: String },
    DoLog,
    /// `expect-proxy layer4`: a PROXY header is expected on the connections the rule matches.
    ExpectProxy,
}

/// Rule pairing a TCP-request connection action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpReqConnRule {
    pub action: TcpReqConnAction,
    pub cond: Option<AclCondition>,
}

/// Modern TCP-request session action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpReqSessionAction {
    TrackSc0 { expr: String, table: Option<String> },
    TrackSc1 { expr: String, table: Option<String> },
    TrackSc2 { expr: String, table: Option<String> },
    SetVar { var_name: String, expr: String },
    SetVarFmt { var_name: String, fmt: String },
    UnsetVar { var_name: String },
    SetSrc { expr: String },
    SetDst { expr: String },
    SetSrcPort { expr: String },
    SetDstPort { expr: String },
    /// `capture <sample> len <n>`: the sample, cut at `len`, in a slot of its own in the
    /// request captures of the proxy holding the rule. `id` is that slot, assigned when the
    /// proxy is built (`None` until then); a stream whose frontend is another proxy ignores it.
    Capture { expr: String, len: usize, id: Option<usize> },
    SilentDrop,
    /// `silent-drop rst-ttl <1-255>`: the RST is sent with that TTL (`SilentDrop` is a TTL of 1).
    SilentDropTtl(u8),
    Reject,
    Accept,
    AttachSrv { name: String },
    DoLog,
    ScIncGpc0 { sc: u8 },
    ScIncGpc1 { sc: u8 },
    ScSetGpt0 { sc: u8, expr: String },
    /// `sc-inc-gpc(<idx>,<sc>)`, `sc-add-gpc(<idx>,<sc>) <value>`, `sc-set-gpt(<idx>,<sc>) <value>`:
    /// the array form of the general purpose storage.
    ScIncGpc { idx: usize, sc: u8 },
    ScAddGpc { idx: usize, sc: u8, expr: String },
    ScSetGpt { idx: usize, sc: u8, expr: String },
}

/// Rule pairing a TCP-request session action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpReqSessionRule {
    pub action: TcpReqSessionAction,
    pub cond: Option<AclCondition>,
}

/// Modern TCP-request content action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpReqContentAction {
    TrackSc0 { expr: String, table: Option<String> },
    TrackSc1 { expr: String, table: Option<String> },
    TrackSc2 { expr: String, table: Option<String> },
    SetVar { var_name: String, expr: String },
    /// `do-resolve(<var>,<resolvers>[,ipv4|ipv6]) <expr>` (T489).
    DoResolve(crate::ast::DoResolve),
    SetVarFmt { var_name: String, fmt: String },
    UnsetVar { var_name: String },
    SetSrc { expr: String },
    SetDst { expr: String },
    SetSrcPort { expr: String },
    SetDstPort { expr: String },
    /// `capture <sample> len <n>`: the sample, cut at `len`, in a slot of its own in the
    /// request captures of the proxy holding the rule. `id` is that slot, assigned when the
    /// proxy is built (`None` until then); a stream whose frontend is another proxy ignores it.
    Capture { expr: String, len: usize, id: Option<usize> },
    SilentDrop,
    /// `silent-drop rst-ttl <1-255>`: the RST is sent with that TTL (`SilentDrop` is a TTL of 1).
    SilentDropTtl(u8),
    Reject,
    Accept,
    SwitchModeHttp { proto: Option<String> },
    ScIncGpc0 { sc: u8 },
    ScIncGpc1 { sc: u8 },
    ScSetGpt0 { sc: u8, expr: String },
    /// `sc-inc-gpc(<idx>,<sc>)`, `sc-add-gpc(<idx>,<sc>) <value>`, `sc-set-gpt(<idx>,<sc>) <value>`:
    /// the array form of the general purpose storage.
    ScIncGpc { idx: usize, sc: u8 },
    ScAddGpc { idx: usize, sc: u8, expr: String },
    ScSetGpt { idx: usize, sc: u8, expr: String },
    DoLog,
    UseService { service: String },
    Lua { name: String },
}

/// What a `tcp-response content` rule can do in Ibex: the parser refuses every other
/// action (`parse_tcp_res_content`), so the runtime has nothing else to handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpResAction {
    Accept,
    Reject,
    SilentDrop,
    SetVar { var_name: String, expr: String },
    SetVarFmt { var_name: String, fmt: String },
    UnsetVar { var_name: String },
}

/// Rule pairing a `tcp-response content` action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResContentRule {
    pub action: TcpResAction,
    pub cond: Option<AclCondition>,
    /// The configuration line the rule was written on, for `last_rule_line`.
    pub line: u32,
}

/// Rule pairing a TCP-request content action with an optional condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpReqContentRule {
    pub action: TcpReqContentAction,
    pub cond: Option<AclCondition>,
    /// The configuration line the rule was written on, for `last_rule_line`.
    pub line: u32,
}

