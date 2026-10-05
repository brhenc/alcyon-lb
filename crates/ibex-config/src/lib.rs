// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// HAProxy 1.0 configuration parser, ported to Rust.
// Derived from HAProxy 1.0.2 (haproxy.c) by Willy Tarreau <willy@meta-x.org>.

//! `HAProxy` 1.0 configuration parser for Ibex.
//!
//! Provides a typed abstract syntax tree (AST), lexical analyzer, and configuration
//! parser matching the syntax and semantics of `HAProxy` 1.0.2.

#![forbid(unsafe_code)]

pub mod ast;
pub mod cond;
pub mod error;
pub mod lexer;
pub mod preproc;
pub mod parser;

use std::fs;
use std::path::Path;

pub use ast::{
    AclCondition, AclRule, AclTerm, BackendSection, BalanceAlgorithm, Config, CookieConfig, DefaultsSection,
    ErrorPageSource, Forwarded, ForwardedValue, FrontendSection, GlobalSection, GlobalSetVar, StatsSocket,
    HashPreserveAffinity, HashType,
    HeaderExp, HttpAfterResAction, HttpAfterResRule, HttpReqAction, HttpReqRule, HttpResAction, RedirectCookie, RedirectKind, RedirectRule, DirectiveMessage,
    HeaderCapture, RE_CONN_FAILED, RE_DISCONNECTED, RE_EARLY_ERROR, RE_JUNK_RESPONSE, RE_STATUSES, RE_STATUS_MASK, RE_TIMEOUT, LOG_OPT_ASAP, LOG_OPT_DONTLOG_NORMAL, LOG_OPT_SEPARATE_ERRORS, HttpResRule, HttpReuse, ListenSection, LogConfig, LogFormatSpec, LogFacility, LogLevel, LogSample, LogTarget, LogForwardBind, LogForwardHost, LogForwardSection, Mode, RingFormat, RingSection, RingServer, RingServerAddr, RetriesValue,
    SampleRef, SectionKind, Server, ServerSsl, SslVerify, StatsConfig, StatusCodeSet, TlsRange, TlsVersion,
    StickRule, StickRuleType, StickTableConfigAst, TcpReqConnAction, TcpReqConnRule,
    TcpReqContentAction, TcpReqContentRule, TcpResAction, TcpResContentRule, TcpReqSessionAction, TcpReqSessionRule,
    TimeoutConfig, UseBackendRule, UseServerRule, Userlist, UserlistUser,
};
pub use error::ConfigError;
pub use parser::parse_str;
pub use parser::parse_str as parse_config;


/// Parses an `HAProxy` 1.0 configuration file from disk.
///
/// # Errors
///
/// Returns a `ConfigError` if the file cannot be read or if parsing fails.
pub fn parse_file(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let path_ref = path.as_ref();
    let content = fs::read_to_string(path_ref).map_err(|e| {
        ConfigError::new(
            1,
            1,
            format!(
                "Error reading configuration file '{}': {e}",
                path_ref.display()
            ),
        )
    })?;
    parse_str(&content)
}
