// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// HAProxy configuration parser, ported to Rust.
// Derived from HAProxy 1.0 - 3.5 by Willy Tarreau <willy@meta-x.org>.

#![allow(clippy::struct_excessive_bools)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{LazyLock, RwLock};
use std::time::Duration;

pub mod global;
pub use global::*;

pub mod proxy;
pub use proxy::*;

pub mod server;
pub use server::*;

pub mod rules_tcp;
pub use rules_tcp::*;

pub mod rules_http;
pub use rules_http::*;

pub mod acl;
pub use acl::*;

pub mod stick;
pub use stick::*;

pub mod userlist;
pub use userlist::*;

pub mod forwarded;
pub use forwarded::*;

pub mod logging;
pub use logging::*;

pub mod checks;
pub use checks::*;

/// Full `HAProxy` configuration containing one or more proxy sections.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    /// Optional global settings.
    pub global: Option<GlobalSection>,
    /// Optional defaults settings.
    pub defaults: Option<DefaultsSection>,
    /// List of proxy listen sections in order of definition (`HAProxy` 1.0 style).
    pub listens: Vec<ListenSection>,
    /// List of frontend sections (`HAProxy` 1.1+ style).
    pub frontends: Vec<FrontendSection>,
    /// List of backend sections (`HAProxy` 1.1+ style).
    pub backends: Vec<BackendSection>,
    /// Every ACL and log-format sample expression in the proxy and defaults sections, in
    /// the order written. Empty for a configuration not built by the parser.
    pub sample_refs: Vec<SampleRef>,
    /// The `userlist` sections, in the order written.
    pub userlists: Vec<Userlist>,
}

