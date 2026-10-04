// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `option forwarded`: which parameters of the RFC 7239 `Forwarded` header to add.

/// Where one parameter's value comes from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ForwardedValue {
    /// Not written.
    #[default]
    Off,
    /// Written from the connection (`for`, `by`, `host`, ... without `-expr`).
    Default,
    /// Written from a sample expression (`for-expr <expr>`).
    Expr(String),
}

/// The parameters `option forwarded` writes, in the order the header has them:
/// `proto`, `host`, `by`, `for`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Forwarded {
    pub proto: bool,
    pub host: ForwardedValue,
    pub by: ForwardedValue,
    pub by_port: ForwardedValue,
    pub for_: ForwardedValue,
    pub for_port: ForwardedValue,
}

impl Forwarded {
    /// `option forwarded` with no parameter: `proto` and `for`.
    #[must_use]
    pub fn plain() -> Self {
        Self { proto: true, for_: ForwardedValue::Default, ..Self::default() }
    }

    /// Every sample expression the option names.
    pub fn exprs(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("host-expr", &self.host),
            ("by-expr", &self.by),
            ("by_port-expr", &self.by_port),
            ("for-expr", &self.for_),
            ("for_port-expr", &self.for_port),
        ]
        .into_iter()
        .filter_map(|(k, v)| if let ForwardedValue::Expr(e) = v { Some((k, e.as_str())) } else { None })
    }
}
