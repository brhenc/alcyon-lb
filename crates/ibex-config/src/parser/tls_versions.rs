// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The TLS version keywords of a `bind` line and of `ssl-default-bind-options` /
//! `ssl-default-server-options` (T153): `ssl-min-ver`, `ssl-max-ver`, `force-tlsvN`,
//! `no-tlsvN`.
//!
//! They narrow a range, `min..=max`, out of the two versions rustls speaks (TLS 1.2 and
//! 1.3). `HAProxy` also accepts `SSLv3`, `TLSv1.0` and `TLSv1.1`; a range that needs one of
//! them cannot be served, so the keyword is refused with a message saying so, except
//! `no-sslv3`, `no-tlsv10` and `no-tlsv11`, which ask for what is already the case.

use super::{ConfigError, Token};
use crate::ast::TlsVersion;

pub(crate) use crate::ast::TlsRange;

fn parse_version(t: &Token, prefix: &str) -> Result<TlsVersion, ConfigError> {
    match t.text.as_str() {
        "TLSv1.2" => Ok(TlsVersion::Tls12),
        "TLSv1.3" => Ok(TlsVersion::Tls13),
        "SSLv3" | "TLSv1.0" | "TLSv1.1" => Err(ConfigError::new(
            t.line,
            t.col,
            format!("{prefix} : '{}' is not supported: rustls speaks TLS 1.2 and 1.3 only, so a client that needs it cannot be served.", t.text),
        )),
        other => Err(ConfigError::new(t.line, t.col, format!("{prefix} : '{other}' : unknown ssl/tls version"))),
    }
}

/// If `tokens[i]` is a version keyword, applies it to `range` and returns the index of its
/// last token; `Ok(None)` when it is not one. `prefix` names the line for the messages.
///
/// # Errors
/// A version that is unknown, one rustls does not speak, or a missing value.
pub(crate) fn version_keyword(range: &mut TlsRange, tokens: &[Token], i: usize, prefix: &str) -> Result<Option<usize>, ConfigError> {
    let kw = &tokens[i];
    let last = match kw.text.as_str() {
        "ssl-min-ver" | "ssl-max-ver" => {
            let Some(v) = tokens.get(i + 1).filter(|t| !t.text.is_empty()) else {
                return Err(ConfigError::new(kw.line, kw.col, format!("{prefix} : '{}' : missing the ssl/tls version", kw.text)));
            };
            let v = parse_version(v, prefix)?;
            if kw.text == "ssl-min-ver" {
                range.min = Some(v);
            } else {
                range.max = Some(v);
            }
            i + 1
        }
        "force-tlsv12" => {
            *range = TlsRange { min: Some(TlsVersion::Tls12), max: Some(TlsVersion::Tls12) };
            i
        }
        "force-tlsv13" => {
            *range = TlsRange { min: Some(TlsVersion::Tls13), max: Some(TlsVersion::Tls13) };
            i
        }
        "force-sslv3" | "force-tlsv10" | "force-tlsv11" => {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("{prefix} : '{}' is not supported: rustls speaks TLS 1.2 and 1.3 only, so a client that needs it cannot be served.", kw.text),
            ));
        }
        "no-tlsv12" => {
            range.min = Some(TlsVersion::Tls13);
            i
        }
        "no-tlsv13" => {
            range.max = Some(TlsVersion::Tls12);
            i
        }
        // rustls never offers these: what the keyword asks for is already the case.
        "no-sslv3" | "no-tlsv10" | "no-tlsv11" => i,
        _ => return Ok(None),
    };
    Ok(Some(last))
}

/// The version range of an `ssl-default-*-options` line; the other options are not
/// versions and are left to whoever reads the raw text.
///
/// # Errors
/// As [`version_keyword`], named after `keyword`.
pub(crate) fn default_options_range(tokens: &[Token], keyword: &str) -> Result<TlsRange, ConfigError> {
    let prefix = format!("'{keyword}'");
    let mut range = TlsRange::default();
    let mut i = 1;
    while i < tokens.len() {
        // `ssl-min-ver` and `ssl-max-ver` take a value; the other options take none, so an
        // unrecognised word is simply the next option.
        i = version_keyword(&mut range, tokens, i, &prefix)?.unwrap_or(i) + 1;
    }
    Ok(range)
}
