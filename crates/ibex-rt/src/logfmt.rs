// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/log.c and doc/configuration.txt section 8.2.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Log-format strings, evaluated through the sample engine.
//!
//! # Why this is not a separate expander
//!
//! `HAProxy`'s log-format is not a private mini-language. `%[...]` takes a **full sample
//! expression**, converters and all, so `%[req.hdr(Host),lower]` is valid in a log line
//! for exactly the same reason it is valid in an ACL. The single-letter aliases
//! (`%ci`, `%ST`, `%B`) are shorthand, not a parallel vocabulary.
//!
//! Ibex previously had a hardcoded expander that understood five aliases and no
//! expressions at all. That is the wrong shape twice over: it cannot express most real
//! log formats, and it means a fetch added for ACLs does not become available to logs.
//! Routing both through one [`Registry`] is what makes adding a fetch benefit every
//! consumer at once.
//!
//! # Compile once
//!
//! A format string is compiled to a [`LogFormat`] at config-parse time and rendered per
//! request. Parsing it per request would put string scanning and expression parsing on
//! the hot path for every logged transaction.

use ibex_sample::{Expr, Registry, SampleContext};

/// Per-request values that are not sample fetches -- timings and byte counters the
/// engine measures directly.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogVars {
    /// `%Tt` -- total time, milliseconds.
    pub total_ms: u64,
    /// `%Ta` -- active time of the request.
    pub active_ms: u64,
    /// `%Tr` -- response time.
    pub response_ms: u64,
    /// `%Tw` -- time spent in queues.
    pub queue_ms: u64,
    /// `%Tc` -- time to establish the backend connection.
    pub connect_ms: u64,
    /// `%B` -- bytes sent to the client.
    pub bytes_out: u64,
    /// `%U` -- bytes read from the client.
    pub bytes_in: u64,
    /// `%ST` -- response status.
    pub status: u16,
    /// `%ac` -- active connections on the process.
    pub act_conn: u32,
    /// `%rc` -- connection retries.
    pub retries: u16,
}

/// A single-letter log-format alias.
///
/// These map to values the engine holds directly. Anything reachable as a sample fetch
/// belongs in `%[...]` instead of here, so this list stays small rather than growing
/// into a second vocabulary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Alias {
    ClientIp,
    ClientPort,
    FrontendName,
    BackendName,
    ServerName,
    Status,
    BytesOut,
    BytesIn,
    TotalMs,
    ActiveMs,
    ResponseMs,
    QueueMs,
    ConnectMs,
    ActConn,
    Retries,
    Method,
    Path,
    Version,
}

#[derive(Clone, Debug)]
enum Segment {
    Literal(String),
    Alias(Alias),
    /// A `%[...]` sample expression, compiled once.
    Expr(Box<Expr>),
}

/// A compiled log-format string.
#[derive(Clone, Debug)]
pub struct LogFormat {
    segments: Vec<Segment>,
}

impl LogFormat {
    /// Compiles a format string.
    ///
    /// Longer aliases are matched before shorter ones, so `%ST` is not read as `%S`
    /// followed by a literal `T`.
    ///
    /// # Errors
    /// Returns a description if a `%[...]` expression is unterminated, does not parse,
    /// or names a fetch or converter the registry does not have.
    pub fn compile(fmt: &str) -> Result<Self, String> {
        Self::compile_checked(fmt, None)
    }

    /// Compiles and validates every expression against `registry`.
    ///
    /// An unknown fetch is a **config error**, as it is in `HAProxy`. Deferring it to
    /// evaluation would mean a typo in a log format silently produces `-` on every
    /// request instead of refusing the reload -- the kind of failure nobody notices
    /// until they need the logs.
    ///
    /// # Errors
    /// As [`Self::compile`], plus unknown fetch or converter names.
    pub fn compile_with_registry(fmt: &str, registry: &Registry) -> Result<Self, String> {
        Self::compile_checked(fmt, Some(registry))
    }

    fn compile_checked(fmt: &str, registry: Option<&Registry>) -> Result<Self, String> {
        let mut segments = Vec::new();
        let mut literal = String::new();
        let bytes = fmt.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] != b'%' {
                literal.push(fmt[i..].chars().next().unwrap_or('%'));
                i += fmt[i..].chars().next().map_or(1, char::len_utf8);
                continue;
            }

            let rest = &fmt[i..];

            if rest.starts_with("%%") {
                literal.push('%');
                i += 2;
                continue;
            }

            // %[<sample expression>] -- the general form.
            if let Some(inner) = rest.strip_prefix("%[") {
                let Some(end) = inner.find(']') else {
                    return Err(format!("unterminated %[ ... ] at offset {i}"));
                };
                let src = &inner[..end];
                let expr = Expr::parse(src)
                    .map_err(|e| format!("bad sample expression '{src}': {e}"))?;
                if let Some(reg) = registry {
                    if reg.get_fetch(&expr.fetch_name).is_none() {
                        return Err(format!(
                            "unknown sample fetch '{}' in log format",
                            expr.fetch_name
                        ));
                    }
                    for (cname, _) in &expr.converters {
                        if reg.get_converter(cname).is_none() {
                            return Err(format!("unknown converter '{cname}' in log format"));
                        }
                    }
                }
                if !literal.is_empty() {
                    segments.push(Segment::Literal(std::mem::take(&mut literal)));
                }
                segments.push(Segment::Expr(Box::new(expr)));
                i += 2 + end + 1;
                continue;
            }

            if let Some((alias, len)) = match_alias(rest) {
                if !literal.is_empty() {
                    segments.push(Segment::Literal(std::mem::take(&mut literal)));
                }
                segments.push(Segment::Alias(alias));
                i += len;
                continue;
            }

            // An unrecognised '%' is emitted verbatim rather than rejected: HAProxy
            // log formats are widely copy-pasted, and refusing to start over an alias
            // we have not implemented yet would be worse than logging it literally.
            literal.push('%');
            i += 1;
        }

        if !literal.is_empty() {
            segments.push(Segment::Literal(literal));
        }
        Ok(LogFormat { segments })
    }

    /// Renders the line.
    ///
    /// A field with no value becomes `-`, as `HAProxy` does. An empty string and a
    /// missing value are different things to a log parser, and collapsing them loses
    /// the distinction.
    #[must_use]
    pub fn render(
        &self,
        registry: &Registry,
        ctx: &SampleContext,
        vars: &LogVars,
        names: &LogNames,
    ) -> String {
        let mut out = String::with_capacity(160);
        for seg in &self.segments {
            match seg {
                Segment::Literal(s) => out.push_str(s),
                Segment::Alias(a) => out.push_str(&render_alias(*a, ctx, vars, names)),
                Segment::Expr(e) => match e.eval_sample(registry, ctx) {
                    Some(s) => out.push_str(&sample_to_log_string(&s)),
                    None => out.push('-'),
                },
            }
        }
        out
    }

    /// Number of compiled segments. Useful in tests to confirm a format actually
    /// parsed into expressions rather than collapsing to one literal.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }
}

/// Names the engine knows that are not sample fetches in this build.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogNames<'a> {
    pub frontend: Option<&'a str>,
    pub backend: Option<&'a str>,
    pub server: Option<&'a str>,
}

fn match_alias(rest: &str) -> Option<(Alias, usize)> {
    // Longer aliases are matched first: %ST must not be read as %S followed by 'T'.
    const TWO: [(&str, Alias); 10] = [
        ("%ci", Alias::ClientIp),
        ("%cp", Alias::ClientPort),
        ("%ft", Alias::FrontendName),
        ("%ST", Alias::Status),
        ("%Ta", Alias::ActiveMs),
        ("%Tr", Alias::ResponseMs),
        ("%Tw", Alias::QueueMs),
        ("%Tc", Alias::ConnectMs),
        ("%Tt", Alias::TotalMs),
        ("%ac", Alias::ActConn),
    ];
    const ONE: [(&str, Alias); 8] = [
        ("%f", Alias::FrontendName),
        ("%b", Alias::BackendName),
        ("%s", Alias::ServerName),
        ("%B", Alias::BytesOut),
        ("%U", Alias::BytesIn),
        ("%r", Alias::Path),
        ("%m", Alias::Method),
        ("%H", Alias::Version),
    ];

    if rest.starts_with("%rc") {
        return Some((Alias::Retries, 3));
    }
    for (pat, a) in TWO {
        if rest.starts_with(pat) {
            return Some((a, pat.len()));
        }
    }
    for (pat, a) in ONE {
        if rest.starts_with(pat) {
            return Some((a, pat.len()));
        }
    }
    None
}

fn render_alias(a: Alias, ctx: &SampleContext, v: &LogVars, n: &LogNames) -> String {
    let dash = || "-".to_string();
    match a {
        Alias::ClientIp => ctx.client_addr.map_or_else(dash, |s| s.ip().to_string()),
        Alias::ClientPort => ctx.client_addr.map_or_else(dash, |s| s.port().to_string()),
        Alias::FrontendName => n.frontend.map_or_else(dash, ToString::to_string),
        Alias::BackendName => n.backend.map_or_else(dash, ToString::to_string),
        Alias::ServerName => n.server.map_or_else(dash, ToString::to_string),
        Alias::Status => v.status.to_string(),
        Alias::BytesOut => v.bytes_out.to_string(),
        Alias::BytesIn => v.bytes_in.to_string(),
        Alias::TotalMs => v.total_ms.to_string(),
        Alias::ActiveMs => v.active_ms.to_string(),
        Alias::ResponseMs => v.response_ms.to_string(),
        Alias::QueueMs => v.queue_ms.to_string(),
        Alias::ConnectMs => v.connect_ms.to_string(),
        Alias::ActConn => v.act_conn.to_string(),
        Alias::Retries => v.retries.to_string(),
        Alias::Method => ctx.req_method.map_or_else(dash, ToString::to_string),
        Alias::Path => ctx.req_uri.map_or_else(dash, ToString::to_string),
        Alias::Version => "HTTP/1.1".to_string(),
    }
}

fn sample_to_log_string(s: &ibex_sample::Sample) -> String {
    use ibex_sample::Sample;
    match s {
        Sample::Str(v) => {
            if v.is_empty() {
                "-".to_string()
            } else {
                v.clone()
            }
        }
        Sample::Sint(v) => v.to_string(),
        Sample::Bool(v) => i32::from(*v).to_string(),
        Sample::Ipv4(v) => v.to_string(),
        Sample::Ipv6(v) => v.to_string(),
        Sample::Bin(v) => format!("{}", v.len()),
        Sample::Meth(v) => format!("{v:?}"),
    }
}
