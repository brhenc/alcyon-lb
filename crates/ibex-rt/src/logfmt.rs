// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/log.c (lf_expr_compile, parse_logformat_alias,
// sess_build_logline) and doc/configuration.txt section 8.2.4.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Log-format strings: `log-format`, `unique-id-format`, and `HAProxy`'s defaults.
//!
//! A format is compiled once, when the configuration loads, into text, aliases (`%ci`,
//! `%{+Q}r`, ...) and sample expressions (`%[req.hdr(host),lower]`, evaluated through
//! the same registry as ACLs), and rendered per transaction from a [`LogData`].
//!
//! Compiling follows `lf_expr_compile`: an alias is the longest run of letters and digits
//! after `%`, and must be one `HAProxy` knows (`no such format alias`); `%%` is a
//! literal `%`; `%{+Q,-X}` sets flags on the next alias or expression, and on everything
//! after it when given to `%o`. An alias or flag `HAProxy` has and Ibex does not render
//! is refused rather than printed wrongly.

use std::fmt::Write as _;
use std::net::SocketAddr;

use ibex_sample::{Expr, Registry, Sample, SampleContext};

use crate::localtime::Civil;

/// One transaction's (or TCP connection's) values, as the engine measured them. Times
/// are milliseconds from the accept, -1 when the event never happened, as in
/// `struct strm_logs`.
#[derive(Clone, Debug)]
pub struct LogData<'a> {
    pub client: Option<SocketAddr>,
    /// The address the client connected to.
    pub frontend_addr: Option<SocketAddr>,
    /// The server connection's destination.
    pub server_addr: Option<SocketAddr>,
    pub frontend: &'a str,
    /// The frontend accepted over TLS (`%ft` appends `~`).
    pub frontend_ssl: bool,
    /// The backend, or the frontend when none was chosen.
    pub backend: &'a str,
    /// HTTP-mode backend (`%Td` measures from the response).
    pub backend_http: bool,
    /// `None` prints `<NOSRV>`.
    pub server: Option<&'a str>,
    /// Accept date: unix seconds and milliseconds.
    pub accept_date: (i64, u32),
    pub t_handshake: i64,
    pub t_idle: i64,
    pub t_request: i64,
    pub t_queue: i64,
    pub t_connect: i64,
    pub t_data: i64,
    pub t_close: i64,
    /// HTTP status, -1 when there is none.
    pub status: i64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    /// `%ts`: two characters, the termination cause and the session state at its end.
    pub term_state: [u8; 2],
    /// `%tsc`'s last two characters: the persistence cookie's status.
    pub cookie_state: [u8; 2],
    pub actconn: u64,
    pub feconn: u64,
    pub beconn: u64,
    pub srvconn: u64,
    pub retries: i64,
    /// `%rc` is prefixed with `+` when the request was redispatched.
    pub redispatched: bool,
    pub srv_queue: u64,
    pub be_queue: u64,
    /// The stream counter (`%rt`).
    pub uniq_id: u64,
    pub log_counter: u64,
    pub pid: u32,
    pub hostname: &'a str,
    /// The request line as received; `None` prints `<BADREQ>`.
    pub request_line: Option<&'a str>,
    /// Header captures, one per configured slot; `None` when the frontend has none.
    pub req_captures: Option<&'a [Option<String>]>,
    pub res_captures: Option<&'a [Option<String>]>,
    pub unique_id: Option<&'a str>,
}

impl Default for LogData<'_> {
    fn default() -> Self {
        LogData {
            client: None,
            frontend_addr: None,
            server_addr: None,
            frontend: "",
            frontend_ssl: false,
            backend: "",
            backend_http: false,
            server: None,
            accept_date: (0, 0),
            t_handshake: 0,
            t_idle: -1,
            t_request: -1,
            t_queue: -1,
            t_connect: -1,
            t_data: -1,
            t_close: 0,
            status: -1,
            bytes_out: 0,
            bytes_in: 0,
            term_state: *b"--",
            cookie_state: *b"--",
            actconn: 0,
            feconn: 0,
            beconn: 0,
            srvconn: 0,
            retries: 0,
            redispatched: false,
            srv_queue: 0,
            be_queue: 0,
            uniq_id: 0,
            log_counter: 0,
            pid: 0,
            hostname: "",
            request_line: None,
            req_captures: None,
            res_captures: None,
            unique_id: None,
        }
    }
}

/// `HAProxy`'s `option httplog` format (`default_http_log_format`).
pub const DEFAULT_HTTP_LOG_FORMAT: &str = "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r";
/// `option tcplog` (`default_tcp_log_format`).
pub const DEFAULT_TCP_LOG_FORMAT: &str = "%ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq";
/// `option httplog clf` (`clf_http_log_format`).
pub const CLF_HTTP_LOG_FORMAT: &str = "%{+Q}o %{-Q}ci - - [%trg] %r %ST %B \"\" \"\" %cp %ms %ft %b %s %TR %Tw %Tc %Tr %Ta %tsc %ac %fc %bc %sc %rc %sq %bq %CC %CS %hrl %hsl";
/// `option tcplog clf` (`clf_tcp_log_format`).
pub const CLF_TCP_LOG_FORMAT: &str = "%{+Q}o %{-Q}ci - - [%T] \"TCP \" 000 %B \"\" \"\" %cp %ms %ft %b %s %Th %Tw %Tc %Tt %U %ts-- %ac %fc %bc %sc %rc %sq %bq \"\" \"\" ";

/// The format string a proxy's `log-format` or `option httplog`/`tcplog` stands for.
/// `option httplog` on a TCP-mode proxy falls back to `tcplog`, as `HAProxy` does ("not
/// usable with frontend ... Falling back to 'option tcplog'").
#[must_use]
pub fn format_string(spec: &ibex_config::LogFormatSpec, mode_http: bool) -> &str {
    use ibex_config::LogFormatSpec;
    match spec {
        LogFormatSpec::Custom(s) => s,
        LogFormatSpec::Http { clf: false } if mode_http => DEFAULT_HTTP_LOG_FORMAT,
        LogFormatSpec::Http { clf: true } if mode_http => CLF_HTTP_LOG_FORMAT,
        LogFormatSpec::Http { clf } | LogFormatSpec::Tcp { clf } => {
            if *clf {
                CLF_TCP_LOG_FORMAT
            } else {
                DEFAULT_TCP_LOG_FORMAT
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Opts {
    quote: bool,
    hex: bool,
    /// `LOG_OPT_MANDATORY` (`+M`): an empty or absent value prints `-`.
    mandatory: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alias {
    Bytes,
    CookieClient,
    CookieServer,
    Hostname,
    UniqueId,
    Status,
    DateGmt,
    TActive,
    TConnect,
    THandshake,
    TIdle,
    DateLocal,
    TRequestTotal,
    TResponse,
    TRequest,
    TData,
    Timestamp,
    TTotal,
    TUser,
    TQueue,
    BytesUp,
    ActConn,
    Backend,
    BeConn,
    BeQueue,
    ClientIp,
    ClientPort,
    Frontend,
    FeConn,
    FrontendIp,
    FrontendPort,
    FrontendXprt,
    HdrReq,
    HdrReqList,
    HdrRes,
    HdrResList,
    HttpMethod,
    HttpPath,
    HttpPathOnly,
    HttpQuery,
    HttpUri,
    HttpVersion,
    LogCount,
    Ms,
    Pid,
    Req,
    Retries,
    Counter,
    Server,
    SrvConn,
    ServerIp,
    ServerPort,
    SrvQueue,
    Date,
    ReqDate,
    ReqDateGmt,
    ReqDateLocal,
    TermState,
    TermStateCk,
}

/// `logformat_aliases` (src/log.c): name, and what Ibex renders for it (`None`: an alias
/// `HAProxy` has that Ibex refuses). `%o` is not here: it renders nothing and sets the
/// options for what follows, so `compile` handles it before looking a name up.
const ALIASES: &[(&str, Option<Alias>)] = &[
    ("OG", None),
    ("B", Some(Alias::Bytes)),
    ("CC", Some(Alias::CookieClient)),
    ("CS", Some(Alias::CookieServer)),
    ("H", Some(Alias::Hostname)),
    ("ID", Some(Alias::UniqueId)),
    ("ST", Some(Alias::Status)),
    ("T", Some(Alias::DateGmt)),
    ("Ta", Some(Alias::TActive)),
    ("Tc", Some(Alias::TConnect)),
    ("Th", Some(Alias::THandshake)),
    ("Ti", Some(Alias::TIdle)),
    ("Tl", Some(Alias::DateLocal)),
    ("Tq", Some(Alias::TRequestTotal)),
    ("Tr", Some(Alias::TResponse)),
    ("TR", Some(Alias::TRequest)),
    ("Td", Some(Alias::TData)),
    ("Ts", Some(Alias::Timestamp)),
    ("Tt", Some(Alias::TTotal)),
    ("Tu", Some(Alias::TUser)),
    ("Tw", Some(Alias::TQueue)),
    ("U", Some(Alias::BytesUp)),
    ("ac", Some(Alias::ActConn)),
    ("b", Some(Alias::Backend)),
    ("bc", Some(Alias::BeConn)),
    ("bi", None),
    ("bp", None),
    ("bq", Some(Alias::BeQueue)),
    ("ci", Some(Alias::ClientIp)),
    ("cp", Some(Alias::ClientPort)),
    ("f", Some(Alias::Frontend)),
    ("fc", Some(Alias::FeConn)),
    ("fi", Some(Alias::FrontendIp)),
    ("fp", Some(Alias::FrontendPort)),
    ("ft", Some(Alias::FrontendXprt)),
    ("hr", Some(Alias::HdrReq)),
    ("hrl", Some(Alias::HdrReqList)),
    ("hs", Some(Alias::HdrRes)),
    ("hsl", Some(Alias::HdrResList)),
    ("HM", Some(Alias::HttpMethod)),
    ("HP", Some(Alias::HttpPath)),
    ("HPO", Some(Alias::HttpPathOnly)),
    ("HQ", Some(Alias::HttpQuery)),
    ("HU", Some(Alias::HttpUri)),
    ("HV", Some(Alias::HttpVersion)),
    ("lc", Some(Alias::LogCount)),
    ("ms", Some(Alias::Ms)),
    ("pid", Some(Alias::Pid)),
    ("r", Some(Alias::Req)),
    ("rc", Some(Alias::Retries)),
    ("rt", Some(Alias::Counter)),
    ("s", Some(Alias::Server)),
    ("sc", Some(Alias::SrvConn)),
    ("si", Some(Alias::ServerIp)),
    ("sp", Some(Alias::ServerPort)),
    ("sq", Some(Alias::SrvQueue)),
    ("sslc", None),
    ("sslv", None),
    ("t", Some(Alias::Date)),
    ("tr", Some(Alias::ReqDate)),
    ("trg", Some(Alias::ReqDateGmt)),
    ("trl", Some(Alias::ReqDateLocal)),
    ("ts", Some(Alias::TermState)),
    ("tsc", Some(Alias::TermStateCk)),
];

#[derive(Clone, Debug)]
enum Node {
    Text(String),
    Alias(Alias, Opts),
    Expr(Box<Expr>, Opts),
}

/// A compiled log-format string.
#[derive(Clone, Debug)]
pub struct LogFormat {
    nodes: Vec<Node>,
}

/// Applies `%{+Q,-X,...}` to `opts` (`parse_logformat_node_args`). Unknown names are
/// ignored, as `HAProxy` ignores them; flags it has that Ibex does not render are refused.
fn apply_flags(arg: &str, opts: Opts) -> Result<Opts, String> {
    let mut signed = arg.split(',').filter_map(|item| match item.as_bytes().first() {
        Some(b'+') => Some((true, &item[1..])),
        Some(b'-') => Some((false, &item[1..])),
        _ => None,
    });
    signed.try_fold(opts, |mut opts, (add, name)| {
        if name == "Q" {
            opts.quote = add;
        } else if name == "X" {
            opts.hex = add;
        } else if name == "M" {
            opts.mandatory = add;
        } else if add && matches!(name, "E" | "bin" | "utf8" | "json" | "cbor") {
            return Err(format!("log-format option '+{name}' is not implemented"));
        }
        Ok(opts)
    })
}

impl LogFormat {
    /// Compiles `fmt`, checking every expression's fetch and converters against
    /// `registry`.
    ///
    /// # Errors
    /// `HAProxy`'s refusals (`no such format alias`, a truncated `%[` or `%{`, a `%` before
    /// a digit or blank, an unknown fetch or converter) and the aliases and options Ibex
    /// does not render.
    pub fn compile(fmt: &str, registry: &Registry) -> Result<Self, String> {
        Self::compile_with(fmt, registry, true)
    }

    /// Compiles a `unique-id-format`: like [`LogFormat::compile`], but an absent value
    /// prints nothing rather than `-` (`HAProxy` compiles it without `LOG_OPT_MANDATORY`).
    ///
    /// # Errors
    /// As [`LogFormat::compile`].
    pub fn compile_unique_id(fmt: &str, registry: &Registry) -> Result<Self, String> {
        Self::compile_with(fmt, registry, false)
    }

    fn compile_with(fmt: &str, registry: &Registry, mandatory: bool) -> Result<Self, String> {
        let b = fmt.as_bytes();
        let mut nodes = Vec::new();
        let mut text = String::new();
        let mut defaults = Opts { mandatory, ..Opts::default() };
        let mut i = 0;
        while i < b.len() {
            if b[i] != b'%' {
                let ch = fmt[i..].chars().next().unwrap_or('%');
                text.push(ch);
                i += ch.len_utf8();
                continue;
            }
            i += 1;
            let mut opts = defaults;
            match b.get(i) {
                None => return Err("truncated line after '%'".to_string()),
                Some(b'%') => {
                    text.push('%');
                    i += 1;
                    continue;
                }
                Some(b'(') => return Err("named log-format fields ('%(name)') are not implemented".to_string()),
                Some(c) if c.is_ascii_digit() || *c == b' ' || *c == b'\t' => {
                    return Err(format!(
                        "unexpected alias name near '{}' at position {i} line : '{fmt}'. Maybe you want to write a single '%', use the syntax '%%'",
                        char::from(*c)
                    ));
                }
                Some(b'{') => {
                    let end = fmt[i..].find('}').ok_or_else(|| format!("truncated line after '{}'", &fmt[i + 1..]))?;
                    let arg = &fmt[i + 1..i + end];
                    opts = apply_flags(arg, opts)?;
                    i += end + 1;
                    if !b.get(i).is_some_and(|c| *c == b'[' || c.is_ascii_alphanumeric()) {
                        return Err(format!("parse argument modifier without alias name near '%{{{arg}}}'"));
                    }
                }
                Some(_) => {}
            }
            if b.get(i) == Some(&b'[') {
                let end = find_expr_end(&fmt[i + 1..]).ok_or_else(|| format!("missing ']' after '{}'", &fmt[i + 1..]))?;
                let src = &fmt[i + 1..i + 1 + end];
                let expr = Expr::parse(src).map_err(|e| format!("failed to parse sample expression <{src}> : {e}"))?;
                if registry.get_fetch(&expr.fetch_name).is_none() {
                    return Err(format!("failed to parse sample expression <{src}> : unknown fetch method '{}'", expr.fetch_name));
                }
                if let Some((c, _)) = expr.converters.iter().find(|(c, _)| !registry.has_converter(c)) {
                    return Err(format!("failed to parse sample expression <{src}> : unknown converter '{c}'"));
                }
                flush(&mut text, &mut nodes);
                nodes.push(Node::Expr(Box::new(expr), opts));
                i += end + 2;
                continue;
            }
            let start = i;
            while b.get(i).is_some_and(u8::is_ascii_alphanumeric) {
                i += 1;
            }
            let name = &fmt[start..i];
            if name.is_empty() {
                // `%` before anything but an alias name (a blank or a digit was refused
                // above) is dropped, and the character is text (LF_INIT).
                continue;
            }
            if name == "o" {
                defaults = opts;
                continue;
            }
            match ALIASES.iter().find(|(n, _)| *n == name) {
                None => {
                    return Err(format!(
                        "no such format alias '{name}'. If you wanted to emit the '%' character verbatim, you need to use '%%'"
                    ));
                }
                Some((_, None)) => return Err(format!("log-format alias '%{name}' is not implemented")),
                Some((_, Some(a))) => {
                    flush(&mut text, &mut nodes);
                    nodes.push(Node::Alias(*a, opts));
                }
            }
        }
        flush(&mut text, &mut nodes);
        Ok(LogFormat { nodes })
    }

    /// Whether the format reads the request line (`%r`, `%HM`, `%HU`, ...): `HAProxy`
    /// keeps a copy of it (`txn->uri`) only for a frontend that logs it.
    #[must_use]
    pub fn uses_request_line(&self) -> bool {
        self.nodes.iter().any(|n| {
            matches!(
                n,
                Node::Alias(
                    Alias::Req
                        | Alias::HttpMethod
                        | Alias::HttpUri
                        | Alias::HttpPath
                        | Alias::HttpPathOnly
                        | Alias::HttpVersion
                        | Alias::HttpQuery,
                    _
                )
            )
        })
    }

    /// Renders the line (`sess_build_logline`).
    #[must_use]
    pub fn render(&self, d: &LogData, registry: &Registry, ctx: &SampleContext) -> String {
        let mut out = String::with_capacity(160);
        for n in &self.nodes {
            match n {
                Node::Text(t) => out.push_str(t),
                Node::Alias(a, o) => alias(&mut out, *a, *o, d),
                Node::Expr(e, o) => match e.eval_sample(registry, ctx) {
                    Some(s) => sample(&mut out, &s, *o),
                    None if o.quote => out.push_str("\"\""),
                    None if o.mandatory => out.push('-'),
                    None => {}
                },
            }
        }
        out
    }

    /// Renders the format outside a log line, where an expression that yields nothing, or
    /// an empty string, writes nothing rather than `-`: what `HAProxy` sends for an
    /// `http-check send hdr x %[str()]` (no header at all, 3.5-dev8-885761-29, 2026-10-03).
    #[must_use]
    pub fn render_value(&self, d: &LogData, registry: &Registry, ctx: &SampleContext) -> String {
        let mut out = String::new();
        for n in &self.nodes {
            match n {
                Node::Text(t) => out.push_str(t),
                Node::Alias(a, o) => alias(&mut out, *a, *o, d),
                Node::Expr(e, o) => match e.eval_sample(registry, ctx) {
                    Some(Sample::Str(v)) if v.is_empty() && !o.quote => {}
                    Some(Sample::Bin(v)) if v.is_empty() && !o.quote => {}
                    Some(s) => sample(&mut out, &s, *o),
                    None if o.quote => out.push_str("\"\""),
                    None => {}
                },
            }
        }
        out
    }
}

fn flush(text: &mut String, nodes: &mut Vec<Node>) {
    if !text.is_empty() {
        nodes.push(Node::Text(std::mem::take(text)));
    }
}

/// The `]` closing `%[`, skipping brackets and quotes inside the expression.
fn find_expr_end(s: &str) -> Option<usize> {
    let (mut depth, mut quote) = (0usize, None);
    for (i, c) in s.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '(') => depth += 1,
            (None, ')') => depth = depth.saturating_sub(1),
            (None, ']') if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

/// `hdr_encode_map`: control characters, DEL and above, and `"#{|}`, as `#XX`.
fn hdr_escaped(b: u8) -> bool {
    b < 32 || b >= 127 || b"\"#{|}".contains(&b)
}

/// `url_encode_map`: control characters, DEL and above, and `"#`, as `#XX`.
fn url_escaped(b: u8) -> bool {
    b < 32 || b >= 127 || b"\"#".contains(&b)
}

/// `lf_encode_string`: `s`, with every byte `escaped` selects written `#XX`, quoted if
/// asked.
fn encoded(out: &mut String, s: &str, escaped: fn(u8) -> bool, o: Opts) {
    if o.quote {
        out.push('"');
    }
    for &c in s.as_bytes() {
        if escaped(c) {
            let _ = write!(out, "#{c:02X}");
        } else {
            out.push(char::from(c));
        }
    }
    if o.quote {
        out.push('"');
    }
}

/// `lf_text`: text, quoted if asked; nothing for none.
fn text(out: &mut String, s: Option<&str>, o: Opts) {
    if o.quote {
        out.push('"');
        out.push_str(s.unwrap_or(""));
        out.push('"');
    } else {
        out.push_str(s.unwrap_or(""));
    }
}

fn ip(out: &mut String, a: Option<SocketAddr>, o: Opts) {
    match a {
        None => out.push('-'),
        Some(SocketAddr::V4(v)) if o.hex => {
            for b in v.ip().octets() {
                let _ = write!(out, "{b:02X}");
            }
        }
        Some(SocketAddr::V6(v)) if o.hex => {
            for b in v.ip().octets() {
                let _ = write!(out, "{b:02X}");
            }
        }
        Some(a) => {
            let _ = write!(out, "{}", a.ip());
        }
    }
}

fn port(out: &mut String, a: Option<SocketAddr>, o: Opts) {
    match a {
        None => out.push('-'),
        Some(a) if o.hex => {
            let _ = write!(out, "{:04X}", a.port());
        }
        Some(a) => {
            let _ = write!(out, "{}", a.port());
        }
    }
}

/// `date2str_log`: `03/Oct/2026:16:48:18.622`.
fn date_ms(out: &mut String, unix: i64, ms: u32) {
    let c = Civil::local(unix);
    let _ = write!(out, "{:02}/{}/{:04}:{:02}:{:02}:{:02}.{ms:03}", c.day, c.month_name(), c.year, c.hour, c.minute, c.second);
}

/// `gmt2str_log` / `localdate2str_log`: `03/Oct/2026:14:48:18 +0000`.
fn date_zone(out: &mut String, c: Civil) {
    let _ = write!(
        out,
        "{:02}/{}/{:04}:{:02}:{:02}:{:02} {}",
        c.day,
        c.month_name(),
        c.year,
        c.hour,
        c.minute,
        c.second,
        c.offset_hhmm()
    );
}

/// The request line's method, target and version, split at blanks as the `%HM`..`%HV`
/// cases of `sess_build_logline` split it; `None` when there is no blank after the
/// method, which they all print as `<BADREQ>`.
fn line_parts(line: &str) -> Option<(&str, &str, &str)> {
    let blank = [' ', '\t'];
    let sp = line.find(blank)?;
    let rest = line[sp..].trim_start_matches(blank);
    let (target, version) = rest.split_once(blank).unwrap_or((rest, ""));
    let version = version.trim_start_matches(blank);
    Some((&line[..sp], target, version.split(blank).next().unwrap_or("")))
}

/// `http_parse_path`: an absolute target's path, from its first `/` after the
/// authority; an origin-form target as it is; nothing for `*` or an authority.
fn path_only(target: &str) -> &str {
    if target.starts_with('/') {
        return target;
    }
    match target.split_once("://") {
        Some((_, rest)) => rest.find('/').map_or("", |p| &rest[p..]),
        None => "",
    }
}

#[allow(clippy::too_many_lines)]
fn alias(out: &mut String, a: Alias, o: Opts, d: &LogData) {
    let int = |out: &mut String, v: i64| {
        let _ = write!(out, "{v}");
    };
    let t_request = d.t_request;
    let badreq = || "<BADREQ>".to_string();
    match a {
        Alias::Bytes => int(out, i64::try_from(d.bytes_out).unwrap_or(i64::MAX)),
        Alias::BytesUp => int(out, i64::try_from(d.bytes_in).unwrap_or(i64::MAX)),
        // Ibex has no `capture cookie`, so there is never a cookie to show.
        Alias::CookieClient | Alias::CookieServer => text(out, Some("-"), o),
        Alias::Hostname => text(out, Some(d.hostname), o),
        Alias::UniqueId => text(out, Some(d.unique_id.unwrap_or("-")), o),
        Alias::Status => int(out, d.status),
        Alias::DateGmt => date_zone(out, Civil::at(d.accept_date.0, 0)),
        Alias::DateLocal => date_zone(out, Civil::local(d.accept_date.0)),
        Alias::THandshake => int(out, d.t_handshake),
        Alias::TIdle => int(out, d.t_idle),
        Alias::TRequestTotal => int(out, t_request),
        Alias::TRequest => int(out, if t_request >= 0 { t_request - d.t_idle - d.t_handshake } else { -1 }),
        Alias::TQueue => int(out, if d.t_queue >= 0 { d.t_queue - t_request } else { -1 }),
        Alias::TConnect => int(out, if d.t_connect >= 0 { d.t_connect - d.t_queue } else { -1 }),
        Alias::TResponse => int(out, if d.t_data >= 0 { d.t_data - d.t_connect } else { -1 }),
        Alias::TData => {
            let from = if d.backend_http { d.t_data } else { d.t_connect };
            int(out, if from >= 0 { d.t_close - from } else { -1 });
        }
        Alias::TActive => int(out, d.t_close - if d.t_idle >= 0 { d.t_idle + d.t_handshake } else { 0 }),
        Alias::TTotal => int(out, d.t_close),
        Alias::TUser => int(out, d.t_close - d.t_idle.max(0)),
        Alias::Timestamp => {
            if o.hex {
                let _ = write!(out, "{:04X}", d.accept_date.0);
            } else {
                int(out, d.accept_date.0);
            }
        }
        Alias::Ms => {
            if o.hex {
                let _ = write!(out, "{:02X}", d.accept_date.1);
            } else {
                let _ = write!(out, "{:03}", d.accept_date.1);
            }
        }
        Alias::Date => date_ms(out, d.accept_date.0, d.accept_date.1),
        Alias::ReqDate | Alias::ReqDateGmt | Alias::ReqDateLocal => {
            let add = if d.t_idle >= 0 { d.t_idle + d.t_handshake } else { 0 };
            let total_ms = d.accept_date.0 * 1000 + i64::from(d.accept_date.1) + add;
            let (secs, ms) = (total_ms.div_euclid(1000), u32::try_from(total_ms.rem_euclid(1000)).unwrap_or(0));
            match a {
                Alias::ReqDate => date_ms(out, secs, ms),
                Alias::ReqDateGmt => date_zone(out, Civil::at(secs, 0)),
                _ => date_zone(out, Civil::local(secs)),
            }
        }
        Alias::ActConn => int(out, i64::try_from(d.actconn).unwrap_or(0)),
        Alias::FeConn => int(out, i64::try_from(d.feconn).unwrap_or(0)),
        Alias::BeConn => int(out, i64::try_from(d.beconn).unwrap_or(0)),
        Alias::SrvConn => int(out, i64::try_from(d.srvconn).unwrap_or(0)),
        Alias::SrvQueue => int(out, i64::try_from(d.srv_queue).unwrap_or(0)),
        Alias::BeQueue => int(out, i64::try_from(d.be_queue).unwrap_or(0)),
        Alias::Retries => {
            if d.redispatched {
                out.push('+');
            }
            int(out, d.retries);
        }
        Alias::Counter => {
            if o.hex {
                let _ = write!(out, "{:04X}", d.uniq_id);
            } else {
                let _ = write!(out, "{}", d.uniq_id);
            }
        }
        Alias::LogCount => {
            let _ = write!(out, "{}", d.log_counter);
        }
        Alias::Pid => {
            if o.hex {
                let _ = write!(out, "{:04X}", d.pid);
            } else {
                let _ = write!(out, "{}", d.pid);
            }
        }
        Alias::Backend => text(out, Some(d.backend), o),
        Alias::Frontend => text(out, Some(d.frontend), o),
        Alias::FrontendXprt => {
            let name = if d.frontend_ssl { format!("{}~", d.frontend) } else { d.frontend.to_string() };
            text(out, Some(&name), o);
        }
        Alias::Server => text(out, Some(d.server.unwrap_or("<NOSRV>")), o),
        Alias::ClientIp => ip(out, d.client, o),
        Alias::ClientPort => port(out, d.client, o),
        Alias::FrontendIp => ip(out, d.frontend_addr, o),
        Alias::FrontendPort => port(out, d.frontend_addr, o),
        Alias::ServerIp => ip(out, d.server_addr, o),
        Alias::ServerPort => port(out, d.server_addr, o),
        Alias::TermState => {
            out.push(char::from(d.term_state[0]));
            out.push(char::from(d.term_state[1]));
        }
        Alias::TermStateCk => {
            for c in d.term_state.iter().chain(&d.cookie_state) {
                out.push(char::from(*c));
            }
        }
        Alias::HdrReq | Alias::HdrRes => {
            let caps = if a == Alias::HdrReq { d.req_captures } else { d.res_captures };
            if let Some(caps) = caps.filter(|c| !c.is_empty()) {
                out.push('{');
                for (n, c) in caps.iter().enumerate() {
                    if n > 0 {
                        out.push('|');
                    }
                    if let Some(c) = c {
                        encoded(out, c, hdr_escaped, Opts { quote: false, ..o });
                    }
                }
                out.push('}');
            }
        }
        Alias::HdrReqList | Alias::HdrResList => {
            let caps = if a == Alias::HdrReqList { d.req_captures } else { d.res_captures };
            if let Some(caps) = caps.filter(|c| !c.is_empty()) {
                for (n, c) in caps.iter().enumerate() {
                    if n > 0 {
                        out.push(' ');
                    }
                    match c {
                        Some(c) => encoded(out, c, hdr_escaped, o),
                        None if o.quote => out.push_str("\"\""),
                        None => out.push('-'),
                    }
                }
            }
        }
        Alias::Req => encoded(out, d.request_line.unwrap_or("<BADREQ>"), url_escaped, o),
        Alias::HttpMethod | Alias::HttpUri | Alias::HttpPath | Alias::HttpPathOnly | Alias::HttpVersion => {
            let value = match d.request_line.and_then(line_parts) {
                None => badreq(),
                Some((m, t, v)) => match a {
                    Alias::HttpMethod => m.to_string(),
                    Alias::HttpUri => t.to_string(),
                    Alias::HttpPath => t.split('?').next().unwrap_or("").to_string(),
                    Alias::HttpPathOnly => path_only(t).split('?').next().unwrap_or("").to_string(),
                    _ => v.to_string(),
                },
            };
            encoded(out, &value, url_escaped, o);
        }
        Alias::HttpQuery => {
            let value = match d.request_line {
                None => badreq(),
                Some(line) => {
                    let q = line.find('?').map_or("", |p| &line[p..]);
                    q.split([' ', '\t']).next().unwrap_or("").to_string()
                }
            };
            encoded(out, &value, url_escaped, o);
        }
    }
}

/// A sample's text in a log line (`lf_text`/`lf_int`): strings quoted if asked, an empty
/// string as `-` (or `""` quoted), binary as its bytes.
fn sample(out: &mut String, s: &Sample, o: Opts) {
    match s {
        Sample::Str(v) if v.is_empty() && !o.quote => {
            if o.mandatory {
                out.push('-');
            }
        }
        Sample::Str(v) => text(out, Some(v), o),
        Sample::Bin(v) if v.is_empty() && !o.quote => {
            if o.mandatory {
                out.push('-');
            }
        }
        Sample::Bin(v) => text(out, Some(&String::from_utf8_lossy(v)), o),
        Sample::Sint(v) => {
            let _ = write!(out, "{v}");
        }
        Sample::Bool(v) => {
            let _ = write!(out, "{}", i32::from(*v));
        }
        Sample::Ipv4(v) => {
            let _ = write!(out, "{v}");
        }
        Sample::Ipv6(v) => {
            let _ = write!(out, "{v}");
        }
        Sample::Meth(v) => text(out, Some(v.as_str()), o),
    }
}
