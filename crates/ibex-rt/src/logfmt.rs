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
    /// The client connection's TLS cipher and protocol (`%sslc`, `%sslv`).
    pub ssl_cipher: Option<&'a str>,
    pub ssl_version: Option<&'a str>,
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
    /// `option logasap`: `%B`, `%Tt`, `%Ta` and `%Tu` are what the stream had reached when
    /// the line was written, which `HAProxy` marks with a leading `+`.
    pub plus: bool,
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
    pub req_captures: Option<&'a [Option<Vec<u8>>]>,
    pub res_captures: Option<&'a [Option<Vec<u8>>]>,
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
            ssl_cipher: None,
            ssl_version: None,
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
            plus: false,
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
/// `option httpslog` (`default_https_log_format`).
pub const DEFAULT_HTTPS_LOG_FORMAT: &str = "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r %[fc_err]/%[ssl_fc_err,hex]/%[ssl_c_err]/%[ssl_c_ca_err]/%[ssl_fc_is_resumed] %[ssl_fc_sni]/%sslv/%sslc";
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
        LogFormatSpec::Https if mode_http => DEFAULT_HTTPS_LOG_FORMAT,
        LogFormatSpec::Https => DEFAULT_TCP_LOG_FORMAT,
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
    /// `+E`: `"`, `\` and `]` get a backslash (`rfc5424_escape_map`).
    esc: bool,
    /// `+json`, `+cbor`: the value is encoded; given to `%o`, the whole line is.
    json: bool,
    cbor: bool,
    /// `+bin`: CBOR as raw bytes instead of hex text.
    bin: bool,
    /// `+utf8`: valid UTF-8 passes through a JSON string.
    utf8: bool,
}

impl Opts {
    const fn encoded(self) -> bool {
        self.json || self.cbor
    }
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
    SslCipher,
    SslVersion,
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
    ("sslc", Some(Alias::SslCipher)),
    ("sslv", Some(Alias::SslVersion)),
    ("t", Some(Alias::Date)),
    ("tr", Some(Alias::ReqDate)),
    ("trg", Some(Alias::ReqDateGmt)),
    ("trl", Some(Alias::ReqDateLocal)),
    ("ts", Some(Alias::TermState)),
    ("tsc", Some(Alias::TermStateCk)),
];

/// What `%(name:type)` asks of an expression's value when the line is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum Cast {
    #[default]
    Same,
    Str,
    Sint,
    Bool,
}

/// `%(name:type)`: the key an encoded line (`%{+json}o`, `%{+cbor}o`) gives the value, and the
/// type it is forced to. Without `%o` an encoded line has no keys and the name is unused.
#[derive(Clone, Debug, Default)]
struct Named {
    name: Option<Box<str>>,
    cast: Cast,
}

#[derive(Clone, Debug)]
enum Node {
    Text(String),
    /// Boxed: a node with no `%(name)` is most of them, and a proxy holds a few dozen.
    Alias(Alias, Opts, Option<Box<Named>>),
    Expr(Box<Expr>, Opts, Option<Box<Named>>),
}

/// A compiled log-format string.
#[derive(Clone, Debug)]
pub struct LogFormat {
    /// A boxed slice: every proxy holds two of these.
    nodes: Box<[Node]>,
    /// The options `%o` gave, for the whole line: whether it is a JSON object or a CBOR map.
    global: Opts,
    /// `LOG_OPT_HTTP`: the value goes into an HTTP header, so each sample has the bytes of
    /// `http_encode_map` written `%XX` (`lf_encode_chunk`).
    http: bool,
}

/// Applies `%{+Q,-X,...}` to `opts` (`parse_logformat_node_args`). Unknown names are
/// ignored, as `HAProxy` ignores them.
fn apply_flags(arg: &str, opts: Opts) -> Opts {
    let signed = arg.split(',').filter_map(|item| match item.as_bytes().first() {
        Some(b'+') => Some((true, &item[1..])),
        Some(b'-') => Some((false, &item[1..])),
        _ => None,
    });
    signed.fold(opts, |mut opts, (add, name)| {
        match name {
            "Q" => opts.quote = add,
            "X" => opts.hex = add,
            "M" => opts.mandatory = add,
            "E" => opts.esc = add,
            "json" => opts.json = add,
            "cbor" => opts.cbor = add,
            "bin" => opts.bin = add,
            "utf8" => opts.utf8 = add,
            _ => {}
        }
        opts
    })
}

/// `lf_expr_postcheck_node_opt`: a node's encoding is the line's when the line has one, `bin`
/// is only ever the line's, and an encoded value takes no `+E`.
fn settle(mut node: Opts, global: Opts) -> Opts {
    if global.encoded() {
        node.json = global.json;
        node.cbor = global.cbor;
    }
    node.bin = global.bin;
    if node.encoded() {
        node.esc = false;
    }
    node
}

/// The aliases whose value is a number: an encoded line carries them as one.
const NUMERIC: &[Alias] = &[
    Alias::Bytes,
    Alias::BytesUp,
    Alias::Status,
    Alias::TActive,
    Alias::TConnect,
    Alias::THandshake,
    Alias::TIdle,
    Alias::TRequestTotal,
    Alias::TResponse,
    Alias::TRequest,
    Alias::TData,
    Alias::Timestamp,
    Alias::Ms,
    Alias::Retries,
    Alias::TTotal,
    Alias::TUser,
    Alias::TQueue,
    Alias::ActConn,
    Alias::BeConn,
    Alias::BeQueue,
    Alias::ClientPort,
    Alias::FeConn,
    Alias::FrontendPort,
    Alias::LogCount,
    Alias::Pid,
    Alias::Counter,
    Alias::SrvConn,
    Alias::ServerPort,
    Alias::SrvQueue,
];

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
    /// prints nothing rather than `-` (`HAProxy` compiles it without `LOG_OPT_MANDATORY`),
    /// and a sample has the bytes of `http_encode_map` written `%XX`, since the id may go
    /// into a header (`LOG_OPT_HTTP`, `proxy_finalize`).
    ///
    /// # Errors
    /// As [`LogFormat::compile`].
    pub fn compile_unique_id(fmt: &str, registry: &Registry) -> Result<Self, String> {
        Self::compile_with(fmt, registry, false).map(|f| LogFormat { http: true, ..f })
    }

    /// `%(name[:type])`, at `i` (the `(`): the name and cast, and where they end.
    fn parse_name(fmt: &str, i: usize) -> Result<(Named, usize), String> {
        let rest = &fmt[i + 1..];
        let Some(close) = rest.find(')') else {
            return Err(format!("truncated line after '{}'", &fmt[i..]));
        };
        let inner = &rest[..close];
        let (name, ty) = inner.split_once(':').map_or((inner, None), |(n, t)| (n, Some(t)));
        if let Some(c) = name.chars().find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))) {
            return Err(format!(
                "invalid character in custom name near '{c}' at position {} line : '{fmt}'",
                i + 1 + name.find(c).unwrap_or(0)
            ));
        }
        let cast = match ty {
            None => Cast::Same,
            Some("str") => Cast::Str,
            Some("sint") => Cast::Sint,
            Some("bool") => Cast::Bool,
            Some("raw") => return Err("log-format output type 'raw' is not implemented".to_string()),
            Some(t) => {
                return Err(format!(
                    "unexpected output type '{t}' at position {} line : '{fmt}'. Supported types are: str, sint, bool, raw",
                    i + 2 + name.len()
                ));
            }
        };
        Ok((Named { name: Some(name.into()), cast }, i + close + 2))
    }

    fn compile_with(fmt: &str, registry: &Registry, mandatory: bool) -> Result<Self, String> {
        let b = fmt.as_bytes();
        let mut nodes = Vec::new();
        let mut text = String::new();
        let mut defaults = Opts { mandatory, ..Opts::default() };
        let mut global = defaults;
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
            let mut named = Named::default();
            if b.get(i) == Some(&b'(') {
                (named, i) = Self::parse_name(fmt, i)?;
                // After a name: an argument, an expression or an alias. A `%` is a literal one, a
                // blank or a digit is refused, and any other character is text, the name
                // dropped (`LF_EDONAME`).
                match b.get(i) {
                    None => return Err(format!("truncated line after '%({})'", named.name.as_deref().unwrap_or(""))),
                    Some(b'%') => {
                        text.push('%');
                        i += 1;
                        continue;
                    }
                    Some(c) if c.is_ascii_digit() || *c == b' ' || *c == b'\t' => {
                        return Err(format!(
                            "unexpected alias name near '{}' at position {i} line : '{fmt}'. Maybe you want to write a single '%', use the syntax '%%'",
                            char::from(*c)
                        ));
                    }
                    Some(c) if !(matches!(c, b'{' | b'[') || c.is_ascii_alphabetic()) => continue,
                    Some(_) => {}
                }
            }
            match b.get(i) {
                None => return Err("truncated line after '%'".to_string()),
                Some(b'%') => {
                    text.push('%');
                    i += 1;
                    continue;
                }
                Some(c) if c.is_ascii_digit() || *c == b' ' || *c == b'\t' => {
                    return Err(format!(
                        "unexpected alias name near '{}' at position {i} line : '{fmt}'. Maybe you want to write a single '%', use the syntax '%%'",
                        char::from(*c)
                    ));
                }
                Some(b'{') => {
                    let end = fmt[i..].find('}').ok_or_else(|| format!("truncated line after '{}'", &fmt[i + 1..]))?;
                    let arg = &fmt[i + 1..i + end];
                    opts = apply_flags(arg, opts);
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
                nodes.push(Node::Expr(Box::new(expr), opts, named.name.is_some().then(|| Box::new(named))));
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
                global = opts;
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
                    nodes.push(Node::Alias(*a, opts, named.name.is_some().then(|| Box::new(named))));
                }
            }
        }
        // A format's trailing blanks are not kept: the parser adds a separator only when
        // something follows it (measured: `log-format "%ci x "` sends no trailing space).
        let kept = text.trim_end_matches(' ').len();
        text.truncate(kept);
        flush(&mut text, &mut nodes);
        for n in &mut nodes {
            match n {
                Node::Alias(_, o, _) | Node::Expr(_, o, _) => *o = settle(*o, global),
                Node::Text(_) => {}
            }
        }
        Ok(LogFormat { nodes: nodes.into_boxed_slice(), global, http: false })
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
                    _,
                    _
                )
            )
        })
    }

    /// Renders the line (`sess_build_logline`).
    #[must_use]
    pub fn render(&self, d: &LogData, registry: &Registry, ctx: &SampleContext) -> String {
        let bytes = self.render_bytes(d, registry, ctx);
        ibex_regex::bytetext::bytes_to_text(&bytes)
    }

    /// Renders the line as bytes: a sample may hold any, and a CBOR line is not text.
    #[must_use]
    pub fn render_bytes(&self, d: &LogData, registry: &Registry, ctx: &SampleContext) -> Vec<u8> {
        let mut out = Out(Vec::with_capacity(160));
        self.render_into(&mut out, d, registry, ctx, true);
        out.0
    }

    /// Renders the line after what `buf` holds: a `log-format-sd` and its line share one
    /// buffer.
    pub fn render_append(&self, buf: &mut Vec<u8>, d: &LogData, registry: &Registry, ctx: &SampleContext) {
        let mut out = Out(std::mem::take(buf));
        self.render_into(&mut out, d, registry, ctx, true);
        *buf = out.0;
    }

    /// Renders the format outside a log line, where an expression that yields nothing, or
    /// an empty string, writes nothing rather than `-`: what `HAProxy` sends for an
    /// `http-check send hdr x %[str()]` (no header at all, 3.5-dev8-885761-29, 2026-10-03).
    #[must_use]
    pub fn render_value(&self, d: &LogData, registry: &Registry, ctx: &SampleContext) -> String {
        let mut out = Out(Vec::new());
        self.render_into(&mut out, d, registry, ctx, false);
        ibex_regex::bytetext::bytes_to_text(&out.0)
    }

    /// The nodes in order. On an encoded line (`%{+json}o`, `%{+cbor}o`) the text between
    /// them is dropped and each named node is a key and its value, inside `{...}` or a CBOR
    /// map; one with no name cannot be a member and is skipped (`sess_build_logline`).
    fn render_into(&self, out: &mut Out, d: &LogData, registry: &Registry, ctx: &SampleContext, log: bool) {
        let g = self.global;
        if g.json {
            out.push('{');
        } else if g.cbor {
            cbor_put(out, &[0xBF], g.bin);
        }
        let mut first = true;
        // `last_isspace` of `sess_build_logline`: a blank is written only after something
        // that is not one, and a field that wrote nothing (`%HQ` of a request without a
        // query, an empty `%hr`) leaves it as it was, so that it takes the blank after it
        // away (measured: `x %hr y` and `C %HQ D` send `x y` and `C D`).
        let mut last_space = true;
        for n in &self.nodes {
            let (o, named, value) = match n {
                Node::Text(t) => {
                    if !g.encoded() {
                        if log {
                            for ch in t.chars() {
                                if ch == ' ' {
                                    if !last_space {
                                        out.push(' ');
                                        last_space = true;
                                    }
                                } else {
                                    out.push(ch);
                                    last_space = false;
                                }
                            }
                        } else {
                            out.push_str(t);
                        }
                    }
                    continue;
                }
                Node::Alias(a, o, named) => (*o, named.as_deref(), Value::Alias(*a)),
                Node::Expr(e, o, named) => (*o, named.as_deref(), Value::Expr(e)),
            };
            if g.encoded() {
                let Some(name) = named.and_then(|n| n.name.as_deref()) else { continue };
                if g.json {
                    if !first {
                        out.push_str(", ");
                    }
                    out.push('"');
                    out.push_str(name);
                    out.push_str("\": ");
                } else {
                    cbor_text(out, name.as_bytes(), g.bin);
                }
                first = false;
            }
            let value_beg = out.0.len();
            match value {
                Value::Expr(e) => match e.eval_sample(registry, ctx) {
                    // Outside a log line an empty value writes nothing, not `-`.
                    Some(Sample::Str(v)) if !log && v.is_empty() && !o.quote && !o.encoded() => {}
                    Some(Sample::Bin(v)) if !log && v.is_empty() && !o.quote && !o.encoded() => {}
                    Some(s) if self.http && !o.encoded() => {
                        let mut plain = Out(Vec::new());
                        sample(&mut plain, &s, o, Cast::Same, !e.converters.is_empty());
                        for &c in &plain.0 {
                            if crate::engine::http_encoded(c) {
                                let _ = write!(out, "%{c:02X}");
                            } else {
                                out.0.push(c);
                            }
                        }
                    }
                    Some(s) => sample(out, &s, o, named.as_ref().map_or(Cast::Same, |n| n.cast), !e.converters.is_empty()),
                    None => missing(out, o, log),
                },
                Value::Alias(a) => {
                    if o.encoded() {
                        // The value as the plain format writes it, then as the encoding carries it:
                        // a number for the aliases that are one, a string for the others.
                        let mut plain = Out(Vec::new());
                        alias(&mut plain, a, Opts { mandatory: false, ..Opts::default() }, d);
                        let value = match std::str::from_utf8(&plain.0).ok().and_then(|s| s.parse::<i64>().ok()) {
                            Some(v) if NUMERIC.contains(&a) => Sample::Sint(v),
                            _ => Sample::Bin(plain.0),
                        };
                        match value {
                            Sample::Bin(b) if b.is_empty() => {}
                            v => sample_encoded(out, &v, o, named.as_ref().map_or(Cast::Same, |n| n.cast), false),
                        }
                    } else if o.esc {
                        let mut plain = Out(Vec::new());
                        alias(&mut plain, a, Opts { esc: false, ..o }, d);
                        escaped_5424(out, &plain.0);
                    } else {
                        alias(out, a, o, d);
                    }
                }
            }
            if out.0.len() != value_beg {
                last_space = false;
            }
            // A value that wrote nothing is `null` in JSON and the null primitive in CBOR, so
            // that the key before it has a value (`sess_build_logline`, `next_fmt`).
            if out.0.len() == value_beg {
                if o.json {
                    out.push_str("null");
                } else if o.cbor {
                    cbor_put(out, &[0xF6], o.bin);
                }
            }
        }
        if g.json {
            out.push('}');
        } else if g.cbor {
            cbor_put(out, &[0xFF], g.bin);
        }
    }
}

/// What a node that is not text computes its value from.
enum Value<'a> {
    Alias(Alias),
    Expr(&'a Expr),
}

/// The output of a rendering: bytes, because a captured header or a decoded sample holds any.
struct Out(Vec<u8>);

impl Out {
    fn push(&mut self, c: char) {
        let mut b = [0u8; 4];
        self.push_str(c.encode_utf8(&mut b));
    }

    /// Text in [`ibex_regex::bytetext`] form: an escaped byte is written as that byte.
    fn push_str(&mut self, s: &str) {
        self.0.extend_from_slice(&ibex_regex::bytetext::text_to_bytes(s));
    }
}

impl std::fmt::Write for Out {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

/// A value that is not there (`lf_text_len` with no text): `""` quoted or JSON, `-` when
/// mandatory, and nothing in CBOR, where an absent or empty text writes no item at all.
fn missing(out: &mut Out, o: Opts, log: bool) {
    if o.json || o.quote {
        out.push_str("\"\"");
    } else if o.mandatory && log && !o.cbor {
        out.push('-');
    }
}

/// `cbor_encode_*`: bytes as hex text, or raw with `+bin`.
fn cbor_put(out: &mut Out, bytes: &[u8], bin: bool) {
    if bin {
        out.0.extend_from_slice(bytes);
    } else {
        for b in bytes {
            let _ = write!(out, "{b:02X}");
        }
    }
}

/// A CBOR item head: the major type's bits and the argument in its shortest form.
fn cbor_head(out: &mut Out, major: u8, n: u64, bin: bool) {
    let mut h = [0u8; 9];
    let len = if n < 24 {
        h[0] = major | n as u8;
        1
    } else if let Ok(v) = u8::try_from(n) {
        h[0] = major | 24;
        h[1] = v;
        2
    } else if let Ok(v) = u16::try_from(n) {
        h[0] = major | 25;
        h[1..3].copy_from_slice(&v.to_be_bytes());
        3
    } else if let Ok(v) = u32::try_from(n) {
        h[0] = major | 26;
        h[1..5].copy_from_slice(&v.to_be_bytes());
        5
    } else {
        h[0] = major | 27;
        h[1..9].copy_from_slice(&n.to_be_bytes());
        9
    };
    cbor_put(out, &h[..len], bin);
}

fn cbor_text(out: &mut Out, s: &[u8], bin: bool) {
    cbor_head(out, 0x60, s.len() as u64, bin);
    cbor_put(out, s, bin);
}

fn cbor_int(out: &mut Out, v: i64, bin: bool) {
    if v >= 0 {
        cbor_head(out, 0x00, v as u64, bin);
    } else {
        cbor_head(out, 0x20, (-1 - v) as u64, bin);
    }
}

/// A binary sample is a byte string of indefinite length: one chunk, then the break.
fn cbor_bytes(out: &mut Out, s: &[u8], bin: bool) {
    cbor_put(out, &[0x5F], bin);
    if !s.is_empty() {
        cbor_head(out, 0x40, s.len() as u64, bin);
        cbor_put(out, s, bin);
    }
    cbor_put(out, &[0xFF], bin);
}

/// A number on an encoded line.
fn number(out: &mut Out, v: i64, o: Opts) {
    if o.cbor {
        cbor_int(out, v, o.bin);
    } else {
        let _ = write!(out, "{v}");
    }
}

fn boolean(out: &mut Out, v: bool, o: Opts) {
    if o.cbor {
        cbor_put(out, &[if v { 0xF5 } else { 0xF4 }], o.bin);
    } else {
        out.push_str(if v { "true" } else { "false" });
    }
}

/// `+E`: `"`, `\` and `]` get a backslash (`rfc5424_escape_map`).
fn escaped_5424(out: &mut Out, s: &[u8]) {
    for &c in s {
        if matches!(c, b'"' | b'\\' | b']') {
            out.0.push(b'\\');
        }
        out.0.push(c);
    }
}

/// The two-character JSON escape for the bytes that have one, `\u00XX` for the others.
fn json_escape_seq(out: &mut Out, b: u8) {
    match b {
        b'"' => out.push_str("\\\""),
        b'\\' => out.push_str("\\\\"),
        8 => out.push_str("\\b"),
        12 => out.push_str("\\f"),
        b'\n' => out.push_str("\\n"),
        b'\r' => out.push_str("\\r"),
        b'\t' => out.push_str("\\t"),
        _ => {
            let _ = write!(out, "\\u{b:04X}");
        }
    }
}

/// `_lf_json_utf8_len`: the length and code point of the valid multi-byte UTF-8 sequence at
/// the start of `s` (no overlong form, no surrogate, nothing above U+10FFFF, and not
/// U+FFFE or U+FFFF).
fn utf8_sequence(s: &[u8]) -> Option<(usize, u32)> {
    let len = match *s.first()? {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let c = std::str::from_utf8(s.get(..len)?).ok()?.chars().next()?;
    (c != '\u{FFFE}' && c != '\u{FFFF}').then_some((len, u32::from(c)))
}

/// A JSON string's content. Only 32..=126 stays as it is, so the output is plain ASCII and no
/// byte can be taken for an introducer; with `+utf8` the valid multi-byte sequences are
/// kept, except the C1 controls, which are escaped like the C0 ones.
fn json_escape(out: &mut Out, s: &[u8], utf8: bool) {
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if b == b'"' || b == b'\\' || b < 0x20 || b >= 0x7F {
            if let Some((len, c)) = utf8.then(|| utf8_sequence(&s[i..])).flatten() {
                if c < 0xA0 {
                    json_escape_seq(out, u8::try_from(c).unwrap_or(0));
                } else {
                    out.0.extend_from_slice(&s[i..i + len]);
                }
                i += len;
                continue;
            }
            json_escape_seq(out, b);
        } else {
            out.0.push(b);
        }
        i += 1;
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
fn encoded(out: &mut Out, s: &[u8], escaped: fn(u8) -> bool, o: Opts) {
    if o.quote {
        out.push('"');
    }
    for &c in s {
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

/// `lf_text`: text, quoted if asked; nothing for none. An encoded line carries it as a JSON
/// string or a CBOR text, and `+E` puts a backslash before `"`, `\` and `]`.
fn text<S: AsRef<[u8]> + ?Sized>(out: &mut Out, s: Option<&S>, o: Opts) {
    let s = s.map_or(&b""[..], AsRef::as_ref);
    if o.json {
        out.push('"');
        json_escape(out, s, o.utf8);
        out.push('"');
    } else if o.cbor {
        // An empty or absent text writes no item (`_lf_text_len`).
        if !s.is_empty() {
            cbor_text(out, s, o.bin);
        }
    } else {
        if o.quote {
            out.push('"');
        }
        if o.esc {
            escaped_5424(out, s);
        } else {
            out.0.extend_from_slice(s);
        }
        if o.quote {
            out.push('"');
        }
    }
}

fn ip(out: &mut Out, a: Option<SocketAddr>, o: Opts) {
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

fn port(out: &mut Out, a: Option<SocketAddr>, o: Opts) {
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

/// The line `HAProxy` writes for a connection that failed before it was a stream
/// (`session_embryonic_build_legacy_err`): `<src>:<port> [<accept date>] <fe>/<listener>:
/// <message>`. The listener is its name if it has one, else its numeric id; a client with
/// no address is `unknown`.
#[must_use]
pub fn connection_error_line(client: Option<SocketAddr>, accept_date: (i64, u32), frontend: &str, listener: &str, message: &str) -> String {
    let mut out = Out(Vec::new());
    let who = client.map_or_else(|| "unknown".to_string(), |a| format!("{}:{}", a.ip(), a.port()));
    let _ = write!(out, "{who} [");
    date_ms(&mut out, accept_date.0, accept_date.1);
    let _ = write!(out, "] {frontend}/{listener}: {message}");
    String::from_utf8_lossy(&out.0).into_owned()
}

/// `date2str_log`: `03/Oct/2026:16:48:18.622`.
fn date_ms(out: &mut Out, unix: i64, ms: u32) {
    let c = Civil::local(unix);
    let _ = write!(out, "{:02}/{}/{:04}:{:02}:{:02}:{:02}.{ms:03}", c.day, c.month_name(), c.year, c.hour, c.minute, c.second);
}

/// `gmt2str_log` / `localdate2str_log`: `03/Oct/2026:14:48:18 +0000`.
fn date_zone(out: &mut Out, c: Civil) {
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
fn alias(out: &mut Out, a: Alias, o: Opts, d: &LogData) {
    let int = |out: &mut Out, v: i64| {
        let _ = write!(out, "{v}");
    };
    let t_request = d.t_request;
    let badreq = || "<BADREQ>".to_string();
    if d.plus && matches!(a, Alias::Bytes | Alias::TActive | Alias::TTotal | Alias::TUser) {
        out.push('+');
    }
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
        Alias::SslCipher => text(out, Some(d.ssl_cipher.unwrap_or("-")), o),
        Alias::SslVersion => text(out, Some(d.ssl_version.unwrap_or("-")), o),
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
        Alias::Req => encoded(out, d.request_line.unwrap_or("<BADREQ>").as_bytes(), url_escaped, o),
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
            encoded(out, value.as_bytes(), url_escaped, o);
        }
        Alias::HttpQuery => {
            let value = match d.request_line {
                None => badreq(),
                Some(line) => {
                    let q = line.find('?').map_or("", |p| &line[p..]);
                    q.split([' ', '\t']).next().unwrap_or("").to_string()
                }
            };
            encoded(out, value.as_bytes(), url_escaped, o);
        }
    }
}

/// A sample's value as text.
fn sample_bytes(s: &Sample) -> std::borrow::Cow<'_, [u8]> {
    use std::borrow::Cow;
    match s {
        Sample::Str(v) => Cow::Borrowed(v.as_bytes()),
        Sample::Bin(v) => Cow::Borrowed(v),
        Sample::Sint(v) => Cow::Owned(v.to_string().into_bytes()),
        Sample::Bool(v) => Cow::Borrowed(if *v { b"1" } else { b"0" }),
        Sample::Ipv4(v) => Cow::Owned(v.to_string().into_bytes()),
        Sample::Ipv6(v) => Cow::Owned(v.to_string().into_bytes()),
        Sample::Meth(v) => Cow::Borrowed(v.as_str().as_bytes()),
    }
}

/// A sample on an encoded line (`%{+json}[...]`, `%{+cbor}[...]`): a number stays a number, a
/// boolean a boolean, and anything else a string; a binary sample from a converter is a CBOR
/// byte string. `%(name:type)` forces the type.
fn sample_encoded(out: &mut Out, s: &Sample, o: Opts, cast: Cast, converted: bool) {
    // A string becomes the integer its leading digits make, 0 when there are none (`atoll`).
    let as_sint = || match s {
        Sample::Sint(v) => Some(*v),
        Sample::Bool(v) => Some(i64::from(*v)),
        Sample::Str(v) => {
            let t = v.trim_start();
            let (neg, digits) = t.strip_prefix('-').map_or((false, t.strip_prefix('+').unwrap_or(t)), |d| (true, d));
            let n = digits.bytes().take_while(u8::is_ascii_digit).fold(0i64, |a, d| a.saturating_mul(10).saturating_add(i64::from(d - b'0')));
            Some(if neg { -n } else { n })
        }
        _ => None,
    };
    match cast {
        Cast::Sint => match as_sint() {
            Some(v) => number(out, v, o),
            None => missing(out, o, true),
        },
        Cast::Bool => match as_sint() {
            Some(v) => boolean(out, v != 0, o),
            None => missing(out, o, true),
        },
        Cast::Str => text(out, Some(&*sample_bytes(s)), o),
        Cast::Same => match s {
            Sample::Sint(v) => number(out, *v, o),
            Sample::Bool(v) => boolean(out, *v, o),
            Sample::Bin(v) if o.cbor && converted => cbor_bytes(out, v, o.bin),
            _ => text(out, Some(&*sample_bytes(s)), o),
        },
    }
}

/// A sample's text in a log line (`lf_text`/`lf_int`): strings quoted if asked, an empty
/// string as `-` (or `""` quoted), binary as its bytes.
fn sample(out: &mut Out, s: &Sample, o: Opts, cast: Cast, converted: bool) {
    if o.encoded() {
        return sample_encoded(out, s, o, cast, converted);
    }
    match s {
        Sample::Str(v) if v.is_empty() && !o.quote => {
            if o.mandatory {
                out.push('-');
            }
        }
        // Written as text, a binary is cast with `c_bin2str`: it ends at the first NUL.
        Sample::Bin(v) => {
            let v = &v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())];
            if v.is_empty() && !o.quote {
                if o.mandatory {
                    out.push('-');
                }
            } else {
                text(out, Some(v), o);
            }
        }
        Sample::Str(v) => text(out, Some(v.as_str()), o),
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
