// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The health-check reply parsers, as pure functions of the bytes a server sent (T242).
//!
//! `check.rs` drives the socket and calls these with what it has read so far and whether
//! the server has closed (`eof`). `None` means "not decided yet, read more"; a
//! [`Verdict`] is the check's result. They take no state, so the fuzz target
//! `check_reply` (fuzz/libfuzzer) feeds them arbitrary server bytes.

/// A check result decided from a reply: passed or failed, with HAProxy's status word,
/// its description, an optional code and the `info:` text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub ok: bool,
    pub status: &'static str,
    pub desc: &'static str,
    pub code: Option<u16>,
    pub info: Option<String>,
}

impl Verdict {
    fn pass(status: &'static str, desc: &'static str, info: Option<String>) -> Self {
        Self { ok: true, status, desc, code: None, info }
    }

    fn fail(status: &'static str, desc: &'static str, code: Option<u16>, info: Option<String>) -> Self {
        Self { ok: false, status, desc, code, info }
    }
}

/// The reply up to its first CR or LF (`cut_crlf`).
pub fn cut_crlf(b: &[u8]) -> &[u8] {
    let end = b.iter().position(|&c| c == b'\r' || c == b'\n').unwrap_or(b.len());
    &b[..end]
}

/// `chunk_asciiencode` (src/chunk.c): printable ASCII as is, every other byte as `<XX>`.
pub fn ascii_encode(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(b.len());
    for &c in b {
        if (0x20..0x7f).contains(&c) {
            out.push(char::from(c));
        } else {
            let _ = write!(out, "<{c:02X}>");
        }
    }
    out
}

/// `option redis-check`. HAProxy's rule: `expect string +PONG error-status L7STS on-error
/// %[res.payload(0,0),cut_crlf]` (src/tcpcheck.c): anything but a PONG is "Layer7 wrong
/// status", with the reply up to its first CR/LF, non-printables as `<XX>`. Measured: an
/// LDAP answer gives `info: "0<0C><02><01><01>a<07>"`.
pub fn redis(b: &[u8], eof: bool) -> Option<Verdict> {
    if !eof && !b.windows(2).any(|w| w == b"\r\n") {
        return None;
    }
    Some(if b.starts_with(b"+PONG") {
        Verdict::pass("L7OK", "Layer7 check passed", Some("Redis server is ok".to_string()))
    } else {
        // L7OK and L7STS always print a code in HAProxy's log line (src/check.c); the rule
        // sets none, so it is 0.
        Verdict::fail("L7STS", "Layer7 wrong status", Some(0), Some(ascii_encode(cut_crlf(b))))
    })
}

/// One SMTP status line (the greeting, or the answer to QUIT): its three-digit code if it
/// starts with one, and the line without its trailing CR/LF.
pub fn smtp_status_line(b: &[u8]) -> (Option<u16>, String) {
    let line = String::from_utf8_lossy(b).trim_end_matches(&['\r', '\n'][..]).to_string();
    let code = line.get(0..3).and_then(|s| s.parse::<u16>().ok());
    (code, line)
}

/// The SMTP answer to HELO/EHLO, possibly multi-line (`250-...` lines then `250 ...`).
/// `None`: no final line yet. Otherwise the final line's code (if it parsed) and info.
///
/// T117: judge only lines that are complete. A reply `248\r\n` arriving as `2`, `4`, `8`,
/// `\r\n` has the shape of a final line ("248", nothing after the code) as soon as the `8`
/// is in; taking it then sent QUIT early and read the trailing CRLF as the QUIT answer.
/// HAProxy's expect (`^(2xx-...\r\n)*2xx[ \r]`, no min-recv) keeps waiting while it cannot
/// decide. At EOF the partial tail counts, as before.
/// The info of a failed SMTP EHLO or QUIT reply that has no status code: `HAProxy`'s rules
/// end on `error-status L7STS on-error "%[res.payload(4,0),ltrim(' '),cut_crlf]"
/// status-code "res.payload(0,3)"` (src/tcpcheck.c), so the status is "wrong status", the
/// code is 0, and the info is what follows the first four bytes, up to the line end.
pub fn smtp_codeless_info(b: &[u8]) -> Option<String> {
    let rest = b.get(4..).unwrap_or(&[]);
    let start = rest.iter().position(|&c| c != b' ').unwrap_or(rest.len());
    let info = cut_crlf(&rest[start..]);
    (!info.is_empty()).then(|| String::from_utf8_lossy(info).into_owned())
}

pub fn smtp_reply(b: &[u8], eof: bool) -> Option<(Option<u16>, Option<String>)> {
    let resp_str = String::from_utf8_lossy(b);
    let mut completed = false;
    let mut last_code = None;
    let mut last_info = None;
    let judged = if eof { &resp_str[..] } else { &resp_str[..resp_str.rfind('\n').map_or(0, |i| i + 1)] };
    for line in judged.lines() {
        if line.len() >= 3
            && line.as_bytes()[0].is_ascii_digit()
            && line.as_bytes()[1].is_ascii_digit()
            && line.as_bytes()[2].is_ascii_digit()
        {
            let code = line[0..3].parse::<u16>().ok();
            if line.len() == 3 || line.as_bytes().get(3) == Some(&b' ') {
                completed = true;
                last_code = code;
                last_info = Some(line.get(4..).unwrap_or("").trim().to_string());
            }
        }
    }
    if !completed && !eof {
        return None;
    }
    Some((last_code, last_info))
}

/// `option ldap-check`: the reply to an anonymous bind must be an LDAPv3 BindResponse;
/// its resultCode 0 passes. The judgement is `check::ldap_bind_reply` (T238).
pub fn ldap(b: &[u8], eof: bool) -> Option<Verdict> {
    crate::check::ldap_bind_reply(b, eof).map(Verdict::from)
}

/// `option mysql-check`: the server's handshake packet, then (with `user`) the answer to
/// the client's authentication packet. The judgement is `check::mysql_reply` (T238).
pub fn mysql(b: &[u8], eof: bool, with_user: bool) -> Option<Verdict> {
    crate::check::mysql_reply(b, eof, with_user).map(Verdict::from)
}

impl From<crate::check::ProtoReply> for Verdict {
    fn from(r: crate::check::ProtoReply) -> Self {
        use crate::check::ProtoReply;
        match r {
            ProtoReply::Passed(info) => Self::pass("L7OK", "Layer7 check passed", info),
            ProtoReply::Invalid(info) => Self::fail("L7RSP", "Layer7 invalid response", None, info),
            ProtoReply::WrongStatus(code, info) => Self::fail("L7STS", "Layer7 wrong status", Some(code), info),
        }
    }
}

/// `option pgsql-check`: an `R` (authentication request) passes, an `E` (error) fails
/// with its first field.
pub fn pgsql(b: &[u8], eof: bool) -> Option<Verdict> {
    if b.len() < 5 && !eof {
        return None;
    }
    Some(if b.first() == Some(&b'R') {
        Verdict::pass("L7OK", "Layer7 check passed", Some("PostgreSQL server is ok".to_string()))
    } else if b.first() == Some(&b'E') {
        let info = if b.len() > 6 {
            let s_bytes = &b[6..];
            let null_pos = s_bytes.iter().position(|&c| c == 0).unwrap_or(s_bytes.len());
            String::from_utf8_lossy(&s_bytes[..null_pos]).to_string()
        } else {
            "Error".to_string()
        };
        Verdict::fail("L7RSP", "Layer7 invalid response", None, Some(info))
    } else {
        Verdict::fail("L7STS", "Layer7 wrong status", None, Some("PostgreSQL unknown error".to_string()))
    })
}

/// `option ssl-hello-chk`: a TLS alert or handshake record type passes.
pub fn ssl_hello(b: &[u8], eof: bool) -> Option<Verdict> {
    let Some(&first_byte) = b.first() else {
        return eof.then(|| {
            Verdict::fail(
                "L6RSP",
                "Layer6 invalid response",
                None,
                Some("TCPCHK got an empty response at step 2".to_string()),
            )
        });
    };
    Some(if first_byte == 0x15 || first_byte == 0x16 {
        Verdict { ok: true, status: "L6OK", desc: "Layer6 check passed", code: None, info: None }
    } else {
        Verdict::fail("L6RSP", "Layer6 invalid response", None, None)
    })
}

/// `tcp-check expect` on what has been read (`tcpcheck_eval_recv` /
/// `tcpcheck_eval_expect`): `None` waits for more, `Some(matched)` decides. Nothing is
/// evaluated on an empty buffer until the response ends (`last_read`: EOF or a full
/// buffer); a string or binary pattern waits for at least its length and `min-recv`; an
/// inconclusive rule without `min-recv` waits unless no more data is coming.
pub fn tcp_expect(
    pattern: &ibex_config::ast::ResolvedTcpExpectPattern,
    min_recv: i64,
    buf: &[u8],
    last_read: bool,
) -> Option<bool> {
    use ibex_config::ast::ResolvedTcpExpectPattern as P;
    let mut wait = buf.is_empty() && !last_read;
    let needed = match pattern {
        P::String(t) => t.len(),
        P::Binary(b) => b.len(),
        P::RString(_) => 0,
    };
    if !wait && !last_read {
        wait = buf.len() < needed || (min_recv > 0 && (buf.len() as i64) < min_recv);
    }
    let matched = !wait && pattern.matches(buf);
    if !wait && !matched && !last_read && min_recv == -1 {
        wait = true;
    }
    (!wait).then_some(matched)
}

/// An `http-check` reply: parsed as the check parses it, then every header value split
/// as `http-check expect hdr` splits it. Returns whether a complete response head was
/// found. For the fuzz target; the check calls the parts directly.
pub fn http_response(buf: &[u8]) -> bool {
    match crate::check::parse_http_response(buf) {
        Ok(Some(resp)) => {
            for (_, v) in &resp.headers {
                let _ = crate::check::header_values(v, false);
                let _ = crate::check::header_values(v, true);
            }
            true
        }
        _ => false,
    }
}
