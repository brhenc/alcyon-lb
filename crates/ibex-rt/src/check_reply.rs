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
    // `expect string +PONG\r\n`: a mismatch is not final while more data may come, so a
    // `-ERR\r\n` reply waits for the close (or a full buffer) like HAProxy.
    if b.starts_with(b"+PONG\r\n") {
        return Some(Verdict::pass("L7OK", "Layer7 check passed", Some("Redis server is ok".to_string())));
    }
    if !eof {
        return None;
    }
    // L7OK and L7STS always print a code in HAProxy's log line (src/check.c); the rule
    // sets none, so it is 0.
    Some(Verdict::fail("L7STS", "Layer7 wrong status", Some(0), Some(ascii_encode(cut_crlf(b)))))
}

/// The info of a failed SMTP `EHLO` or `QUIT` reply that has no status code: `HAProxy`'s rules
/// end on `error-status L7STS on-error "%[res.payload(4,0),ltrim(' '),cut_crlf]"
/// status-code "res.payload(0,3)"` (src/tcpcheck.c), so the status is "wrong status", the
/// code is 0, and the info is what follows the first four bytes, up to the line end.
#[must_use]
pub fn smtp_codeless_info(b: &[u8]) -> Option<String> {
    let rest = b.get(4..).unwrap_or(&[]);
    let start = rest.iter().position(|&c| c != b' ').unwrap_or(rest.len());
    let info = cut_crlf(&rest[start..]);
    (!info.is_empty()).then(|| String::from_utf8_lossy(info).into_owned())
}

/// The first three bytes as a number, 0 if they are not three digits (`res.payload(0,3)`).
fn smtp_code(b: &[u8]) -> u16 {
    b.get(0..3)
        .filter(|d| d.iter().all(u8::is_ascii_digit))
        .map_or(0, |d| d.iter().fold(0u16, |n, &c| n * 10 + u16::from(c - b'0')))
}

/// The verdict on the SMTP greeting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpGreeting {
    /// A 2xx greeting: send the HELO/EHLO.
    Accepted,
    /// Not `NNN` followed by a space or CR (L7RSP), with the reply up to its line end.
    Invalid(Option<String>),
    /// Another status (L7STS): code and info.
    Failed(u16, Option<String>),
}

/// The SMTP greeting: `expect rstring ^[0-9]{3}[ \r] min-recv 4` (L7RSP, info = the reply
/// up to the line end), then `^2[0-9]{2}[ \r] min-recv 4` (L7STS). Four bytes decide, a CRLF
/// is not needed, and a multi-line greeting (`220-x`) is "invalid response". Under four bytes
/// nothing is judged, even after the close.
pub fn smtp_greeting(b: &[u8]) -> Option<SmtpGreeting> {
    if b.len() < 4 {
        return None;
    }
    if !(b[..3].iter().all(u8::is_ascii_digit) && matches!(b[3], b' ' | b'\r')) {
        let line = cut_crlf(b);
        return Some(SmtpGreeting::Invalid((!line.is_empty()).then(|| ascii_encode(line))));
    }
    Some(if b[0] == b'2' {
        SmtpGreeting::Accepted
    } else {
        SmtpGreeting::Failed(smtp_code(b), smtp_codeless_info(b))
    })
}

/// The answer to QUIT: `expect rstring ^2[0-9]{2}[- \r] min-recv 4`. `Ok((code, info))` passes,
/// `Err((code, info))` is "wrong status" (also a reply cut short by the close, measured as
/// code 0); `None` waits for four bytes.
pub fn smtp_quit(b: &[u8], eof: bool) -> Option<Result<(u16, Option<String>), (u16, Option<String>)>> {
    if b.len() < 4 && !eof {
        return None;
    }
    let r = (smtp_code(b), smtp_codeless_info(b));
    let ok = b.len() >= 4 && b[0] == b'2' && b[1].is_ascii_digit() && b[2].is_ascii_digit() && matches!(b[3], b'-' | b' ' | b'\r');
    Some(if ok { Ok(r) } else { Err(r) })
}

/// The verdict on the answer to HELO/EHLO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpEhlo {
    /// The reply matches the rule: go on to QUIT.
    Accepted,
    /// The rule failed: its status code (0 if the first three bytes are not a number) and info.
    Failed(u16, Option<String>),
}

/// The SMTP answer to HELO/EHLO, possibly multi-line (`250-...` lines then `250 ...`).
///
/// `HAProxy`'s rule is the regex `^(2[0-9]{2}-[^\r]*\r\n)*2[0-9]{2}[ \r]` with no `min-recv`
/// (src/tcpcheck.c). A reply that does not match yet is not judged while more data may come,
/// and one that never matches (`450\r\n`, `XYZ\r\n`, a lone `250`) is judged only when the server
/// closes or a buffer fills: measured on HAProxy 3.5-dev8, `450\r\n` with the connection
/// held open is "Layer7 timeout". Then the code is the first three bytes if they are a
/// number, the info what follows the first four, up to the line end.
///
/// T117: this also keeps `2`, `4`, `8`, `\r\n` arriving separately from being taken for a
/// final `248` before the line ends.
pub fn smtp_reply(b: &[u8], eof: bool) -> Option<SmtpEhlo> {
    let is_2xx = |l: &[u8]| l.len() >= 3 && l[0] == b'2' && l[1].is_ascii_digit() && l[2].is_ascii_digit();
    let mut at = 0;
    let matched = loop {
        let l = &b[at..];
        if !is_2xx(l) {
            break false;
        }
        match l.get(3) {
            Some(b' ' | b'\r') => break true,
            Some(b'-') => {
                // `[^\r]*\r\n`: the line must end in CRLF.
                match l.iter().position(|&c| c == b'\r').and_then(|i| l.get(i + 1).map(|&n| (i, n))) {
                    Some((i, b'\n')) => at += i + 2,
                    _ => break false,
                }
            }
            _ => break false,
        }
    };
    if matched {
        return Some(SmtpEhlo::Accepted);
    }
    if !eof {
        return None;
    }
    Some(SmtpEhlo::Failed(smtp_code(b), smtp_codeless_info(b)))
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

/// `option pgsql-check` (src/tcpcheck.c): `expect !rstring ^E min-recv 5` fails with the
/// reply from offset 6 as info, then `expect rbinary ^52000000XX000000(00|02|03|04|05|06|07|09|0A)
/// min-recv 9` passes only an authentication request (`R`, length, then one of those types).
/// Anything else is "wrong status ... unknown error"; under 9 bytes nothing is decided until
/// the server closes.
pub fn pgsql(b: &[u8], eof: bool) -> Option<Verdict> {
    if b.first() == Some(&b'E') && (b.len() >= 5 || eof) {
        let rest = b.get(6..).unwrap_or(&[]);
        let rest = &rest[..rest.iter().position(|&c| c == 0).unwrap_or(rest.len())];
        let info = (!rest.is_empty()).then(|| ascii_encode(rest));
        return Some(Verdict::fail("L7RSP", "Layer7 invalid response", None, info));
    }
    if b.len() < 9 && !eof {
        return None;
    }
    let auth_request = b.len() >= 9
        && b[0] == b'R'
        && b[1..4] == [0, 0, 0]
        && b[5..8] == [0, 0, 0]
        && matches!(b[8], 0 | 2..=7 | 9 | 10);
    Some(if auth_request {
        Verdict::pass("L7OK", "Layer7 check passed", Some("PostgreSQL server is ok".to_string()))
    } else {
        Verdict::fail("L7STS", "Layer7 wrong status", Some(0), Some("PostgreSQL unknown error".to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::ProtoReply;

    #[test]
    fn smtp_multiline_reply_must_end_each_line_in_crlf() {
        // `250-` followed by a bare LF: not a reply line, the EHLO is refused at EOF.
        assert!(matches!(smtp_reply(b"250-a\nb", true), Some(SmtpEhlo::Failed(..))));
        assert!(matches!(smtp_reply(b"250-a\r\n250 b\r\n", false), Some(SmtpEhlo::Accepted)));
    }

    #[test]
    fn ldap_and_mysql_replies_become_verdicts() {
        let v = ldap(b"X", true).expect("decided");
        assert!(!v.ok);
        assert_eq!(v.status, "L7RSP");
        assert_eq!(ldap(b"", false), None);
        let v = mysql(b"", true, false).expect("decided");
        assert_eq!(v.status, "L7RSP");
        assert_eq!(v.info.as_deref(), Some("TCPCHK got an empty response at step 2"));
        assert_eq!(mysql(b"", false, false), None);
    }

    #[test]
    fn protocol_reply_conversion_keeps_status_code_and_info() {
        let v = Verdict::from(ProtoReply::Passed(Some("ok".into())));
        assert!(v.ok);
        assert_eq!((v.status, v.desc, v.code), ("L7OK", "Layer7 check passed", None));
        assert_eq!(v.info.as_deref(), Some("ok"));
        let v = Verdict::from(ProtoReply::Invalid(None));
        assert!(!v.ok);
        assert_eq!((v.status, v.desc, v.code, v.info), ("L7RSP", "Layer7 invalid response", None, None));
        let v = Verdict::from(ProtoReply::WrongStatus(3, Some("x".into())));
        assert!(!v.ok);
        assert_eq!((v.status, v.desc, v.code), ("L7STS", "Layer7 wrong status", Some(3)));
        assert_eq!(v.info.as_deref(), Some("x"));
    }

    #[test]
    fn pgsql_replies() {
        let ok = pgsql(b"R\0\0\0\x08\0\0\0\0", false).expect("decided");
        assert!(ok.ok);
        assert_eq!(ok.info.as_deref(), Some("PostgreSQL server is ok"));
        assert_eq!(pgsql(b"R\0\0", false), None);
        let bad = pgsql(b"Rxxxxxxxxx", false).expect("decided");
        assert_eq!((bad.status, bad.code), ("L7STS", Some(0)));
        assert_eq!(bad.info.as_deref(), Some("PostgreSQL unknown error"));
    }

    #[test]
    fn ssl_hello_replies() {
        let empty = ssl_hello(b"", true).expect("decided");
        assert_eq!(empty.status, "L6RSP");
        assert_eq!(empty.info.as_deref(), Some("TCPCHK got an empty response at step 2"));
        assert_eq!(ssl_hello(b"", false), None);
        for first in [0x15u8, 0x16] {
            let v = ssl_hello(&[first, 3, 3], false).expect("decided");
            assert!(v.ok);
            assert_eq!((v.status, v.desc), ("L6OK", "Layer6 check passed"));
        }
        let v = ssl_hello(b"H", false).expect("decided");
        assert!(!v.ok);
        assert_eq!(v.status, "L6RSP");
    }

    #[test]
    fn tcp_expect_waits_and_decides() {
        use ibex_config::ast::ResolvedTcpExpectPattern as P;
        let s = P::String("OK".into());
        assert_eq!(tcp_expect(&s, 0, b"", false), None);
        assert_eq!(tcp_expect(&s, 0, b"O", false), None);
        assert_eq!(tcp_expect(&s, 0, b"OK", false), Some(true));
        assert_eq!(tcp_expect(&s, 0, b"NO", false), Some(false));
        assert_eq!(tcp_expect(&s, 0, b"", true), Some(false));
        assert_eq!(tcp_expect(&s, 5, b"OK", false), None);
        assert_eq!(tcp_expect(&s, -1, b"NO", false), None);
        assert_eq!(tcp_expect(&s, -1, b"NO", true), Some(false));
    }

    #[test]
    fn http_response_reports_a_complete_head_only() {
        assert!(http_response(b"HTTP/1.1 200 OK\r\nX: a, b\r\n\r\n"));
        assert!(!http_response(b"HTTP/1.1 200 OK\r\nX: a"));
        assert!(!http_response(b"garbage\r\n\r\n"));
    }
}
