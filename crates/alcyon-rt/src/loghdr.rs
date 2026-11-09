// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/log.c (build_log_header, parse_log_message).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The syslog header a log line is written under, and the parsing of one received.
//!
//! [`build_header`] is `build_log_header`: given a format (or none, in which case the
//! message's metadata says which one fits), the facility, the level and the metadata fields
//! of the message, it writes what goes in front of the text. [`parse`] is
//! `parse_log_message`, which a `log-forward` section uses to take a received message
//! apart. A ring formats its events with the first and a forwarding section feeds both.

use std::io::Write as _;

use alcyon_config::RingFormat;

use crate::localtime::Civil;

const LEGACYTIME_LEN: usize = 15;
const ISOTIME_MINLEN: usize = 20;

/// The fields of a syslog message (`LOG_META_*`). An empty one is absent.
#[derive(Clone, Copy, Debug, Default)]
pub struct Meta<'a> {
    pub time: &'a [u8],
    pub host: &'a [u8],
    pub tag: &'a [u8],
    pub pid: &'a [u8],
    pub msgid: &'a [u8],
    pub stdata: &'a [u8],
    /// The message carried a `<PRI>`: it can be rebuilt as a `priority` message.
    pub prio: bool,
}

/// `HAProxy`'s monthname table.
const MONTHS: [&[u8]; 12] =
    [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

fn now_parts() -> (i64, u32) {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or((0, 0), |d| (i64::try_from(d.as_secs()).unwrap_or(0), d.subsec_micros()))
}

/// `2026-10-04T18:26:22.537895+02:00`: local time, microseconds, offset with a colon.
fn iso_now(out: &mut Vec<u8>, unix: i64, micros: u32) {
    let c = Civil::local(unix);
    let sign = if c.offset < 0 { '-' } else { '+' };
    let m = c.offset.unsigned_abs() / 60;
    let _ = write!(
        out,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{micros:06}{sign}{:02}:{:02}",
        c.year,
        c.month,
        c.day,
        c.hour,
        c.minute,
        c.second,
        m / 60,
        m % 60
    );
}

/// Appends the header of a message to `out` (`build_log_header`).
///
/// `format` of `None` is `LOG_FORMAT_UNSPEC`: the format is chosen from what `meta` holds, so
/// that a forwarded message keeps the shape it arrived in.
pub fn build_header(out: &mut Vec<u8>, format: Option<RingFormat>, facility: u8, level: u8, meta: &Meta) {
    let format = format.unwrap_or_else(|| {
        if !meta.host.is_empty() {
            if meta.time == b"-" || meta.time.len() >= ISOTIME_MINLEN {
                RingFormat::Rfc5424
            } else {
                RingFormat::Rfc3164
            }
        } else if !meta.tag.is_empty() {
            RingFormat::Local
        } else if meta.prio {
            RingFormat::Priority
        } else {
            RingFormat::Raw
        }
    });
    let (unix, micros) = now_parts();

    // The priority.
    match format {
        RingFormat::Local | RingFormat::Rfc3164 | RingFormat::Rfc5424 | RingFormat::Priority => {
            let _ = write!(out, "<{}>", u32::from(facility) * 8 + u32::from(level));
        }
        RingFormat::Timed | RingFormat::Short => {
            let _ = write!(out, "<{level}>");
        }
        RingFormat::Iso | RingFormat::Raw => {}
    }

    // The timestamp.
    match format {
        RingFormat::Local | RingFormat::Rfc3164 => legacy_time(out, meta, unix),
        RingFormat::Rfc5424 | RingFormat::Timed | RingFormat::Iso => {
            if format == RingFormat::Rfc5424 {
                out.extend_from_slice(b"1 ");
                if meta.time == b"-" {
                    out.extend_from_slice(b"- ");
                    return rest(out, format, meta);
                }
            }
            iso_time(out, meta, unix, micros);
        }
        RingFormat::Priority | RingFormat::Short | RingFormat::Raw => {}
    }
    rest(out, format, meta);
}

/// `Oct  4 18:26:22 `, from the message's own time when it has one.
fn legacy_time(out: &mut Vec<u8>, meta: &Meta, unix: i64) {
    if meta.time.len() == LEGACYTIME_LEN {
        out.extend_from_slice(meta.time);
        out.push(b' ');
        return;
    }
    if meta.time.len() >= ISOTIME_MINLEN {
        // `1970-01-01T00:00:00...`: the month is digits 5-6, the day 8-9.
        let t = meta.time;
        let month = 10 * usize::from(t[5].wrapping_sub(b'0')) + usize::from(t[6].wrapping_sub(b'0'));
        let month = month.saturating_sub(1);
        if month <= 11 {
            out.extend_from_slice(MONTHS[month]);
            out.push(b' ');
            out.push(if t[8] == b'0' { b' ' } else { t[8] });
            out.push(t[9]);
            out.push(b' ');
            out.extend_from_slice(&t[11..19]);
            out.push(b' ');
            return;
        }
    }
    let c = Civil::local(unix);
    let _ = write!(out, "{} {:>2} {:02}:{:02}:{:02} ", c.month_name(), c.day, c.hour, c.minute, c.second);
}

/// The ISO timestamp: the message's own when it has one, its legacy time converted, or now.
fn iso_time(out: &mut Vec<u8>, meta: &Meta, unix: i64, micros: u32) {
    if meta.time.len() >= ISOTIME_MINLEN {
        out.extend_from_slice(meta.time);
        out.push(b' ');
        return;
    }
    if meta.time.len() == LEGACYTIME_LEN {
        let t = meta.time;
        if let Some(month) = MONTHS.iter().position(|m| *m == &t[..3]) {
            let c = Civil::local(unix);
            // A month after this one's is last year's.
            let year = if (c.month as usize) <= month { c.year - 1 } else { c.year };
            let _ = write!(
                out,
                "{year:4}-{:02}-{}{}T",
                month + 1,
                if t[4] == b' ' { b'0' } else { t[4] } as char,
                t[5] as char
            );
            out.extend_from_slice(&t[7..15]);
            out.extend_from_slice(b"-00:00 ");
            return;
        }
    }
    iso_now(out, unix, micros);
    out.push(b' ');
}

/// What follows the timestamp: host, tag and the other fields.
fn rest(out: &mut Vec<u8>, format: RingFormat, meta: &Meta) {
    let field = |out: &mut Vec<u8>, v: &[u8]| {
        if v.is_empty() {
            out.extend_from_slice(b"- ");
        } else {
            out.extend_from_slice(v);
            out.push(b' ');
        }
    };
    match format {
        RingFormat::Rfc3164 | RingFormat::Local => {
            if format == RingFormat::Rfc3164 {
                if meta.host.is_empty() {
                    // The caller is meant to fill the hostname, which is mandatory.
                    out.extend_from_slice(b"localhost ");
                } else {
                    out.extend_from_slice(meta.host);
                    out.push(b' ');
                }
            }
            if meta.tag.is_empty() {
                return;
            }
            out.extend_from_slice(meta.tag);
            if !meta.pid.is_empty() {
                out.push(b'[');
                out.extend_from_slice(meta.pid);
                out.push(b']');
            }
            out.extend_from_slice(b": ");
        }
        RingFormat::Rfc5424 => {
            field(out, meta.host);
            field(out, meta.tag);
            field(out, meta.pid);
            field(out, meta.msgid);
            field(out, meta.stdata);
        }
        RingFormat::Priority | RingFormat::Short | RingFormat::Timed | RingFormat::Iso | RingFormat::Raw => {}
    }
}

/// A message taken apart: the priority if it had one, its fields, and the text.
#[derive(Debug)]
pub struct Parsed<'a> {
    /// `-1` when the message had no `<PRI>`.
    pub level: i32,
    pub facility: i32,
    pub meta: Meta<'a>,
    pub text: &'a [u8],
}

/// `parse_log_message`.
#[must_use]
pub fn parse(buf: &[u8]) -> Parsed<'_> {
    let mut out = Parsed { level: -1, facility: -1, meta: Meta::default(), text: buf };
    if buf.len() < 2 || buf[0] != b'<' {
        return out;
    }
    let mut p = 1;
    let mut pri = 0i32;
    while p < buf.len() && buf[p] != b'>' {
        if !buf[p].is_ascii_digit() {
            return out;
        }
        pri = pri.saturating_mul(10).saturating_add(i32::from(buf[p] - b'0'));
        p += 1;
    }
    if p >= buf.len() {
        return out;
    }
    out.facility = pri >> 3;
    out.level = pri & 7;
    p += 1;
    out.meta.prio = true;
    let body = &buf[p..];
    out.text = body;

    if body.len() > 2 && body[0] == b'1' && body[1] == b' ' {
        if let Some((meta, text)) = parse_5424(&body[2..]) {
            out.meta = Meta { prio: true, ..meta };
            out.text = text;
        }
    } else if body.len() > LEGACYTIME_LEN {
        if let Some((meta, text)) = parse_3164(body) {
            out.meta = Meta { prio: true, ..meta };
            out.text = text;
        }
    }
    out
}

/// Splits `s` at its first blank; the field must not be empty.
fn word(s: &[u8]) -> Option<(&[u8], &[u8])> {
    if s.is_empty() || s[0] == b' ' {
        return None;
    }
    let end = s.iter().position(|&c| c == b' ')?;
    Some((&s[..end], &s[end + 1..]))
}

/// Maps the `-` NILVALUE to an absent field.
fn nil(v: &[u8]) -> &[u8] {
    if v == b"-" {
        b""
    } else {
        v
    }
}

/// `1 TIMESTAMP HOSTNAME TAG PID MSGID STDATA text`, after the `1 `. `None` is a bad
/// format: every field is dropped and only the priority is kept.
fn parse_5424(s: &[u8]) -> Option<(Meta<'_>, &[u8])> {
    let mut meta = Meta::default();
    let rest;
    if s.len() > 2 && s[0] == b'-' && s[1] == b' ' {
        meta.time = &s[..1];
        rest = &s[2..];
    } else if s.len() > ISOTIME_MINLEN {
        // `1970-01-01T00:00:00[.frac](Z|+00:00)` followed by a blank.
        let mut p = 19;
        if s[p] == b'.' {
            p += 1;
            while *s.get(p)? != b'Z' && s[p] != b'+' && s[p] != b'-' {
                if !s[p].is_ascii_digit() {
                    return None;
                }
                p += 1;
                if p >= s.len() {
                    return None;
                }
            }
        }
        if *s.get(p)? == b'Z' {
            p += 1;
        } else {
            p += 6;
        }
        if p >= s.len() || s[p] != b' ' {
            return None;
        }
        meta.time = &s[..p];
        rest = &s[p + 1..];
    } else {
        return None;
    }
    let (host, rest) = word(rest)?;
    let (tag, rest) = word(rest)?;
    let (pid, rest) = word(rest)?;
    let (msgid, rest) = word(rest)?;
    meta.host = nil(host);
    meta.tag = nil(tag);
    meta.pid = nil(pid);
    meta.msgid = nil(msgid);
    // Structured data: `-`, or bracketed elements with no blank outside them.
    if rest.first() == Some(&b'[') {
        let (mut p, mut inside) = (0, false);
        loop {
            let c = *rest.get(p)?;
            if inside {
                if c == b']' && rest[p - 1] != b'\\' {
                    inside = false;
                }
            } else if c == b'[' {
                inside = true;
            } else if c == b' ' {
                break;
            } else {
                return None;
            }
            p += 1;
        }
        meta.stdata = &rest[..p];
        Some((meta, &rest[p + 1..]))
    } else if rest.first() == Some(&b'-') && rest.get(1) == Some(&b' ') {
        Some((meta, &rest[2..]))
    } else {
        None
    }
}

/// `Jan  1 00:00:00 HOSTNAME [TAG[PID]: ]text`.
fn parse_3164(s: &[u8]) -> Option<(Meta<'_>, &[u8])> {
    if !MONTHS.iter().any(|m| *m == &s[..3]) || s[LEGACYTIME_LEN] != b' ' {
        return None;
    }
    let mut meta = Meta { time: &s[..LEGACYTIME_LEN], ..Meta::default() };
    let (host, text) = word(&s[LEGACYTIME_LEN + 1..])?;
    meta.host = host;
    if text.is_empty() {
        return Some((meta, text));
    }
    // A tag has a trailing `:` and a blank after it.
    let Some(colon) = text.iter().position(|&c| c == b' ' || c == b':').filter(|&i| text[i] == b':') else {
        return Some((meta, text));
    };
    if text.get(colon + 1) != Some(&b' ') {
        return Some((meta, text));
    }
    let tagpid = &text[..colon];
    match tagpid.iter().position(|&c| c == b'[') {
        Some(open) => {
            // `tag[pid]`: the `]` must be the last character before the colon.
            if tagpid.last() != Some(&b']') {
                return Some((meta, text));
            }
            meta.tag = &tagpid[..open];
            meta.pid = &tagpid[open + 1..tagpid.len() - 1];
        }
        None => meta.tag = tagpid,
    }
    Some((meta, &text[colon + 2..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_5424_message_comes_apart_and_goes_back_together() {
        let m = b"<134>1 2026-10-04T18:17:12-00:00 h t 12 id - the text";
        let p = parse(m);
        assert_eq!((p.facility, p.level), (16, 6));
        assert_eq!(p.meta.host, b"h");
        assert_eq!(p.meta.tag, b"t");
        assert_eq!(p.meta.pid, b"12");
        assert_eq!(p.meta.msgid, b"id");
        assert_eq!(p.text, b"the text");
        let mut out = Vec::new();
        build_header(&mut out, None, 16, 6, &p.meta);
        assert_eq!(out, b"<134>1 2026-10-04T18:17:12-00:00 h t 12 id - ");
    }

    #[test]
    fn a_3164_message_taken_without_a_hostname_reads_its_tag_as_the_host() {
        // What `haproxy` itself sends (no hostname): `HAProxy` reads `haproxy[1]:` as the
        // host, and the rest is text, as the oracle's log-forward does.
        let p = parse(b"<134>Oct  4 18:17:12 haproxy[1]: 127.0.0.1:5 GET");
        assert_eq!(p.meta.host, b"haproxy[1]:");
        assert!(p.meta.tag.is_empty());
        assert_eq!(p.text, b"127.0.0.1:5 GET");
        let mut out = Vec::new();
        build_header(&mut out, Some(RingFormat::Rfc5424), 16, 6, &p.meta);
        assert!(out.starts_with(b"<134>1 "), "{}", String::from_utf8_lossy(&out));
        assert!(out.ends_with(b"-10-04T18:17:12-00:00 haproxy[1]: - - - - "), "{}", String::from_utf8_lossy(&out));
    }

    #[test]
    fn short_and_priority_formats_carry_only_the_priority() {
        let mut out = Vec::new();
        build_header(&mut out, Some(RingFormat::Short), 16, 6, &Meta::default());
        assert_eq!(out, b"<6>");
        out.clear();
        build_header(&mut out, Some(RingFormat::Priority), 18, 6, &Meta::default());
        assert_eq!(out, b"<150>");
    }

    fn header(format: Option<RingFormat>, meta: &Meta) -> String {
        let mut out = Vec::new();
        build_header(&mut out, format, 16, 6, meta);
        String::from_utf8(out).expect("text")
    }

    #[test]
    fn every_format_writes_the_header_haproxy_does_for_a_message_with_no_fields() {
        let none = Meta::default();
        let iso = header(Some(RingFormat::Iso), &none);
        assert!(iso.starts_with("20") && iso.contains('T') && iso.ends_with(' '), "{iso}");
        assert!(header(Some(RingFormat::Timed), &none).starts_with("<6>20"));
        assert!(header(Some(RingFormat::Rfc3164), &none).ends_with(" localhost "));
        assert!(!header(Some(RingFormat::Local), &none).ends_with(':'));
        assert!(header(Some(RingFormat::Rfc5424), &none).ends_with(" - - - - - "));
        assert_eq!(header(Some(RingFormat::Rfc5424), &Meta { time: b"-", ..none }), "<134>1 - - - - - - ");
        assert_eq!(header(Some(RingFormat::Raw), &none), "");
        // With no format, a message with only a priority is rebuilt as one, and one with
        // nothing is text.
        assert_eq!(header(None, &Meta { prio: true, ..none }), "<134>");
        assert_eq!(header(None, &none), "");
    }

    #[test]
    fn a_legacy_time_comes_from_an_iso_one_and_the_other_way() {
        let iso = Meta { time: b"2026-10-05T18:17:12.5+02:00", host: b"h", ..Meta::default() };
        assert_eq!(header(Some(RingFormat::Rfc3164), &iso), "<134>Oct  5 18:17:12 h ");
        // A month that is not one, and a legacy time whose month is no month, are today.
        let bad = Meta { time: b"2026-13-04T18:17:12-00:00", ..iso };
        assert!(header(Some(RingFormat::Local), &bad).starts_with("<134>"));
        let legacy = Meta { time: b"Xyz  4 18:17:12", ..Meta::default() };
        assert!(header(Some(RingFormat::Iso), &legacy).contains('T'));
        // A month later than this one's is last year's, and a day's padding becomes a zero.
        let dec = Meta { time: b"Dec  4 18:17:12", ..Meta::default() };
        let got = header(Some(RingFormat::Iso), &dec);
        assert!(got.contains("-12-04T18:17:12-00:00 "), "{got}");
        // `Local` with a tag and a pid, and with neither.
        let tagged = Meta { time: b"Oct  4 18:17:12", tag: b"t", pid: b"9", ..Meta::default() };
        assert_eq!(header(Some(RingFormat::Local), &tagged), "<134>Oct  4 18:17:12 t[9]: ");
        let bare = Meta { time: b"Oct  4 18:17:12", ..Meta::default() };
        assert_eq!(header(Some(RingFormat::Local), &bare), "<134>Oct  4 18:17:12 ");
    }

    #[test]
    fn a_5424_header_has_every_shape_of_timestamp_and_structured_data() {
        let p = parse(b"<134>1 2026-10-04T18:17:12.123456+02:00 h t 1 m [a=b][c=\"d\\]\"] hello");
        assert_eq!(p.meta.time, b"2026-10-04T18:17:12.123456+02:00");
        assert_eq!(p.meta.stdata, b"[a=b][c=\"d\\]\"]");
        assert_eq!(p.text, b"hello");
        let p = parse(b"<134>1 2026-10-04T18:17:12Z h t 1 m - hi");
        assert_eq!((p.meta.time, p.text), (&b"2026-10-04T18:17:12Z"[..], &b"hi"[..]));
        // Anything that does not fit keeps the priority and nothing else.
        for bad in [
            &b"<134>1 garbage"[..],
            b"<134>1 2026-10-04T18:17:12.12x456Z h t 1 m - hi",
            b"<134>1 2026-10-04T18:17:12.1234",
            b"<134>1 2026-10-04T18:17:12Zh t 1 m - hi",
            b"<134>1 - h t",
            b"<134>1 - h t 1 m x hello",
            b"<134>1 - h t 1 m [a=b",
            b"<134>1 - h t 1 m [a=b]x hello",
            b"<134>1 - h t 1 m -x",
        ] {
            let p = parse(bad);
            assert!(p.meta.prio && p.meta.host.is_empty() && p.meta.time.is_empty(), "{}", String::from_utf8_lossy(bad));
            assert_eq!((p.facility, p.level), (16, 6));
        }
    }

    #[test]
    fn a_3164_header_has_every_shape_of_host_and_tag() {
        let p = parse(b"<13>Oct  4 18:17:12 host just text");
        assert_eq!((p.meta.host, p.meta.tag, p.text), (&b"host"[..], &b""[..], &b"just text"[..]));
        let p = parse(b"<13>Oct  4 18:17:12 host tag: msg");
        assert_eq!((p.meta.tag, p.meta.pid, p.text), (&b"tag"[..], &b""[..], &b"msg"[..]));
        let p = parse(b"<13>Oct  4 18:17:12 host tag[7]: msg");
        assert_eq!((p.meta.tag, p.meta.pid, p.text), (&b"tag"[..], &b"7"[..], &b"msg"[..]));
        // A `]` that is not last, a colon with no blank after it, no colon, a host with nothing
        // after it: no tag.
        for (m, text) in [
            (&b"<13>Oct  4 18:17:12 host tag[7]x: msg"[..], &b"tag[7]x: msg"[..]),
            (b"<13>Oct  4 18:17:12 host tag:msg", b"tag:msg"),
            (b"<13>Oct  4 18:17:12 host a b c", b"a b c"),
            (b"<13>Oct  4 18:17:12 host ", b""),
        ] {
            let p = parse(m);
            assert_eq!((p.meta.host, p.meta.tag, p.text), (&b"host"[..], &b""[..], text), "{}", String::from_utf8_lossy(m));
        }
        // Not a legacy header at all: the priority is all that is kept.
        for bad in [&b"<13>Foo  4 18:17:12 host x"[..], b"<13>Oct  4 18:17:12Xhost x", b"<13>Oct  4 18:17:12  x"] {
            let p = parse(bad);
            assert!(p.meta.prio && p.meta.host.is_empty(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_priority_that_is_not_one_is_not_read() {
        for m in [&b"<1x>text"[..], b"<12", b"x"] {
            let p = parse(m);
            assert_eq!((p.level, p.facility), (-1, -1), "{}", String::from_utf8_lossy(m));
        }
        let p = parse(b"<134>");
        assert_eq!((p.facility, p.level, p.text), (16, 6, &b""[..]));
        // No digits at all is still a priority, 0: `HAProxy` reads `<>` the same way.
        let p = parse(b"<>x");
        assert_eq!((p.facility, p.level, p.text), (0, 0, &b"x"[..]));
    }

    #[test]
    fn a_message_without_a_priority_is_text_only() {
        let p = parse(b"just text");
        assert_eq!(p.level, -1);
        assert_eq!(p.text, b"just text");
    }
}
