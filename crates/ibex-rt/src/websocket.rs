// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The websocket handshake across the proxy (tasks/T281 item 3, T274 I1-I2): what the
//! request asked for, and the rules a response is held to against it. The request head
//! itself is checked by the parser (`ibex_proto::h1`, `check_upgrade`).
//!
//! `HAProxy`: `h1_search_websocket_key` and the end of `h1_process_mux` (adding a key or an
//! accept that is missing) in `src/mux_h1.c`, the 101 check of `http_wait_for_response` in
//! `src/http_ana.c`.

use ibex_proto::upgrade::{clean_value, tokens};

/// RFC 6455 section 1.3.
const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// What a request asked for, kept for its response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReqWs {
    /// `Connection: upgrade` with an `Upgrade` header that is still there.
    pub upgrade: bool,
    /// The client's key, when the request is a websocket handshake with one of 24
    /// characters; 24 NULs otherwise, as `HAProxy` computes the accept from then.
    pub key: [u8; 24],
    /// The key the proxy wrote itself, the request having none: the server's accept must
    /// match it.
    pub sent_key: Option<[u8; 24]>,
}

impl ReqWs {
    /// Whether [`Self::of`] reads a header of this name: the others it passes over.
    #[must_use]
    pub fn reads(name: &[u8]) -> bool {
        name.eq_ignore_ascii_case(b"connection") || name.eq_ignore_ascii_case(b"upgrade") || name.eq_ignore_ascii_case(b"sec-websocket-key")
    }

    /// Reads a request head's headers. With `write_key` (`option
    /// accept-unsafe-violations-in-http-request`), a websocket handshake without any
    /// `Sec-WebSocket-Key` gets one, returned second, to be added to the head.
    pub fn of<'a>(headers: impl Iterator<Item = (&'a str, &'a str)>, write_key: bool) -> (ReqWs, Option<String>) {
        let (mut conn_upg, mut upg_hdr, mut websocket) = (false, false, false);
        let (mut key, mut any_key) = (None, false);
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("connection") {
                conn_upg |= tokens(value).any(|t| t.eq_ignore_ascii_case("upgrade"));
            } else if name.eq_ignore_ascii_case("upgrade") {
                upg_hdr = true;
                websocket |= tokens(value).any(|t| t.eq_ignore_ascii_case("websocket"));
            } else if name.eq_ignore_ascii_case("sec-websocket-key") {
                any_key = true;
                if key.is_none() && value.len() == 24 {
                    key = <[u8; 24]>::try_from(value.as_bytes()).ok();
                }
            }
        }
        let upgrade = conn_upg && upg_hdr;
        let handshake = upgrade && websocket;
        let mut ws = ReqWs { upgrade, key: key.filter(|_| handshake).unwrap_or([0; 24]), sent_key: None };
        let written = (handshake && !any_key && write_key).then(|| {
            let mut raw = [0u8; 16];
            raw[..8].copy_from_slice(&crate::lb::next_random_u64().to_le_bytes());
            raw[8..].copy_from_slice(&crate::lb::next_random_u64().to_le_bytes());
            let k = base64(&raw);
            ws.sent_key = <[u8; 24]>::try_from(k.as_bytes()).ok();
            k
        });
        (ws, written)
    }
}

/// The `Sec-WebSocket-Accept` that answers `key`.
#[must_use]
pub fn accept(key: &[u8; 24]) -> String {
    let mut input = Vec::with_capacity(24 + GUID.len());
    input.extend_from_slice(key);
    input.extend_from_slice(GUID);
    base64(&ibex_sample::hash::sha1_digest(&input))
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            out.push(if i <= chunk.len() { char::from(ALPHABET[((n >> shift) & 63) as usize]) } else { '=' });
        }
    }
    out
}

/// What becomes of a response head.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Relayed as it is.
    Keep,
    /// 502.
    Refuse,
    /// Relayed as this head.
    Rewrite(Vec<u8>),
}

/// A response head (status line to the empty line) against what its request asked for.
/// A `101` needs `Connection: upgrade` on both sides (with or without `option
/// accept-unsafe-violations-in-http-response`); its accept must answer the key the proxy
/// wrote, when it wrote one (unless the option). Any response with `Connection: upgrade` and
/// `Upgrade: websocket` but no accept gets the one the client's key calls for, and `h2c` and
/// `h2` go from `Upgrade`. (A websocket `101` without an accept was refused before this
/// without the option: `ibex_proto::response_head`.)
#[must_use]
pub fn check_response(head: &[u8], status: u16, req: &ReqWs, accept_unsafe: bool) -> Verdict {
    // The usual response names no upgrade: nothing to read, nothing allocated.
    if status != 101 && !head.windows(7).any(|w| w.eq_ignore_ascii_case(b"upgrade")) {
        return Verdict::Keep;
    }
    check_upgrade_response(head, status, req, accept_unsafe)
}

/// [`check_response`] of a response that names an upgrade.
#[cold]
#[inline(never)]
fn check_upgrade_response(head: &[u8], status: u16, req: &ReqWs, accept_unsafe: bool) -> Verdict {
    let text = String::from_utf8_lossy(head);
    let lines: Vec<&str> = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    let (mut conn_upg, mut websocket, mut srv_accept) = (false, false, None);
    // Each `Upgrade` line that changes: its index and what it becomes.
    let mut edits: Vec<(usize, String)> = Vec::new();
    for (i, line) in lines.iter().enumerate().skip(1) {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("connection") {
            conn_upg |= tokens(value).any(|t| t.eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("upgrade") {
            let clean = clean_value(value);
            websocket |= tokens(clean.as_deref().unwrap_or(value)).any(|t| t.eq_ignore_ascii_case("websocket"));
            if let Some(c) = clean {
                edits.push((i, c));
            }
        } else if name.eq_ignore_ascii_case("sec-websocket-accept") && srv_accept.is_none() {
            srv_accept = Some(value);
        }
    }
    if status == 101 && !(req.upgrade && conn_upg) {
        return Verdict::Refuse;
    }
    if let (101, true, Some(got), Some(sent)) = (status, conn_upg && websocket, srv_accept, req.sent_key) {
        if !got.eq_ignore_ascii_case(&accept(&sent)) && !accept_unsafe {
            return Verdict::Refuse;
        }
    }
    let add_accept = conn_upg && websocket && srv_accept.is_none();
    if edits.is_empty() && !add_accept {
        return Verdict::Keep;
    }
    let mut out = Vec::with_capacity(head.len() + 64);
    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() {
            continue;
        }
        match edits.iter().find(|(j, _)| *j == i) {
            Some((_, c)) if c.is_empty() => continue,
            Some((_, c)) => {
                let name = line.split_once(':').map_or("Upgrade", |(n, _)| n);
                out.extend_from_slice(format!("{name}: {c}").as_bytes());
            }
            None => out.extend_from_slice(line.as_bytes()),
        }
        out.extend_from_slice(b"\r\n");
    }
    if add_accept {
        out.extend_from_slice(format!("sec-websocket-accept: {}\r\n", accept(&req.key)).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    Verdict::Rewrite(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_of_the_rfc_example_and_of_no_key() {
        assert_eq!(accept(b"dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        // What `HAProxy` 3.5-dev8 sends when it holds no client key (measured).
        assert_eq!(accept(&[0; 24]), "X7sdFi1aZDLMcFz+yURsFmFjwvU=");
    }

    #[test]
    fn a_written_key_is_24_characters_of_base64() {
        let h = [("Connection", "upgrade"), ("Upgrade", "websocket")];
        let (ws, k) = ReqWs::of(h.iter().copied(), true);
        let k = k.expect("a key");
        assert_eq!(k.len(), 24);
        assert!(k.ends_with("=="));
        assert_eq!(ws.sent_key.map(|s| s.to_vec()), Some(k.into_bytes()));
        assert_eq!(ReqWs::of(h.iter().copied(), false).1, None);
    }
}
