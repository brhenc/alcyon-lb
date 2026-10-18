// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/ssl_sock.c (ssl_sock_parse_clienthello) and
// include/haproxy/ssl_sock-t.h (struct ssl_capture).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `ClientHello` capture behind `tune.ssl.capture-buffer-size` and the
//! `ssl_fc_cipherlist_*` / `ssl_fc_*list_bin` / `ssl_fc_protocol_hello_id` fetches.
//!
//! [`parse_clienthello`] is a branch-for-branch port of `ssl_sock_parse_clienthello`, which
//! `OpenSSL`'s message callback calls with each handshake message the client sent. rustls has no
//! such callback and gives no raw `ClientHello`, so [`HelloTap`] stands in for it: it is fed the
//! raw bytes the client sent during the handshake, reassembles handshake messages from the
//! records of content type 22, and hands each one to the parser, as `OpenSSL` would.

use std::ops::Range;

/// What `HAProxy` keeps of a `ClientHello` (`struct ssl_capture`): the legacy version, the `XXH64`
/// of the whole cipher-suite list, and in `data`, at most `tune.ssl.capture-buffer-size` bytes:
/// the cipher suites, the extension ids, then the supported groups, the EC point formats, the
/// supported versions and the signature algorithms, each list cut to the room that is left.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SslCapture {
    pub xxh64: u64,
    pub protocol_version: u16,
    pub data: Vec<u8>,
    pub ciphersuite: Range<usize>,
    pub extensions: Range<usize>,
    pub ec: Range<usize>,
    pub ec_formats: Range<usize>,
    pub supver: Range<usize>,
    pub sigalgs: Range<usize>,
    /// The JA4 parts of the whole hello (Ibex-only, `ssl_fc_ja4`); independent of the size.
    pub ja4: Option<crate::ja4::Ja4Parts>,
}

impl SslCapture {
    fn part(&self, r: &Range<usize>) -> &[u8] {
        self.data.get(r.clone()).unwrap_or(&[])
    }

    /// The offered cipher suites, 2 bytes each, as captured (`ssl_fc_cipherlist_bin`).
    #[must_use]
    pub fn ciphersuite(&self) -> &[u8] {
        self.part(&self.ciphersuite)
    }

    /// The extension ids, 2 bytes each, in the order offered (`ssl_fc_extlist_bin`).
    #[must_use]
    pub fn extensions(&self) -> &[u8] {
        self.part(&self.extensions)
    }

    /// The supported groups list (`ssl_fc_eclist_bin`).
    #[must_use]
    pub fn ec(&self) -> &[u8] {
        self.part(&self.ec)
    }

    /// The EC point formats list (`ssl_fc_ecformats_bin`).
    #[must_use]
    pub fn ec_formats(&self) -> &[u8] {
        self.part(&self.ec_formats)
    }

    /// The supported versions list (`ssl_fc_supported_versions_bin`).
    #[must_use]
    pub fn supver(&self) -> &[u8] {
        self.part(&self.supver)
    }

    /// The signature algorithms list (`ssl_fc_sigalgs_bin`).
    #[must_use]
    pub fn sigalgs(&self) -> &[u8] {
        self.part(&self.sigalgs)
    }
}

/// `exclude_tls_grease` (`ssl_utils.c`): `input` without its `GREASE` (RFC 8701) pairs -- two
/// equal bytes whose low nibble is 0xa -- in a buffer of `size` bytes (`HAProxy` writes into a
/// trash chunk, `tune.bufsize` long): the walk stops when the next pair no longer fits, and an
/// odd trailing byte is kept if there is room. Used by the `(1)` argument of the list fetches.
#[must_use]
pub fn exclude_tls_grease(input: &[u8], size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ptr = 0;
    while ptr + 1 < input.len() {
        let (a, b) = (input.get(ptr).copied().unwrap_or(0), input.get(ptr + 1).copied().unwrap_or(0));
        if a != b || (a & 0x0f) != 0x0a {
            if out.len() + 2 <= size {
                out.push(a);
                out.push(b);
            } else {
                break;
            }
        }
        ptr += 2;
    }
    if size > out.len() {
        if let Some(&last) = input.get(ptr) {
            out.push(last);
        }
    }
    out
}

fn be16(b: &[u8], at: usize) -> Option<usize> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(usize::from(u16::from_be_bytes([*s.first()?, *s.get(1)?])))
}

fn byte(b: &[u8], at: usize) -> Option<usize> {
    b.get(at).map(|&v| usize::from(v))
}

/// Parses one handshake message `msg` (from its type byte; the record header is not there)
/// into `into`, keeping at most `cap` bytes. A message that is not a `ClientHello`, or one too
/// short to reach its cipher suites, leaves `into` as it was; a second `ClientHello` (after a
/// `HelloRetryRequest`) is parsed again into the same capture, which it replaces whole. Past the
/// cipher suites, a list that does not fit or a malformed length ends the capture where it is:
/// what was taken is kept (`goto store_capture`).
pub fn parse_clienthello(msg: &[u8], cap: usize, into: &mut Option<SslCapture>) {
    // `write_p` and `content_type` are the caller's: only received handshake records come here.
    // At least the 4 bytes of type and length, and the type is client_hello (1).
    if msg.len() < 4 || msg.first() != Some(&1) {
        return;
    }
    let (Some(a), Some(b), Some(c)) = (byte(msg, 1), byte(msg, 2), byte(msg, 3)) else { return };
    let rec_len = (a << 16) + (b << 8) + c;
    // `len < rec_len + 4`; `end` is 4 + rec_len, and positions below are relative to byte 4.
    let Some(body) = msg.get(4..4 + rec_len) else { return };
    let end = body.len();

    // Protocol version, 2 bytes (`msg + 2 > end` is the `None`).
    let Some(protocol_version) = be16(body, 0) else { return };
    let mut pos = 2usize;

    // The random: 4 + 28 bytes.
    pos += 4 + 28;
    if pos > end {
        return;
    }

    // Session id: its length byte, then that many bytes. At `end` the C reads the byte past it
    // and then returns whatever it is, as here.
    let Some(sid) = byte(body, pos) else { return };
    pos += sid + 1;
    if pos > end {
        return;
    }

    // Cipher suites length.
    if pos + 2 > end {
        return;
    }
    let Some(cs_len) = be16(body, pos) else { return };
    pos += 2;
    if pos + cs_len > end {
        return;
    }
    let Some(suites) = body.get(pos..pos + cs_len) else { return };

    // Get or allocate the capture: a second ClientHello parses into the same one (its
    // buffer is reused), and every field is reset first (`memset`).
    let mut data = into.take().map(|c| c.data).unwrap_or_default();
    data.clear();
    data.reserve(cap.min(end));
    let cs_take = cap.min(cs_len);
    data.extend_from_slice(suites.get(..cs_take).unwrap_or(&[]));
    let mut capture = SslCapture {
        xxh64: ibex_crypt::xxh64::hash_xxh64(suites, 0),
        protocol_version: u16::try_from(protocol_version).unwrap_or(0),
        data,
        ciphersuite: 0..cs_take,
        ja4: crate::ja4::parse(msg),
        ..SslCapture::default()
    };
    pos += cs_len;
    let mut offset = cs_take;
    store_lists(body, pos, cap, &mut offset, &mut capture);
    *into = Some(capture);
}

/// From the compression methods on: the extension ids, then the four lists. Returning early
/// is `goto store_capture`; the caller stores the capture either way.
fn store_lists(body: &[u8], mut pos: usize, cap: usize, offset: &mut usize, capture: &mut SslCapture) {
    let end = body.len();
    // Compression methods: length byte, then that many bytes.
    let Some(comp) = byte(body, pos) else { return };
    pos += comp + 1;
    if pos > end {
        return;
    }

    // Extensions.
    if pos + 2 > end {
        return;
    }
    let Some(ext_len) = be16(body, pos) else { return };
    pos += 2;
    if pos + ext_len > end {
        return;
    }
    let extensions_end = pos + ext_len;
    capture.extensions = *offset..*offset;

    let mut ec: Option<(usize, usize)> = None;
    let mut ec_formats: Option<(usize, usize)> = None;
    let mut supver: Option<(usize, usize)> = None;
    let mut sigalgs: Option<(usize, usize)> = None;

    // `while (msg + 4 < extensions_end)`: strictly less, so a last extension with no data
    // (4 bytes that end exactly at `extensions_end`) is not looked at, its id not captured.
    while pos + 4 < extensions_end {
        if cap >= *offset + 2 {
            let Some(id) = body.get(pos..pos + 2) else { return };
            capture.data.extend_from_slice(id);
            *offset += 2;
            capture.extensions.end = *offset;
        } else {
            break;
        }
        let Some(extension_id) = be16(body, pos) else { return };
        let Some(mut rec_len) = be16(body, pos + 2) else { return };
        pos += 2 + 2;
        if pos + rec_len > extensions_end {
            return;
        }
        let list_end = pos + rec_len;
        // Each list case replaces `rec_len` with the list's own length, and the C then steps
        // over that, not over the extension: bytes after the list are read as the next one.
        // 10 supported_groups and 13 signature_algorithms have a 2-byte list length, 11
        // ec_point_formats and 43 supported_versions a 1-byte one; each case of the C is the
        // same three checks with its own width.
        let width = match extension_id {
            10 | 13 => 2,
            11 | 43 => 1,
            _ => 0,
        };
        if width > 0 {
            if pos + width > list_end {
                return;
            }
            let Some(l) = (if width == 2 { be16(body, pos) } else { byte(body, pos) }) else { return };
            rec_len = l;
            pos += width;
            if pos + rec_len > list_end {
                return;
            }
            let found = Some((pos, rec_len));
            match extension_id {
                10 => ec = found,
                11 => ec_formats = found,
                13 => sigalgs = found,
                _ => supver = found,
            }
        }
        pos += rec_len;
    }

    // The four lists, in this order, each cut to what is left of `cap`.
    for (list, slot) in [(ec, 0u8), (ec_formats, 1), (supver, 2), (sigalgs, 3)] {
        let Some((start, len)) = list else { continue };
        let take = len.min(cap.saturating_sub(*offset));
        let Some(bytes) = body.get(start..start + take) else { return };
        capture.data.extend_from_slice(bytes);
        let r = *offset..*offset + take;
        match slot {
            0 => capture.ec = r,
            1 => capture.ec_formats = r,
            2 => capture.supver = r,
            _ => capture.sigalgs = r,
        }
        *offset += take;
    }
}

/// Largest TLS record body a peer may send (`2^14 + 2048`, the ciphertext bound); a record
/// header announcing more is not TLS, and the tap stops.
const MAX_RECORD: usize = 16_384 + 2_048;
/// Largest handshake message the tap reassembles: rustls refuses anything above 64 KiB.
const MAX_HANDSHAKE: usize = 0xffff;

/// Watches the bytes a TLS client sends during the handshake and runs [`parse_clienthello`]
/// on each handshake message, as `OpenSSL`'s message callback does for `HAProxy`.
///
/// Records of content type 22 are reassembled into handshake messages (a `ClientHello` may span
/// records); the others are skipped. Under TLS 1.2 the client's handshake records after its
/// `ChangeCipherSpec` are encrypted, so the tap stops there; under TLS 1.3 encrypted records are
/// type 23, and a `ChangeCipherSpec` is the compatibility one that may come before a second
/// `ClientHello`, so it goes on.
#[derive(Debug)]
pub struct HelloTap {
    cap: usize,
    rec: Vec<u8>,
    hs: Vec<u8>,
    capture: Option<SslCapture>,
    done: bool,
    /// `ibex.ja4-compat spec`: the JA4 of each capture follows the specification text.
    ja4_spec: bool,
}

impl HelloTap {
    /// A tap keeping `cap` bytes, or `None` at 0: `HAProxy` registers no callback then.
    #[must_use]
    pub fn new(cap: usize) -> Option<Self> {
        (cap > 0).then(|| Self { cap, rec: Vec::new(), hs: Vec::new(), capture: None, done: false, ja4_spec: false })
    }

    /// `ibex.ja4-compat spec` (true) or `foxio` (false, the default) for the captures made from now on.
    pub fn set_ja4_spec(&mut self, spec: bool) {
        self.ja4_spec = spec;
    }

    /// Feeds bytes the client sent, in order. `tls12` is whether the session negotiated TLS 1.2
    /// (known once the server has answered the `ClientHello`).
    pub fn feed(&mut self, bytes: &[u8], tls12: bool) {
        if self.done || bytes.is_empty() {
            return;
        }
        self.rec.extend_from_slice(bytes);
        let mut used = 0usize;
        while let Some([t, _, _, h, l]) = self.rec.get(used..used + 5) {
            let (typ, len) = (*t, usize::from(u16::from_be_bytes([*h, *l])));
            if len > MAX_RECORD {
                self.stop();
                return;
            }
            let Some(body) = self.rec.get(used + 5..used + 5 + len) else { break };
            match typ {
                22 => self.hs.extend_from_slice(body),
                20 if tls12 => {
                    self.stop();
                    return;
                }
                _ => {}
            }
            used += 5 + len;
            if typ == 22 && !self.messages() {
                self.stop();
                return;
            }
        }
        self.rec.drain(..used.min(self.rec.len()));
    }

    /// Parses the complete handshake messages in `hs`. `false` when the stream cannot be TLS.
    fn messages(&mut self) -> bool {
        let mut used = 0usize;
        while let Some([_, a, b, c]) = self.hs.get(used..used + 4) {
            let len = (usize::from(*a) << 16) | (usize::from(*b) << 8) | usize::from(*c);
            if len > MAX_HANDSHAKE {
                return false;
            }
            let Some(msg) = self.hs.get(used..used + 4 + len) else { break };
            parse_clienthello(msg, self.cap, &mut self.capture);
            if let Some(j) = self.capture.as_mut().and_then(|cap| cap.ja4.as_mut()) {
                j.spec = self.ja4_spec;
            }
            used += 4 + len;
        }
        self.hs.drain(..used.min(self.hs.len()));
        true
    }

    /// No more parsing; the capture so far is kept.
    pub fn stop(&mut self) {
        self.done = true;
        self.rec = Vec::new();
        self.hs = Vec::new();
    }

    #[must_use]
    pub const fn capture(&self) -> Option<&SslCapture> {
        self.capture.as_ref()
    }

    /// The capture, for the connection's TLS facts once the handshake is over.
    #[must_use]
    pub fn into_capture(self) -> Option<SslCapture> {
        self.capture
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().fold(String::new(), |mut s, x| {
            use std::fmt::Write as _;
            let _ = write!(s, "{x:02X}");
            s
        })
    }

    /// The `ClientHello` (handshake message, no record header) of
    /// `openssl s_client -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256
    /// -groups X25519:P-256 -sigalgs ECDSA+SHA256:RSA-PSS+SHA256 -servername localhost -alpn
    /// http/1.1` (`OpenSSL` 3.5.9), read off the socket. Its last extension is 0x001b with data.
    const HELLO1: &str = "010000d4030302beb8aab3fd88b7ebe7983b24ec2ba05ad3acf0183e8c0adc7d16f20c566d4620a5e23364ef5dbce076
        78a7bb74fc5966291ffef47ee18eba63456c3f7b5530fc000413011303010000870000000e000c0000096c6f63616c68
        6f7374000b000403000102000a00060004001d0017002300000010000b000908687474702f312e310016000000170000
        000d0006000404030804002b0003020304002d00020101003300260024001d0020d530296e5d76223fcf78b9e8b75609
        7bcb9479635bdc6c036ae2d8dd1b580104001b0003020001";

    fn parse(msg: &[u8], cap: usize) -> Option<SslCapture> {
        let mut c = None;
        parse_clienthello(msg, cap, &mut c);
        c
    }

    /// Every fetch of the family on `HAProxy` 3.5-dev8 for the same client (the lists do not
    /// depend on the random, the session id or the key share), N = 1024 and N = 16.
    #[test]
    fn a_real_hello_gives_haproxys_values() {
        let m = unhex(HELLO1);
        let c = parse(&m, 1024).unwrap();
        assert_eq!(c.protocol_version, 771);
        assert_eq!(hex(c.ciphersuite()), "13011303");
        assert_eq!(hex(c.extensions()), "0000000B000A0023001000160017000D002B002D0033001B");
        assert_eq!(hex(c.ec()), "001D0017");
        assert_eq!(hex(c.ec_formats()), "000102");
        assert_eq!(hex(c.supver()), "0304");
        assert_eq!(hex(c.sigalgs()), "04030804");
        assert_eq!(c.xxh64.cast_signed(), -6_702_061_577_286_444_033, "ssl_fc_cipherlist_xxh");
        assert_eq!(c.data.len(), 4 + 24 + 4 + 3 + 2 + 4);

        let c = parse(&m, 16).unwrap();
        assert_eq!(hex(c.ciphersuite()), "13011303");
        assert_eq!(hex(c.extensions()), "0000000B000A002300100016");
        assert!(c.ec().is_empty() && c.ec_formats().is_empty() && c.supver().is_empty() && c.sigalgs().is_empty());
        assert_eq!(c.xxh64.cast_signed(), -6_702_061_577_286_444_033, "over the whole list");
        assert_eq!(c.data.len(), 16);

        // Cut inside the cipher list: the hash is still of all of it.
        let c = parse(&m, 3).unwrap();
        assert_eq!(hex(c.ciphersuite()), "130113");
        assert!(c.extensions().is_empty());
        // Room for 13 extension ids and part of the groups list (from the C: 4 + 24 = 28,
        // then 2 of the 4 bytes of the groups).
        let c = parse(&m, 30).unwrap();
        assert_eq!(hex(c.extensions()), "0000000B000A0023001000160017000D002B002D0033001B");
        assert_eq!(hex(c.ec()), "001D");
        assert!(c.ec_formats().is_empty());
        assert_eq!(c.ec_formats, 30..30, "the offset is set even with no room");
    }

    #[test]
    fn grease_rows() {
        let g = |v: &str| hex(&exclude_tls_grease(&unhex(v), 16384));
        assert_eq!(g(""), "");
        assert_eq!(g("0a0a 1301 1303"), "13011303");
        assert_eq!(g("1301 0a0a"), "1301");
        assert_eq!(g("1301 0a0b"), "13010A0B", "bytes differ: not GREASE");
        assert_eq!(g("0b0a"), "0B0A");
        assert_eq!(g("2a2a 3a3a"), "");
        assert_eq!(g("fafa 1301 dada"), "1301");
        assert_eq!(g("1301 1b1b"), "13011B1B", "low nibble must be a");
        assert_eq!(g("1301 aa"), "1301AA", "odd trailing byte kept");
        assert_eq!(g("0a0a 0a"), "0A", "odd trailing byte kept after a GREASE pair");
        // A full output stops the walk; the C then copies the byte at `ptr` only with room left.
        assert_eq!(hex(&exclude_tls_grease(&unhex("1301 1303 1304"), 4)), "13011303");
        assert_eq!(hex(&exclude_tls_grease(&unhex("1301 1303 1304"), 5)), "1301130313");
    }

    fn client_hello(ciphers: &[u8], exts: &[u8]) -> Vec<u8> {
        let mut b = vec![0x03, 0x03];
        b.extend([7u8; 32]);
        b.push(0);
        b.extend((ciphers.len() as u16).to_be_bytes());
        b.extend(ciphers);
        b.extend([1, 0]);
        b.extend((exts.len() as u16).to_be_bytes());
        b.extend(exts);
        let mut m = vec![1, 0, (b.len() >> 8) as u8, b.len() as u8];
        m.extend(b);
        m
    }

    /// Two hand-built `ClientHello`s with `GREASE` in every list. Not measured on `HAProxy`
    /// (a client that sends `GREASE` is a browser, and the oracle host has none to hand): the
    /// expected values are computed from the C (`ssl_sock_parse_clienthello` keeps every id
    /// and list as sent, except that the loop `msg + 4 < extensions_end` never reads a last
    /// extension of 4 bytes (the empty `4a4a` and `3a3a` below); `exclude_tls_grease` then drops the pairs).
    #[test]
    fn grease_hellos_filter_per_the_c() {
        let exts = unhex(
            "0a0a 0000 000a 000a 0008 3a3a 001d 0017 1a1a  \
             000b 0002 0100  002b 0007 06 2a2a 0304 0303  000d 0006 0004 0403 5a5a  4a4a 0000",
        );
        let m = client_hello(&unhex("6a6a 1301 1302 c02b"), &exts);
        let c = parse(&m, 1024).unwrap();
        assert_eq!(hex(c.ciphersuite()), "6A6A13011302C02B");
        assert_eq!(hex(&exclude_tls_grease(c.ciphersuite(), 16384)), "13011302C02B");
        assert_eq!(hex(c.extensions()), "0A0A000A000B002B000D");
        assert_eq!(hex(&exclude_tls_grease(c.extensions(), 16384)), "000A000B002B000D");
        assert_eq!(hex(c.ec()), "3A3A001D00171A1A");
        assert_eq!(hex(&exclude_tls_grease(c.ec(), 16384)), "001D0017");
        assert_eq!(hex(c.ec_formats()), "00");
        assert_eq!(hex(c.supver()), "2A2A03040303");
        assert_eq!(hex(&exclude_tls_grease(c.supver(), 16384)), "03040303");
        assert_eq!(hex(c.sigalgs()), "04035A5A");
        assert_eq!(hex(&exclude_tls_grease(c.sigalgs(), 16384)), "0403");

        let m = client_hello(&unhex("0a0a fafa"), &unhex("2a2a 0000 3a3a 0000"));
        let c = parse(&m, 64).unwrap();
        assert_eq!(hex(c.ciphersuite()), "0A0AFAFA");
        assert!(exclude_tls_grease(c.ciphersuite(), 16384).is_empty());
        assert_eq!(hex(c.extensions()), "2A2A");
        assert!(exclude_tls_grease(c.extensions(), 16384).is_empty());
    }

    /// No input may panic: every prefix of the hello, and every prefix with each byte flipped.
    #[test]
    fn truncated_and_garbled_inputs_do_not_panic() {
        let m = unhex(HELLO1);
        for n in 0..=m.len() {
            for cap in [0, 1, 16, 1024] {
                let _ = parse(&m[..n], cap);
            }
        }
        // A prefix shorter than the announced length is not a ClientHello yet.
        assert!(parse(&m[..m.len() - 1], 1024).is_none());
        for i in 0..m.len() {
            for v in [0x00, 0xff, 0x01, 0x80] {
                let mut g = m.clone();
                g[i] = v;
                let _ = parse(&g, 1024);
                let mut t = HelloTap::new(64).unwrap();
                let mut rec = vec![22, 3, 1];
                rec.extend_from_slice(&u16::try_from(g.len()).unwrap().to_be_bytes());
                rec.extend_from_slice(&g);
                t.feed(&rec, false);
            }
        }
    }

    /// Hand-built from the C, not measured (`HAProxy` cannot be shown these): a last extension
    /// with no data is not looked at (`msg + 4 < extensions_end`), and a list shorter than its
    /// extension makes the next id come from inside that extension.
    #[test]
    fn haproxys_loop_bounds_are_kept() {
        // version, random, empty session id, one suite, null compression.
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        // ec_point_formats (11) with 1 format, then extended_master_secret (23) with no data.
        let exts = [0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00];
        body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&exts);
        let mut m = vec![1, 0, 0, u8::try_from(body.len()).unwrap()];
        m.extend_from_slice(&body);
        let c = parse(&m, 64).unwrap();
        assert_eq!(hex(c.extensions()), "000B", "0x0017 is the last 4 bytes: not captured");
        assert_eq!(hex(c.ec_formats()), "00");

        // supported_groups (10) of outer length 8 holding a 2-byte list, then 4 bytes that the
        // C reads as the next extension (id 0x00aa, length 0), then one more real extension.
        let exts = [
            0x00, 0x0a, 0x00, 0x08, 0x00, 0x02, 0x00, 0x1d, 0x00, 0xaa, 0x00, 0x00, //
            0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
        ];
        let mut body2 = body[..body.len() - 12].to_vec();
        body2.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        body2.extend_from_slice(&exts);
        let mut m = vec![1, 0, 0, u8::try_from(body2.len()).unwrap()];
        m.extend_from_slice(&body2);
        let c = parse(&m, 64).unwrap();
        assert_eq!(hex(c.extensions()), "000A00AA002B");
        assert_eq!(hex(c.ec()), "001D");
        assert_eq!(hex(c.supver()), "0304");
    }

    /// A second `ClientHello` replaces the capture; a message that is not one leaves it.
    #[test]
    fn a_second_hello_parses_into_the_same_capture() {
        let m = unhex(HELLO1);
        let mut c = None;
        parse_clienthello(&m, 1024, &mut c);
        let first = c.clone().unwrap();
        parse_clienthello(&[2, 0, 0, 0], 1024, &mut c);
        assert_eq!(c.as_ref(), Some(&first));
        parse_clienthello(&m, 16, &mut c);
        assert_eq!(hex(c.unwrap().extensions()), "0000000B000A002300100016");
    }

    fn records(msg: &[u8], split: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [&msg[..split], &msg[split..]] {
            out.extend_from_slice(&[22, 3, 1]);
            out.extend_from_slice(&u16::try_from(part.len()).unwrap().to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// The tap reassembles a hello split over two records, fed one byte at a time, and skips
    /// what is not a handshake record.
    #[test]
    fn the_tap_reassembles_records() {
        let m = unhex(HELLO1);
        let want = parse(&m, 1024);
        for split in [1, 3, 4, 100, m.len() - 1] {
            let wire = records(&m, split);
            let mut t = HelloTap::new(1024).unwrap();
            for b in &wire {
                t.feed(std::slice::from_ref(b), false);
            }
            assert_eq!(t.capture(), want.as_ref(), "split at {split}");
        }
        // A ChangeCipherSpec under TLS 1.3 does not stop it (a second hello may follow).
        let mut t = HelloTap::new(1024).unwrap();
        t.feed(&[20, 3, 3, 0, 1, 1], false);
        t.feed(&records(&m, 10), false);
        assert_eq!(t.capture(), want.as_ref());
        // Under TLS 1.2 it does: what follows is encrypted.
        let mut t = HelloTap::new(1024).unwrap();
        t.feed(&[20, 3, 3, 0, 1, 1], true);
        t.feed(&records(&m, 10), true);
        assert!(t.capture().is_none());
        assert!(HelloTap::new(0).is_none(), "size 0: no tap");
    }

    /// A message whose own length field is right but whose body ends early, at every length:
    /// each check of the C (`msg + n > end` -> return) ends the parse where it is. Computed from
    /// the C, not measured: `HAProxy` is never shown such a message by a TLS client.
    #[test]
    fn a_body_that_ends_early_stops_at_the_c_check() {
        let full = client_hello(&[0x13, 0x01, 0x13, 0x02], &[0, 10, 0, 4, 0, 2, 0, 29]);
        let body = &full[4..];
        // Cipher list ends at 2 + 32 + 1 + 2 + 4 = 41; compression at 43; ext length at 45.
        for n in 0..body.len() {
            let [hi, lo] = u16::try_from(n).unwrap().to_be_bytes();
            let mut m = vec![1, 0, hi, lo];
            m.extend(&body[..n]);
            let got = parse(&m, 1024);
            if n < 41 {
                assert!(got.is_none(), "body of {n} bytes");
            } else {
                assert_eq!(got.unwrap().ciphersuite(), &[0x13, 0x01, 0x13, 0x02], "body of {n} bytes");
            }
        }
    }

    /// A record longer than TLS allows is not TLS: the tap stops and keeps what it has.
    #[test]
    fn an_oversized_record_stops_the_tap() {
        let mut t = HelloTap::new(1024).unwrap();
        t.feed(&[22, 3, 1, 0xff, 0xff], false);
        t.feed(&records(&unhex(HELLO1), 10), false);
        assert!(t.capture().is_none());
    }
}
