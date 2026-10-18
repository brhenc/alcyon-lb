// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Reading a certificate the way `ssl_sample.c` does, for the `ssl_f_*` fetches (T398).
//!
//! `HAProxy` asks OpenSSL for each piece (`X509_get_version`, `OBJ_nid2sn`, ...); this walks
//! the DER of the certificate instead, with the bounds-checked reader the SNI code uses, and
//! gives the same text. Names `OpenSSL` knows that the tables below do not are a documented
//! gap (see `tradeoff.md`): an attribute or algorithm OID missing here is shown dotted, or as
//! `UNDEF`.

use crate::config::Der;
use std::fmt::Write as _;

/// The parts of a certificate the `ssl_*_` fetches read. Everything borrows from the DER.
#[derive(Debug, Clone, Copy)]
pub struct Cert<'a> {
    /// `X509_get_version`: 0 for v1, 2 for v3.
    pub version: u8,
    /// The serial number's content octets (`ASN1_STRING_get0_data`), sign padding included.
    pub serial: &'a [u8],
    /// The signature algorithm OID (content octets).
    pub sig_oid: &'a [u8],
    /// The issuer `Name` (the SEQUENCE's content).
    pub issuer: &'a [u8],
    /// `notBefore`: ASN.1 tag and content.
    pub not_before: (u8, &'a [u8]),
    /// `notAfter`: ASN.1 tag and content.
    pub not_after: (u8, &'a [u8]),
    /// The subject `Name` (the SEQUENCE's content).
    pub subject: &'a [u8],
    /// The public key algorithm OID (content octets).
    pub key_oid: &'a [u8],
}

impl<'a> Cert<'a> {
    /// Parses the leading fields of a DER certificate; `None` for anything malformed.
    #[must_use]
    pub fn parse(der: &'a [u8]) -> Option<Self> {
        let mut cert = Der::new(der).child()?;
        let mut tbs = cert.child()?;
        let mut first = tbs.tlv()?;
        let mut version = 0;
        if first.tag == 0xA0 {
            let v = Der::new(first.value).tlv()?;
            version = *v.value.last()?;
            first = tbs.tlv()?;
        }
        let serial = first.value;
        let sig = tbs.tlv()?;
        let sig_oid = Der::new(sig.value).tlv()?.value;
        let issuer = tbs.tlv()?.value;
        let mut validity = tbs.child()?;
        let nb = validity.tlv()?;
        let na = validity.tlv()?;
        let subject = tbs.tlv()?.value;
        let mut spki = tbs.child()?;
        let alg = spki.tlv()?;
        let key_oid = Der::new(alg.value).tlv()?.value;
        Some(Self {
            version,
            serial,
            sig_oid,
            issuer,
            not_before: (nb.tag, nb.value),
            not_after: (na.tag, na.value),
            subject,
            key_oid,
        })
    }
}

/// `ssl_sock_get_time`: a `GeneralizedTime` without its century (`YYMMDDHHMMSSZ`), a `UTCTime`
/// as it is, and nothing for what is too short or a `UTCTime` from 1950 on (year `5x`-`9x`).
#[must_use]
pub fn time_text(time: (u8, &[u8])) -> Option<&[u8]> {
    let (tag, data) = time;
    match tag {
        0x18 if data.len() >= 12 && data.starts_with(b"20") => data.get(2..),
        0x17 if data.len() >= 10 && data[0] < b'5' => Some(data),
        _ => None,
    }
}

/// `OBJ_nid2sn(X509_get_signature_nid())`; `UNDEF` for what the table lacks.
#[must_use]
pub fn sig_alg_name(oid: &[u8]) -> &'static str {
    const RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01];
    const ECDSA: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04];
    if let Some(rest) = oid.strip_prefix(RSA) {
        return match rest {
            [4] => "RSA-MD5",
            [5] => "RSA-SHA1",
            [10] => "RSASSA-PSS",
            [11] => "RSA-SHA256",
            [12] => "RSA-SHA384",
            [13] => "RSA-SHA512",
            [14] => "RSA-SHA224",
            _ => "UNDEF",
        };
    }
    if let Some(rest) = oid.strip_prefix(ECDSA) {
        return match rest {
            [1] => "ecdsa-with-SHA1",
            [3, 1] => "ecdsa-with-SHA224",
            [3, 2] => "ecdsa-with-SHA256",
            [3, 3] => "ecdsa-with-SHA384",
            [3, 4] => "ecdsa-with-SHA512",
            _ => "UNDEF",
        };
    }
    match oid {
        [0x2B, 0x65, 0x70] => "ED25519",
        [0x2B, 0x65, 0x71] => "ED448",
        _ => "UNDEF",
    }
}

/// `OBJ_nid2sn(OBJ_obj2nid(<public key algorithm>))`; `UNDEF` for what the table lacks.
#[must_use]
pub fn key_alg_name(oid: &[u8]) -> &'static str {
    match oid {
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01] => "rsaEncryption",
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A] => "RSASSA-PSS",
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01] => "id-ecPublicKey",
        [0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01] => "DSA",
        [0x2B, 0x65, 0x6E] => "X25519",
        [0x2B, 0x65, 0x6F] => "X448",
        [0x2B, 0x65, 0x70] => "ED25519",
        [0x2B, 0x65, 0x71] => "ED448",
        _ => "UNDEF",
    }
}

/// The short name `OBJ_nid2sn` gives an attribute type, or its dotted form (`i2t_ASN1_OBJECT`).
fn attr_name(oid: &[u8]) -> String {
    let known = match oid {
        [0x55, 0x04, n] => match n {
            3 => "CN",
            4 => "SN",
            5 => "serialNumber",
            6 => "C",
            7 => "L",
            8 => "ST",
            9 => "street",
            10 => "O",
            11 => "OU",
            12 => "title",
            13 => "description",
            15 => "businessCategory",
            17 => "postalCode",
            41 => "name",
            42 => "GN",
            43 => "initials",
            44 => "generationQualifier",
            46 => "dnQualifier",
            65 => "pseudonym",
            97 => "organizationIdentifier",
            _ => "",
        },
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01] => "emailAddress",
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x02] => "unstructuredName",
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x08] => "unstructuredAddress",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01] => "UID",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19] => "DC",
        _ => "",
    };
    if known.is_empty() {
        dotted(oid)
    } else {
        known.to_string()
    }
}

/// An OID's content octets as `1.2.3`.
fn dotted(oid: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u64 = 0;
    let mut first = true;
    for &b in oid {
        acc = acc.checked_shl(7).unwrap_or(0) | u64::from(b & 0x7f);
        if b & 0x80 != 0 {
            continue;
        }
        if first {
            let (a, r) = if acc < 80 { (acc / 40, acc % 40) } else { (2, acc - 80) };
            let _ = write!(out, "{a}.{r}");
            first = false;
        } else {
            let _ = write!(out, ".{acc}");
        }
        acc = 0;
    }
    out
}

/// One `AttributeTypeAndValue`, with the index of the RDN (the SET) it sits in.
struct Entry<'a> {
    rdn: usize,
    oid: &'a [u8],
    tag: u8,
    value: &'a [u8],
}

/// The entries of a `Name`, in order; `None` when it is malformed.
fn entries(name: &[u8]) -> Option<Vec<Entry<'_>>> {
    let mut out = Vec::new();
    let mut rdns = Der::new(name);
    let mut rdn = 0;
    while !rdns.is_empty() {
        let set = rdns.tlv()?;
        let mut set = Der::new(set.value);
        while !set.is_empty() {
            let mut atv = set.child()?;
            let oid = atv.tlv()?;
            let val = atv.tlv()?;
            out.push(Entry { rdn, oid: oid.value, tag: val.tag, value: val.value });
        }
        rdn += 1;
    }
    Some(out)
}

/// The value as the fetches copy it: an embedded NUL refuses it (`None`), trailing NULs
/// shrink to one (`ssl_sock_get_dn_entry`).
fn nul_checked(v: &[u8]) -> Option<&[u8]> {
    match v.iter().position(|&b| b == 0) {
        None => Some(v),
        Some(p) if v[p..].iter().all(|&b| b == 0) => Some(&v[..=p]),
        Some(_) => None,
    }
}

/// `ssl_sock_get_dn_oneline`: `/CN=a/O=b`, values as they are. `None` for no entry or a value
/// with an embedded NUL.
#[must_use]
pub fn dn_oneline(name: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for e in entries(name)? {
        let v = nul_checked(e.value)?;
        out.push(b'/');
        out.extend_from_slice(attr_name(e.oid).as_bytes());
        out.push(b'=');
        out.extend_from_slice(v);
    }
    (!out.is_empty()).then_some(out)
}

/// `ssl_sock_get_dn_entry`: the `pos`th occurrence of attribute `entry` (case-insensitive
/// short name), counted from the end when `pos` is negative. Position 0 matches nothing.
#[must_use]
pub fn dn_entry(name: &[u8], entry: &str, pos: i64) -> Option<Vec<u8>> {
    let all = entries(name)?;
    let mut cur: i64 = 0;
    for i in 0..all.len() {
        let e = if pos < 0 { &all[all.len() - 1 - i] } else { &all[i] };
        if !attr_name(e.oid).eq_ignore_ascii_case(entry) {
            continue;
        }
        cur += if pos < 0 { -1 } else { 1 };
        if cur != pos {
            continue;
        }
        return Some(nul_checked(e.value)?.to_vec());
    }
    None
}

/// `X509_NAME_print_ex(XN_FLAG_RFC2253)`: RDNs last to first, joined with `,`, the entries of
/// a multi-valued RDN with `+`, special characters escaped.
#[must_use]
pub fn dn_rfc2253(name: &[u8]) -> Option<Vec<u8>> {
    let all = entries(name)?;
    let mut out = Vec::new();
    let mut i = all.len();
    while i > 0 {
        let rdn = all[i - 1].rdn;
        let mut start = i - 1;
        while start > 0 && all[start - 1].rdn == rdn {
            start -= 1;
        }
        if !out.is_empty() {
            out.push(b',');
        }
        for (k, e) in all[start..i].iter().enumerate() {
            if k > 0 {
                out.push(b'+');
            }
            out.extend_from_slice(attr_name(e.oid).as_bytes());
            out.push(b'=');
            escape_2253(e.tag, e.value, &mut out);
        }
        i = start;
    }
    (!out.is_empty()).then_some(out)
}

fn escape_2253(tag: u8, v: &[u8], out: &mut Vec<u8>) {
    // The string types OpenSSL prints as text; anything else is dumped as `#<hex of DER>`.
    if !matches!(tag, 0x0C | 0x13 | 0x14 | 0x16 | 0x1A) {
        out.push(b'#');
        let mut der = vec![tag];
        if v.len() < 0x80 {
            der.push(u8::try_from(v.len()).unwrap_or(0));
        } else {
            let be = v.len().to_be_bytes();
            let skip = be.iter().take_while(|&&b| b == 0).count();
            der.push(0x80 | u8::try_from(be.len() - skip).unwrap_or(0));
            der.extend_from_slice(&be[skip..]);
        }
        der.extend_from_slice(v);
        for b in der {
            out.extend_from_slice(format!("{b:02X}").as_bytes());
        }
        return;
    }
    let n = v.len();
    for (i, &b) in v.iter().enumerate() {
        let esc = matches!(b, b',' | b'+' | b'"' | b'\\' | b'<' | b'>' | b';')
            || (i == 0 && (b == b' ' || b == b'#'))
            || (i + 1 == n && b == b' ');
        if b < 0x20 || b == 0x7f || b >= 0x80 {
            out.extend_from_slice(format!("\\{b:02X}").as_bytes());
        } else {
            if esc {
                out.push(b'\\');
            }
            out.push(b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_shown_as_openssl_shows_them() {
        assert_eq!(time_text((0x17, b"330917162600Z")), Some(&b"330917162600Z"[..]));
        assert_eq!(time_text((0x18, b"20510917162600Z")), Some(&b"510917162600Z"[..]));
        // UTCTime from 1950 on, and anything too short, give no sample.
        assert_eq!(time_text((0x17, b"500917162600Z")), None);
        assert_eq!(time_text((0x17, b"3309")), None);
        assert_eq!(time_text((0x18, b"2051")), None);
    }

    #[test]
    fn an_unknown_attribute_is_dotted_and_a_name_is_escaped() {
        // 1.2.840.113549.1.1.1
        assert_eq!(dotted(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]), "1.2.840.113549.1.1.1");
        let mut out = Vec::new();
        escape_2253(0x0C, b" a,b+c#", &mut out);
        assert_eq!(out, b"\\ a\\,b\\+c#");
    }

    #[test]
    fn garbage_is_no_certificate() {
        assert!(Cert::parse(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
        assert!(Cert::parse(&[]).is_none());
    }
}
