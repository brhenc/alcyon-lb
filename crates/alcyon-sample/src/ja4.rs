// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `ssl_fc_ja4`: the JA4 TLS client fingerprint string (an Alcyon-only fetch; see
//! `alcyon_tls::ja4` for the parsing and the FoxIO licence note).

use crate::hash::sha256_digest;
use alcyon_tls::Ja4Parts;

/// First 12 hex characters of the SHA-256 of `s`; twelve zeros for an empty list (the spec does
/// this rather than hash nothing).
fn h12(s: &str) -> String {
    if s.is_empty() {
        return "000000000000".to_string();
    }
    sha256_digest(s.as_bytes()).iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// `t13d1516h2_8daaf6152771_e5627efa2ab1`.
#[must_use]
pub fn ja4(p: &Ja4Parts) -> String {
    format!("{}_{}_{}", p.a(), h12(&p.b), h12(&p.c()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example of `technical_details/JA4.md`.
    #[test]
    fn spec_example_hashes() {
        assert_eq!(h12("002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"), "8daaf6152771");
        let c = "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01";
        assert_eq!(h12(&format!("{c}_0403,0804,0401,0503,0805,0501,0806,0601")), "e5627efa2ab1");
        assert_eq!(h12(c), "6d807ffa2a79");
        assert_eq!(h12(""), "000000000000");
    }

    /// The two modes differ when there is nothing to list but signature algorithms: no real
    /// hello does that, so the parts are built by hand. FoxIO's Python tool hashes `_` and the
    /// algorithms, the specification says twelve zeros.
    #[test]
    fn no_extensions_but_sigalgs_by_mode() {
        let mut p = Ja4Parts { prefix: "t13d0100".into(), alpn_foxio: "00".into(), alpn_spec: "00".into(), b: "1301".into(), sigalgs: "0403,0804".into(), ..Ja4Parts::default() };
        assert_eq!(ja4(&p), format!("t13d010000_{}_{}", h12("1301"), h12("_0403,0804")));
        p.spec = true;
        assert_eq!(ja4(&p), format!("t13d010000_{}_000000000000", h12("1301")));
        // With extensions the two modes agree.
        p.exts = "000d".into();
        assert_eq!(p.c(), "000d_0403,0804");
        p.spec = false;
        assert_eq!(p.c(), "000d_0403,0804");
    }

    /// Every ClientHello in `testdata/ja4_vectors.txt` (FoxIO's published pcaps and expected values).
    #[test]
    fn published_vectors() {
        let mut n = 0;
        let mut differs = Vec::new();
        for line in include_str!("../testdata/ja4_vectors.txt").lines().filter(|l| !l.starts_with('#')) {
            let mut f = line.split('\t');
            let (want, hex, src) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
            let msg: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
            let mut parts = alcyon_tls::ja4::parse(&msg).unwrap_or_else(|| panic!("{src}: not parsed"));
            // The file holds FoxIO's own published values: foxio mode must give all of them.
            let (foxio, spec) = (ja4(&parts), {
                parts.spec = true;
                ja4(&parts)
            });
            if foxio != spec {
                differs.push(format!("{src}: foxio {foxio}, spec {spec}"));
            }
            assert_eq!(foxio, want, "{src} (foxio mode)");
            n += 1;
        }
        assert!(n > 10, "{n} vectors");
        // Only the non-ASCII ALPN vector changes between the modes.
        assert_eq!(differs, ["tls-non-ascii-alpn.pcapng: foxio t13d151699_8daaf6152771_e5627efa2ab1, spec t13d1516bd_8daaf6152771_e5627efa2ab1"]);
    }
}
