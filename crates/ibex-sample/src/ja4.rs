// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `ssl_fc_ja4`: the JA4 TLS client fingerprint string (an Ibex-only fetch; see
//! `ibex_tls::ja4` for the parsing and the FoxIO licence note).

use crate::hash::sha256_digest;
use ibex_tls::Ja4Parts;

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
    format!("{}_{}_{}", p.a, h12(&p.b), h12(&p.c))
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

    /// Every ClientHello in `testdata/ja4_vectors.txt` (FoxIO's published pcaps and expected values).
    #[test]
    fn published_vectors() {
        let mut n = 0;
        for line in include_str!("../testdata/ja4_vectors.txt").lines().filter(|l| !l.starts_with('#')) {
            let mut f = line.split('\t');
            let (want, hex, src) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
            let msg: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
            let parts = ibex_tls::ja4::parse(&msg).unwrap_or_else(|| panic!("{src}: not parsed"));
            assert_eq!(ja4(&parts), want, "{src}");
            n += 1;
        }
        assert!(n > 10, "{n} vectors");
    }
}
