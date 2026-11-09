// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The raw-buffer parsers (`rawpayload`: ClientHello, RDP cookie, `payload_lv`) on arbitrary
//! and on mangled input. The bounds checks are the point: none may read outside the buffer
//! (a panic here), and a value found in a prefix of the data is the value of all of it.

#![forbid(unsafe_code)]

use alcyon_sample::rawpayload::{self as rp, Raw};
use proptest::prelude::*;

fn ext(ty: u16, body: &[u8]) -> Vec<u8> {
    let mut v = ty.to_be_bytes().to_vec();
    v.extend((body.len() as u16).to_be_bytes());
    v.extend(body);
    v
}

fn hello(exts: &[u8], session: usize) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend(0..32u8);
    body.push(session as u8);
    body.extend(vec![7u8; session]);
    body.extend([0, 4, 0x13, 1, 0x13, 2, 1, 0]);
    body.extend((exts.len() as u16).to_be_bytes());
    body.extend(exts);
    let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
    hs.extend(body);
    let mut rec = vec![0x16, 3, 1, (hs.len() >> 8) as u8, hs.len() as u8];
    rec.extend(hs);
    rec
}

fn valid_hello(session: usize) -> Vec<u8> {
    let mut e = ext(0, b"\x00\x0e\x00\x00\x0bwww.test.or");
    e.extend(ext(16, b"\x00\x0c\x02h2\x08http/1.1"));
    e.extend(ext(10, b"\x00\x04\x00\x1d\x00\x17"));
    e.extend(ext(13, b"\x00\x04\x04\x03\x08\x04"));
    e.extend(ext(51, b"\x00\x09\x00\x1d\x00\x01\xaa\x00\x17\x00\x00"));
    e.extend(ext(35, b"\xaa\xbb"));
    hello(&e, session)
}

/// Every fetch over `d`, the values that are found.
fn all(d: &[u8]) -> Vec<Option<Vec<u8>>> {
    let args: Vec<String> = vec!["0".into(), "2".into(), "+1".into()];
    vec![
        rp::hello_type(d).found().map(|v| v.to_be_bytes().to_vec()),
        rp::ssl_ver(d).found().map(|v| v.to_be_bytes().to_vec()),
        rp::st_ext(d).found().map(|v| v.to_be_bytes().to_vec()),
        rp::ec_ext(d).found().map(|v| vec![u8::from(v)]),
        rp::cipherlist(d).found(),
        rp::supported_groups(d).found(),
        rp::sigalgs(d).found(),
        rp::keyshare_groups(d).found(),
        rp::sni(d).found(),
        rp::alpn(d).found().map(|v| v.concat()),
        rp::rdp_cookie(d, None).found(),
        rp::rdp_cookie_cnt(d, Some("mstshash")).found().map(|v| v.to_be_bytes().to_vec()),
        rp::payload_lv(d, &args).found(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// No input makes a parser read out of bounds.
    #[test]
    fn arbitrary_bytes_never_panic(d in proptest::collection::vec(any::<u8>(), 0..200)) {
        let _ = all(&d);
    }

    /// Nor does a valid hello with bytes overwritten, inserted or dropped.
    #[test]
    fn mangled_hellos_never_panic(
        session in 0usize..33,
        edits in proptest::collection::vec((0usize..400, any::<u8>(), 0u8..3), 0..6),
        cut in 0usize..400,
    ) {
        let mut d = valid_hello(session);
        for (at, b, kind) in edits {
            let at = at % d.len().max(1);
            match kind {
                0 => d[at] = b,
                1 => d.insert(at, b),
                _ => { d.remove(at); }
            }
        }
        d.truncate(cut.min(d.len()));
        let _ = all(&d);
    }

    /// What a prefix of a hello yields is what all of it yields: a parser that answers has seen
    /// everything it needs, and one that is unsure says so.
    #[test]
    fn a_value_found_in_a_prefix_is_the_value_of_the_whole(session in 0usize..33, cut in 0usize..400) {
        let full = valid_hello(session);
        let cut = cut.min(full.len());
        let (p, f) = (all(&full[..cut]), all(&full));
        for (i, (a, b)) in p.iter().zip(&f).enumerate() {
            if let Some(a) = a {
                prop_assert_eq!(Some(a), b.as_ref(), "fetch #{} at {} bytes", i, cut);
            }
        }
    }

    /// The whole of a valid hello is never "too short" for any of the hello fetches.
    #[test]
    fn a_whole_hello_is_never_too_short(session in 0usize..33) {
        let d = valid_hello(session);
        prop_assert!(!matches!(rp::sni(&d), Raw::TooShort));
        prop_assert_eq!(rp::sni(&d), Raw::Found(b"www.test.or".to_vec()));
        prop_assert_eq!(rp::alpn(&d), Raw::Found(vec![b"h2".to_vec(), b"http/1.1".to_vec()]));
        prop_assert_eq!(rp::ssl_ver(&d), Raw::Found(0x0003_0003));
    }
}
