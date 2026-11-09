// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! R2: a header a rule writes from a sample of a Latin-1 header holds the client's bytes as
//! escape characters ([`alcyon_regex::bytetext`]); `add_header` and `insert_header` flag it, so
//! the wire gets the bytes and a fetch reads them (`header_bytes`), as `http-request
//! set-header x "%[req.hdr(y)]"` does on HAProxy 3.5-dev8-885761-29 (the server got
//! `caf\xe9`; `crates/alcyon-rt/tests/it/bytes_samples_oracle.rs`).

use alcyon_proto::htx::HtxSlice;

fn wire_and_flags(edit: impl FnOnce(&mut HtxSlice<'_>)) -> (Vec<u8>, Vec<(Vec<u8>, Vec<u8>, bool)>) {
    let mut buf = [0u8; 4096];
    let mut htx = HtxSlice::new(&mut buf);
    htx.push_req_line("GET", "/", "HTTP/1.1").unwrap();
    htx.push_header("host", "h").unwrap();
    htx.push_eoh().unwrap();
    edit(&mut htx);
    let view = htx.as_ref();
    let hdrs = view.header_bytes().map(|(n, v, l)| (n.to_vec(), v.to_vec(), l)).collect();
    (view.write_h1_wire_vec(), hdrs)
}

#[test]
fn a_rule_header_with_an_escaped_byte_goes_out_as_the_byte() {
    let text = alcyon_regex::bytetext::bytes_to_text(b"caf\xe9");
    for (how, edit) in [
        ("add_header", Box::new(|h: &mut HtxSlice<'_>| h.add_header("x-a", &text).unwrap()) as Box<dyn Fn(&mut HtxSlice<'_>)>),
        ("insert_header", Box::new(|h: &mut HtxSlice<'_>| h.insert_header(1, "x-a", &text).unwrap())),
    ] {
        let (wire, hdrs) = wire_and_flags(|h| edit(h));
        assert!(wire.windows(11).any(|w| w == b"x-a: caf\xe9\r\n"), "{how}: {}", wire.escape_ascii());
        assert!(hdrs.iter().any(|(n, _, latin1)| n == b"x-a" && *latin1), "{how}: not flagged");
        // A plain value is not flagged.
        let (_, hdrs) = wire_and_flags(|h| {
            h.add_header("x-b", "plain").unwrap();
            h.insert_header(1, "x-c", "caf\u{e9}").unwrap();
        });
        assert!(hdrs.iter().all(|(_, _, latin1)| !latin1), "{how}: {hdrs:?}");
    }
}
