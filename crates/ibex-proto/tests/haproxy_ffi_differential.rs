// SPDX-License-Identifier: GPL-2.0-or-later

//! Differential testing of Ibex H1 parser vs `HAProxy` C reference parser (T16).

#![cfg(feature = "haproxy-ffi")]

use ibex_proto::htx::HtxSlice;
use ibex_proto::parser::{self, Differential, HttpParser, OnMismatch, ParserKind, H1};

#[test]
fn test_haproxy_ffi_differential_corpus() {
    let ffi_parser = parser::build(ParserKind::HaproxyFfi).expect("HaproxyFfi parser must build");
    
    let corpus: &[(&str, &[u8])] = &[
        // 1. Basic requests
        ("basic_get", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ("basic_post_cl", b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"),
        ("basic_chunked", b"POST /stream HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
        
        // 2. Framing conflicts and smuggling vectors (RFC 7230 / CL.TE / TE.CL)
        ("cl_te", b"POST /smuggle HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"),
        ("te_cl", b"POST /smuggle HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX"),
        ("duplicate_cl_agreeing", b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"),
        ("duplicate_cl_conflicting", b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"),
        ("comma_cl_agreeing", b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5, 5\r\n\r\nhello"),
        ("comma_cl_differing", b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5, 6\r\n\r\nhello"),
        ("negative_cl", b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: -5\r\n\r\nhello"),
        ("signed_cl", b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: +5\r\n\r\nhello"),
        ("non_numeric_cl", b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: five\r\n\r\nhello"),
        
        // 3. Strict framing & syntactic edge cases
        ("whitespace_before_colon", b"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n"),
        ("empty_header_name", b"GET / HTTP/1.1\r\n: value\r\n\r\n"),
        ("nul_in_header_name", b"GET / HTTP/1.1\r\nHo\0st: example.com\r\n\r\n"),
        ("nul_in_header_value", b"GET / HTTP/1.1\r\nHost: exam\0ple.com\r\n\r\n"),
        ("obs_fold", b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Fold: foo\r\n bar\r\n\r\n"),
        ("obs_fold_without_header", b"GET / HTTP/1.1\r\n bar\r\nHost: example.com\r\n\r\n"),
        ("bare_cr", b"GET / HTTP/1.1\r\nHost: example.com\r\r\n\r\n"),
        ("lf_only", b"GET / HTTP/1.1\nHost: example.com\n\n"),
    ];

    let mut disagreements = Vec::new();

    for (name, input) in corpus {
        let ffi_candidate = parser::build(ParserKind::HaproxyFfi).expect("HaproxyFfi parser must build");
        let diff = Differential::new(Box::new(H1), ffi_candidate, OnMismatch::Observe);
        let mut stream = diff.stream(false);
        let mut buf = [0u8; 16384];
        let mut htx = HtxSlice::new(&mut buf);
        
        let _ = stream.parse(input, &mut htx);
        // Look at stream's internal disagreements if any
        // Note: HttpStream trait hides mismatches() on dyn HttpStream, so we test primary & candidate directly
        
        let mut p_stream = H1.stream(false);
        let mut p_buf = [0u8; 16384];
        let mut p_htx = HtxSlice::new(&mut p_buf);
        let p_res = p_stream.parse(input, &mut p_htx);

        let mut c_stream = ffi_parser.stream(false);
        let mut c_buf = [0u8; 16384];
        let mut c_htx = HtxSlice::new(&mut c_buf);
        let c_res = c_stream.parse(input, &mut c_htx);

        let mut diff_detail = None;
        match (&p_res, &c_res) {
            (Ok(n1), Ok(n2)) => {
                if n1 != n2 {
                    diff_detail = Some(format!("consumed bytes mismatch: h1={n1} vs ffi={n2}"));
                } else if p_htx.as_ref() != c_htx.as_ref() {
                    diff_detail = Some(format!("HTX block mismatch: h1={:?} vs ffi={:?}", p_htx.as_ref(), c_htx.as_ref()));
                }
            }
            (Ok(n1), Err(e2)) => {
                diff_detail = Some(format!("h1 accepted ({n1} bytes) but ffi rejected: {e2}"));
            }
            (Err(e1), Ok(n2)) => {
                diff_detail = Some(format!("h1 rejected ({e1}) but ffi accepted ({n2} bytes)"));
            }
            (Err(_), Err(_)) => {
                // Both rejected - agreement on rejection
            }
        }

        if let Some(detail) = diff_detail {
            disagreements.push((*name, detail));
        }
    }

    println!("============================================================");
    println!("Differential Results: H1 vs HAProxy FFI ({} cases)", corpus.len());
    println!("Total Disagreements: {}", disagreements.len());
    for (name, detail) in &disagreements {
        println!("  - [{name}]: {detail}");
    }
    println!("============================================================");

    // As mandated by T16 brief:
    // "The deliverable is the list of disagreements, not a green run. Do not fix h1.rs;
    // it is the thing being measured. The deliverable is the list."
    // So the test records and outputs all disagreements without failing the test suite.
}
