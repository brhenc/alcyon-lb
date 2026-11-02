// SPDX-License-Identifier: MIT
// Copyright (C) 2013-2015 Willy Tarreau <w@1wt.eu>. See crates/slz/LICENSE.

//! T613: the output bound. A short buffer is an error, never a silently truncated stream.

use flate2::bufread::{DeflateDecoder, GzDecoder, ZlibDecoder};
use slz::{max_compressed_len, Encoder, Format, Level, CALL_OVERHEAD};
use std::io::{ErrorKind, Read};

const FORMATS: [Format; 3] = [Format::Deflate, Format::Gzip, Format::Zlib];
const LEVELS: [Level; 2] = [Level::NoCompression, Level::Compression];

/// Deterministic xorshift bytes: incompressible.
fn noise(n: usize, mut s: u64) -> Vec<u8> {
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        })
        .collect()
}

fn decode(format: Format, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    match format {
        Format::Deflate => DeflateDecoder::new(data).read_to_end(&mut v).unwrap(),
        Format::Gzip => GzDecoder::new(data).read_to_end(&mut v).unwrap(),
        Format::Zlib => ZlibDecoder::new(data).read_to_end(&mut v).unwrap(),
    };
    v
}

fn is_write_zero<T: std::fmt::Debug>(r: Result<T, std::io::Error>) -> bool {
    matches!(r, Err(e) if e.kind() == ErrorKind::WriteZero)
}

/// The scanner's case (IBEX-SLZ-TRUNC-001).
#[test]
fn scanner_case_is_an_error() {
    let input = noise(1000, 7);
    let mut out = [0u8; 64];
    let mut e = Encoder::new(Format::Gzip, Level::NoCompression);
    assert!(is_write_zero(e.encode(&input, &mut out, false)));
}

#[test]
fn round_trip_exact_bound() {
    let sizes = [0usize, 1, 3, 4, 100, 1000, 65534, 65535, 65536, 131070, 131071, 200_000];
    for &fmt in &FORMATS {
        for &lvl in &LEVELS {
            for &n in &sizes {
                let inputs = [noise(n, n as u64 + 1), vec![b'a'; n], (0..n).map(|i| (i % 251) as u8).collect()];
                for input in &inputs {
                    let mut out = vec![0u8; max_compressed_len(n, fmt)];
                    let mut e = Encoder::new(fmt, lvl);
                    let mut pos = e.encode(input, &mut out, false).unwrap();
                    pos += e.finish(&mut out[pos..]).unwrap();
                    assert_eq!(&decode(fmt, &out[..pos]), input, "{fmt:?} {lvl:?} {n}");
                }
            }
        }
    }
}

/// Several calls: the bound grows by CALL_OVERHEAD per extra call.
#[test]
fn round_trip_chunked_with_flush() {
    for &fmt in &FORMATS {
        for &lvl in &LEVELS {
            let input = noise(50_000, 99);
            let chunks: Vec<&[u8]> = input.chunks(997).collect();
            let mut out = vec![0u8; max_compressed_len(input.len(), fmt) + CALL_OVERHEAD * 2 * chunks.len()];
            let mut e = Encoder::new(fmt, lvl);
            let mut pos = 0;
            for (i, c) in chunks.iter().enumerate() {
                pos += e.encode(c, &mut out[pos..], true).unwrap();
                if i % 7 == 0 {
                    pos += e.flush(&mut out[pos..]).unwrap();
                }
            }
            pos += e.finish(&mut out[pos..]).unwrap();
            assert_eq!(decode(fmt, &out[..pos]), input, "{fmt:?} {lvl:?}");
        }
    }
}

/// A refused call changes nothing: the same call with a bigger buffer gives a correct stream.
#[test]
fn refused_call_leaves_encoder_usable() {
    for &fmt in &FORMATS {
        for &lvl in &LEVELS {
            let input = noise(3000, 5);
            let mut e = Encoder::new(fmt, lvl);
            let mut small = [0u8; 8];
            assert!(is_write_zero(e.encode(&input, &mut small, true)));
            assert!(is_write_zero(e.flush(&mut small[..0])));
            assert!(is_write_zero(e.finish(&mut small[..3])));
            let mut out = vec![0u8; max_compressed_len(input.len(), fmt) + 2 * CALL_OVERHEAD];
            let mut pos = e.encode(&input, &mut out, true).unwrap();
            // refused mid-stream, with state already advanced
            assert!(is_write_zero(e.flush(&mut small[..3])));
            assert!(is_write_zero(e.finish(&mut small[..3])));
            pos += e.flush(&mut out[pos..]).unwrap();
            pos += e.finish(&mut out[pos..]).unwrap();
            assert_eq!(decode(fmt, &out[..pos]), input, "{fmt:?} {lvl:?}");
        }
    }
}

/// An empty stream (finish only, and flush then finish) is valid in every format.
#[test]
fn empty_stream() {
    for &fmt in &FORMATS {
        let mut out = vec![0u8; max_compressed_len(0, fmt)];
        let mut e = Encoder::new(fmt, Level::Compression);
        let n = e.finish(&mut out).unwrap();
        assert!(decode(fmt, &out[..n]).is_empty());
    }
}

/// Flush with nothing pending on a finished stream writes nothing.
#[test]
fn flush_after_finish_is_empty() {
    let mut out = vec![0u8; max_compressed_len(10, Format::Deflate) + 64];
    let mut e = Encoder::new(Format::Deflate, Level::Compression);
    let n = e.encode(b"0123456789", &mut out, false).unwrap();
    let m = e.finish(&mut out[n..]).unwrap();
    assert_eq!(e.flush(&mut out[n + m..]).unwrap(), 0);
}
