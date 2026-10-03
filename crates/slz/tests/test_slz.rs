// SPDX-License-Identifier: MIT
// Copyright (C) 2013-2015 Willy Tarreau <w@1wt.eu>. See crates/slz/LICENSE.

use slz::{Encoder, Format, Level};
use serde::Deserialize;
use std::fs;
use std::io::Read;
use flate2::bufread::{DeflateDecoder, GzDecoder, ZlibDecoder};

#[derive(Deserialize)]
#[allow(dead_code)]
struct Vector {
    name: String,
    format: String,
    level: i32,
    in_hex: String,
    out_hex: String,
    in_len: usize,
    out_len: usize,
    crc32: u32,
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn test_vectors() {
    let data = fs::read_to_string("../../data/slz_vectors.json").unwrap();
    let vectors: Vec<Vector> = serde_json::from_str(&data).unwrap();
    
    let mut exact_matches = 0;
    let mut round_trips = 0;

    for (i, vec) in vectors.iter().enumerate() {
        let input = hex_to_bytes(&vec.in_hex);
        let expected_out = hex_to_bytes(&vec.out_hex);
        let format = match vec.format.as_str() {
            "rfc1951" => Format::Deflate,
            "rfc1952" => Format::Gzip,
            "rfc1950" => Format::Zlib,
            _ => panic!("unknown format"),
        };
        let level = match vec.level {
            0 => Level::NoCompression,
            1 => Level::Compression,
            _ => panic!("unknown level"),
        };

        let mut encoder = Encoder::new(format, level);
        let mut out = vec![0; vec.out_len + 1024];
        let mut pos = 0;
        
        pos += encoder.encode(&input, &mut out[pos..], false).unwrap();
        pos += encoder.finish(&mut out[pos..]).unwrap();
        
        let actual_out = &out[..pos];
        
        // Exact match test
        if actual_out == expected_out {
            exact_matches += 1;
        } else {
            println!("Mismatch on vector {} ({}, {}, lvl {})", i, vec.name, vec.format, vec.level);
            println!("Expected length: {}, Actual length: {}", expected_out.len(), actual_out.len());
            for j in 0..actual_out.len().max(expected_out.len()) {
                let e = expected_out.get(j).copied();
                let a = actual_out.get(j).copied();
                if e != a {
                    println!("Mismatch at index {}: expected {:02x?}, got {:02x?}", j, e, a);
                    break;
                }
            }
        }

        // Round trip test
        let decompressed = match format {
            Format::Deflate => {
                let mut d = DeflateDecoder::new(actual_out);
                let mut res = Vec::new();
                d.read_to_end(&mut res).ok().map(|_| res)
            }
            Format::Gzip => {
                let mut d = GzDecoder::new(actual_out);
                let mut res = Vec::new();
                d.read_to_end(&mut res).ok().map(|_| res)
            }
            Format::Zlib => {
                let mut d = ZlibDecoder::new(actual_out);
                let mut res = Vec::new();
                d.read_to_end(&mut res).ok().map(|_| res)
            }
        };

        if let Some(dec) = decompressed {
            if dec == input {
                round_trips += 1;
            } else {
                println!("Round trip mismatch on vector {}", i);
            }
        } else {
            println!("Decompression failed on vector {}", i);
        }
    }
    
    println!("EXACT MATCHES: {}/{}", exact_matches, vectors.len());
    println!("ROUND TRIPS: {}/{}", round_trips, vectors.len());
    assert_eq!(exact_matches, vectors.len(), "Not all vectors matched exactly");
    assert_eq!(round_trips, vectors.len(), "Not all vectors round-tripped");
}
