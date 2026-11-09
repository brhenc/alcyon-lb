// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `h3bench <ip:port> <requests> <best|worst> [get|post]`: one HTTP/3 connection, the requests
//! one after the other, the client's ACK policy fixed (`src/client.rs`). Prints h2load's
//! `requests:` and `UDP datagram:` lines (what `tools/measure/insreq.sh` reads), then the
//! client's datagrams per request over the requests alone. Exits 1 if a request failed.

// A measuring tool run from a shell: its errors go to stderr (the clippy.toml ban is for alcyon).
#![allow(clippy::disallowed_macros)]

mod client;

use client::{AckPolicy, Client};
use std::net::SocketAddr;
use std::process::ExitCode;

/// The POST variant's body (one DATA frame).
const POST_BODY: &[u8] = b"0123456789abcdef0123456789abcdef";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let usage = || {
        eprintln!("usage: h3bench <ip:port> <requests> <best|worst> [get|post]");
        ExitCode::from(2)
    };
    if args.len() < 4 || args.len() > 5 {
        return usage();
    }
    let (Ok(addr), Ok(n), Some(policy)) = (args[1].parse::<SocketAddr>(), args[2].parse::<u64>(), AckPolicy::parse(&args[3])) else {
        return usage();
    };
    let body: &[u8] = match args.get(4).map(String::as_str) {
        None | Some("get") => b"",
        Some("post") => POST_BODY,
        Some(_) => return usage(),
    };
    let req = client::request_bytes(body);
    let result = Client::connect(addr, policy).and_then(|mut c| {
        // H3BENCH_GAP_US (default 200): the least time between two client datagrams.
        let gap = std::env::var("H3BENCH_GAP_US").ok().and_then(|v| v.parse().ok()).unwrap_or(200);
        c.set_gap(std::time::Duration::from_micros(gap));
        let handshake = c.counts;
        let run = c.run(n, &req)?;
        Ok((handshake, run, c.close()?))
    });
    match result {
        Ok((handshake, run, total)) => {
            println!("requests: {n} total, {n} started, {n} done, {} succeeded, {} failed, 0 errored, 0 timeout", run.ok, n - run.ok);
            println!("UDP datagram: {} sent, {} received", total.sent, total.received);
            println!(
                "h3bench: {policy:?}, {n} requests: client {:.4} datagrams/req, server {:.4} datagrams/req (requests only; handshake {} sent {} received)",
                run.client_per_request(),
                run.server_per_request(),
                handshake.sent,
                handshake.received
            );
            if run.ok == n {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("h3bench: {e}");
            ExitCode::from(1)
        }
    }
}
