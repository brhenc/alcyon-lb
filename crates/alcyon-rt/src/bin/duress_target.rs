// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A QUIC listener driven by the real engine, for duress measurement.
//!
//! The first version of this binary drove `alcyon_quic::listener::QuicListener` from its own
//! hand-rolled loop. That measured the loop as much as it measured Alcyon, which matters: the
//! anti-amplification result depends entirely on when the transport is told time has passed
//! and how often its transmits are drained. This builds the engine from a
//! configuration and drives it with `Engine::run_once`, so what is measured is the path a deployed Alcyon would take.

use alcyon_config::parse_str;
use alcyon_rt::Engine;

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4433);
    // Where the requests go. Without one the backend is an unused address and a request
    // answers 503, which is enough to measure the handshake and amplification behaviour.
    let backend = std::env::args().nth(2).unwrap_or_else(|| "127.0.0.1:9".to_string());

    // Argument 3 is the certificate; by default the one in this checkout.
    let cert = std::env::args()
        .nth(3)
        .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/certs/localhost.pem").to_string());

    // The listener comes from the configuration, as it does in a deployed Alcyon: the engine
    // builds it, hands every request to the frontend's stream engine and drives it.
    let cfg = parse_str(&format!(
        "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\ttimeout server 10s\n\
         frontend fe\n\tbind quic4@127.0.0.1:{port} ssl crt {cert} alpn h3\n\tdefault_backend be\n\
         backend be\n\tserver s1 {backend}\n"
    ))
    .expect("parse config");
    let mut engine = Engine::new(&cfg, 1024).expect("build engine");

    println!("{port}");
    use std::io::Write;
    std::io::stdout().flush().expect("flush");

    // SIGUSR1 ends the loop and returns from main, so the process exits normally (and writes
    // its coverage profile) instead of dying to the signal's default action.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGUSR1, std::sync::Arc::clone(&stop)).expect("SIGUSR1 handler");
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        if engine.run_once().is_err() {
            break;
        }
    }
}
