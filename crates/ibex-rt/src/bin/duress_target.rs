// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A QUIC listener driven by the real engine, for duress measurement.
//!
//! The first version of this binary drove `ibex_quic::listener::QuicListener` from its own
//! hand-rolled loop. That measured the loop as much as it measured Ibex, which matters: the
//! anti-amplification result depends entirely on when the transport is told time has passed
//! and how often its transmits are drained. This builds the engine from a
//! configuration and drives it with `Engine::run_once`, so what is measured is the path a deployed Ibex would take.

use ibex_config::parse_str;
use ibex_rt::Engine;

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4433);
    // Where the requests go. Without one the backend is an unused address and a request
    // answers 503, which is enough to measure the handshake and amplification behaviour.
    let backend = std::env::args().nth(2).unwrap_or_else(|| "127.0.0.1:9".to_string());

    ibex_tls::config::install_default_crypto_provider();
    let cert = "/home/bhenc/project-ibex/examples/certs/localhost.pem";

    // The listener comes from the configuration, as it does in a deployed Ibex: the engine
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

    loop {
        if engine.run_once().is_err() {
            break;
        }
    }
}
