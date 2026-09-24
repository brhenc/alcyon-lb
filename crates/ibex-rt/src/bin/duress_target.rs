// SPDX-License-Identifier: GPL-2.0-or-later
//! A QUIC listener driven by the real engine, for duress measurement.
//!
//! The first version of this binary drove `ibex_quic::listener::QuicListener` from its own
//! hand-rolled loop. That measured the loop as much as it measured Ibex, which matters: the
//! anti-amplification result depends entirely on when the transport is told time has passed
//! and how often its transmits are drained. This uses `Engine::add_quic_listener` and
//! `Engine::run_once`, so what is measured is the path a deployed Ibex would take.

use std::net::SocketAddr;

use ibex_config::parse_str;
use ibex_rt::Engine;

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4433);
    let backend: Option<SocketAddr> = std::env::args().nth(2).and_then(|s| s.parse().ok());

    ibex_tls::config::install_default_crypto_provider();
    let cert = std::path::Path::new("/home/bhenc/project-ibex/examples/certs/localhost.pem");
    let (certs, key) = ibex_tls::config::load_cert_file(cert).expect("load certificate");
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("build TLS config");
    tls.alpn_protocols = vec![b"h3".to_vec()];

    // A minimal config so the engine has somewhere to put its scheduler and pools; the QUIC
    // listener is added directly rather than through the config surface, which does not yet
    // parse `bind quic4@`.
    let cfg = parse_str(
        "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\ttimeout server 10s\n",
    )
    .expect("parse minimal config");
    let mut engine = Engine::new(&cfg, 1024).expect("build engine");

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let bound = engine
        .add_quic_listener(addr, &tls, backend)
        .expect("bind QUIC listener");

    println!("{bound}");
    use std::io::Write;
    std::io::stdout().flush().expect("flush");

    loop {
        if engine.run_once().is_err() {
            break;
        }
    }
}
