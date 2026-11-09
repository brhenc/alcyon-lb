// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.alcyon.crypto-provider` (T460): the TCP configurations of `alcyon_tls::tcp` built on either
//! provider complete a TLS 1.2 and a TLS 1.3 handshake, in memory, and run on the provider they
//! were asked for. The two are told apart by the name of their `secure_random` (`Ring`, and
//! `RingAlcyon` in the vendored `rustls-ringalcyon`): their `DEFAULT_PROVIDER` is a `const` whose
//! statics are copied into each crate that names it, so no address tells them apart.

use alcyon_config::{TlsCryptoProvider, TlsVersion};
use alcyon_tls::config::BackendTlsOptions;
use alcyon_tls::conn::{TlsCtx, VecInput};
use alcyon_tls::tcp::{build_backend_client_config_with, rustls24, BindTls};
use rustls24::crypto::CryptoProvider;
use rustls24::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::sync::Arc;

/// Which provider `p` is.
fn which(p: &CryptoProvider) -> Option<TlsCryptoProvider> {
    match format!("{:?}", p.secure_random).as_str() {
        "Ring" => Some(TlsCryptoProvider::Ring),
        "RingAlcyon" => Some(TlsCryptoProvider::RingAlcyon),
        _ => None,
    }
}

#[test]
fn the_two_providers_have_names_apart() {
    assert_eq!(which(&rustls24_ring::DEFAULT_PROVIDER), Some(TlsCryptoProvider::Ring));
    assert_eq!(which(&rustls24_ringalcyon::DEFAULT_PROVIDER), Some(TlsCryptoProvider::RingAlcyon));
}

fn handshake(srv: &mut TlsCtx, cli: &mut TlsCtx) {
    let (mut sin, mut cin) = (VecInput::default(), VecInput::default());
    for _ in 0..30 {
        srv.handshake(&mut sin).expect("server handshake");
        cli.handshake(&mut cin).expect("client handshake");
        let mut moved = false;
        let out = cli.pending_tx().to_vec();
        if !out.is_empty() {
            cli.tx_done(out.len());
            sin.extend(&out, srv);
            moved = true;
        }
        let out = srv.pending_tx().to_vec();
        if !out.is_empty() {
            srv.tx_done(out.len());
            cin.extend(&out, cli);
            moved = true;
        }
        if !moved && !srv.is_handshaking() && !cli.is_handshaking() {
            return;
        }
    }
    panic!("the handshake did not finish");
}

#[test]
fn each_provider_completes_tls12_and_tls13_front_and_back() {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let der = CertificateDer::from(c.cert.der().to_vec());
    let key = c.key_pair.serialize_der();
    for kind in TlsCryptoProvider::ALL {
        let bind = BindTls::single_with(vec![der.clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone())), vec![], kind)
            .expect("bind");
        assert_eq!(bind.provider, kind);
        assert_eq!(which(bind.config.provider()), Some(kind), "bind of {kind:?}");
        for (max_ver, version) in [(TlsVersion::Tls12, "TLSv1.2"), (TlsVersion::Tls13, "TLSv1.3")] {
            let opts = BackendTlsOptions { verify_required: false, max_ver: Some(max_ver), ..Default::default() };
            let cfg = build_backend_client_config_with(&opts, kind).expect("client config");
            assert_eq!(which(cfg.provider()), Some(kind), "server line of {kind:?}");
            let mut srv = TlsCtx::accept(Arc::clone(&bind));
            let mut cli = TlsCtx::connect(&cfg, ServerName::try_from("localhost").unwrap(), Some("localhost".into()));
            handshake(&mut srv, &mut cli);
            assert_eq!(srv.tls_info.protocol_version.as_deref(), Some(version), "{kind:?}");
            assert_eq!(cli.tls_info.protocol_version.as_deref(), Some(version), "{kind:?}");
        }
    }
}

/// `ring-alcyon` is the zeroizing fork: the `zeroize` feature of `ringalcyon` is on in the graph
/// Alcyon builds (the wipes themselves are tested in ringalcyon, `vendor/README.md`).
#[test]
fn ringalcyon_is_built_with_zeroize() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let out = std::process::Command::new(env!("CARGO"))
        .args(["tree", "--offline", "-e", "features", "-p", "alcyon-tls", "-i", "ringalcyon", "--prefix", "none"])
        .current_dir(root)
        .output()
        .expect("cargo tree");
    let tree = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "cargo tree: {}", String::from_utf8_lossy(&out.stderr));
    assert!(tree.lines().any(|l| l.starts_with("ringalcyon feature \"zeroize\"")), "{tree}");
}
