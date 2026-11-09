// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T462: after each handshake step, the stack below `TlsCtx`'s frame holds none of the
//! handshake's secrets (`alcyon_alloc::scrub_stack`, under `tune.alcyon.ssl-zero-buffers`).
//!
//! The secrets are known through a `KeyLog` on both configurations (TLS 1.3 traffic secrets,
//! the TLS 1.2 master secret): rustls derives them with ring's HKDF/PRF, whose `Copy` HMAC
//! outputs and the moves of rustls's own secret types leave copies in the frames below.
//! Each step is the same call depth: `step` paints the stack below it, calls the TLS layer, and
//! copies what is below it out (`alcyon_alloc::stack_probe`, test-only). The scrub off on this
//! thread (its copy of the setting only, the other tests keep theirs), the copies must hold a
//! secret, so that the probe is shown to see them; on, none. The same runs measure how deep the
//! handshake goes below `TlsCtx` (the first painted byte that changed), which
//! `alcyon_alloc::STACK_SCRUB_BYTES` must exceed.
//!
//! Runs in a thread of its own with an 8 MiB stack, so that the probe's window (1 MiB) is
//! mapped stack whatever the test harness's thread size.

#![cfg(target_arch = "x86_64")]

use alcyon_alloc::stack_probe;
use alcyon_tls::config::BackendTlsOptions;
use alcyon_tls::conn::{TlsCtx, VecInput};
use alcyon_config::TlsCryptoProvider;
use alcyon_tls::tcp::{build_backend_client_config_with, rustls24, BindTls};
use rustls24::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::sync::{Arc, Mutex};

/// The window the probe reads and paints below `step`'s frame.
const WINDOW: usize = 1024 * 1024;
const PAINT: u8 = 0xa5;

#[derive(Debug, Default)]
struct Secrets(Mutex<Vec<(String, Vec<u8>)>>);

impl rustls24::KeyLog for Secrets {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        self.0.lock().unwrap().push((label.to_string(), secret.to_vec()));
    }
}

#[derive(Clone, Copy, Debug)]
enum Cert {
    Rsa4096,
    P384,
}

#[derive(Clone, Copy, Debug)]
enum Kx {
    X25519,
    P384,
}

fn load(cert: Cert) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let pem: &[u8] = match cert {
        Cert::Rsa4096 => include_bytes!("../data/stack-scrub-rsa4096.pem"),
        Cert::P384 => include_bytes!("../data/stack-scrub-p384.pem"),
    };
    let certs = rustls_pemfile::certs(&mut &*pem).collect::<Result<Vec<_>, _>>().expect("certs");
    let key = rustls_pemfile::private_key(&mut &*pem).expect("key").expect("a key");
    (certs, key)
}

/// A bind on `cert` logging its secrets to `log`; with `kx` P-384, the server accepts only
/// that group (the client's X25519 share gets a `HelloRetryRequest`).
fn bind(prov: TlsCryptoProvider, cert: Cert, kx: Kx, log: &Arc<Secrets>) -> Arc<BindTls> {
    let (certs, key) = load(cert);
    let b = BindTls::single_with(certs, key, vec![], prov).expect("bind");
    let mut cfg = (*b.config).clone();
    if let Kx::P384 = kx {
        let mut p = (*alcyon_tls::provider::of(b.provider, true, true)).clone();
        p.kx_groups = p.kx_groups.iter().copied().filter(|g| g.name() == rustls24::crypto::kx::NamedGroup::secp384r1).collect();
        assert_eq!(p.kx_groups.len(), 1, "the provider has P-384");
        let mut c = rustls24::ServerConfig::builder(Arc::new(p))
            .with_no_client_auth()
            .with_server_credential_resolver(Arc::clone(&cfg.cert_resolver))
            .expect("P-384 config");
        c.ticketer.clone_from(&cfg.ticketer);
        cfg = c;
    }
    cfg.key_log = Arc::clone(log) as Arc<dyn rustls24::KeyLog>;
    let cfg = Arc::new(cfg);
    Arc::new(BindTls::from_parts(Arc::clone(&cfg), cfg, Arc::clone(&b.resolver), b.provider))
}

/// One call into the TLS layer at a fixed depth: paints the window below, calls, copies the
/// window into `snap`.
#[inline(never)]
fn step(ctx: &mut TlsCtx, input: &mut VecInput, snap: &mut [u8]) -> Result<(), rustls24::Error> {
    stack_probe::paint_below(snap.len(), PAINT);
    let r = ctx.handshake(input);
    stack_probe::copy_below(snap);
    r
}

/// [`step`] for the client's first flight (`TlsCtx::connect`).
#[inline(never)]
fn connect_step(cfg: &Arc<rustls24::ClientConfig>, snap: &mut [u8]) -> TlsCtx {
    stack_probe::paint_below(snap.len(), PAINT);
    let ctx = TlsCtx::connect(cfg, ServerName::try_from("localhost").unwrap(), Some("localhost".into()));
    stack_probe::copy_below(snap);
    ctx
}

struct Outcome {
    /// How far below `step`'s frame the deepest call wrote.
    depth: usize,
    /// Secrets (label) found in a copy, and in which step.
    found: Vec<(String, usize)>,
    secrets: usize,
    version: String,
}

fn shuttle(from: &mut TlsCtx, to_in: &mut VecInput, to: &TlsCtx) -> bool {
    let out = from.pending_tx().to_vec();
    if out.is_empty() {
        return false;
    }
    from.tx_done(out.len());
    to_in.extend(&out, to);
    true
}

fn handshake(prov: TlsCryptoProvider, cert: Cert, kx: Kx, tls12: bool, scrub: bool) -> Outcome {
    stack_probe::set_thread_ssl_zero_buffers(scrub);
    let log = Arc::new(Secrets::default());
    let b = bind(prov, cert, kx, &log);
    let max_ver = tls12.then_some(alcyon_config::TlsVersion::Tls12);
    let opts = BackendTlsOptions { verify_required: false, max_ver, ..Default::default() };
    let mut ccfg = (*build_backend_client_config_with(&opts, prov).expect("client config")).clone();
    ccfg.key_log = Arc::clone(&log) as Arc<dyn rustls24::KeyLog>;
    let ccfg = Arc::new(ccfg);

    let mut snaps: Vec<Vec<u8>> = Vec::new();
    let mut snap = vec![0u8; WINDOW];
    let mut cli = connect_step(&ccfg, &mut snap);
    snaps.push(snap.clone());
    let mut srv = TlsCtx::accept(b);
    let (mut sin, mut cin) = (VecInput::default(), VecInput::default());
    for _ in 0..30 {
        let mut moved = shuttle(&mut cli, &mut sin, &srv);
        if srv.is_handshaking() {
            step(&mut srv, &mut sin, &mut snap).expect("server handshake");
            snaps.push(snap.clone());
        }
        moved |= shuttle(&mut srv, &mut cin, &cli);
        if cli.is_handshaking() {
            step(&mut cli, &mut cin, &mut snap).expect("client handshake");
            snaps.push(snap.clone());
        }
        if !moved && !srv.is_handshaking() && !cli.is_handshaking() {
            break;
        }
    }
    stack_probe::set_thread_ssl_zero_buffers(true);
    assert!(!srv.is_handshaking() && !cli.is_handshaking(), "{cert:?} {kx:?} tls12={tls12}: handshake did not finish");
    let version = srv.tls_info.protocol_version.clone().unwrap_or_default();
    let depth = snaps.iter().map(|s| s.iter().position(|&b| b != PAINT).map_or(0, |i| WINDOW - i)).max().unwrap_or(0);
    let secrets = log.0.lock().unwrap().clone();
    let mut found = Vec::new();
    for (label, secret) in &secrets {
        for (i, s) in snaps.iter().enumerate() {
            if s.windows(secret.len()).any(|w| w == secret.as_slice()) && !found.contains(&(label.clone(), i)) {
                found.push((label.clone(), i));
            }
        }
    }
    Outcome { depth, found, secrets: secrets.len(), version }
}

/// Both providers, both certificates, both key exchanges, both versions.
fn cases() -> impl Iterator<Item = (TlsCryptoProvider, Cert, Kx, bool)> {
    [TlsCryptoProvider::Ring, TlsCryptoProvider::RingAlcyon].into_iter().flat_map(|p| {
        [Cert::Rsa4096, Cert::P384]
            .into_iter()
            .flat_map(move |c| [Kx::X25519, Kx::P384].into_iter().flat_map(move |k| [false, true].map(|v| (p, c, k, v))))
    })
}

fn in_big_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new().stack_size(8 << 20).spawn(f).expect("thread").join().expect("probe thread")
}

#[test]
fn no_handshake_secret_is_left_on_the_stack_below_the_tls_layer() {
    in_big_thread(|| {
        let mut deepest = 0;
        for (prov, cert, kx, tls12) in cases() {
                    let off = handshake(prov, cert, kx, tls12, false);
                    let on = handshake(prov, cert, kx, tls12, true);
                    eprintln!(
                        "stack_scrub: {prov:?} {cert:?} {kx:?} {}: depth {} B, {} secrets logged, (secret, step) found: {} without the scrub, {} with",
                        off.version,
                        off.depth,
                        off.secrets,
                        off.found.len(),
                        on.found.len()
                    );
                    assert_eq!(off.version, if tls12 { "TLSv1.2" } else { "TLSv1.3" });
                    assert!(off.secrets > 0, "the key log saw the secrets");
                    // The control: without the scrub the probe sees what the handshake left.
                    assert!(!off.found.is_empty(), "{cert:?} {kx:?} {}: the probe found no secret even without the scrub", off.version);
                    assert!(on.found.is_empty(), "{cert:?} {kx:?} {}: secrets left on the stack: {:?}", on.version, on.found);
                    deepest = deepest.max(off.depth);
        }
        eprintln!("stack_scrub: deepest {deepest} B, STACK_SCRUB_BYTES {}", alcyon_alloc::STACK_SCRUB_BYTES);
        assert!(deepest < alcyon_alloc::STACK_SCRUB_BYTES, "the handshake went {deepest} B deep, past the scrub");
    });
}

#[test]
#[allow(clippy::naive_bytecount)] // no bytecount dependency for a test
fn the_scrub_follows_ssl_zero_buffers_on_this_thread() {
    // Off, nothing is zeroed: the painted window is still painted after a call that does
    // nothing else.
    in_big_thread(|| {
        let mut snap = vec![0u8; 256 * 1024];
        stack_probe::set_thread_ssl_zero_buffers(false);
        scrub_at_depth(&mut snap);
        stack_probe::set_thread_ssl_zero_buffers(true);
        let zeros_off = snap.iter().filter(|&&b| b == 0).count();
        scrub_at_depth(&mut snap);
        let zeros_on = snap.iter().filter(|&&b| b == 0).count();
        assert!(zeros_off < 1024, "off: {zeros_off} zero bytes below");
        assert!(zeros_on >= alcyon_alloc::STACK_SCRUB_BYTES.min(snap.len()) - 1024, "on: only {zeros_on} zero bytes below");
    });
}

#[inline(never)]
fn scrub_at_depth(snap: &mut [u8]) {
    stack_probe::paint_below(snap.len(), PAINT);
    alcyon_alloc::scrub_stack();
    stack_probe::copy_below(snap);
}
