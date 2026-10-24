// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T460: `tune.ibex.crypto-provider ring|ring-ibex` (Ibex-only) picks the rustls provider of
//! every TCP TLS configuration, `set ssl crypto-provider` changes it at run time for the
//! handshakes that start after it, and `show ssl crypto-provider` reports the provider and the
//! handshakes completed on each. `ring-ibex` with a TLS user still on rustls 0.23 (QUIC,
//! log-forward TLS binds, ring TLS servers) is refused at startup: those would run on vanilla
//! ring while the operator asked for the zeroizing fork.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ibex-t460-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A self-signed `localhost` certificate and key in `d/c.pem`, and the certificate.
fn cert(d: &std::path::Path) -> (String, rustls::pki_types::CertificateDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let path = d.join("c.pem");
    std::fs::write(&path, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("write pem");
    (path.display().to_string(), ck.cert.der().clone())
}

/// `ibex -c` on `cfg`: whether it passed, and what it wrote.
fn check(tag: &str, cfg: &str) -> (bool, String) {
    let d = dir(tag);
    let (pem, _) = cert(&d);
    let path = d.join("c.cfg");
    std::fs::write(&path, cfg.replace("{pem}", &pem)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("ibex -c");
    let _ = std::fs::remove_dir_all(&d);
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

fn port() -> u16 {
    common::reserve_addr().port()
}

#[test]
fn ring_ibex_with_a_rustls_023_user_is_refused_and_ring_is_not() {
    let quic = format!("frontend fe\n  bind quic4@127.0.0.1:{} ssl crt {{pem}} alpn h3\n", port());
    let logfwd = format!("log-forward lf\n  bind 127.0.0.1:{} ssl crt {{pem}}\n  log 127.0.0.1:{} local0\n", port(), port());
    let ring = format!("ring r\n  format rfc5424\n  size 4096\n  server s 127.0.0.1:{} ssl verify none\n", port());
    for (what, body, says) in [("quic", &quic, "QUIC bind"), ("logfwd", &logfwd, "log-forward 'lf'"), ("ring", &ring, "ring 'r'")] {
        let (ok, out) = check(what, &format!("global\n  tune.ibex.crypto-provider ring-ibex\n{body}"));
        assert!(!ok, "{what}: ring-ibex accepted: {out}");
        assert!(out.contains("'tune.ibex.crypto-provider ring-ibex'") && out.contains(says) && out.contains("rustls 0.23"), "{what}: {out}");
        let (ok, out) = check(what, &format!("global\n  tune.ibex.crypto-provider ring\n{body}"));
        assert!(ok, "{what}: ring refused: {out}");
    }
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// `show ssl crypto-provider`: the current provider, and the handshakes of `ring` and `ring-ibex`.
fn shown(sock: &str) -> (String, u64, u64) {
    let out = cli(sock, "show ssl crypto-provider");
    let mut current = String::new();
    let (mut ring, mut ibex) = (None, None);
    for l in out.lines() {
        let w: Vec<&str> = l.split_whitespace().collect();
        match w.as_slice() {
            ["current", p] => current = (*p).to_string(),
            ["provider", "ring", "handshakes", n] => ring = n.parse().ok(),
            ["provider", "ring-ibex", "handshakes", n] => ibex = n.parse().ok(),
            _ => {}
        }
    }
    (current, ring.unwrap_or_else(|| panic!("no ring line: {out:?}")), ibex.unwrap_or_else(|| panic!("no ring-ibex line: {out:?}")))
}

/// `provider` serves two frontends, one to a backend on TLS 1.2 and one on TLS 1.3, both to an
/// origin on a TLS bind of the same process; `None` leaves the keyword out.
fn start(tag: &str, provider: Option<&str>) -> (Ibex, String, [SocketAddr; 2], rustls::pki_types::CertificateDer<'static>) {
    let d = dir(tag);
    let (pem, der) = cert(&d);
    let sock = d.join("cli.sock").display().to_string();
    let (f12, f13, origin) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let kw = provider.map(|p| format!("  tune.ibex.crypto-provider {p}\n")).unwrap_or_default();
    let cfg = format!(
        "global\n  nbthread 2\n  stats socket {sock} level admin\n{kw}\
         defaults\n  mode http\n  http-reuse never\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f12\n  bind {f12} ssl crt {pem} ssl-min-ver TLSv1.2 ssl-max-ver TLSv1.2\n  default_backend b12\n\
         frontend f13\n  bind {f13} ssl crt {pem} ssl-min-ver TLSv1.3\n  default_backend b13\n\
         backend b12\n  server s {origin} ssl verify none ssl-max-ver TLSv1.2\n\
         backend b13\n  server s {origin} ssl verify none ssl-min-ver TLSv1.3\n\
         listen origin\n  bind {origin} ssl crt {pem}\n  http-request return status 200 content-type text/plain lf-string \"%[ssl_fc_protocol]\"\n"
    );
    let path = d.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, d);
    for a in [f12, f13, origin] {
        assert!(common::wait_listening(a), "ibex did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    (ibex, sock, [f12, f13], der)
}

type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn client(cert: &rustls::pki_types::CertificateDer<'static>, version: &'static rustls::SupportedProtocolVersion) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("root");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
}

fn tls_connect(addr: SocketAddr, cert: &rustls::pki_types::CertificateDer<'static>, version: &'static rustls::SupportedProtocolVersion) -> Tls {
    connect_with(addr, client(cert, version))
}

/// A connection of `cfg`, which keeps the sessions its connections were given (resumption).
fn connect_with(addr: SocketAddr, cfg: Arc<rustls::ClientConfig>) -> Tls {
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(cfg, name).expect("client");
    let tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    rustls::StreamOwned::new(conn, tcp)
}

/// One request on `tls`; the answer's body (the origin's `ssl_fc_protocol`).
fn request(tls: &mut Tls, close: bool) -> String {
    let conn = if close { "Connection: close\r\n" } else { "" };
    tls.write_all(format!("GET / HTTP/1.1\r\nHost: localhost\r\n{conn}\r\n").as_bytes()).expect("write");
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let text = String::from_utf8_lossy(&out).into_owned();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let len = head.lines().find_map(|l| l.strip_prefix("content-length: ").or_else(|| l.strip_prefix("Content-Length: "))).and_then(|n| n.trim().parse::<usize>().ok());
            if len.is_some_and(|n| body.len() >= n) {
                assert!(head.starts_with("HTTP/1.1 200"), "{text}");
                return body.to_string();
            }
        }
        match tls.read(&mut buf) {
            Ok(0) | Err(_) => panic!("no whole answer: {text:?}"),
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
}

/// Waits up to 3 s for the counters to read `want`; the last reading.
fn settle(sock: &str, want: (u64, u64)) -> (String, u64, u64) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let s = shown(sock);
        if (s.1, s.2) == want || Instant::now() >= deadline {
            return s;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn each_provider_serves_tls12_and_tls13_front_and_back_and_counts_its_handshakes() {
    for (provider, name) in [(None, "ring"), (Some("ring"), "ring"), (Some("ring-ibex"), "ring-ibex")] {
        let (_ibex, sock, [f12, f13], der) = start(&format!("hs-{name}-{}", provider.is_some()), provider);
        assert_eq!(shown(&sock), (name.to_string(), 0, 0), "{provider:?} at start");
        for (addr, version, proto) in [(f12, &rustls::version::TLS12, "TLSv1.2"), (f13, &rustls::version::TLS13, "TLSv1.3")] {
            let mut t = tls_connect(addr, &der, version);
            assert_eq!(request(&mut t, true), proto, "{provider:?}: the origin's protocol");
            assert_eq!(t.conn.protocol_version(), Some(version.version), "{provider:?}: the client's");
        }
        // Each request: the client to the frontend, the backend to the origin, as the origin.
        let want = if name == "ring" { (6, 0) } else { (0, 6) };
        assert_eq!(settle(&sock, want), (name.to_string(), want.0, want.1), "{provider:?} after two requests");
    }
}

/// `set ssl crypto-provider`: a connection open before the swap keeps serving on the provider it
/// started with; handshakes after it run on the new one; a resumed session from before the swap
/// becomes a full handshake (the ticket keys are the provider's), never a failed one; an unknown
/// name, and a swap that cannot load a certificate, change nothing.
#[test]
fn a_swap_at_run_time_moves_new_handshakes_and_keeps_open_connections() {
    let (_ibex, sock, [f12, f13], der) = start("swap", None);
    let resuming = client(&der, &rustls::version::TLS13);
    let mut first = connect_with(f13, Arc::clone(&resuming));
    assert_eq!(request(&mut first, true), "TLSv1.3");
    let mut again = connect_with(f13, Arc::clone(&resuming));
    assert_eq!(request(&mut again, true), "TLSv1.3");
    assert_eq!(again.conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed), "resumption works before the swap");
    let mut kept = tls_connect(f13, &der, &rustls::version::TLS13);
    assert_eq!(request(&mut kept, false), "TLSv1.3");
    assert_eq!(settle(&sock, (9, 0)), ("ring".to_string(), 9, 0), "three requests on ring");

    for bad in ["openssl", "", "ring ring-ibex"] {
        let out = cli(&sock, &format!("set ssl crypto-provider {bad}"));
        assert!(out.contains("'set ssl crypto-provider' expects 'ring' or 'ring-ibex'"), "{bad:?}: {out:?}");
    }
    assert_eq!(shown(&sock), ("ring".to_string(), 9, 0), "an unknown name changes nothing");

    let out = cli(&sock, "set ssl crypto-provider ring-ibex");
    assert!(out.contains("now 'ring-ibex'"), "{out:?}");
    assert_eq!(shown(&sock).0, "ring-ibex");
    // The open connection keeps its session, and its server connection (the session's own,
    // http-reuse never or not): no new handshake.
    assert_eq!(request(&mut kept, false), "TLSv1.3", "the connection from before the swap");
    assert_eq!(settle(&sock, (9, 0)), ("ring-ibex".to_string(), 9, 0));
    let mut t = tls_connect(f12, &der, &rustls::version::TLS12);
    assert_eq!(request(&mut t, true), "TLSv1.2");
    let mut after = connect_with(f13, Arc::clone(&resuming));
    assert_eq!(request(&mut after, true), "TLSv1.3", "a session from before the swap still connects");
    assert_eq!(after.conn.handshake_kind(), Some(rustls::HandshakeKind::Full), "its ticket does not open under the new provider");
    assert_eq!(settle(&sock, (9, 6)), ("ring-ibex".to_string(), 9, 6));

    // Back again: the configurations built at startup serve.
    let out = cli(&sock, "set ssl crypto-provider ring");
    assert!(out.contains("now 'ring'"), "{out:?}");
    let mut t = tls_connect(f12, &der, &rustls::version::TLS12);
    assert_eq!(request(&mut t, true), "TLSv1.2");
    assert_eq!(settle(&sock, (12, 6)), ("ring".to_string(), 12, 6));
    // The swap to a provider already current is accepted and changes nothing.
    assert!(cli(&sock, "set ssl crypto-provider ring").contains("now 'ring'"));
    assert_eq!(shown(&sock), ("ring".to_string(), 12, 6));
    assert_eq!(request(&mut kept, true), "TLSv1.3", "still serving after two swaps");
}

#[test]
fn a_swap_that_cannot_build_every_configuration_changes_nothing() {
    let (ibex, sock, [f12, _], der) = start("swapfail", Some("ring"));
    let mut t = tls_connect(f12, &der, &rustls::version::TLS12);
    assert_eq!(request(&mut t, true), "TLSv1.2");
    // Every worker has loaded the certificate (each builds its listeners when it starts).
    std::thread::sleep(Duration::from_millis(300));
    // The certificate cannot be loaded again: the configurations of `ring-ibex` cannot be built.
    std::fs::write(ibex.1.join("c.pem"), "not a certificate\n").unwrap();
    let out = cli(&sock, "set ssl crypto-provider ring-ibex");
    assert!(out.contains("unchanged") && out.contains("'ring'") && out.contains("c.pem"), "{out:?}");
    assert_eq!(settle(&sock, (3, 0)), ("ring".to_string(), 3, 0));
    let mut t = tls_connect(f12, &der, &rustls::version::TLS12);
    assert_eq!(request(&mut t, true), "TLSv1.2");
    assert_eq!(settle(&sock, (6, 0)), ("ring".to_string(), 6, 0), "ring still serves");
}

#[test]
fn a_swap_to_ring_ibex_with_quic_is_refused_at_run_time() {
    let d = dir("swapquic");
    let (pem, _) = cert(&d);
    let sock = d.join("cli.sock").display().to_string();
    let (tcp, quic) = (common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "global\n  stats socket {sock} level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {pem} alpn h3\n  http-request return status 200\n"
    );
    std::fs::write(d.join("c.cfg"), cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(d.join("c.cfg")).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _ibex = Ibex(child, d);
    assert!(common::wait_listening(tcp));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = cli(&sock, "set ssl crypto-provider ring-ibex");
    assert!(out.contains("unchanged") && out.contains("QUIC bind") && out.contains("rustls 0.23"), "{out:?}");
    assert_eq!(shown(&sock).0, "ring");
}
