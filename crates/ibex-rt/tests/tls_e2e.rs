// SPDX-License-Identifier: GPL-2.0-or-later

//! TLS end to end: the daemon serves HTTPS, and refuses to start when it cannot.
//!
//! This replaces `tls_fail_closed.rs`, which asserted that any `bind ... ssl` was
//! rejected because no transport existed. The transport exists now, so the property
//! under test changes from "refuse all TLS" to "serve TLS, or refuse for a reason" --
//! but the risk it guards has not moved. A listener on :443 that answers in cleartext,
//! to clients that believe they negotiated TLS, is worse than one that is down.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The daemon binary, as cargo built it for this test.
///
/// `CARGO_BIN_EXE_ibex` rather than a hand-built `target/debug/ibex` path: cargo
/// guarantees the binary exists and is finished before the test runs. Reaching into
/// `target/` directly raced the linker under `cargo test --workspace`, where the binary
/// is rebuilt while other test binaries are already running -- the test passed alone and
/// failed in the full suite, which is the worst way for a test to be wrong.
fn ibex_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_ibex"))
}


fn write_file(name: &str, body: &[u8]) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("ibex_tls_{}_{}", std::process::id(), name));
    std::fs::write(&p, body).expect("write");
    p
}

/// A PEM bundle holding a self-signed certificate and its key, as a `crt` file must.
fn cert_bundle(sans: &[&str]) -> (String, Vec<u8>) {
    let names: Vec<String> = sans.iter().map(|s| (*s).to_string()).collect();
    let c = rcgen::generate_simple_self_signed(names)
        .expect("generate cert");
    let pem = format!("{}{}", c.cert.pem(), c.key_pair.serialize_pem());
    (pem, c.cert.der().to_vec())
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(cfg: &std::path::Path) -> Option<Daemon> {
    let bin = ibex_bin();
    if !bin.exists() {
        eprintln!("skipping: {} not built", bin.display());
        return None;
    }
    Some(Daemon(
        Command::new(bin)
            .arg("-f")
            .arg(cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    ))
}

fn wait_for_port(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// The daemon completes a real TLS handshake and proxies the request underneath it.
#[test]
fn https_is_served_end_to_end() {
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    let (pem, der) = cert_bundle(&["localhost"]);
    let crt = write_file("e2e.pem", pem.as_bytes());

    // A backend that answers one request.
    let backend = std::net::TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let backend_port = backend.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = backend.accept() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret",
            );
        }
    });

    let port = common::reserve_port();
    let cfg = write_file(
        "e2e.cfg",
        format!(
            "defaults\n\tmode http\n\ttimeout connect 5s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\nfrontend fe\n\tbind 127.0.0.1:{port} ssl crt {}\n\t\
             default_backend be\n\nbackend be\n\tserver s1 127.0.0.1:{backend_port}\n",
            crt.display()
        )
        .as_bytes(),
    );

    let Some(_daemon) = start(&cfg) else { return };
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    // Same reason as the runtime: pick the provider rather than let feature unification
    // decide whether this test can construct a TLS client.
    ibex_tls::install_default_crypto_provider();

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(der))
        .expect("trust the test cert");
    let client_cfg = std::sync::Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let name = ServerName::try_from("localhost").expect("name");
    let conn = ClientConnection::new(client_cfg, name).expect("client conn");
    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut tls = StreamOwned::new(conn, sock);

    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write request through TLS");

    let mut got = Vec::new();
    let _ = tls.read_to_end(&mut got);
    let text = String::from_utf8_lossy(&got);

    assert!(
        text.starts_with("HTTP/1.1 200"),
        "expected a proxied response over TLS, got: {text:?}"
    );
    assert!(
        text.contains("secret"),
        "the backend body did not come back: {text:?}"
    );

    let _ = std::fs::remove_file(&cfg);
    let _ = std::fs::remove_file(&crt);
}

/// A TLS port must never answer a plaintext request as though it were HTTP.
///
/// This is the downgrade the old guard existed to prevent, tested directly: speak HTTP
/// at the TLS listener and check that nothing resembling a response comes back.
#[test]
fn a_tls_port_does_not_answer_cleartext() {
    let (pem, _) = cert_bundle(&["localhost"]);
    let crt = write_file("cleartext.pem", pem.as_bytes());
    let port = common::reserve_port();
    let cfg = write_file(
        "cleartext.cfg",
        format!(
            "defaults\n\tmode http\n\ttimeout connect 5s\n\ttimeout client 5s\n\t\
             timeout server 5s\n\nfrontend fe\n\tbind 127.0.0.1:{port} ssl crt {}\n\t\
             default_backend be\n\nbackend be\n\tserver s1 127.0.0.1:1\n",
            crt.display()
        )
        .as_bytes(),
    );

    let Some(_daemon) = start(&cfg) else { return };
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
    sock.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write cleartext");

    let mut buf = Vec::new();
    let _ = sock.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    assert!(
        !text.contains("HTTP/1."),
        "a TLS listener answered a cleartext request in the clear: {text:?}"
    );

    let _ = std::fs::remove_file(&cfg);
    let _ = std::fs::remove_file(&crt);
}

/// `ssl` with a certificate that cannot be loaded must refuse to start.
#[test]
fn a_missing_certificate_refuses_to_start() {
    let bin = ibex_bin();
    if !bin.exists() {
        return;
    }
    let port = common::reserve_port();
    let cfg = write_file(
        "missing.cfg",
        format!(
            "defaults\n\tmode http\n\ttimeout connect 5s\n\ttimeout client 5s\n\t\
             timeout server 5s\n\nfrontend fe\n\tbind 127.0.0.1:{port} ssl crt \
             /nonexistent/nope.pem\n\tdefault_backend be\n\nbackend be\n\t\
             server s1 127.0.0.1:1\n"
        )
        .as_bytes(),
    );
    let out = Command::new(&bin)
        .arg("-f")
        .arg(&cfg)
        .output()
        .expect("run ibex");
    assert!(
        !out.status.success(),
        "a bind whose certificate cannot be loaded must not start"
    );
    let _ = std::fs::remove_file(&cfg);
}

/// `ssl` with no `crt` is the same mistake and must be refused too.
#[test]
fn ssl_without_a_certificate_refuses_to_start() {
    let bin = ibex_bin();
    if !bin.exists() {
        return;
    }
    let port = common::reserve_port();
    let cfg = write_file(
        "nocrt.cfg",
        format!(
            "defaults\n\tmode http\n\ttimeout connect 5s\n\ttimeout client 5s\n\t\
             timeout server 5s\n\nfrontend fe\n\tbind 127.0.0.1:{port} ssl\n\t\
             default_backend be\n\nbackend be\n\tserver s1 127.0.0.1:1\n"
        )
        .as_bytes(),
    );
    let out = Command::new(&bin)
        .arg("-f")
        .arg(&cfg)
        .output()
        .expect("run ibex");
    assert!(
        !out.status.success(),
        "'ssl' with no 'crt' must not start: the port would be bound and undecryptable"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("crt"),
        "the refusal must name what is missing, got: {err}"
    );
    let _ = std::fs::remove_file(&cfg);
}

/// `-c` must load certificates, not just parse the file.
///
/// Reporting a config valid and then failing to start on it moves the discovery from CI
/// to production. `HAProxy`'s `-c` loads them.
#[test]
fn config_check_validates_certificates() {
    let bin = ibex_bin();
    if !bin.exists() {
        return;
    }
    let port = common::reserve_port();
    let cfg = write_file(
        "check.cfg",
        format!(
            "defaults\n\tmode http\n\ttimeout connect 5s\n\ttimeout client 5s\n\t\
             timeout server 5s\n\nfrontend fe\n\tbind 127.0.0.1:{port} ssl crt \
             /nonexistent/nope.pem\n\tdefault_backend be\n\nbackend be\n\t\
             server s1 127.0.0.1:1\n"
        )
        .as_bytes(),
    );
    let out = Command::new(&bin)
        .arg("-c")
        .arg("-f")
        .arg(&cfg)
        .output()
        .expect("run ibex -c");
    assert!(
        !out.status.success(),
        "-c reported a config valid whose certificate cannot be loaded; it would then \
         fail at startup, in production rather than in CI"
    );
    let _ = std::fs::remove_file(&cfg);
}

/// A plaintext bind still starts. The refusal must be about TLS, not about binds.
#[test]
fn a_plaintext_bind_still_starts() {
    let bin = ibex_bin();
    if !bin.exists() {
        return;
    }
    let port = common::reserve_port();
    let cfg = write_file(
        "plain.cfg",
        format!(
            "defaults\n\tmode http\n\ttimeout connect 5s\n\ttimeout client 5s\n\t\
             timeout server 5s\n\nfrontend fe\n\tbind 127.0.0.1:{port}\n\t\
             default_backend be\n\nbackend be\n\tserver s1 127.0.0.1:1\n"
        )
        .as_bytes(),
    );
    let out = Command::new(&bin)
        .arg("-c")
        .arg("-f")
        .arg(&cfg)
        .output()
        .expect("run ibex -c");
    assert!(
        out.status.success(),
        "a plaintext config must still validate: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_file(&cfg);
}

/// A client negotiating ALPN h2 over TLS receives an HTTP/2 response end-to-end through the daemon.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_is_served_over_tls_end_to_end() {
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
    use ibex_proto::h2::{H2_CONN_PREFACE, Frame, FrameHeader, FRAME_HEADER_LEN, frame_flags};
    use ibex_proto::hpack::HpackEncoder;
    use ibex_proto::htx::HeaderField;

    let (pem, der) = cert_bundle(&["localhost"]);
    let crt = write_file("h2_e2e.pem", pem.as_bytes());

    // A backend that answers one request.
    let backend = std::net::TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let backend_port = backend.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = backend.accept() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret",
            );
        }
    });

    let port = common::reserve_port();
    let cfg = write_file(
        "h2_e2e.cfg",
        format!(
            "defaults\n\tmode http\n\ttimeout connect 5s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\nfrontend fe\n\tbind 127.0.0.1:{port} ssl crt {} alpn h2,http/1.1\n\t\
             default_backend be\n\nbackend be\n\tserver s1 127.0.0.1:{backend_port}\n",
            crt.display()
        )
        .as_bytes(),
    );

    let Some(_daemon) = start(&cfg) else { return };
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    ibex_tls::install_default_crypto_provider();

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(der))
        .expect("trust the test cert");
    let mut client_cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h2".to_vec()];

    let name = ServerName::try_from("localhost").expect("name");
    let conn = ClientConnection::new(std::sync::Arc::new(client_cfg), name).expect("client conn");
    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut tls = StreamOwned::new(conn, sock);

    // Client writes preface + settings + HEADERS for stream 1
    let mut client_bytes = Vec::new();
    client_bytes.extend_from_slice(H2_CONN_PREFACE);
    client_bytes.extend_from_slice(&Frame::Settings { flags: 0, settings: vec![] }.encode());

    let mut enc = HpackEncoder::new();
    let headers = vec![
        HeaderField { name: ":method".into(), value: "GET".into() },
        HeaderField { name: ":path".into(), value: "/".into() },
        HeaderField { name: ":scheme".into(), value: "https".into() },
        HeaderField { name: ":authority".into(), value: "localhost".into() },
    ];
    let frame = Frame::Headers {
        flags: frame_flags::END_HEADERS | frame_flags::END_STREAM,
        stream_id: 1,
        header_block: enc.encode(&headers),
    };
    client_bytes.extend_from_slice(&frame.encode());

    tls.write_all(&client_bytes).expect("write h2 client request");
    tls.flush().expect("flush client request");

    assert_eq!(tls.conn.alpn_protocol(), Some(&b"h2"[..]), "expected ALPN h2 negotiated");

    let mut rx_buf = vec![0u8; 4096];
    let mut total_read = 0;
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut saw_status_200 = false;
    let mut saw_body_secret = false;

    while Instant::now() < deadline {
        match tls.read(&mut rx_buf[total_read..]) {
            Ok(0) => break,
            Ok(n) => {
                total_read += n;
                // Parse H2 frames received from daemon
                let mut cursor = 0;
                while cursor + FRAME_HEADER_LEN <= total_read {
                    let Ok(header) = FrameHeader::decode(&rx_buf[cursor..]) else { break };
                    let frame_end = cursor + FRAME_HEADER_LEN + header.length as usize;
                    if frame_end > total_read {
                        break;
                    }
                    let payload = &rx_buf[cursor + FRAME_HEADER_LEN..frame_end];
                    if let Ok(f) = Frame::decode(&header, payload) {
                        match f {
                            Frame::Headers { stream_id: 1, header_block, .. } => {
                                let mut dec = ibex_proto::hpack::HpackDecoder::new();
                                if let Ok(hdrs) = dec.decode(&header_block) {
                                    if hdrs.iter().any(|h| h.name == ":status" && h.value == "200") {
                                        saw_status_200 = true;
                                    }
                                }
                            }
                            Frame::Data { stream_id: 1, data, .. }
                                if data.windows(6).any(|w| w == b"secret") =>
                            {
                                saw_body_secret = true;
                            }
                            _ => {}
                        }
                    }
                    cursor = frame_end;
                }
                if saw_status_200 && saw_body_secret {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }

    assert!(saw_status_200, "daemon failed to answer HTTP/2 HEADERS with :status 200, received: {:?}", String::from_utf8_lossy(&rx_buf[..total_read]));
    assert!(saw_body_secret, "daemon failed to answer HTTP/2 DATA with backend payload 'secret'");

    let _ = std::fs::remove_file(&cfg);
    let _ = std::fs::remove_file(&crt);
}

