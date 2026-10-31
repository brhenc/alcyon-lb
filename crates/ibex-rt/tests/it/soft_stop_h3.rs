// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Soft stop of a QUIC listener (T108), as `soft_stop.rs` does for TCP: `SIGUSR1` -- which
//! `-sf <pid>` sends to the old process on every reload -- stops accepting, lets the HTTP/3
//! requests in flight finish, and exits. Before T108 the process left at once and curl
//! timed out, because a QUIC connection is not a session and the engine only counted those.

use crate::common;

use rustix::process::{kill_process, Pid, Signal};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// A backend that answers `/slow` after `delay` (never when `None`) and everything else at once.
fn slow_backend(delay: Option<Duration>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).unwrap_or(0);
                if !buf[..n].starts_with(b"GET /slow") {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nfast");
                    return;
                }
                match delay {
                    Some(d) => {
                        thread::sleep(d);
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow");
                    }
                    None => thread::sleep(Duration::from_secs(30)),
                }
            });
        }
    });
    addr
}

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
    quic: SocketAddr,
}

impl Ibex {
    fn start(be: SocketAddr, global: &str) -> Self {
        let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
        let tcp = common::reserve_addr();
        let quic = common::reserve_addr();
        let cfg = format!(
            "global\n  nbthread 1\n{global}\
             defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
             frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt}\n  default_backend be\n\
             backend be\n  server s1 {be}\n"
        );
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write cfg");
        let child = common::ibex_command(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(f.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ibex");
        assert!(common::wait_listening(tcp), "ibex never started listening on {tcp}");
        Self { child, _cfg: f, quic }
    }

    fn signal(&self, sig: Signal) {
        let pid = Pid::from_raw(i32::try_from(self.child.id()).expect("pid")).expect("pid");
        kill_process(pid, sig).expect("kill");
    }

    fn wait_exit(&mut self, within: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Ok(Some(st)) = self.child.try_wait() {
                return Some(st);
            }
            thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn require_curl_http3() {
    let ok = Command::new("curl")
        .arg("--version")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP3"));
    assert!(ok, "this test needs a curl with HTTP/3; it fails rather than skips");
}

fn curl(quic: SocketAddr, extra: &[&str], urls: &[&str]) -> Child {
    let mut c = Command::new("curl");
    c.args(["-sS", "--http3-only", "-k", "--max-time", "8", "--resolve"])
        .arg(format!("localhost:{}:127.0.0.1", quic.port()))
        .args(extra);
    for u in urls {
        c.arg(format!("https://localhost:{}{u}", quic.port()));
    }
    c.args(["-o", "-", "-w", "\n__STATUS__%{http_code} __VER__%{http_version}\n"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn curl")
}

crate::h3_both_paths! {
/// The request the old process is serving when `-sf` signals it must be completed over its
/// QUIC connection, and the process then leaves on its own.
fn sigusr1_finishes_the_h3_request_in_flight_then_exits() {
    require_curl_http3();
    let be = slow_backend(Some(Duration::from_millis(1500)));
    let mut ibex = Ibex::start(be, "");
    let client = curl(ibex.quic, &[], &["/slow"]);
    thread::sleep(Duration::from_millis(400));

    let signalled = Instant::now();
    ibex.signal(Signal::Usr1);
    let early = ibex.wait_exit(Duration::from_millis(400));
    assert!(early.is_none(), "the process left with an HTTP/3 request in flight: {early:?}");

    let out = client.wait_with_output().expect("curl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("slow") && stdout.contains("__STATUS__200 __VER__3"),
        "the in-flight HTTP/3 request must complete through a soft stop.\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let st = ibex.wait_exit(Duration::from_secs(3));
    assert!(
        st.is_some_and(|s| s.success()),
        "after the response, the process must exit cleanly; got {st:?} {:?} after the signal",
        signalled.elapsed()
    );
}
}

crate::h3_both_paths! {
/// While the old process drains, a new QUIC connection is refused rather than taken: its
/// client must go to the process that replaces this one.
fn a_soft_stopping_process_refuses_new_quic_connections() {
    require_curl_http3();
    let be = slow_backend(Some(Duration::from_millis(2500)));
    let mut ibex = Ibex::start(be, "");
    let first = curl(ibex.quic, &[], &["/slow"]);
    thread::sleep(Duration::from_millis(400));
    ibex.signal(Signal::Usr1);
    thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    let late = curl(ibex.quic, &[], &["/slow"]).wait_with_output().expect("curl");
    let late_out = String::from_utf8_lossy(&late.stdout);
    assert!(
        !late_out.contains("__STATUS__200"),
        "a connection opened after the soft stop must not be served.\nstdout: {late_out}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the refusal must be prompt, not a timeout: {:?}",
        started.elapsed()
    );

    let out = first.wait_with_output().expect("curl");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("__STATUS__200 __VER__3"),
        "the connection that was already there must still be served.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(ibex.wait_exit(Duration::from_secs(3)).is_some_and(|s| s.success()));
}
}

crate::h3_both_paths! {
/// `hard-stop-after` bounds a QUIC soft stop too: a request the backend never answers does
/// not keep the process alive indefinitely.
fn hard_stop_after_bounds_an_h3_soft_stop() {
    require_curl_http3();
    let be = slow_backend(None);
    let mut ibex = Ibex::start(be, "  hard-stop-after 700ms\n");
    let client = curl(ibex.quic, &[], &["/slow"]);
    thread::sleep(Duration::from_millis(400));

    let started = Instant::now();
    ibex.signal(Signal::Usr1);
    let st = ibex.wait_exit(Duration::from_secs(4));
    let took = started.elapsed();
    assert!(st.is_some_and(|s| s.success()), "hard-stop-after 700ms must end the soft stop; got {st:?}");
    // Both bounds: leaving at once is the T108 defect and would satisfy the upper one alone.
    assert!(
        took >= Duration::from_millis(500) && took < Duration::from_millis(2500),
        "hard-stop-after 700ms: the process exited after {took:?}"
    );
    let _ = client.wait_with_output();
}
}

/// A QUIC client that completes the handshake, negotiates `h3`, sends nothing, and keeps
/// answering the server's packets. curl cannot stand in for it: when idled with `--rate` it
/// stops servicing the connection, so it never acknowledges anything and a server that waits
/// for acknowledgements waits for it.
struct IdleClient {
    connected: Arc<AtomicBool>,
    /// When the server closed the connection, and with which application error code.
    closed: Arc<Mutex<Option<(Instant, Option<u64>)>>>,
    /// Bytes of response received on the request stream, when `get` was asked for.
    received: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl IdleClient {
    /// Connects; with `get`, also sends `GET <path>` (QPACK static table only, no dynamic state)
    /// once the handshake is done, and then goes quiet.
    fn connect(server: SocketAddr, get: Option<&'static str>) -> Self {
        use ibex_quic::quinn_proto::{
            crypto::rustls::QuicClientConfig, ClientConfig, ConnectionError, Endpoint, EndpointConfig, Event,
        };
        use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        #[derive(Debug)]
        struct Any;
        impl ServerCertVerifier for Any {
            fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                rustls::crypto::CryptoProvider::get_default()
                    .map(|p| p.signature_verification_algorithms.supported_schemes())
                    .unwrap_or_default()
            }
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut tls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(Any)).with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let client_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).expect("quic client config")));

        let connected = Arc::new(AtomicBool::new(false));
        let closed = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let received = Arc::new(AtomicUsize::new(0));
        let (c2, cl2, st2, rx2) = (Arc::clone(&connected), Arc::clone(&closed), Arc::clone(&stop), Arc::clone(&received));
        let thread = thread::spawn(move || {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("bind client");
            sock.set_read_timeout(Some(Duration::from_millis(5))).expect("timeout");
            let mut ep = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
            let (handle, mut conn) = ep.connect(Instant::now(), client_cfg, server, "localhost").expect("connect");
            let mut buf = vec![0u8; 2048];
            let mut out = Vec::new();
            let mut req_stream = None;
            while !st2.load(Ordering::Relaxed) {
                let now = Instant::now();
                if let Ok((n, from)) = sock.recv_from(&mut buf) {
                    let mut resp = Vec::new();
                    if let Some(ev) = ep.handle(now, from, None, None, buf[..n].into(), &mut resp) {
                        if let ibex_quic::quinn_proto::DatagramEvent::ConnectionEvent(_, e) = ev {
                            conn.handle_event(e);
                        }
                    }
                }
                if conn.poll_timeout().is_some_and(|t| t <= now) {
                    conn.handle_timeout(now);
                }
                while let Some(e) = conn.poll_endpoint_events() {
                    if let Some(ce) = ep.handle_event(handle, e) {
                        conn.handle_event(ce);
                    }
                }
                while let Some(ev) = conn.poll() {
                    match ev {
                        Event::Connected => {
                            c2.store(true, Ordering::Relaxed);
                            if let Some(path) = get {
                                let id = conn.streams().open(ibex_quic::quinn_proto::Dir::Bi).expect("open request stream");
                                let mut fields = vec![0x00, 0x00, 0xd1, 0xd7, 0x50, 9];
                                fields.extend_from_slice(b"localhost");
                                fields.extend_from_slice(&[0x51, u8::try_from(path.len()).expect("short path")]);
                                fields.extend_from_slice(path.as_bytes());
                                let mut req = vec![0x01, u8::try_from(fields.len()).expect("short field section")];
                                req.extend_from_slice(&fields);
                                let mut send = conn.send_stream(id);
                                send.write(&req).expect("write request");
                                send.finish().expect("finish request");
                                req_stream = Some(id);
                            }
                        }
                        Event::ConnectionLost { reason } => {
                            let code = match reason {
                                ConnectionError::ApplicationClosed(a) => Some(a.error_code.into_inner()),
                                _ => None,
                            };
                            *cl2.lock().expect("lock") = Some((Instant::now(), code));
                        }
                        _ => {}
                    }
                }
                if let Some(id) = req_stream {
                    let mut rs = conn.recv_stream(id);
                    let chunks = rs.read(true);
                    if let Ok(mut chunks) = chunks {
                        while let Ok(Some(c)) = chunks.next(usize::MAX) {
                            rx2.fetch_add(c.bytes.len(), Ordering::Relaxed);
                        }
                        let _ = chunks.finalize();
                    }
                }
                loop {
                    out.clear();
                    let Some(t) = conn.poll_transmit(Instant::now(), 1, &mut out) else { break };
                    let _ = sock.send_to(&out[..t.size], t.destination);
                }
            }
        });
        Self { connected, closed, received, stop, thread: Some(thread) }
    }

    fn wait_connected(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.connected.load(Ordering::Relaxed) {
            assert!(Instant::now() < deadline, "the idle QUIC client never completed its handshake");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_response(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.received.load(Ordering::Relaxed) == 0 {
            assert!(Instant::now() < deadline, "the idle QUIC client got no response to its request");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn closed(&self) -> Option<(Instant, Option<u64>)> {
        *self.closed.lock().expect("lock")
    }
}

impl Drop for IdleClient {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

crate::h3_both_paths! {
/// An HTTP/3 connection that is open but idle is not work in flight: the server closes it
/// (H3_NO_ERROR, 0x100) and the process leaves, instead of waiting for the client's own idle
/// timeout. A request in flight on another connection is what makes the stop wait at all.
fn an_idle_h3_connection_does_not_hold_a_soft_stop_open() {
    require_curl_http3();
    let be = slow_backend(Some(Duration::from_millis(1500)));
    let mut ibex = Ibex::start(be, "");
    // It asks for something and gets it, so what is idle is a connection whose response has
    // been delivered and acknowledged -- the state `unacked` tracks.
    let idle = IdleClient::connect(ibex.quic, Some("/fast"));
    idle.wait_connected();
    idle.wait_response();
    thread::sleep(Duration::from_millis(200));
    let busy = curl(ibex.quic, &[], &["/slow"]);
    thread::sleep(Duration::from_millis(400));
    assert!(idle.closed().is_none(), "setup: the idle connection must be open before the signal");

    ibex.signal(Signal::Usr1);
    let out = busy.wait_with_output().expect("curl");
    let done = Instant::now();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("slow\n__STATUS__200 __VER__3"),
        "the request in flight must complete.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let st = ibex.wait_exit(Duration::from_millis(1500));
    assert!(
        st.is_some_and(|s| s.success()),
        "an idle HTTP/3 connection held the soft stop open; got {st:?} {:?} after the last response",
        done.elapsed()
    );
    let closed = idle.closed();
    assert_eq!(
        closed.map(|c| c.1),
        Some(Some(0x100)),
        "the idle connection must be closed by the server with H3_NO_ERROR, not abandoned"
    );
}
}

crate::h3_both_paths! {
/// A request the listener refuses itself (here a header block too large for the HTX buffer)
/// is answered with an error over the same connection, and that response is as owed as any
/// other: the connection is not closed under it by a soft stop.
fn an_error_response_is_delivered_and_the_stop_completes() {
    require_curl_http3();
    let be = slow_backend(Some(Duration::from_millis(0)));
    let mut ibex = Ibex::start(be, "");
    let big = format!("X-Big: {}", "a".repeat(20_000));
    let client = curl(ibex.quic, &["-H", &big], &["/slow"]);
    let out = client.wait_with_output().expect("curl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Since T130 the head is refused by the stream engine, as on H1, where Ibex answers 400
    // (HAProxy 3.5 answers 431 on H1, and over HTTP/3 does not answer at all: curl times
    // out). Either error is a delivered response, which is what this test is about.
    // Through the h3 mux (`tune.ibex.h3-path mux`, T509) the HEADERS frame past `bufsize - 4`
    // is `H3_EXCESSIVE_LOAD` before any stream exists, and nothing answers it, as HAProxy.
    let mux = common::h3_mux();
    assert!(
        stdout.contains("__STATUS__431 __VER__3") || stdout.contains("__STATUS__400 __VER__3") || (mux && stdout.contains("__STATUS__000")),
        "an oversized request must be refused with an error over HTTP/3.\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    ibex.signal(Signal::Usr1);
    assert!(ibex.wait_exit(Duration::from_secs(3)).is_some_and(|s| s.success()));
}
}
