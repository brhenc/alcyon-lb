// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T569: a QUIC peer that ignores ACK_FREQUENCY and acknowledges every packet, told apart from
//! one that honours it, by the per-connection counters quinn-proto keeps (`AckStats`, vendored
//! change 8) as the `ibex_fc_quic_ack_*` fetches, `show quic ibex-acks` and the `QuicAck*` lines
//! of `show info` give them.
//!
//! `HAProxy` 3.5-dev10 (`reference/haproxy-quic`) has no equivalent: it sends no ACK_FREQUENCY,
//! and neither its `quic_*` stats (`src/quic_stats.c`) nor its fetches (`doc/configuration.txt`)
//! count the peer's ACK-only packets. The names are Ibex extensions (docs/differences.md).
//!
//! Both clients are quinn-proto driven by hand and advertise `min_ack_delay`, so Ibex sends both
//! ACK_FREQUENCY (threshold 2: an ACK every third ack-eliciting packet, or after 25 ms). The
//! compliant one reads its socket every 150 us and acknowledges as quinn-proto decides. The
//! flooder takes the datagrams one at a time and runs its clock 30 ms ahead after each, so its
//! `max_ack_delay` timer fires for every packet: an immediate ACK-only per packet, as a peer
//! that ignored the frame would send. Each response is ~12 kB, about ten packets.

use crate::common;

use ibex_quic::quinn_proto::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, ConnectionHandle, Dir, Endpoint, EndpointConfig, StreamId,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

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
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

struct Rig {
    _ibex: common::Ibex,
    dir: std::path::PathBuf,
    sock: String,
    quic: SocketAddr,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Ibex on the mux path with ACK_FREQUENCY on (`ack` the extra global lines), answering every
/// request with a 12 kB body and the connection's counters in headers, or 429 once the
/// unexplained ACKs pass 20.
fn start(tag: &str, ack: &str) -> Rig {
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let quic = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("t569-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let sock = dir.join("cli.sock").display().to_string();
    let body = dir.join("body.txt");
    std::fs::write(&body, vec![b'x'; 12_000]).expect("body");
    let cfg = format!(
        "global\n  stats socket {sock} level admin\n  nbthread 1\n  tune.ibex.h3-path mux\n{ack}\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
         frontend fe\n  bind quic4@{quic} ssl crt {crt} alpn h3\n\
         \x20 http-request return status 429 if {{ ibex_fc_quic_ack_excess gt 20 }}\n\
         \x20 http-request return status 200 content-type text/plain file {} hdr x-excess \"%[ibex_fc_quic_ack_excess]\" hdr x-ratio \"%[ibex_fc_quic_ack_ratio]\" hdr x-only \"%[ibex_fc_quic_ack_only_rcvd]\" hdr x-sent \"%[ibex_fc_quic_ack_eliciting_sent]\"\n",
        body.display()
    );
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).expect("cfg");
    let child = common::ibex_command(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let ibex = common::Ibex(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket (config refused?)");
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(300));
    Rig { _ibex: ibex, dir, sock, quic }
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// A response: status and the `x-*` headers.
#[derive(Debug, Default)]
struct Resp {
    status: u16,
    hdrs: Vec<(String, String)>,
    body: usize,
}

impl Resp {
    fn hdr(&self, n: &str) -> Option<&str> {
        self.hdrs.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str())
    }
}

struct Client {
    sock: UdpSocket,
    ep: Endpoint,
    handle: ConnectionHandle,
    conn: Connection,
    buf: Vec<u8>,
    /// `Some`: the flooder, its clock this far ahead of the real one.
    skew: Option<Duration>,
}

impl Client {
    fn connect(server: SocketAddr, flood: bool) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut ctls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(std::sync::Arc::new(Any)).with_no_client_auth();
        ctls.alpn_protocols = vec![b"h3".to_vec()];
        let mut client_cfg = ClientConfig::new(std::sync::Arc::new(QuicClientConfig::try_from(ctls).expect("client config")));
        // Both advertise `min_ack_delay`: both are sent ACK_FREQUENCY.
        let mut tc = ibex_quic::quinn_proto::TransportConfig::default();
        tc.ack_frequency_config(Some(ibex_quic::quinn_proto::AckFrequencyConfig::default()));
        client_cfg.transport_config(std::sync::Arc::new(tc));
        let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
        sock.set_nonblocking(true).expect("nonblocking");
        let mut ep = Endpoint::new(std::sync::Arc::new(EndpointConfig::default()), None, true, None);
        let (handle, conn) = ep.connect(Instant::now(), client_cfg, server, "localhost").expect("connect");
        let mut c = Self { sock, ep, handle, conn, buf: vec![0u8; 65536], skew: None };
        c.run_until(Duration::from_secs(4), |c| !c.conn.is_handshaking());
        assert!(!c.conn.is_handshaking(), "no handshake");
        let ctl = c.conn.streams().open(Dir::Uni).expect("control stream");
        let mut b = vec![0x00];
        ibex_proto::mux_h3::encode_frame(&mut b, 0x04, b"");
        c.conn.send_stream(ctl).write(&b).expect("write control");
        // The flooder starts misbehaving once the connection is up.
        if flood {
            c.skew = Some(Duration::ZERO);
        }
        c
    }

    fn now(&self) -> Instant {
        Instant::now() + self.skew.unwrap_or_default()
    }

    fn transmit(&mut self) {
        let now = self.now();
        let mut out = Vec::new();
        while let Some(t) = self.conn.poll_transmit(now, 1, &mut out) {
            let _ = self.sock.send_to(&out[..t.size], t.destination);
            out.clear();
        }
    }

    fn timers(&mut self) {
        let now = self.now();
        if self.conn.poll_timeout().is_some_and(|t| t <= now) {
            self.conn.handle_timeout(now);
        }
        while let Some(e) = self.conn.poll_endpoint_events() {
            if let Some(ce) = self.ep.handle_event(self.handle, e) {
                self.conn.handle_event(ce);
            }
        }
        while self.conn.poll().is_some() {}
    }

    fn step(&mut self) {
        self.transmit();
        thread::sleep(Duration::from_micros(150));
        while let Ok((n, from)) = self.sock.recv_from(&mut self.buf) {
            let now = self.now();
            let mut resp = Vec::new();
            if let Some(ibex_quic::quinn_proto::DatagramEvent::ConnectionEvent(_, e)) =
                self.ep.handle(now, from, None, None, self.buf[..n].into(), &mut resp)
            {
                self.conn.handle_event(e);
            }
            if let Some(s) = self.skew.as_mut() {
                // Past `max_ack_delay` (25 ms) at once: an ACK for this very packet.
                *s += Duration::from_millis(30);
                self.timers();
                self.transmit();
            }
        }
        self.timers();
    }

    fn run_until(&mut self, within: Duration, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            self.step();
            if done(self) {
                return true;
            }
        }
        false
    }

    fn get(&mut self) -> Resp {
        let id: StreamId = self.conn.streams().open(Dir::Bi).expect("stream credit");
        let mut s = self.conn.send_stream(id);
        let req = get_frame();
        assert_eq!(s.write(&req).expect("write"), req.len());
        s.finish().expect("finish");
        let mut all = Vec::new();
        let ended = self.run_until(Duration::from_secs(5), |c| {
            let mut rs = c.conn.recv_stream(id);
            let Ok(mut chunks) = rs.read(true) else { return true };
            let end = loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(ch)) => all.extend_from_slice(&ch.bytes),
                    Ok(None) => break true,
                    Err(_) => break false,
                }
            };
            let _ = chunks.finalize();
            end
        });
        assert!(ended, "no complete response");
        parse(&all)
    }
}

fn lit(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    let mut n = Vec::new();
    ibex_proto::hpack::encode_integer(name.len(), 3, 0, &mut n);
    n[0] |= 0x20;
    out.extend_from_slice(&n);
    out.extend_from_slice(name);
    ibex_proto::hpack::encode_integer(value.len(), 7, 0, out);
    out.extend_from_slice(value);
}

fn get_frame() -> Vec<u8> {
    let mut b = vec![0x00, 0x00];
    for (n, v) in [(&b":method"[..], &b"GET"[..]), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"localhost")] {
        lit(&mut b, n, v);
    }
    let mut out = Vec::new();
    ibex_proto::mux_h3::encode_frame(&mut out, 0x01, &b);
    out
}

fn parse(mut b: &[u8]) -> Resp {
    let mut r = Resp::default();
    while !b.is_empty() {
        let mut off = 0;
        let ty = ibex_proto::h3::parse_varint(b, &mut off).expect("type");
        let len = usize::try_from(ibex_proto::h3::parse_varint(b, &mut off).expect("len")).expect("len");
        assert!(off + len <= b.len(), "truncated frame");
        if ty == 0x01 && r.status == 0 {
            let fields = ibex_proto::qpack::decode_qpack_static(&b[off..off + len]).expect("qpack");
            for f in fields {
                if f.name == ":status" {
                    r.status = f.value.parse().expect("status");
                } else if f.name.starts_with("x-") {
                    r.hdrs.push((f.name.to_string(), f.value.to_string()));
                }
            }
        } else if ty == 0x00 {
            r.body += len;
        }
        b = &b[off + len..];
    }
    r
}

fn num(r: &Resp, h: &str) -> u64 {
    r.hdr(h).unwrap_or_else(|| panic!("no {h} in {r:?}")).parse().unwrap_or_else(|_| panic!("{h} not a number: {r:?}"))
}

/// The compliant client is never over the bar; the flooder is, and the rule denies it.
#[test]
fn a_peer_ignoring_ack_frequency_is_counted_and_denied_a_compliant_one_is_not() {
    common::on_h3_path("mux", || {
        let rig = start("cmp", "  tune.ibex.quic-ack-frequency on\n  tune.ibex.quic-ack-frequency-threshold 2\n  tune.ibex.quic-ack-frequency-max-delay 25ms\n");

        let mut good = Client::connect(rig.quic, false);
        let mut last = Resp::default();
        for _ in 0..8 {
            last = good.get();
            assert_eq!(last.status, 200, "compliant client refused: {last:?}");
            assert_eq!(last.body, 12_000);
            // Idle past `max_ack_delay`: the response's last packets are acknowledged by the
            // timer, in an ACK-only packet (otherwise the ACK rides on the next request).
            good.run_until(Duration::from_millis(60), |_| false);
        }
        eprintln!("compliant: {last:?}");
        assert!(num(&last, "x-only") >= 5, "the compliant client sent no ACK-only packets to judge: {last:?}");
        assert!(num(&last, "x-excess") <= 2, "compliant client counted as excess: {last:?}");
        let good_ratio = num(&last, "x-ratio");

        let mut bad = Client::connect(rig.quic, true);
        let mut statuses = Vec::new();
        let mut seen = Resp::default();
        for _ in 0..8 {
            let r = bad.get();
            statuses.push(r.status);
            if r.status == 200 {
                seen = r;
            }
        }
        eprintln!("flooder: {statuses:?} last 200: {seen:?}");
        assert!(num(&seen, "x-excess") > 5, "flooder not counted: {seen:?}");
        assert!(num(&seen, "x-ratio") > good_ratio * 2, "flood ratio {} vs compliant {good_ratio}", num(&seen, "x-ratio"));
        assert_eq!(statuses.last(), Some(&429), "the rule never denied the flooder: {statuses:?}");

        // `show quic ibex-acks`: one line per connection, the flooder's excess well above.
        let out = cli(&rig.sock, "show quic ibex-acks");
        eprintln!("{out}");
        assert!(out.starts_with("# conn/frontend"), "{out}");
        let excess: Vec<u64> = out.lines().skip(1).filter(|l| !l.is_empty()).map(|l| l.split_whitespace().last().expect("col").parse().expect("excess")).collect();
        assert_eq!(excess.len(), 2, "{out}");
        assert!(excess.iter().any(|&e| e <= 2) && excess.iter().any(|&e| e > 20), "{out}");

        // Ended, the connections' counts are in `show info`.
        good.conn.close(Instant::now(), 0u32.into(), b"".to_vec().into());
        bad.conn.close(bad.now(), 0u32.into(), b"".to_vec().into());
        good.step();
        bad.step();
        let deadline = Instant::now() + Duration::from_secs(5);
        while cli(&rig.sock, "show quic all").lines().filter(|l| !l.is_empty()).count() > 1 {
            assert!(Instant::now() < deadline, "the connections never ended");
            thread::sleep(Duration::from_millis(50));
        }
        let info = cli(&rig.sock, "show info");
        let field = |n: &str| info.lines().find_map(|l| l.strip_prefix(n)).map(|v| v.trim().parse::<u64>().expect("n"));
        assert!(field("QuicAckFreqExcess: ").is_some_and(|v| v > 20), "{info}");
        assert!(field("QuicAckOnlyRcvd: ").is_some_and(|v| v > 20), "{info}");
        assert!(field("QuicAckElicitingSent: ").is_some_and(|v| v > 100), "{info}");
    });
}

/// Without the setting no ACK_FREQUENCY is sent: the plain counts and ratio are there, the excess
/// has no sample (the peer is never called non-compliant: `hdr` adds no header for an empty
/// value), and `show info` has no `QuicAck*` line.
#[test]
fn without_ack_frequency_the_excess_has_no_sample_and_the_ratio_is_still_counted() {
    common::on_h3_path("mux", || {
        let rig = start("off", "");
        let mut bad = Client::connect(rig.quic, true);
        let mut r = Resp::default();
        for _ in 0..4 {
            r = bad.get();
            assert_eq!(r.status, 200, "{r:?}");
        }
        eprintln!("off: {r:?}");
        assert_eq!(r.hdr("x-excess"), None, "{r:?}");
        assert!(num(&r, "x-only") > 10 && num(&r, "x-sent") > 10 && num(&r, "x-ratio") > 0, "{r:?}");
        let info = cli(&rig.sock, "show info");
        assert!(!info.contains("QuicAck"), "{info}");
    });
}
