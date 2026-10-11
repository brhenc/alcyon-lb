// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The syslog lines of `option httplog`, `option httpslog`, `option tcplog` and the default
//! (no option) format, against the lines the reference `HAProxy` (3.5-dev8-885761-29) sent
//! for the same requests on 2026-10-04 (T165). The traffic goes one request at a time to
//! `frontend fe` (`use_backend dead` for `/dead`, a redirect for `/red`, a deny for `/deny`,
//! `backend be` with one origin that takes a second over `/slow`; `timeout server 300ms`,
//! `retries 3`). The client's port and the timings vary, so each line is compared with the
//! port and every non-negative timing replaced: `-1` stays, since it says the step never
//! happened.
//!
//! What `HAProxy` showed that Ibex did not before this test:
//! * a datagram ends with a line feed;
//! * an empty `%hr` or `%hs` takes the blank after it away (`0/0 "GET`, not `0/0   "GET`);
//! * `%sc` of a lone request is 0 (the stream has let go of the server when it logs);
//! * the second request on a kept-alive server connection has `%Tw` and `%Tc` of 0, not
//!   `-1` and the time since the request;
//! * `option httpslog` exists, and with no format option there is one `Connect from` line
//!   per connection and none per request.
//!
//! Reaches the data path in `logfmt.rs` (`render_into`, the formats), `syslog.rs` (the line
//! feed) and `engine.rs` (`stream_log_line`, `connect_http_backend`, the accept path).

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon(Child, std::path::PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_file(&self.1);
    }
}

fn origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in listener.incoming().flatten() {
            thread::spawn(move || serve(c));
        }
    });
    port
}

fn serve(mut c: TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match c.read(&mut chunk) {
                Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                _ => return,
            }
        }
        let end = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("head") + 4;
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        buf.drain(..end);
        let path = head.split(' ').nth(1).unwrap_or("/").to_string();
        let reply: &[u8] = match path.as_str() {
            "/slow" => {
                thread::sleep(Duration::from_secs(1));
                return;
            }
            "/404" => b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope",
            _ => b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: a=b\r\n\r\nhello",
        };
        if c.write_all(reply).is_err() {
            return;
        }
    }
}

fn exchange(port: u16, data: &[u8]) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    s.write_all(data).expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
}

fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").into_bytes()
}

/// Runs the daemon under `mode` and `option_line`, sends `traffic`, and returns the raw
/// datagrams the collector got.
fn run(mode: &str, option_line: &str, traffic: impl FnOnce(u16)) -> Vec<Vec<u8>> {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_millis(400))).expect("timeout");
    let log_port = collector.local_addr().expect("addr").port();
    let origin = origin();
    let dead = common::reserve_port();
    let port = common::reserve_port();
    let http_rules = if mode == "http" {
        "  use_backend dead if { path /dead }\n  acl isred path /red\n  http-request redirect location /x if isred\n  acl isdeny path /deny\n  http-request deny if isdeny\n"
    } else {
        ""
    };
    let cfg = format!(
        "global\n  log 127.0.0.1:{log_port} local0\n\
         defaults\n  mode {mode}\n  log global\n  {option_line}\n  timeout connect 300ms\n  timeout client 5s\n  timeout server 300ms\n\
         frontend fe\n  bind 127.0.0.1:{port}\n{http_rules}  default_backend be\n\
         backend be\n  server s1 127.0.0.1:{origin}\n\
         backend dead\n  server d1 127.0.0.1:{dead}\n"
    );
    let path = std::env::temp_dir().join(format!("ibex_t165_log_{}_{}.cfg", std::process::id(), port));
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let _d = Daemon(child, path);
    assert!(common::wait_listening(format!("127.0.0.1:{port}").parse().expect("addr")), "the daemon never listened");
    // `wait_listening` connects once: let that connection's line (if any) go, and drop it.
    thread::sleep(Duration::from_millis(300));
    while collector.recv(&mut [0u8; 65535]).is_ok() {}
    traffic(port);
    thread::sleep(Duration::from_millis(300));
    let mut got = Vec::new();
    let mut buf = vec![0u8; 65535];
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until {
        match collector.recv(&mut buf) {
            Ok(n) => got.push(buf[..n].to_vec()),
            Err(_) => break,
        }
    }
    got
}

/// The message after the syslog header, the line feed checked and cut, the client port and
/// the timings masked.
fn normalise(datagram: &[u8]) -> String {
    assert_eq!(datagram.last(), Some(&b'\n'), "a datagram ends with a line feed: {:?}", String::from_utf8_lossy(datagram));
    let text = String::from_utf8_lossy(&datagram[..datagram.len() - 1]).into_owned();
    let msg = text.split_once("]: ").expect("syslog header").1.to_string();
    // `ip:port [date] ...`: the port and the date go.
    let (src, rest) = msg.split_once(' ').unwrap_or((&msg, ""));
    let rest = rest.split_once("] ").map_or(rest.to_string(), |(_, r)| r.to_string());
    let src = src.split(':').next().unwrap_or("");
    format!("{src} {rest}")
}

/// `%TR/%Tw/%Tc/%Tr/%Ta` (word `at` of the line, after the server) and tcplog's
/// `%Tw/%Tc/%Tt`, masked.
fn mask_timings(line: &str, at: usize) -> String {
    let mut words: Vec<String> = line.split(' ').map(String::from).collect();
    if let Some(w) = words.get_mut(at + 1) {
        *w = w
            .split('/')
            .map(|p| if p.parse::<i64>().is_ok_and(|v| v >= 0) { "N".to_string() } else { p.to_string() })
            .collect::<Vec<_>>()
            .join("/");
    }
    words.join(" ")
}

fn http_traffic(port: u16) {
    let mut keepalive = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n".to_vec();
    keepalive.extend(get("/c"));
    exchange(port, &keepalive);
    for p in ["/404", "/red", "/deny", "/slow"] {
        exchange(port, &get(p));
    }
    exchange(port, b"BAD\r\n\r\n");
    exchange(port, &get("/dead"));
}

#[test]
fn httplog_lines_equal_haproxys() {
    let got = run("http", "option httplog", http_traffic);
    let lines: Vec<String> = got.iter().map(|d| mask_timings(&normalise(d), 2)).collect();
    // `HAProxy`: the same lines, `%ac/%fc/%bc/%sc/%rc` as shown, `0/0` queues.
    let want = [
        r#"127.0.0.1 fe be/s1 N/N/N/N/N 200 67 - - ---- 1/1/0/0/0 0/0 "GET /a HTTP/1.1""#,
        r#"127.0.0.1 fe be/s1 N/N/N/N/N 200 67 - - ---- 1/1/0/0/0 0/0 "GET /b HTTP/1.1""#,
        r#"127.0.0.1 fe be/s1 N/N/N/N/N 200 67 - - ---- 1/1/0/0/0 0/0 "GET /c HTTP/1.1""#,
        r#"127.0.0.1 fe be/s1 N/N/N/N/N 404 60 - - ---- 1/1/0/0/0 0/0 "GET /404 HTTP/1.1""#,
        r#"127.0.0.1 fe fe/<NOSRV> N/-1/-1/-1/N 302 0 - - LR-- 1/1/0/0/0 0/0 "GET /red HTTP/1.1""#,
        r#"127.0.0.1 fe fe/<NOSRV> N/-1/-1/-1/N 403 0 - - PR-- 1/1/0/0/0 0/0 "GET /deny HTTP/1.1""#,
        r#"127.0.0.1 fe be/s1 N/N/N/-1/N 504 0 - - sH-- 1/1/0/0/0 0/0 "GET /slow HTTP/1.1""#,
        r#"127.0.0.1 fe fe/<NOSRV> -1/-1/-1/-1/N 400 0 - - PR-- 1/1/0/0/0 0/0 "<BADREQ>""#,
        r#"127.0.0.1 fe dead/d1 N/N/-1/-1/N 503 0 - - SC-- 1/1/0/0/3 0/0 "GET /dead HTTP/1.1""#,
    ];
    assert_eq!(lines, want, "\n{lines:#?}");
}

#[test]
fn httpslog_adds_the_tls_fields_and_they_are_empty_without_tls() {
    let got = run("http", "option httpslog", |port| {
        exchange(port, &get("/a"));
        exchange(port, &get("/404"));
    });
    let lines: Vec<String> = got.iter().map(|d| mask_timings(&normalise(d), 2)).collect();
    let want = [
        r#"127.0.0.1 fe be/s1 N/N/N/N/N 200 67 - - ---- 1/1/0/0/0 0/0 "GET /a HTTP/1.1" 0/-/-/-/0 -/-/-"#,
        r#"127.0.0.1 fe be/s1 N/N/N/N/N 404 60 - - ---- 1/1/0/0/0 0/0 "GET /404 HTTP/1.1" 0/-/-/-/0 -/-/-"#,
    ];
    assert_eq!(lines, want, "\n{lines:#?}");
}

#[test]
fn tcplog_lines_equal_haproxys() {
    // The origin is an HTTP one that keeps the connection: `timeout server` ends it (`sD`).
    let got = run("tcp", "option tcplog", |port| exchange(port, b"GET /ok HTTP/1.0\r\n\r\n"));
    let lines: Vec<String> = got.iter().map(|d| mask_timings(&normalise(d), 2)).collect();
    assert_eq!(lines, [r#"127.0.0.1 fe be/s1 N/N/N 60 sD 1/1/0/0/0 0/0"#.to_string()], "\n{lines:#?}");
}

#[test]
fn default_format_logs_one_connect_line_per_connection() {
    let got = run("http", "", |port| {
        let mut keepalive = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n".to_vec();
        keepalive.extend(get("/c"));
        exchange(port, &keepalive);
        exchange(port, &get("/404"));
    });
    let lines: Vec<String> = got
        .iter()
        .map(|d| {
            assert_eq!(d.last(), Some(&b'\n'));
            let t = String::from_utf8_lossy(&d[..d.len() - 1]).into_owned();
            let msg = t.split_once("]: ").expect("header").1.to_string();
            // `Connect from 127.0.0.1:PORT to 127.0.0.1:PORT (fe/HTTP)`: the ports go.
            msg.split(' ').map(|w| if w.starts_with("127.0.0.1:") { "127.0.0.1:P" } else { w }).collect::<Vec<_>>().join(" ")
        })
        .collect();
    let line = "Connect from 127.0.0.1:P to 127.0.0.1:P (fe/HTTP)";
    assert_eq!(lines, [line, line], "\n{lines:#?}");
}

#[test]
fn an_empty_capture_takes_the_blank_after_it() {
    // `x %hr y` sent `x y` (a blank run is one blank, and an empty `%hr` writes no blank).
    let got = run("http", "log-format \"[%hr] x %hr y %hs z  w\"", |port| exchange(port, &get("/a")));
    let line = String::from_utf8_lossy(&got[0]).into_owned();
    assert!(line.ends_with("[] x y z w\n"), "{line:?}");
}

#[test]
fn an_empty_field_takes_the_blank_after_it() {
    // T282, measured on 3.5-dev8-885761-29 (`/a` has no query, so `%HQ` is empty): a blank is
    // written only after something that is not one, so a field that wrote nothing takes the
    // blank that follows it away, whichever field it is. The fields that write `-` or `""`
    // for nothing still count as data.
    for (format, expect) in [
        ("A %HQ B", "A B\n"),
        ("A %HQ %HQ B", "A B\n"),
        ("A %HQ  B", "A B\n"),
        ("%HQ B", "B\n"),
        ("A %HQ%hr B", "A B\n"),
        ("A %{+E}HQ B", "A B\n"),
        ("A %HQ", "A \n"),
        ("A %{+Q}HQ B", "A \"\" B\n"),
        ("A %[str()] %HQ B", "A - B\n"),
    ] {
        let got = run("http", &format!("log-format \"{}\"", format.replace('"', "\\\"")), |port| exchange(port, &get("/a")));
        let line = String::from_utf8_lossy(&got[0]).into_owned();
        assert!(line.ends_with(&format!("]: {expect}")), "{format:?}: {line:?}");
    }
}

/// Over TLS (TLS 1.3, one suite offered, SNI `localhost`), as `HAProxy` logged it with an
/// ECDSA certificate: `fe~`, then `fc_err/ssl_fc_err,hex/ssl_c_err/ssl_c_ca_err/resumed`
/// (`0/0000000000000000/0/0/0`) and `sni/version/cipher`.
#[test]
fn httpslog_over_tls_shows_the_session() {
    use rustls::crypto::{ring, CryptoProvider};
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, Stream};
    use std::sync::Arc;

    let _ = ring::default_provider().install_default();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params.subject_alt_names.push(rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])));
    let key = rcgen::KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("cert");
    let pem = std::env::temp_dir().join(format!("ibex_t165_tls_{}.pem", std::process::id()));
    std::fs::write(&pem, format!("{}{}", cert.pem(), key.serialize_pem())).expect("write pem");

    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_millis(500))).expect("timeout");
    let log_port = collector.local_addr().expect("addr").port();
    let origin = origin();
    let port = common::reserve_port();
    let cfg = format!(
        "global\n  log 127.0.0.1:{log_port} local0\n\
         defaults\n  mode http\n  log global\n  option httpslog\n  timeout connect 300ms\n  timeout client 5s\n  timeout server 2s\n\
         frontend fe\n  bind 127.0.0.1:{port} ssl crt {}\n  default_backend be\n\
         backend be\n  server s1 127.0.0.1:{origin}\n",
        pem.display()
    );
    let path = std::env::temp_dir().join(format!("ibex_t165_tls_{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let _d = Daemon(child, path);
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");

    let suite = ring::default_provider().cipher_suites.into_iter().find(|s| format!("{:?}", s.suite()) == "TLS13_AES_256_GCM_SHA384").expect("suite");
    let provider = Arc::new(CryptoProvider { cipher_suites: vec![suite], ..ring::default_provider() });
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).expect("root");
    let client = Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    // No probe connection: one that closes during the handshake is a session too. The
    // request itself is retried until the daemon listens.
    let deadline = Instant::now() + Duration::from_secs(5);
    let out = loop {
        let mut conn = ClientConnection::new(client.clone(), ServerName::try_from("localhost").expect("name")).expect("conn");
        if let Ok(mut tcp) = TcpStream::connect(addr) {
            tcp.set_read_timeout(Some(Duration::from_secs(3))).ok();
            let mut tls = Stream::new(&mut conn, &mut tcp);
            tls.write_all(b"GET /a HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write");
            let mut out = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = tls.read(&mut buf) {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            break out;
        }
        assert!(Instant::now() < deadline, "the daemon never listened");
        thread::sleep(Duration::from_millis(50));
    };
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200"), "{out:?}");
    thread::sleep(Duration::from_millis(300));
    let mut line = vec![0u8; 65535];
    let n = collector.recv(&mut line).expect("a log line");
    let got = mask_timings(&normalise(&line[..n]), 2);
    let _ = std::fs::remove_file(&pem);
    assert_eq!(
        got,
        r#"127.0.0.1 fe~ be/s1 N/N/N/N/N 200 67 - - ---- 1/1/0/0/0 0/0 "GET /a HTTP/1.1" 0/0000000000000000/0/0/0 localhost/TLSv1.3/TLS_AES_256_GCM_SHA384"#
    );
}

/// `log /path local0` (a unix datagram socket) delivers the same line as UDP does, with its
/// line feed. Not measured on the reference: its `sendmsg()` to a socket bound here failed
/// with ENOENT on 2026-10-04 (3.5-dev8-885761-29), so this is the UDP line's header and
/// message sent to the path, as `log.c` builds one line for every kind of target. Before
/// this the target was accepted, warned about once, and every line dropped.
#[test]
fn a_unix_socket_log_target_receives_the_line() {
    let sock_path = std::env::temp_dir().join(format!("ibex_t165_log_{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);
    let collector = std::os::unix::net::UnixDatagram::bind(&sock_path).expect("bind");
    collector.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let port = common::reserve_port();
    let cfg = format!(
        "global\n  log {} local0\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout client 5s\n\
         frontend fe\n  bind 127.0.0.1:{port}\n  http-request return status 200\n",
        sock_path.display()
    );
    let path = std::env::temp_dir().join(format!("ibex_t165_unix_{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let _d = Daemon(child, path);
    assert!(common::wait_listening(format!("127.0.0.1:{port}").parse().expect("addr")), "the daemon never listened");
    thread::sleep(Duration::from_millis(300));
    while collector.set_nonblocking(true).is_ok() && collector.recv(&mut [0u8; 65535]).is_ok() {}
    collector.set_nonblocking(false).expect("blocking");
    exchange(port, &get("/a"));
    let mut buf = vec![0u8; 65535];
    let n = collector.recv(&mut buf).expect("a datagram");
    let _ = std::fs::remove_file(&sock_path);
    assert_eq!(buf[n - 1], b'\n');
    let line = normalise(&buf[..n]);
    assert_eq!(mask_timings(&line, 2), r#"127.0.0.1 fe fe/<NOSRV> N/-1/-1/-1/N 200 0 - - LR-- 1/1/0/0/0 0/0 "GET /a HTTP/1.1""#);
}

/// A unix target in the abstract namespace (`unix@@name`: a leading `@`), and the same
/// socket named by two `log` lines, which share one sink.
#[test]
fn an_abstract_unix_target_and_a_shared_one_receive_the_line() {
    use std::os::linux::net::SocketAddrExt;
    let name = format!("ibex_t165_abs_{}", std::process::id());
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract");
    let collector = std::os::unix::net::UnixDatagram::bind_addr(&addr).expect("bind");
    collector.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let port = common::reserve_port();
    // The global target is also named by the frontend: one socket, so one line per request.
    let cfg = format!(
        "global\n  log unix@@{name} local0\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout client 5s\n\
         frontend fe\n  bind 127.0.0.1:{port}\n  log unix@@{name} local0\n  http-request return status 200\n"
    );
    let path = std::env::temp_dir().join(format!("ibex_t165_abs_{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let _d = Daemon(child, path);
    assert!(common::wait_listening(format!("127.0.0.1:{port}").parse().expect("addr")), "the daemon never listened");
    thread::sleep(Duration::from_millis(300));
    collector.set_nonblocking(true).expect("nonblocking");
    while collector.recv(&mut [0u8; 65535]).is_ok() {}
    collector.set_nonblocking(false).expect("blocking");
    exchange(port, &get("/a"));
    let mut buf = vec![0u8; 65535];
    let n = collector.recv(&mut buf).expect("a datagram");
    assert_eq!(mask_timings(&normalise(&buf[..n]), 2), r#"127.0.0.1 fe fe/<NOSRV> N/-1/-1/-1/N 200 0 - - LR-- 1/1/0/0/0 0/0 "GET /a HTTP/1.1""#);
}
