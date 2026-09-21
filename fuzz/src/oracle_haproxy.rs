// SPDX-License-Identifier: GPL-2.0-or-later
//! HAProxy 3.5 Differential Oracle.
//!
//! Spawns a real, isolated HAProxy 3.5 instance on dynamic ephemeral ports with a
//! concurrent synthetic HTTP backend. Feeds test cases over a real TCP socket and
//! derives accepted/rejected status from client responses, and framing/smuggling from backend.

#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub const SENTINEL_URI: &str = "/sentinel_differential_check";
pub const SENTINEL_REQ: &[u8] = b"GET /sentinel_differential_check HTTP/1.1\r\nHost: sentinel\r\n\r\n";

/// Forwarded request intercepted by the backend server.
#[derive(Debug, Clone)]
pub struct ForwardedRequest {
    pub raw: Vec<u8>,
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub header_count: usize,
    pub body: Vec<u8>,
    pub body_len: usize,
}

/// Result of querying HAProxy with an input payload.
#[derive(Debug, Clone)]
pub struct HaproxyParseResult {
    pub accepted: bool,
    pub status_code: Option<u16>,
    pub client_response: Vec<u8>,
    pub forwarded_req: Option<ForwardedRequest>,
    pub saw_sentinel_request: bool,
    pub next_request_smuggled: bool,
    pub backend_request_count: usize,
    pub error_message: Option<String>,
}

/// Manages a running HAProxy process and its concurrent backend HTTP echo server.
pub struct HaproxyOracle {
    haproxy_bin: PathBuf,
    fe_port: u16,
    be_port: u16,
    cfg_file: PathBuf,
    process: Option<Child>,
    backend_running: Arc<AtomicBool>,
    received_requests: Arc<Mutex<VecDeque<ForwardedRequest>>>,
}

impl HaproxyOracle {
    pub fn new<P: AsRef<Path>>(haproxy_bin: P) -> Result<Self, String> {
        let bin_path = haproxy_bin.as_ref().to_path_buf();
        if !bin_path.exists() {
            return Err(format!("HAProxy binary not found at {}", bin_path.display()));
        }

        // Allocate dynamic ports
        let (fe_port, be_port) = get_two_free_ports()?;

        let received_requests = Arc::new(Mutex::new(VecDeque::new()));
        let backend_running = Arc::new(AtomicBool::new(true));

        // Start concurrent backend server
        start_concurrent_backend(be_port, Arc::clone(&backend_running), Arc::clone(&received_requests))?;

        // Write HAProxy config
        let cfg_file = std::env::temp_dir().join(format!("ibex_fuzz_haproxy_{}_{}.cfg", std::process::id(), fe_port));
        let cfg_content = format!(
            "global\n\
             \tlog stdout format raw local0\n\
             \ttune.bufsize 32768\n\
             defaults\n\
             \tmode http\n\
             \ttimeout connect 500ms\n\
             \ttimeout client 1000ms\n\
             \ttimeout server 1000ms\n\
             \ttimeout http-request 1000ms\n\
             frontend fe\n\
             \tbind 127.0.0.1:{fe_port}\n\
             \tdefault_backend be\n\
             backend be\n\
             \tserver s1 127.0.0.1:{be_port}\n"
        );
        fs::write(&cfg_file, cfg_content).map_err(|e| format!("Failed to write HAProxy config: {e}"))?;

        // Launch HAProxy process
        let child = Command::new(&bin_path)
            .args(["-f", cfg_file.to_str().unwrap(), "-d"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to spawn HAProxy: {e}"))?;

        let mut oracle = Self {
            haproxy_bin: bin_path,
            fe_port,
            be_port,
            cfg_file,
            process: Some(child),
            backend_running,
            received_requests,
        };

        // Wait for HAProxy to bind and be ready
        let mut ready = false;
        for _ in 0..30 {
            thread::sleep(Duration::from_millis(50));
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", fe_port)) {
                let _ = stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n");
                let mut buf = [0u8; 64];
                let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                if let Ok(n) = stream.read(&mut buf) {
                    if n > 0 {
                        ready = true;
                        break;
                    }
                }
            }
        }

        if !ready {
            oracle.stop();
            return Err("HAProxy failed to start or bind within timeout".into());
        }

        // Drain healthz request from queue
        if let Ok(mut q) = oracle.received_requests.lock() {
            q.clear();
        }

        Ok(oracle)
    }

    /// Evaluates raw HTTP input against HAProxy.
    pub fn test_input(&mut self, input: &[u8], check_sentinel: bool) -> HaproxyParseResult {
        // Clear previous backend requests
        if let Ok(mut q) = self.received_requests.lock() {
            q.clear();
        }

        let mut stream = match TcpStream::connect(("127.0.0.1", self.fe_port)) {
            Ok(s) => s,
            Err(e) => {
                return HaproxyParseResult {
                    accepted: false,
                    status_code: None,
                    client_response: Vec::new(),
                    forwarded_req: None,
                    saw_sentinel_request: false,
                    next_request_smuggled: false,
                    backend_request_count: 0,
                    error_message: Some(format!("Failed to connect to HAProxy: {e}")),
                };
            }
        };

        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(300)));

        let mut wire_to_send = input.to_vec();
        if check_sentinel {
            wire_to_send.extend_from_slice(SENTINEL_REQ);
        }

        if let Err(e) = stream.write_all(&wire_to_send) {
            return HaproxyParseResult {
                accepted: false,
                status_code: None,
                client_response: Vec::new(),
                forwarded_req: None,
                saw_sentinel_request: false,
                next_request_smuggled: false,
                backend_request_count: 0,
                error_message: Some(format!("Failed to send data to HAProxy: {e}")),
            };
        }

        let mut client_response = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    client_response.extend_from_slice(&buf[..n]);
                    // If we received response headers:
                    if client_response.windows(4).any(|w| w == b"\r\n\r\n") {
                        if let Some(status) = parse_response_status(&client_response) {
                            if status >= 400 {
                                // HAProxy rejected directly with 4xx error (e.g. 400 Bad Request)
                                break;
                            }
                            if check_sentinel {
                                // If sentinel was pipelined, check if we received second response
                                let ok_count = client_response
                                    .windows(15)
                                    .filter(|w| *w == b"HTTP/1.1 200 OK")
                                    .count();
                                if ok_count >= 2 {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }

        // Give backend a brief moment to finish any in-flight handling
        thread::sleep(Duration::from_millis(15));
        drop(stream);

        // Fetch requests seen by backend
        let be_reqs: Vec<ForwardedRequest> = {
            if let Ok(mut q) = self.received_requests.lock() {
                q.drain(..).collect()
            } else {
                Vec::new()
            }
        };

        let backend_request_count = be_reqs.len();
        let status_code = parse_response_status(&client_response);

        // Accepted is derived from the CLIENT-side response: 2xx or 3xx status
        let accepted = status_code.map_or(false, |s| (200..400).contains(&s));

        let forwarded_req = be_reqs.first().cloned();
        let mut saw_sentinel = false;
        let mut next_smuggled = false;

        for req in be_reqs.iter().skip(1) {
            if req.uri == SENTINEL_URI {
                saw_sentinel = true;
            } else {
                next_smuggled = true;
            }
        }

        // Also check if sentinel was swallowed into first request's body
        if let Some(ref req1) = forwarded_req {
            if req1.body.windows(SENTINEL_URI.len()).any(|w| w == SENTINEL_URI.as_bytes()) {
                next_smuggled = true;
            }
        }

        HaproxyParseResult {
            accepted,
            status_code,
            client_response,
            forwarded_req,
            saw_sentinel_request: saw_sentinel,
            next_request_smuggled: next_smuggled,
            backend_request_count,
            error_message: None,
        }
    }

    pub fn stop(&mut self) {
        self.backend_running.store(false, Ordering::SeqCst);
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if self.cfg_file.exists() {
            let _ = fs::remove_file(&self.cfg_file);
        }
    }
}

impl Drop for HaproxyOracle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn get_two_free_ports() -> Result<(u16, u16), String> {
    let l1 = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let p1 = l1.local_addr().map_err(|e| e.to_string())?.port();
    let l2 = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let p2 = l2.local_addr().map_err(|e| e.to_string())?.port();
    drop(l1);
    drop(l2);
    Ok((p1, p2))
}

fn start_concurrent_backend(
    port: u16,
    running: Arc<AtomicBool>,
    queue: Arc<Mutex<VecDeque<ForwardedRequest>>>,
) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("Backend bind failed: {e}"))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    thread::spawn(move || {
        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let q = Arc::clone(&queue);
                    let r = Arc::clone(&running);
                    thread::spawn(move || {
                        handle_backend_connection(stream, r, q);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    Ok(())
}

fn handle_backend_connection(
    mut stream: TcpStream,
    running: Arc<AtomicBool>,
    queue: Arc<Mutex<VecDeque<ForwardedRequest>>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1000)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1000)));

    let mut raw_buf = Vec::new();
    let mut chunk = [0u8; 4096];

    while running.load(Ordering::SeqCst) {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw_buf.extend_from_slice(&chunk[..n]);

                while let Some((req, consumed)) = try_parse_http_request(&raw_buf) {
                    if let Ok(mut q) = queue.lock() {
                        q.push_back(req);
                    }
                    raw_buf.drain(..consumed);

                    // Respond with 200 OK
                    if stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
                        .is_err()
                    {
                        return;
                    }
                }
            }
            Err(_) => break,
        }
    }
}

fn try_parse_http_request(buf: &[u8]) -> Option<(ForwardedRequest, usize)> {
    let eoh = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header_bytes = &buf[..eoh];
    let header_str = std::str::from_utf8(header_bytes).ok()?;

    let mut lines = header_str.lines();
    let start_line = lines.next()?;
    let mut start_parts = start_line.split_whitespace();
    let method = start_parts.next()?.to_string();
    let uri = start_parts.next()?.to_string();
    let version = start_parts.next().unwrap_or("HTTP/1.1").to_string();

    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let name = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if name == "content-length" {
                if let Ok(l) = val.parse::<usize>() {
                    content_length = Some(l);
                }
            } else if name == "transfer-encoding" && val.to_ascii_lowercase().contains("chunked") {
                is_chunked = true;
            }
            headers.push((k.trim().to_string(), val));
        }
    }

    let header_count = headers.len();
    let body_start = eoh + 4;

    if is_chunked {
        let body_slice = &buf[body_start..];
        let (decoded_body, chunked_bytes_consumed) = decode_chunked_body(body_slice)?;
        let consumed = body_start + chunked_bytes_consumed;
        Some((
            ForwardedRequest {
                raw: buf[..consumed].to_vec(),
                method,
                uri,
                version,
                headers,
                header_count,
                body: decoded_body.clone(),
                body_len: decoded_body.len(),
            },
            consumed,
        ))
    } else if let Some(cl) = content_length {
        if buf.len() >= body_start + cl {
            let consumed = body_start + cl;
            let body = buf[body_start..consumed].to_vec();
            Some((
                ForwardedRequest {
                    raw: buf[..consumed].to_vec(),
                    method,
                    uri,
                    version,
                    headers,
                    header_count,
                    body,
                    body_len: cl,
                },
                consumed,
            ))
        } else {
            None
        }
    } else {
        // Bodyless request
        let consumed = body_start;
        Some((
            ForwardedRequest {
                raw: buf[..consumed].to_vec(),
                method,
                uri,
                version,
                headers,
                header_count,
                body: Vec::new(),
                body_len: 0,
            },
            consumed,
        ))
    }
}

fn decode_chunked_body(input: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut cursor = 0;
    let mut decoded = Vec::new();

    loop {
        if cursor >= input.len() {
            return None;
        }
        let line_end = input[cursor..].windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(&input[cursor..cursor + line_end]).ok()?;
        let size_part = size_str.split(';').next()?.trim();
        let size = usize::from_str_radix(size_part, 16).ok()?;

        cursor += line_end + 2;

        if size == 0 {
            if cursor + 2 <= input.len() && &input[cursor..cursor + 2] == b"\r\n" {
                cursor += 2;
                return Some((decoded, cursor));
            }
            let trailer_end = input[cursor..].windows(4).position(|w| w == b"\r\n\r\n")?;
            cursor += trailer_end + 4;
            return Some((decoded, cursor));
        }

        if cursor + size > input.len() {
            return None;
        }
        decoded.extend_from_slice(&input[cursor..cursor + size]);
        cursor += size;

        if cursor + 2 <= input.len() && &input[cursor..cursor + 2] == b"\r\n" {
            cursor += 2;
        } else if cursor + 1 <= input.len() && input[cursor] == b'\n' {
            cursor += 1;
        } else {
            return None;
        }
    }
}

fn parse_response_status(resp: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(resp).ok()?;
    let first_line = s.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let _ver = parts.next()?;
    let code = parts.next()?.parse::<u16>().ok()?;
    Some(code)
}
