// SPDX-License-Identifier: GPL-2.0-or-later
//! HAProxy 3.5 Differential Oracle.
//!
//! Spawns a real, isolated HAProxy 3.5 instance on dynamic ephemeral ports with a
//! synthetic HTTP backend. Feeds test cases over a real TCP socket and inspects
//! the exact normalized request and pipelining boundaries forwarded by HAProxy.

#![forbid(unsafe_code)]

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

/// Manages a running HAProxy process and its backend HTTP echo server.
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

        // Start backend thread
        start_backend_server(be_port, Arc::clone(&backend_running), Arc::clone(&received_requests))?;

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

        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

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
                    // If we got responses, break once complete or timeout
                    if client_response.windows(4).any(|w| w == b"\r\n\r\n") {
                        // Give backend a moment to process pipelined sentinel
                        thread::sleep(Duration::from_millis(20));
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        // Close stream
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

        let forwarded_req = be_reqs.first().cloned();
        let accepted = forwarded_req.is_some() && status_code.map_or(false, |s| s < 400);

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

fn start_backend_server(
    port: u16,
    running: Arc<AtomicBool>,
    queue: Arc<Mutex<VecDeque<ForwardedRequest>>>,
) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("Backend bind failed: {e}"))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    thread::spawn(move || {
        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

                    let mut raw_buf = Vec::new();
                    let mut chunk = [0u8; 4096];

                    while running.load(Ordering::SeqCst) {
                        match stream.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => {
                                raw_buf.extend_from_slice(&chunk[..n]);

                                // Parse HTTP requests out of raw_buf
                                while let Some((req, consumed)) = try_parse_http_request(&raw_buf) {
                                    if let Ok(mut q) = queue.lock() {
                                        q.push_back(req);
                                    }
                                    raw_buf.drain(..consumed);

                                    // Respond with 200 OK
                                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n");
                                }
                            }
                            Err(_) => break,
                        }
                    }
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
        // Find chunked terminator 0\r\n\r\n
        let body_slice = &buf[body_start..];
        let term = body_slice.windows(5).position(|w| w == b"0\r\n\r\n")?;
        let consumed = body_start + term + 5;
        let body = body_slice[..term].to_vec();
        Some((
            ForwardedRequest {
                raw: buf[..consumed].to_vec(),
                method,
                uri,
                version,
                headers,
                header_count,
                body: body.clone(),
                body_len: body.len(),
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

fn parse_response_status(resp: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(resp).ok()?;
    let first_line = s.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let _ver = parts.next()?;
    let code = parts.next()?.parse::<u16>().ok()?;
    Some(code)
}
