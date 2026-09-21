// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy 1.0 - 3.5 HTTP header action and response generation engine.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Zero-allocation HTTP header manipulation, synthetic response generation,
//! and log format string formatting.

use std::io::Write;
use std::net::SocketAddr;

/// Injects or updates an HTTP header in `buf` before the end of headers boundary (`\r\n\r\n`).
///
/// If a header with `name` (case-insensitive) already exists, its value is replaced with `value`,
/// and any duplicate matching headers are removed.
/// If the header does not exist, it is inserted immediately before the end of headers marker.
///
/// Returns the new valid length of the buffer on success, or `None` if the buffer is malformed
/// or lacks sufficient capacity to accommodate the new header.
pub fn inject_http_header(buf: &mut [u8], name: &str, value: &str) -> Option<usize> {
    let (eoh_pos, eoh_len) = find_eoh(buf)?;
    let valid_len = determine_valid_len(buf, eoh_pos, eoh_len);
    inject_http_header_with_len(buf, valid_len, name, value)
}

/// Injects or updates an HTTP header in `buf` with an explicitly specified `valid_len`.
///
/// Returns the new valid length of the buffer on success, or `None` if the buffer is malformed
/// or lacks sufficient capacity.
pub fn inject_http_header_with_len(
    buf: &mut [u8],
    mut valid_len: usize,
    name: &str,
    value: &str,
) -> Option<usize> {
    let (eoh_pos, _) = find_eoh(&buf[..valid_len])?;
    let (start_content, start_delim) = find_line_end(&buf[..valid_len])?;
    let start_line_end = start_content + start_delim;

    let use_crlf = !buf.starts_with(b"\n") && find_first_crlf(&buf[..valid_len]);
    let delim = if use_crlf { "\r\n" } else { "\n" };
    let new_header_str = format!("{name}: {value}{delim}");
    let new_hdr_bytes = new_header_str.as_bytes();
    let new_hdr_len = new_hdr_bytes.len();

    // Scan for all existing headers matching `name` (case-insensitive)
    let mut matches = Vec::new();
    let mut cursor = start_line_end;
    while cursor < eoh_pos {
        let Some((line_content_len, line_delim_len)) = find_line_end(&buf[cursor..eoh_pos]) else {
            break;
        };
        let line_end = cursor + line_content_len;
        let line_total = line_content_len + line_delim_len;
        let line_slice = &buf[cursor..line_end];

        if let Some(colon_idx) = line_slice.iter().position(|&b| b == b':') {
            if let Ok(hdr_name) = std::str::from_utf8(&line_slice[..colon_idx]) {
                if hdr_name.trim().eq_ignore_ascii_case(name) {
                    matches.push((cursor, cursor + line_total));
                }
            }
        }
        cursor += line_total;
    }

    if matches.is_empty() {
        // Header does not exist -> insert before eoh_pos
        if valid_len + new_hdr_len > buf.len() {
            return None;
        }
        buf.copy_within(eoh_pos..valid_len, eoh_pos + new_hdr_len);
        buf[eoh_pos..eoh_pos + new_hdr_len].copy_from_slice(new_hdr_bytes);
        valid_len += new_hdr_len;
        Some(valid_len)
    } else {
        // Header exists:
        // 1. Remove duplicate occurrences (from last to second)
        for &(start, end) in matches[1..].iter().rev() {
            let shift = end - start;
            buf.copy_within(end..valid_len, start);
            valid_len -= shift;
            buf[valid_len..valid_len + shift].fill(0);
        }

        // 2. Replace the first occurrence in place
        let (first_start, first_end) = matches[0];
        let old_len = first_end - first_start;

        match new_hdr_len.cmp(&old_len) {
            std::cmp::Ordering::Equal => {
                buf[first_start..first_start + new_hdr_len].copy_from_slice(new_hdr_bytes);
            }
            std::cmp::Ordering::Less => {
                let shrink = old_len - new_hdr_len;
                buf[first_start..first_start + new_hdr_len].copy_from_slice(new_hdr_bytes);
                buf.copy_within(first_end..valid_len, first_start + new_hdr_len);
                valid_len -= shrink;
                buf[valid_len..valid_len + shrink].fill(0);
            }
            std::cmp::Ordering::Greater => {
                let grow = new_hdr_len - old_len;
                if valid_len + grow > buf.len() {
                    return None;
                }
                buf.copy_within(first_end..valid_len, first_start + new_hdr_len);
                buf[first_start..first_start + new_hdr_len].copy_from_slice(new_hdr_bytes);
                valid_len += grow;
            }
        }

        Some(valid_len)
    }
}

/// Removes all HTTP headers matching `name` (case-insensitive) from `buf`.
///
/// Shifts the remaining headers and payload leftwards and zeroes out the vacated trailing space.
/// Returns the new valid length of the buffer on success, or `None` if the buffer is malformed.
pub fn remove_http_header(buf: &mut [u8], name: &str) -> Option<usize> {
    let (eoh_pos, eoh_len) = find_eoh(buf)?;
    let valid_len = determine_valid_len(buf, eoh_pos, eoh_len);
    remove_http_header_with_len(buf, valid_len, name)
}

/// Removes all HTTP headers matching `name` (case-insensitive) with an explicitly specified `valid_len`.
///
/// Returns the new valid length of the buffer on success, or `None` if the buffer is malformed.
pub fn remove_http_header_with_len(
    buf: &mut [u8],
    mut valid_len: usize,
    name: &str,
) -> Option<usize> {
    let (eoh_pos, _) = find_eoh(&buf[..valid_len])?;
    let (start_content, start_delim) = find_line_end(&buf[..valid_len])?;
    let start_line_end = start_content + start_delim;

    let mut matches = Vec::new();
    let mut cursor = start_line_end;
    while cursor < eoh_pos {
        let Some((line_content_len, line_delim_len)) = find_line_end(&buf[cursor..eoh_pos]) else {
            break;
        };
        let line_end = cursor + line_content_len;
        let line_total = line_content_len + line_delim_len;
        let line_slice = &buf[cursor..line_end];

        if let Some(colon_idx) = line_slice.iter().position(|&b| b == b':') {
            if let Ok(hdr_name) = std::str::from_utf8(&line_slice[..colon_idx]) {
                if hdr_name.trim().eq_ignore_ascii_case(name) {
                    matches.push((cursor, cursor + line_total));
                }
            }
        }
        cursor += line_total;
    }

    if matches.is_empty() {
        return Some(valid_len);
    }

    // Remove matching headers in reverse order
    for (start, end) in matches.into_iter().rev() {
        let shift = end - start;
        buf.copy_within(end..valid_len, start);
        valid_len -= shift;
        buf[valid_len..valid_len + shift].fill(0);
    }

    Some(valid_len)
}

/// Formats a log format string supporting `%ci`, `%cp`, `%[src]`, `%[src_port]`, `%Tr`, and literals.
#[must_use]
pub fn format_log_format_string(
    fmt: &str,
    client_addr: Option<SocketAddr>,
    elapsed_ms: u64,
) -> String {
    let mut out = String::with_capacity(fmt.len() + 32);
    let bytes = fmt.as_bytes();
    let mut i = 0;

    let client_ip = client_addr.map_or_else(|| "-".to_string(), |a| a.ip().to_string());
    let client_port = client_addr.map_or_else(|| "-".to_string(), |a| a.port().to_string());
    let elapsed_str = elapsed_ms.to_string();

    while i < bytes.len() {
        if bytes[i] == b'%' {
            let rem = &fmt[i..];
            if rem.starts_with("%%") {
                out.push('%');
                i += 2;
            } else if rem.starts_with("%ci") {
                out.push_str(&client_ip);
                i += 3;
            } else if rem.starts_with("%cp") {
                out.push_str(&client_port);
                i += 3;
            } else if rem.starts_with("%[src]") {
                out.push_str(&client_ip);
                i += 6;
            } else if rem.starts_with("%[src_port]") {
                out.push_str(&client_port);
                i += 11;
            } else if rem.starts_with("%Tr") || rem.starts_with("%Tt") || rem.starts_with("%Ta") {
                out.push_str(&elapsed_str);
                i += 3;
            } else {
                out.push('%');
                i += 1;
            }
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b'%' {
                i += 1;
            }
            out.push_str(&fmt[start..i]);
        }
    }

    out
}

/// Returns the standard RFC HTTP reason phrase for a given status code.
#[must_use]
pub const fn status_reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        410 => "Gone",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

/// Returns the default body string for a given status code.
#[must_use]
pub const fn default_body_for_status(status: u16) -> &'static str {
    match status {
        200 => "OK\n",
        201 => "Created\n",
        400 => "Bad Request\n",
        401 => "Unauthorized\n",
        403 => "Forbidden\n",
        404 => "Not Found\n",
        405 => "Method Not Allowed\n",
        408 => "Request Timeout\n",
        429 => "Too Many Requests\n",
        500 => "Internal Server Error\n",
        502 => "Bad Gateway\n",
        503 => "Service Unavailable\n",
        504 => "Gateway Timeout\n",
        _ => "",
    }
}

/// Generates an RFC-compliant HTTP synthetic response with `Content-Type`, `Content-Length`,
/// `Connection: close`, and payload.
#[must_use]
pub fn build_synthetic_response(
    status: u16,
    content_type: Option<&str>,
    body: Option<&str>,
) -> Vec<u8> {
    let reason = status_reason_phrase(status);
    let payload = match body {
        Some(b) => b.as_bytes(),
        None => default_body_for_status(status).as_bytes(),
    };
    let ct = content_type.unwrap_or("text/plain");

    let mut res = Vec::with_capacity(128 + payload.len());
    let _ = write!(
        res,
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {ct}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        payload.len()
    );
    res.extend_from_slice(payload);
    res
}

fn find_eoh(buf: &[u8]) -> Option<(usize, usize)> {
    for i in 0..buf.len() {
        if i + 4 <= buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some((i + 2, 2));
        }
        if i + 2 <= buf.len() && &buf[i..i + 2] == b"\n\n" {
            return Some((i + 1, 1));
        }
    }
    None
}

fn find_line_end(buf: &[u8]) -> Option<(usize, usize)> {
    for i in 0..buf.len() {
        if buf[i] == b'\n' {
            if i > 0 && buf[i - 1] == b'\r' {
                return Some((i - 1, 2));
            }
            return Some((i, 1));
        }
    }
    None
}

fn find_first_crlf(buf: &[u8]) -> bool {
    for i in 0..buf.len().saturating_sub(1) {
        if &buf[i..i + 2] == b"\r\n" {
            return true;
        }
    }
    false
}

fn determine_valid_len(buf: &[u8], eoh_pos: usize, eoh_len: usize) -> usize {
    let eoh_end = eoh_pos + eoh_len;
    if let Ok(headers_str) = std::str::from_utf8(&buf[..eoh_pos]) {
        for line in headers_str.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    if let Ok(cl) = v.trim().parse::<usize>() {
                        return (eoh_end + cl).min(buf.len());
                    }
                }
            }
        }
    }

    if buf.len() > eoh_end {
        if let Some(last_pos) = buf[eoh_end..].iter().rposition(|&b| b != 0) {
            return eoh_end + last_pos + 1;
        }
        return eoh_end;
    }

    buf.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_new_header_into_request() {
        let mut buf = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        buf.resize(128, 0);

        let new_len = inject_http_header(&mut buf, "X-Forwarded-Proto", "https").expect("inject");
        let result = std::str::from_utf8(&buf[..new_len]).unwrap();

        assert!(result.starts_with("GET /index.html HTTP/1.1\r\n"));
        assert!(result.contains("Host: example.com\r\n"));
        assert!(result.contains("X-Forwarded-Proto: https\r\n"));
        assert!(result.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_inject_update_existing_header() {
        let mut buf =
            b"GET / HTTP/1.1\r\nHost: old.example.com\r\nUser-Agent: curl\r\n\r\n".to_vec();
        buf.resize(128, 0);

        let new_len = inject_http_header(&mut buf, "HOST", "new.example.com").expect("update");
        let result = std::str::from_utf8(&buf[..new_len]).unwrap();

        assert!(!result.contains("old.example.com"));
        assert!(result.contains("HOST: new.example.com\r\n"));
        assert!(result.contains("User-Agent: curl\r\n"));
    }

    #[test]
    fn test_inject_update_existing_header_shorter() {
        let mut buf = b"GET / HTTP/1.1\r\nHost: long-domain-name.example.com\r\n\r\n".to_vec();
        buf.resize(128, 0);

        let new_len = inject_http_header(&mut buf, "Host", "short.io").expect("update");
        let result = std::str::from_utf8(&buf[..new_len]).unwrap();

        assert_eq!(result, "GET / HTTP/1.1\r\nHost: short.io\r\n\r\n");
    }

    #[test]
    fn test_inject_with_body_preservation() {
        let mut buf =
            b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        buf.resize(128, 0);

        let new_len = inject_http_header(&mut buf, "X-Client-IP", "127.0.0.1").expect("inject");
        let result = std::str::from_utf8(&buf[..new_len]).unwrap();

        assert!(result.contains("X-Client-IP: 127.0.0.1\r\n"));
        assert!(result.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn test_remove_header() {
        let mut buf =
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n"
                .to_vec();

        let new_len = remove_http_header(&mut buf, "user-agent").expect("remove");
        let result = std::str::from_utf8(&buf[..new_len]).unwrap();

        assert!(!result.contains("User-Agent"));
        assert!(result.contains("Host: example.com\r\n"));
        assert!(result.contains("Accept: */*\r\n"));
        assert_eq!(
            result,
            "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
        );
    }

    #[test]
    fn test_remove_duplicate_headers() {
        let mut buf =
            b"GET / HTTP/1.1\r\nX-Foo: 1\r\nHost: example.com\r\nX-Foo: 2\r\n\r\n".to_vec();

        let new_len = remove_http_header(&mut buf, "X-Foo").expect("remove");
        let result = std::str::from_utf8(&buf[..new_len]).unwrap();

        assert_eq!(result, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    }

    #[test]
    fn test_format_log_format_string() {
        let addr: SocketAddr = "192.168.1.50:54321".parse().unwrap();
        let fmt = "client=%ci port=%cp src=%[src] time=%Tr ms %% literal";
        let out = format_log_format_string(fmt, Some(addr), 125);
        assert_eq!(
            out,
            "client=192.168.1.50 port=54321 src=192.168.1.50 time=125 ms % literal"
        );

        let out_none = format_log_format_string("%ci:%cp (%Tr ms)", None, 0);
        assert_eq!(out_none, "-:- (0 ms)");
    }

    #[test]
    fn test_build_synthetic_response_variants() {
        // 200 OK
        let r200 = build_synthetic_response(200, None, None);
        let s200 = String::from_utf8(r200).unwrap();
        assert!(s200.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s200.contains("Content-Type: text/plain\r\n"));
        assert!(s200.contains("Content-Length: 3\r\n"));
        assert!(s200.contains("Connection: close\r\n"));
        assert!(s200.ends_with("\r\n\r\nOK\n"));

        // 429 Too Many Requests
        let r429 = build_synthetic_response(429, None, None);
        let s429 = String::from_utf8(r429).unwrap();
        assert!(s429.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
        assert!(s429.contains("Content-Length: 18\r\n"));
        assert!(s429.ends_with("\r\n\r\nToo Many Requests\n"));

        // 403 Forbidden
        let r403 = build_synthetic_response(403, None, None);
        let s403 = String::from_utf8(r403).unwrap();
        assert!(s403.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(s403.contains("Content-Length: 10\r\n"));
        assert!(s403.ends_with("\r\n\r\nForbidden\n"));

        // 503 Service Unavailable
        let r503 = build_synthetic_response(503, None, None);
        let s503 = String::from_utf8(r503).unwrap();
        assert!(s503.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(s503.contains("Content-Length: 20\r\n"));
        assert!(s503.ends_with("\r\n\r\nService Unavailable\n"));

        // Custom content type and body
        let r_custom = build_synthetic_response(
            429,
            Some("application/json"),
            Some("{\"error\":\"rate_limited\"}"),
        );
        let s_custom = String::from_utf8(r_custom).unwrap();
        assert!(s_custom.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
        assert!(s_custom.contains("Content-Type: application/json\r\n"));
        assert!(s_custom.contains("Content-Length: 24\r\n"));
        assert!(s_custom.ends_with("\r\n\r\n{\"error\":\"rate_limited\"}"));
    }
}
