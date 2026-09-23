#!/usr/bin/env python3
"""Robust HTTP/1.1 backend for differential and duress test suites."""

from __future__ import annotations

import http.server
import socketserver
import sys
import threading


class RobustHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass  # Suppress logging for benchmark throughput

    def do_GET(self):
        if self.path.startswith("/large-"):
            # Large response generator
            try:
                size_mb = int(self.path.split("-")[1].replace("mb", ""))
            except Exception:
                size_mb = 10
            total_bytes = size_mb * 1024 * 1024
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(total_bytes))
            self.end_headers()
            chunk = b"X" * 65536
            written = 0
            while written < total_bytes:
                to_write = min(len(chunk), total_bytes - written)
                self.wfile.write(chunk[:to_write])
                written += to_write
            return

        body = b"hello-from-quic-backend\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len) if content_len > 0 else b""
        resp = b"ECHO: " + post_data
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_backend(port: int = 0) -> Tuple[ThreadingServer, int]:
    server = ThreadingServer(("127.0.0.1", port), RobustHandler)
    actual_port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, actual_port


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    server, actual_port = start_backend(port)
    print(f"{actual_port}", flush=True)
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        server.shutdown()
