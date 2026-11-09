#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""
Smoke test verifying that Project Alcyon starts with a reference configuration,
terminates TLS on https://localhost:8443/, and proxies requests to an upstream
Nginx process, verified with curl.
"""

import http.server
import os
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time

CERT_PEM = "examples/certs/localhost.pem"
CONFIG_FILE = "examples/reference_nginx_8443.cfg"
# The binary `cargo build` writes: CARGO_TARGET_DIR when it is set (T109).
ALCYON_BIN = os.path.join(os.environ.get("CARGO_TARGET_DIR") or "target", "debug", "alcyon")

class MockNginxHandler(http.server.BaseHTTPRequestHandler):
    def version_string(self):
        return "nginx/1.24.0"

    def do_GET(self):
        body = (
            b"<!DOCTYPE html>\n"
            b"<html>\n"
            b"<head><title>Welcome to nginx!</title></head>\n"
            b"<body>\n"
            b"<h1>Welcome to nginx proxied by Alcyon!</h1>\n"
            b"<p>If you see this page, the Alcyon TLS reverse proxy successfully\n"
            b"terminated HTTPS and proxied to this upstream Nginx process.</p>\n"
            b"</body>\n"
            b"</html>\n"
        )
        self.send_response(200)
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        sys.stderr.write(f"[mock-nginx] {args[0]} - {args[1]}\n")

def wait_for_port(port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.05)
    return False

def main():
    # 1. Build alcyon if needed
    if not os.path.exists(ALCYON_BIN):
        print("[smoke] Building alcyon binary...")
        subprocess.check_call(["cargo", "build", "--bin", "alcyon"])

    # 2. Check cert
    if not os.path.exists(CERT_PEM):
        sys.exit(f"Error: Certificate file '{CERT_PEM}' not found.")

    # 3. Start Mock Nginx server on port 8080
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 8080), MockNginxHandler)
    nginx_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    nginx_thread.start()
    print("[smoke] Upstream Nginx process listening on 127.0.0.1:8080")

    # 4. Start Alcyon daemon on port 8443
    print(f"[smoke] Starting Alcyon daemon with config {CONFIG_FILE}...")
    alcyon_proc = subprocess.Popen(
        [ALCYON_BIN, "-f", CONFIG_FILE],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        if not wait_for_port(8443, timeout=5.0):
            stdout, stderr = alcyon_proc.communicate(timeout=1)
            sys.exit(f"Error: Alcyon failed to listen on port 8443.\nstderr: {stderr.decode()}")

        print("[smoke] Alcyon is listening on https://localhost:8443/ (TLS terminated)")

        # 5. Execute curl
        curl_cmd = [
            "curl",
            "-4",
            "-v",
            "--cacert", CERT_PEM,
            "https://localhost:8443/",
        ]
        print(f"[smoke] Executing: {' '.join(curl_cmd)}")
        curl_res = subprocess.run(
            curl_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )

        stdout = curl_res.stdout.decode("utf-8", errors="replace")
        stderr = curl_res.stderr.decode("utf-8", errors="replace")

        print("\n" + "=" * 30 + " CURL TRACE (stderr) " + "=" * 30)
        print(stderr)
        print("=" * 30 + " CURL RESPONSE (stdout) " + "=" * 30)
        print(stdout)
        print("=" * 70 + "\n")

        # 6. Verify assertions
        assert curl_res.returncode == 0, f"curl exited with non-zero status {curl_res.returncode}"
        assert "200 OK" in stderr or "200 OK" in stdout, "Expected HTTP 200 OK"
        assert "Server: nginx/1.24.0" in stderr or "server: nginx/1.24.0" in stderr, "Expected Server: nginx header"
        assert "Welcome to nginx proxied by Alcyon!" in stdout, "Expected Nginx welcome body"
        assert "TLSv1.3" in stderr or "SSL connection using TLSv1.3" in stderr, "Expected TLS 1.3 negotiated"

        print(">>> SMOKE TEST PASSED SUCCESSFULLY! <<<")
        print("Alcyon successfully terminated TLS on port 8443 and proxied request to Nginx backend.")
        return 0

    finally:
        # Cleanup
        alcyon_proc.terminate()
        try:
            alcyon_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            alcyon_proc.kill()
        httpd.shutdown()
        httpd.server_close()

if __name__ == "__main__":
    sys.exit(main())
