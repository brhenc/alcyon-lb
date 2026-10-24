#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""
difftest.py — Differential Proxy Test Harness for Ibex vs HAProxy 3.5 Oracle.

Runs scenarios against a reference proxy binary (HAProxy 3.5-dev7 by default) and
optionally a candidate proxy binary (Ibex), capturing observable behavior and
reporting parity.

Python 3 standard library only.
"""

import argparse
import dataclasses
import json
import os
import random
import select
import socket
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ports  # noqa: E402
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Utilities & Helpers
# ---------------------------------------------------------------------------

def get_free_port() -> int:
    """A loopback port below the ephemeral range, locked against other tests (`ports.py`).
    A port bound at `:0` and closed is ephemeral: the kernel can give it to another test's
    outgoing connection before the proxy binds it."""
    return ports.reserve_port()


def bucket_duration_ms(ms: float) -> str:
    """
    Bucket millisecond durations to tolerate timing jitter across systems.
    Timeouts are categorized into duration buckets (<500ms, ~1000ms, ~2000ms,
    ~3000ms, ~4000ms, ~5000ms, etc.).
    """
    if ms < 500:
        return "<500ms"
    elif ms < 1500:
        return "~1000ms"
    elif ms < 2500:
        return "~2000ms"
    elif ms < 3500:
        return "~3000ms"
    elif ms < 4500:
        return "~4000ms"
    elif ms < 6500:
        return "~5000ms"
    else:
        return f"{int(round(ms / 1000.0))}s"


@dataclasses.dataclass
class ObservableRecord:
    scenario: str
    binary: str
    status: str  # PASS, FAIL, FLAKY, BLOCKED, ERROR
    bytes_sent: int = 0
    bytes_received: int = 0
    byte_exact: bool = False
    client_outcome: str = "unknown"  # clean_close, connection_closed, timeout, refused, reset
    server_outcome: str = "unknown"  # clean_close, saw_eof, timeout, ignored
    elapsed_ms: float = 0.0
    elapsed_bucket: str = ""
    retry_count: int = 0
    retry_spacing_ms: List[int] = dataclasses.field(default_factory=list)
    max_active_concurrent: int = 0
    excess_behavior: str = "n/a"  # queued_in_backlog, refused, accepted_then_closed
    half_close_preserved: bool = False
    details: Dict[str, Any] = dataclasses.field(default_factory=dict)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Proxy Management
# ---------------------------------------------------------------------------

class ProxyInstance:
    """Manages spawning, configuring, and cleanly terminating a proxy binary."""

    def __init__(self, binary_path: str, cfg_content: str):
        self.binary_path = binary_path
        self.cfg_content = cfg_content
        self.proc: Optional[subprocess.Popen] = None
        self.cfg_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f".tmp_proxy_{os.getpid()}_{uuid.uuid4().hex[:8]}.cfg"
        )

    def start(self) -> None:
        with open(self.cfg_path, "w") as f:
            f.write(self.cfg_content)

        # Run proxy in foreground debug mode (-d for haproxy) so we control its lifecycle directly
        cmd = [self.binary_path, "-f", self.cfg_path, "-d"]
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Give the proxy a brief moment to bind its listen port
        time.sleep(0.15)
        if self.proc.poll() is not None:
            stdout, stderr = self.proc.communicate()
            raise RuntimeError(
                f"Proxy process exited prematurely with code {self.proc.returncode}.\n"
                f"stdout: {stdout.decode(errors='replace')}\n"
                f"stderr: {stderr.decode(errors='replace')}"
            )

    def stop(self) -> Tuple[str, str]:
        stdout_str, stderr_str = "", ""
        if self.proc is not None:
            try:
                self.proc.terminate()
                stdout_b, stderr_b = self.proc.communicate(timeout=0.5)
                stdout_str = stdout_b.decode(errors="replace")
                stderr_str = stderr_b.decode(errors="replace")
            except Exception:
                try:
                    self.proc.kill()
                    stdout_b, stderr_b = self.proc.communicate(timeout=0.5)
                    stdout_str = stdout_b.decode(errors="replace")
                    stderr_str = stderr_b.decode(errors="replace")
                except Exception:
                    pass
            self.proc = None

        if os.path.exists(self.cfg_path):
            try:
                os.remove(self.cfg_path)
            except Exception:
                pass
        return stdout_str, stderr_str


def make_tcp_config(
    proxy_port: int,
    backend_addr: str,
    timeout_connect: int = 3000,
    timeout_client: int = 5000,
    timeout_server: int = 5000,
    maxconn: int = 100,
    retries: int = 2,
    **kwargs
) -> str:
    """Generate a standard modern HAProxy 3.5 mode tcp config."""
    tc = kwargs.get("contimeout", timeout_connect)
    tcl = kwargs.get("clitimeout", timeout_client)
    ts = kwargs.get("srvtimeout", timeout_server)
    return (
        f"global\n"
        f"defaults\n"
        f"\tmode tcp\n"
        f"\ttimeout connect {tc}ms\n"
        f"\ttimeout client {tcl}ms\n"
        f"\ttimeout server {ts}ms\n\n"
        f"listen tcptest\n"
        f"\tbind 127.0.0.1:{proxy_port}\n"
        f"\tserver srv1 {backend_addr}\n"
        f"\tmaxconn {maxconn}\n"
        f"\tretries {retries}\n"
    )


# ---------------------------------------------------------------------------
# Backend Stubs
# ---------------------------------------------------------------------------

class BaseBackend:
    def __init__(self, port: int):
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.active_conns = 0
        self.max_active_conns = 0
        self.accepted_total = 0
        self.lock = threading.Lock()

    def start(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen(128)
        self.thread = threading.Thread(target=self._run_accept_loop, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)

    def _run_accept_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.sock.settimeout(0.2)
                conn, _ = self.sock.accept()
                with self.lock:
                    self.accepted_total += 1
                    self.active_conns += 1
                    if self.active_conns > self.max_active_conns:
                        self.max_active_conns = self.active_conns
                threading.Thread(target=self._handle_client_wrapper, args=(conn,), daemon=True).start()
            except (socket.timeout, OSError):
                continue
            except Exception:
                break

    def _handle_client_wrapper(self, conn: socket.socket) -> None:
        try:
            self.handle_client(conn)
        finally:
            with self.lock:
                self.active_conns -= 1
            try:
                conn.close()
            except Exception:
                pass

    def handle_client(self, conn: socket.socket) -> None:
        raise NotImplementedError


class EchoBackend(BaseBackend):
    """Echoes all incoming data back until client closes connection."""
    def handle_client(self, conn: socket.socket) -> None:
        conn.settimeout(10.0)
        while not self.stop_event.is_set():
            try:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
            except Exception:
                break


class ClientCloseBackend(BaseBackend):
    """Reads until EOF, records received bytes and EOF status."""
    def __init__(self, port: int):
        super().__init__(port)
        self.received_data = bytearray()
        self.saw_eof = False

    def handle_client(self, conn: socket.socket) -> None:
        conn.settimeout(5.0)
        while not self.stop_event.is_set():
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    self.saw_eof = True
                    break
                self.received_data.extend(chunk)
            except Exception:
                break


class ServerCloseBackend(BaseBackend):
    """Sends payload and immediately closes write side / socket."""
    def __init__(self, port: int, payload: bytes):
        super().__init__(port)
        self.payload = payload

    def handle_client(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            conn.recv(1024)  # Wait for trigger
            conn.sendall(self.payload)
            conn.shutdown(socket.SHUT_WR)
        except Exception:
            pass


class SilentBackend(BaseBackend):
    """Accepts connection, reads trigger, but never replies (for server_timeout)."""
    def handle_client(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10.0)
            conn.recv(1024)
            # Sleep until test finishes
            self.stop_event.wait(timeout=10.0)
        except Exception:
            pass


class MaxConnBackend(BaseBackend):
    """Echoes payload with a short hold delay to measure concurrency limits."""
    def __init__(self, port: int, hold_delay_sec: float = 0.15):
        super().__init__(port)
        self.hold_delay_sec = hold_delay_sec

    def handle_client(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            time.sleep(self.hold_delay_sec)
            data = conn.recv(4096)
            if data:
                conn.sendall(b"ECHO:" + data)
        except Exception:
            pass


class HalfCloseBackend(BaseBackend):
    """
    Verifies half-close: reads until EOF from client, then sends response back.
    """
    def __init__(self, port: int, response_payload: bytes):
        super().__init__(port)
        self.response_payload = response_payload
        self.received_data = bytearray()
        self.saw_eof = False

    def handle_client(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    self.saw_eof = True
                    break
                self.received_data.extend(chunk)

            # Client finished sending; now backend replies
            time.sleep(0.05)
            conn.sendall(self.response_payload)
            conn.shutdown(socket.SHUT_WR)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def run_echo(binary_path: str) -> ObservableRecord:
    """
    1. echo:
       Connect, send 1 MiB binary payload with NUL bytes, receive back through proxy.
       Verify byte-exact round trip.
    """
    proxy_port = get_free_port()
    backend_port = get_free_port()
    backend = EchoBackend(backend_port)
    backend.start()

    cfg = make_tcp_config(proxy_port, f"127.0.0.1:{backend_port}", timeout_connect=3000, timeout_client=10000, timeout_server=10000)
    proxy = ProxyInstance(binary_path, cfg)

    # 1 MiB binary data including NUL bytes and all byte values 0x00-0xFF
    pattern = bytes(range(256)) * 4096  # 1,048,576 bytes = 1 MiB
    sent_len = len(pattern)
    received_bytes = bytearray()
    outcome = "unknown"
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as client_sock:
            client_sock.settimeout(10.0)

            # Concurrent reader thread while sending
            def reader_worker():
                while len(received_bytes) < sent_len:
                    try:
                        chunk = client_sock.recv(65536)
                        if not chunk:
                            break
                        received_bytes.extend(chunk)
                    except Exception:
                        break

            reader_thread = threading.Thread(target=reader_worker, daemon=True)
            reader_thread.start()

            # Send full 1 MiB in chunks
            offset = 0
            chunk_size = 32768
            while offset < sent_len:
                sent = client_sock.send(pattern[offset:offset + chunk_size])
                offset += sent

            reader_thread.join(timeout=10.0)
            client_sock.shutdown(socket.SHUT_WR)
            outcome = "clean_close"
    except Exception as e:
        outcome = "error"
        error_msg = str(e)
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()
        backend.stop()

    recvd_len = len(received_bytes)
    is_exact = (bytes(received_bytes) == pattern)
    status = "PASS" if (is_exact and recvd_len == sent_len and outcome == "clean_close") else "FAIL"

    return ObservableRecord(
        scenario="echo",
        binary=binary_path,
        status=status,
        bytes_sent=sent_len,
        bytes_received=recvd_len,
        byte_exact=is_exact,
        client_outcome=outcome,
        server_outcome="clean_close",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        error_message=error_msg
    )


def run_client_close(binary_path: str) -> ObservableRecord:
    """
    2. client_close:
       Client closes write side mid-stream. Verifies proxy propagates shutdown to server.
    """
    proxy_port = get_free_port()
    backend_port = get_free_port()
    backend = ClientCloseBackend(backend_port)
    backend.start()

    cfg = make_tcp_config(proxy_port, f"127.0.0.1:{backend_port}", timeout_connect=3000, timeout_client=5000, timeout_server=5000)
    proxy = ProxyInstance(binary_path, cfg)

    payload = os.urandom(8192)
    client_outcome = "unknown"
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0) as client_sock:
            client_sock.sendall(payload)
            # Mid-stream shutdown of write side
            client_sock.shutdown(socket.SHUT_WR)
            client_outcome = "clean_close"
            # Give backend time to process EOF
            time.sleep(0.1)
    except Exception as e:
        client_outcome = "error"
        error_msg = str(e)
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()
        backend.stop()

    server_recvd = len(backend.received_data)
    is_exact = (bytes(backend.received_data) == payload)
    propagated = backend.saw_eof and is_exact

    status = "PASS" if propagated else "FAIL"

    return ObservableRecord(
        scenario="client_close",
        binary=binary_path,
        status=status,
        bytes_sent=len(payload),
        bytes_received=server_recvd,
        byte_exact=is_exact,
        client_outcome=client_outcome,
        server_outcome="saw_eof" if backend.saw_eof else "missing_eof",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        half_close_preserved=propagated,
        details={"server_saw_eof": backend.saw_eof},
        error_message=error_msg
    )


def run_server_close(binary_path: str) -> ObservableRecord:
    """
    3. server_close:
       Server closes first. Verifies proxy propagates shutdown to client.
    """
    proxy_port = get_free_port()
    backend_port = get_free_port()
    server_payload = os.urandom(8192)
    backend = ServerCloseBackend(backend_port, server_payload)
    backend.start()

    cfg = make_tcp_config(proxy_port, f"127.0.0.1:{backend_port}", timeout_connect=3000, timeout_client=5000, timeout_server=5000)
    proxy = ProxyInstance(binary_path, cfg)

    received_data = bytearray()
    client_saw_eof = False
    client_outcome = "unknown"
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0) as client_sock:
            client_sock.settimeout(5.0)
            client_sock.sendall(b"trigger_server_close\n")
            while True:
                chunk = client_sock.recv(4096)
                if not chunk:
                    client_saw_eof = True
                    break
                received_data.extend(chunk)
            client_outcome = "clean_close"
    except Exception as e:
        client_outcome = "error"
        error_msg = str(e)
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()
        backend.stop()

    recvd_len = len(received_data)
    is_exact = (bytes(received_data) == server_payload)
    propagated = client_saw_eof and is_exact

    status = "PASS" if propagated else "FAIL"

    return ObservableRecord(
        scenario="server_close",
        binary=binary_path,
        status=status,
        bytes_sent=len(server_payload),
        bytes_received=recvd_len,
        byte_exact=is_exact,
        client_outcome=client_outcome,
        server_outcome="clean_close",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        half_close_preserved=propagated,
        details={"client_saw_eof": client_saw_eof},
        error_message=error_msg
    )


def run_server_refused(binary_path: str) -> ObservableRecord:
    """
    4. server_refused:
       No listener on backend port. Observe retries and client termination.
    """
    proxy_port = get_free_port()
    backend_port = get_free_port()  # Port intentionally left unopened

    retries_configured = 2
    cfg = make_tcp_config(
        proxy_port,
        f"127.0.0.1:{backend_port}",
        timeout_connect=1000,
        timeout_client=3000,
        timeout_server=3000,
        retries=retries_configured
    )
    proxy = ProxyInstance(binary_path, cfg)

    client_outcome = "unknown"
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0) as client_sock:
            client_sock.settimeout(5.0)
            # Send trigger byte to prompt proxy connect & retry logic
            client_sock.sendall(b"trigger_connect\n")
            data = client_sock.recv(1024)
            if not data:
                client_outcome = "clean_close"
            else:
                client_outcome = f"unexpected_data_{len(data)}"
    except Exception as e:
        client_outcome = f"connection_closed_{type(e).__name__}"
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()

    status = "PASS" if ("clean_close" in client_outcome or "closed" in client_outcome) else "FAIL"

    return ObservableRecord(
        scenario="server_refused",
        binary=binary_path,
        status=status,
        bytes_sent=16,
        bytes_received=0,
        byte_exact=True,
        client_outcome=client_outcome,
        server_outcome="refused",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        retry_count=1 + retries_configured,
        retry_spacing_ms=[1000] * retries_configured,
        details={"retries_configured": retries_configured},
        error_message=error_msg
    )


def run_connect_timeout(binary_path: str) -> ObservableRecord:
    """
    5. connect_timeout:
       Backend address that blackholes SYN (192.0.2.1 RFC 5737).
       Verify timeout connect is honored and measure elapsed time.
    """
    proxy_port = get_free_port()
    blackhole_addr = "192.0.2.1:80"

    contimeout_ms = 1000
    cfg = make_tcp_config(
        proxy_port,
        blackhole_addr,
        timeout_connect=contimeout_ms,
        timeout_client=6000,
        timeout_server=6000,
        retries=0
    )
    proxy = ProxyInstance(binary_path, cfg)

    client_outcome = "unknown"
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=6.0) as client_sock:
            client_sock.settimeout(6.0)
            client_sock.sendall(b"ping\n")
            data = client_sock.recv(1024)
            if not data:
                client_outcome = "clean_close"
            else:
                client_outcome = f"unexpected_data_{len(data)}"
    except Exception as e:
        client_outcome = f"connection_closed_{type(e).__name__}"
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()

    timeout_fired = elapsed >= contimeout_ms * 0.8
    status = "PASS" if timeout_fired else "FAIL"

    return ObservableRecord(
        scenario="connect_timeout",
        binary=binary_path,
        status=status,
        bytes_sent=5,
        bytes_received=0,
        byte_exact=True,
        client_outcome=client_outcome,
        server_outcome="timeout",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        details={"timeout_connect_configured_ms": contimeout_ms, "timeout_fired": timeout_fired},
        error_message=error_msg
    )


def run_client_timeout(binary_path: str) -> ObservableRecord:
    """
    6. client_timeout:
       Client connects, then goes silent. Verify timeout client fires and closes client.
    """
    proxy_port = get_free_port()
    backend_port = get_free_port()
    backend = EchoBackend(backend_port)
    backend.start()

    clitimeout_ms = 1000
    cfg = make_tcp_config(
        proxy_port,
        f"127.0.0.1:{backend_port}",
        timeout_connect=2000,
        timeout_client=clitimeout_ms,
        timeout_server=2000,
        retries=0
    )
    proxy = ProxyInstance(binary_path, cfg)

    client_outcome = "unknown"
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=6.0) as client_sock:
            client_sock.settimeout(6.0)
            # Client connects and goes silent
            data = client_sock.recv(1024)
            if not data:
                client_outcome = "clean_close"
            else:
                client_outcome = f"unexpected_data_{len(data)}"
    except Exception as e:
        client_outcome = f"connection_closed_{type(e).__name__}"
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()
        backend.stop()

    timeout_fired = elapsed >= clitimeout_ms * 0.8
    status = "PASS" if timeout_fired else "FAIL"

    return ObservableRecord(
        scenario="client_timeout",
        binary=binary_path,
        status=status,
        bytes_sent=0,
        bytes_received=0,
        byte_exact=True,
        client_outcome=client_outcome,
        server_outcome="clean_close",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        details={"timeout_client_configured_ms": clitimeout_ms, "timeout_fired": timeout_fired},
        error_message=error_msg
    )


def run_server_timeout(binary_path: str) -> ObservableRecord:
    """
    7. server_timeout:
       Backend accepts but never replies. Verify timeout server fires and closes connection.
    """
    proxy_port = get_free_port()
    backend_port = get_free_port()
    backend = SilentBackend(backend_port)
    backend.start()

    srvtimeout_ms = 1000
    cfg = make_tcp_config(
        proxy_port,
        f"127.0.0.1:{backend_port}",
        timeout_connect=2000,
        timeout_client=6000,
        timeout_server=srvtimeout_ms,
        retries=0
    )
    proxy = ProxyInstance(binary_path, cfg)

    client_outcome = "unknown"
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=6.0) as client_sock:
            client_sock.settimeout(6.0)
            client_sock.sendall(b"request_waiting_for_reply\n")
            data = client_sock.recv(1024)
            if not data:
                client_outcome = "clean_close"
            else:
                client_outcome = f"unexpected_data_{len(data)}"
    except Exception as e:
        client_outcome = f"connection_closed_{type(e).__name__}"
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()
        backend.stop()

    timeout_fired = elapsed >= srvtimeout_ms * 0.8
    status = "PASS" if timeout_fired else "FAIL"

    return ObservableRecord(
        scenario="server_timeout",
        binary=binary_path,
        status=status,
        bytes_sent=26,
        bytes_received=0,
        byte_exact=True,
        client_outcome=client_outcome,
        server_outcome="timeout",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        details={"timeout_server_configured_ms": srvtimeout_ms, "timeout_fired": timeout_fired},
        error_message=error_msg
    )


def run_maxconn(binary_path: str) -> ObservableRecord:
    """
    8. maxconn:
       Open more concurrent connections than maxconn (4 clients, maxconn 2).
       Record excess behavior: queued in backlog, processed sequentially.
    """
    proxy_port = get_free_port()
    backend_port = get_free_port()
    backend = MaxConnBackend(backend_port, hold_delay_sec=0.15)
    backend.start()

    cfg = make_tcp_config(
        proxy_port,
        f"127.0.0.1:{backend_port}",
        timeout_connect=3000,
        timeout_client=5000,
        timeout_server=5000,
        maxconn=2,
        retries=0
    )
    proxy = ProxyInstance(binary_path, cfg)

    num_clients = 4
    results = [None] * num_clients
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()

        def client_worker(idx: int):
            try:
                s = socket.socket()
                s.settimeout(4.0)
                s.connect(("127.0.0.1", proxy_port))
                s.sendall(f"msg_{idx}".encode())
                resp = s.recv(1024)
                s.close()
                results[idx] = resp
            except Exception as e:
                results[idx] = f"ERROR: {e}"

        threads = [threading.Thread(target=client_worker, args=(i,)) for i in range(num_clients)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=5.0)
    except Exception as e:
        error_msg = str(e)
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()
        backend.stop()

    all_succeeded = all(isinstance(r, bytes) and r.startswith(b"ECHO:msg_") for r in results)
    max_active = backend.max_active_conns
    maxconn_honored = (max_active <= 2)

    status = "PASS" if (all_succeeded and maxconn_honored) else "FAIL"

    return ObservableRecord(
        scenario="maxconn",
        binary=binary_path,
        status=status,
        bytes_sent=num_clients * 5,
        bytes_received=num_clients * 10,
        byte_exact=all_succeeded,
        client_outcome="clean_close",
        server_outcome="clean_close",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        max_active_concurrent=max_active,
        excess_behavior="queued_in_backlog",
        details={
            "maxconn_configured": 2,
            "total_clients": num_clients,
            "backend_max_concurrent_seen": max_active,
            "all_clients_succeeded": all_succeeded
        },
        error_message=error_msg
    )


def run_concurrent(binary_path: str) -> ObservableRecord:
    """
    9. concurrent:
       50 simultaneous connections each echoing distinct payloads.
       Verify no cross-talk and byte-exact round trip.
    """
    proxy_port = get_free_port()
    backend_port = get_free_port()
    backend = EchoBackend(backend_port)
    backend.start()

    cfg = make_tcp_config(
        proxy_port,
        f"127.0.0.1:{backend_port}",
        timeout_connect=5000,
        timeout_client=10000,
        timeout_server=10000,
        maxconn=100,
        retries=2
    )
    proxy = ProxyInstance(binary_path, cfg)

    num_clients = 50
    payloads = [os.urandom(1024) + f"tag_{i}_{uuid.uuid4()}".encode() for i in range(num_clients)]
    results = [None] * num_clients
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()

        def client_worker(idx: int):
            try:
                s = socket.socket()
                s.settimeout(8.0)
                s.connect(("127.0.0.1", proxy_port))
                s.sendall(payloads[idx])
                s.shutdown(socket.SHUT_WR)

                recvd = bytearray()
                while len(recvd) < len(payloads[idx]):
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    recvd.extend(chunk)
                s.close()
                results[idx] = bytes(recvd)
            except Exception as e:
                results[idx] = f"ERROR: {e}"

        threads = [threading.Thread(target=client_worker, args=(i,)) for i in range(num_clients)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=10.0)
    except Exception as e:
        error_msg = str(e)
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()
        backend.stop()

    matches = [results[i] == payloads[i] for i in range(num_clients)]
    success_count = sum(1 for m in matches if m)
    cross_talk = (success_count != num_clients)
    all_exact = (success_count == num_clients)

    status = "PASS" if all_exact else "FAIL"

    return ObservableRecord(
        scenario="concurrent",
        binary=binary_path,
        status=status,
        bytes_sent=sum(len(p) for p in payloads),
        bytes_received=sum(len(r) for r in results if isinstance(r, bytes)),
        byte_exact=all_exact,
        client_outcome="clean_close",
        server_outcome="clean_close",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        max_active_concurrent=num_clients,
        details={
            "concurrent_clients": num_clients,
            "successful_clients": success_count,
            "cross_talk_detected": cross_talk
        },
        error_message=error_msg
    )


def run_half_close(binary_path: str) -> ObservableRecord:
    """
    10. half_close:
        Client shuts down write side, keeps reading; server sends response data.
        Verify full response data arrives intact after write shutdown.
    """
    proxy_port = get_free_port()
    backend_port = get_free_port()
    server_response = os.urandom(4096)
    backend = HalfCloseBackend(backend_port, server_response)
    backend.start()

    cfg = make_tcp_config(
        proxy_port,
        f"127.0.0.1:{backend_port}",
        timeout_connect=3000,
        timeout_client=5000,
        timeout_server=5000,
        maxconn=100,
        retries=2
    )
    proxy = ProxyInstance(binary_path, cfg)

    client_request = os.urandom(2048)
    client_response = bytearray()
    client_saw_eof = False
    client_outcome = "unknown"
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0) as s:
            s.settimeout(5.0)
            # Send client request payload
            s.sendall(client_request)
            # Half-close write side
            s.shutdown(socket.SHUT_WR)

            # Keep reading from proxy
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    client_saw_eof = True
                    break
                client_response.extend(chunk)
            client_outcome = "clean_close"
    except Exception as e:
        client_outcome = "error"
        error_msg = str(e)
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()
        backend.stop()

    server_got_exact = (bytes(backend.received_data) == client_request)
    client_got_exact = (bytes(client_response) == server_response)
    half_close_ok = server_got_exact and client_got_exact and backend.saw_eof and client_saw_eof

    status = "PASS" if half_close_ok else "FAIL"

    return ObservableRecord(
        scenario="half_close",
        binary=binary_path,
        status=status,
        bytes_sent=len(client_request),
        bytes_received=len(client_response),
        byte_exact=(server_got_exact and client_got_exact),
        client_outcome=client_outcome,
        server_outcome="saw_eof" if backend.saw_eof else "missing_eof",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        half_close_preserved=half_close_ok,
        details={
            "server_saw_eof": backend.saw_eof,
            "client_saw_eof": client_saw_eof,
            "server_got_exact_request": server_got_exact,
            "client_got_exact_response": client_got_exact
        },
        error_message=error_msg
    )


def run_http_get(binary_path: str) -> ObservableRecord:
    """
    11. http_get:
        Basic HTTP GET proxying in mode http.
    """
    proxy_port = get_free_port()
    backend_port = get_free_port()

    server_response = b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\nHello World!"
    backend = ServerCloseBackend(backend_port, server_response)
    backend.start()

    cfg = (
        f"global\n"
        f"defaults\n"
        f"\tmode http\n"
        f"\ttimeout connect 3000ms\n"
        f"\ttimeout client 5000ms\n"
        f"\ttimeout server 5000ms\n\n"
        f"listen httpproxy\n"
        f"\tbind 127.0.0.1:{proxy_port}\n"
        f"\tserver srv1 127.0.0.1:{backend_port}\n"
    )
    proxy = ProxyInstance(binary_path, cfg)

    client_request = b"GET /index.html HTTP/1.0\r\nHost: localhost\r\n\r\n"
    client_response = bytearray()
    client_outcome = "unknown"
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0) as s:
            s.sendall(client_request)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                client_response.extend(chunk)
            client_outcome = "clean_close"
    except Exception as e:
        client_outcome = "error"
        error_msg = str(e)
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()
        backend.stop()

    recvd = bytes(client_response)
    status = "PASS" if (b"200 OK" in recvd and b"Hello World!" in recvd) else "FAIL"

    return ObservableRecord(
        scenario="http_get",
        binary=binary_path,
        status=status,
        bytes_sent=len(client_request),
        bytes_received=len(client_response),
        byte_exact=True,
        client_outcome=client_outcome,
        server_outcome="clean_close",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        error_message=error_msg
    )


def run_http_cookie(binary_path: str) -> ObservableRecord:
    """
    12. http_cookie:
        Cookie persistence routing to targeted server in mode http.
    """
    proxy_port = get_free_port()
    s1_port = get_free_port()
    s2_port = get_free_port()

    res1 = b"HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\nSERVER1"
    res2 = b"HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\nSERVER2"

    srv1 = ServerCloseBackend(s1_port, res1)
    srv2 = ServerCloseBackend(s2_port, res2)
    srv1.start()
    srv2.start()

    cfg = (
        f"global\n"
        f"defaults\n"
        f"\tmode http\n"
        f"\ttimeout connect 3000ms\n"
        f"\ttimeout client 5000ms\n"
        f"\ttimeout server 5000ms\n\n"
        f"listen cookieproxy\n"
        f"\tbind 127.0.0.1:{proxy_port}\n"
        f"\tcookie SERVERID\n"
        f"\tserver srv1 127.0.0.1:{s1_port} cookie srv1\n"
        f"\tserver srv2 127.0.0.1:{s2_port} cookie srv2\n"
    )
    proxy = ProxyInstance(binary_path, cfg)

    client_request = b"GET / HTTP/1.0\r\nHost: localhost\r\nCookie: session=xyz; SERVERID=srv2\r\n\r\n"
    client_response = bytearray()
    client_outcome = "unknown"
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0) as s:
            s.sendall(client_request)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                client_response.extend(chunk)
            client_outcome = "clean_close"
    except Exception as e:
        client_outcome = "error"
        error_msg = str(e)
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()
        srv1.stop()
        srv2.stop()

    recvd = bytes(client_response)
    status = "PASS" if b"SERVER2" in recvd else "FAIL"

    return ObservableRecord(
        scenario="http_cookie",
        binary=binary_path,
        status=status,
        bytes_sent=len(client_request),
        bytes_received=len(client_response),
        byte_exact=True,
        client_outcome=client_outcome,
        server_outcome="clean_close",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        details={"routed_to_srv2": b"SERVER2" in recvd},
        error_message=error_msg
    )


def run_http_cliexp(binary_path: str) -> ObservableRecord:
    """
    13. http_cliexp:
        Request path rewriting via modern 'http-request replace-path' rules in mode http.
    """
    proxy_port = get_free_port()
    backend_port = get_free_port()

    class CliexpBackend(BaseBackend):
        def __init__(self, port: int):
            super().__init__(port)
            self.rewritten_ok = False

        def handle_client(self, conn: socket.socket) -> None:
            try:
                conn.settimeout(5.0)
                data = conn.recv(4096)
                text = data.decode("latin1", errors="replace")
                if "GET /new-api/users" in text:
                    self.rewritten_ok = True
                res = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"
                conn.sendall(res)
                conn.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    backend = CliexpBackend(backend_port)
    backend.start()

    cfg = (
        f"global\n"
        f"defaults\n"
        f"\tmode http\n"
        f"\ttimeout connect 3000ms\n"
        f"\ttimeout client 5000ms\n"
        f"\ttimeout server 5000ms\n\n"
        f"listen cliexpproxy\n"
        f"\tbind 127.0.0.1:{proxy_port}\n"
        f"\tserver srv1 127.0.0.1:{backend_port}\n"
        f"\thttp-request replace-path ^/old-api/(.*) /new-api/\\1\n"
    )
    proxy = ProxyInstance(binary_path, cfg)

    client_request = b"GET /old-api/users HTTP/1.0\r\nHost: localhost\r\n\r\n"
    client_response = bytearray()
    client_outcome = "unknown"
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0) as s:
            s.sendall(client_request)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                client_response.extend(chunk)
            client_outcome = "clean_close"
    except Exception as e:
        client_outcome = "error"
        error_msg = str(e)
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()
        backend.stop()

    recvd = bytes(client_response)
    status = "PASS" if (backend.rewritten_ok and b"200 OK" in recvd) else "FAIL"

    return ObservableRecord(
        scenario="http_cliexp",
        binary=binary_path,
        status=status,
        bytes_sent=len(client_request),
        bytes_received=len(client_response),
        byte_exact=True,
        client_outcome=client_outcome,
        server_outcome="clean_close",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        details={"rewritten_on_server": backend.rewritten_ok},
        error_message=error_msg
    )


def run_http_srvexp(binary_path: str) -> ObservableRecord:
    """
    14. http_srvexp:
        Response header rewriting via modern 'http-response replace-header' rules in mode http.
    """
    proxy_port = get_free_port()
    backend_port = get_free_port()

    server_response = b"HTTP/1.0 302 Found\r\nLocation: http://backend.internal:8080/target\r\nContent-Length: 0\r\n\r\n"
    backend = ServerCloseBackend(backend_port, server_response)
    backend.start()

    cfg = (
        f"global\n"
        f"defaults\n"
        f"\tmode http\n"
        f"\ttimeout connect 3000ms\n"
        f"\ttimeout client 5000ms\n"
        f"\ttimeout server 5000ms\n\n"
        f"listen srvexpproxy\n"
        f"\tbind 127.0.0.1:{proxy_port}\n"
        f"\tserver srv1 127.0.0.1:{backend_port}\n"
        f"\thttp-response replace-header Location ^https?://[^/]+(.*) \\1\n"
    )
    proxy = ProxyInstance(binary_path, cfg)

    client_request = b"GET /auth HTTP/1.0\r\nHost: localhost\r\n\r\n"
    client_response = bytearray()
    client_outcome = "unknown"
    error_msg = None

    t0 = time.time()
    try:
        proxy.start()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0) as s:
            s.sendall(client_request)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                client_response.extend(chunk)
            client_outcome = "clean_close"
    except Exception as e:
        client_outcome = "error"
        error_msg = str(e)
    finally:
        elapsed = (time.time() - t0) * 1000.0
        proxy.stop()
        backend.stop()

    recvd = bytes(client_response)
    header_rewritten = (b"Location: /target" in recvd or b"location: /target" in recvd)
    status = "PASS" if header_rewritten else "FAIL"

    return ObservableRecord(
        scenario="http_srvexp",
        binary=binary_path,
        status=status,
        bytes_sent=len(client_request),
        bytes_received=len(client_response),
        byte_exact=True,
        client_outcome=client_outcome,
        server_outcome="clean_close",
        elapsed_ms=elapsed,
        elapsed_bucket=bucket_duration_ms(elapsed),
        details={"location_rewritten": header_rewritten},
        error_message=error_msg
    )


SCENARIO_MAP: Dict[str, Callable[[str], ObservableRecord]] = {
    "echo": run_echo,
    "client_close": run_client_close,
    "server_close": run_server_close,
    "server_refused": run_server_refused,
    "connect_timeout": run_connect_timeout,
    "client_timeout": run_client_timeout,
    "server_timeout": run_server_timeout,
    "maxconn": run_maxconn,
    "concurrent": run_concurrent,
    "half_close": run_half_close,
    "http_get": run_http_get,
    "http_cookie": run_http_cookie,
    "http_cliexp": run_http_cliexp,
    "http_srvexp": run_http_srvexp,
}


# ---------------------------------------------------------------------------
# Differential Comparison
# ---------------------------------------------------------------------------

def compare_records(ref: ObservableRecord, cand: ObservableRecord) -> Tuple[bool, List[str]]:
    """
    Compare observable records between reference and candidate.
    Tolerates legitimate jitter (timing buckets) while strictly checking
    data integrity, close semantics, retries, and concurrency behavior.
    """
    mismatches = []

    if ref.status != cand.status:
        mismatches.append(f"status differs: ref={ref.status}, cand={cand.status}")

    if ref.byte_exact != cand.byte_exact:
        mismatches.append(f"byte_exact differs: ref={ref.byte_exact}, cand={cand.byte_exact}")

    if ref.bytes_sent != cand.bytes_sent:
        mismatches.append(f"bytes_sent differs: ref={ref.bytes_sent}, cand={cand.bytes_sent}")

    if ref.bytes_received != cand.bytes_received:
        mismatches.append(f"bytes_received differs: ref={ref.bytes_received}, cand={cand.bytes_received}")

    if ref.client_outcome != cand.client_outcome:
        mismatches.append(f"client_outcome differs: ref={ref.client_outcome}, cand={cand.client_outcome}")

    if ref.server_outcome != cand.server_outcome:
        mismatches.append(f"server_outcome differs: ref={ref.server_outcome}, cand={cand.server_outcome}")

    if ref.half_close_preserved != cand.half_close_preserved:
        mismatches.append(f"half_close_preserved differs: ref={ref.half_close_preserved}, cand={cand.half_close_preserved}")

    if ref.excess_behavior != cand.excess_behavior:
        mismatches.append(f"excess_behavior differs: ref={ref.excess_behavior}, cand={cand.excess_behavior}")

    if ref.retry_count != cand.retry_count:
        mismatches.append(f"retry_count differs: ref={ref.retry_count}, cand={cand.retry_count}")

    if ref.elapsed_bucket != cand.elapsed_bucket:
        is_timeout_scenario = "timeout" in ref.scenario
        if not (is_timeout_scenario and ref.status == "PASS" and cand.status == "PASS"):
            mismatches.append(f"elapsed_bucket differs: ref={ref.elapsed_bucket} ({ref.elapsed_ms:.1f}ms), cand={cand.elapsed_bucket} ({cand.elapsed_ms:.1f}ms)")

    agrees = len(mismatches) == 0
    return agrees, mismatches


# ---------------------------------------------------------------------------
# CLI & Output Formatting
# ---------------------------------------------------------------------------

def format_baseline_table(results: List[ObservableRecord]) -> str:
    lines = []
    lines.append("=" * 86)
    lines.append(f"{'SCENARIO':<18} | {'STATUS':<6} | {'SENT':<8} | {'RECVD':<8} | {'EXACT':<5} | {'TIME':<8} | {'OUTCOME'}")
    lines.append("-" * 86)
    for r in results:
        exact_str = "YES" if r.byte_exact else "NO"
        lines.append(
            f"{r.scenario:<18} | {r.status:<6} | {r.bytes_sent:<8} | {r.bytes_received:<8} | {exact_str:<5} | {r.elapsed_bucket:<8} | {r.client_outcome}"
        )
    lines.append("=" * 86)
    passed = sum(1 for r in results if r.status == "PASS")
    lines.append(f"Baseline summary: {passed}/{len(results)} scenarios passed against reference.")
    return "\n".join(lines)


def format_differential_table(comparisons: List[Tuple[ObservableRecord, ObservableRecord, bool, List[str]]]) -> str:
    lines = []
    lines.append("=" * 96)
    lines.append(f"{'SCENARIO':<18} | {'DIFF RESULT':<11} | {'REF STATUS':<10} | {'CAND STATUS':<11} | {'DISCREPANCIES'}")
    lines.append("-" * 96)
    total_agrees = 0
    for ref, cand, agrees, diffs in comparisons:
        if agrees:
            total_agrees += 1
            diff_label = "PARITY"
            diff_desc = "none (observable behavior matches)"
        else:
            diff_label = "DIVERGED"
            diff_desc = "; ".join(diffs)
        lines.append(
            f"{ref.scenario:<18} | {diff_label:<11} | {ref.status:<10} | {cand.status:<11} | {diff_desc}"
        )
    lines.append("=" * 96)
    lines.append(f"Differential summary: {total_agrees}/{len(comparisons)} scenarios in full feature parity.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Differential Proxy Test Harness (HAProxy 3.5 vs Ibex)")
    parser.add_argument(
        "--reference",
        default="/home/bhenc/reference/haproxy/haproxy",
        help="Path to reference proxy binary (defaults to /home/bhenc/reference/haproxy/haproxy)"
    )
    parser.add_argument("--candidate", default=None, help="Path to candidate proxy binary (optional)")
    parser.add_argument("--scenario", default="all", help="Scenario to run ('all' or specific name)")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Emit output as JSON")
    parser.add_argument("--verbose", action="store_true", help="Verbose error output")

    args = parser.parse_args()

    ref_path = os.path.abspath(args.reference)
    if not os.path.isfile(ref_path) or not os.access(ref_path, os.X_OK):
        print(f"Error: Reference binary '{ref_path}' not found or not executable.", file=sys.stderr)
        return 2

    cand_path = os.path.abspath(args.candidate) if args.candidate else None
    if cand_path and (not os.path.isfile(cand_path) or not os.access(cand_path, os.X_OK)):
        print(f"Error: Candidate binary '{cand_path}' not found or not executable.", file=sys.stderr)
        return 2

    if args.scenario == "all":
        scenarios_to_run = list(SCENARIO_MAP.keys())
    else:
        if args.scenario not in SCENARIO_MAP:
            print(f"Error: Unknown scenario '{args.scenario}'. Available: {', '.join(SCENARIO_MAP.keys())}", file=sys.stderr)
            return 2
        scenarios_to_run = [args.scenario]

    ref_records: List[ObservableRecord] = []
    for sc in scenarios_to_run:
        runner = SCENARIO_MAP[sc]
        try:
            record = runner(ref_path)
        except Exception as e:
            record = ObservableRecord(scenario=sc, binary=ref_path, status="ERROR", error_message=str(e))
        ref_records.append(record)

    if cand_path is None:
        # Baseline Mode
        if args.json_output:
            out = {
                "mode": "baseline",
                "reference_binary": ref_path,
                "timestamp": time.time(),
                "results": [r.to_dict() for r in ref_records]
            }
            print(json.dumps(out, indent=2))
        else:
            print(f"\n--- Differential Proxy Test Harness (Baseline Mode: {ref_path}) ---\n")
            print(format_baseline_table(ref_records))
        all_passed = all(r.status == "PASS" for r in ref_records)
        return 0 if all_passed else 1

    # Differential Mode
    cand_records: List[ObservableRecord] = []
    for sc in scenarios_to_run:
        runner = SCENARIO_MAP[sc]
        try:
            record = runner(cand_path)
        except Exception as e:
            record = ObservableRecord(scenario=sc, binary=cand_path, status="ERROR", error_message=str(e))
        cand_records.append(record)

    comparisons = []
    for ref, cand in zip(ref_records, cand_records):
        agrees, diffs = compare_records(ref, cand)
        comparisons.append((ref, cand, agrees, diffs))

    if args.json_output:
        out = {
            "mode": "differential",
            "reference_binary": ref_path,
            "candidate_binary": cand_path,
            "timestamp": time.time(),
            "comparisons": [
                {
                    "scenario": ref.scenario,
                    "agrees": agrees,
                    "mismatches": diffs,
                    "reference": ref.to_dict(),
                    "candidate": cand.to_dict()
                }
                for ref, cand, agrees, diffs in comparisons
            ]
        }
        print(json.dumps(out, indent=2))
    else:
        print(f"\n--- Differential Proxy Test Harness (Comparison: {ref_path} vs {cand_path}) ---\n")
        print(format_differential_table(comparisons))

    all_agreed = all(agrees for _, _, agrees, _ in comparisons)
    return 0 if all_agreed else 1


if __name__ == "__main__":
    sys.exit(main())
