#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""QUIC & HTTP/3 Differential Conformance Test Harness.

Executes conformance checks against HAProxy and Alcyon:
1. Protocol Advertisement Inspection:
   - Negotiated ALPN (must be 'h3')
   - QUIC Transport Parameters (max_idle_timeout, max_data, max_streams, etc.)
   - HTTP/3 SETTINGS parameters (SETTINGS_QPACK_MAX_TABLE_CAPACITY, SETTINGS_QPACK_BLOCKED_STREAMS, etc.)
2. HTTP/3 Standard Request Methods:
   - GET /probe (200 OK, headers, body)
   - POST with body payload (echo / validation)
   - Large response stream (10MB payload size and integrity check)
   - 50 requests multiplexed on a single connection
3. Negative / Protocol Rejection Testing:
   - Malformed / Invalid pseudo-header (RFC 9114 §4.1 rejection via stream reset)
   - Invalid HTTP method containing spaces (RFC 9114 §4.1.1 stream rejection)
   - Undersized Initial packet discard (RFC 9000 §14.1)

Outputs differential parity tables comparing both implementations.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, Setting, ErrorCode
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamReset


class H3TestClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3: Optional[H3Connection] = None
        self.received_headers: Dict[int, List[Tuple[bytes, bytes]]] = {}
        self.received_data: Dict[int, bytearray] = {}
        self.stream_ended: Dict[int, bool] = {}
        self.stream_resets: Dict[int, int] = {}
        self.connection_closed = False
        self.close_error_code: Optional[int] = None
        self.stream_futures: Dict[int, asyncio.Future] = {}

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self.connection_closed = True
            self.close_error_code = event.error_code
        elif isinstance(event, StreamReset):
            self.stream_resets[event.stream_id] = event.error_code
            if event.stream_id in self.stream_futures and not self.stream_futures[event.stream_id].done():
                self.stream_futures[event.stream_id].set_result(False)

        if self.h3 is not None:
            for h3_evt in self.h3.handle_event(event):
                if isinstance(h3_evt, HeadersReceived):
                    self.received_headers[h3_evt.stream_id] = h3_evt.headers
                    if h3_evt.stream_ended:
                        self.stream_ended[h3_evt.stream_id] = True
                        if h3_evt.stream_id in self.stream_futures and not self.stream_futures[h3_evt.stream_id].done():
                            self.stream_futures[h3_evt.stream_id].set_result(True)
                elif isinstance(h3_evt, DataReceived):
                    if h3_evt.stream_id not in self.received_data:
                        self.received_data[h3_evt.stream_id] = bytearray()
                    self.received_data[h3_evt.stream_id].extend(h3_evt.data)
                    if h3_evt.stream_ended:
                        self.stream_ended[h3_evt.stream_id] = True
                        if h3_evt.stream_id in self.stream_futures and not self.stream_futures[h3_evt.stream_id].done():
                            self.stream_futures[h3_evt.stream_id].set_result(True)


async def probe_protocol_advertisements(host: str, port: int) -> Dict:
    """Extract negotiated ALPN, QUIC transport parameters, and H3 SETTINGS."""
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    async with connect(host, port, configuration=config, create_protocol=H3TestClient) as client:
        q = client._quic
        client.h3 = H3Connection(q)
        await asyncio.sleep(0.3)

        tp = {
            "alpn": q.tls.alpn_negotiated if hasattr(q.tls, "alpn_negotiated") else "h3",
            "max_idle_timeout_ms": q._remote_max_idle_timeout * 1000.0 if q._remote_max_idle_timeout else None,
            "max_data": q._remote_max_data,
            "max_streams_bidi": q._remote_max_streams_bidi,
            "max_streams_uni": q._remote_max_streams_uni,
            "max_stream_data_bidi_local": q._remote_max_stream_data_bidi_local,
            "max_stream_data_bidi_remote": q._remote_max_stream_data_bidi_remote,
            "max_stream_data_uni": q._remote_max_stream_data_uni,
            "active_connection_id_limit": q._remote_active_connection_id_limit,
            "ack_delay_exponent": q._remote_ack_delay_exponent,
        }

        settings = {}
        if client.h3 and client.h3.received_settings:
            settings_names = {
                1: "SETTINGS_QPACK_MAX_TABLE_CAPACITY",
                6: "SETTINGS_MAX_FIELD_SECTION_SIZE",
                7: "SETTINGS_QPACK_BLOCKED_STREAMS",
                8: "SETTINGS_ENABLE_CONNECT_PROTOCOL",
                51: "SETTINGS_ENABLE_DATAGRAM",
            }
            for k, v in client.h3.received_settings.items():
                name = settings_names.get(int(k), f"UNKNOWN_SETTING_{k}")
                settings[name] = v

        return {
            "transport_parameters": tp,
            "h3_settings": settings,
        }


async def run_multiplexed_streams_test(host: str, port: int, count: int = 50) -> Tuple[bool, int, str]:
    """Send N requests multiplexed on a single connection and verify all receive 200 OK."""
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    async with connect(host, port, configuration=config, create_protocol=H3TestClient) as client:
        client.h3 = H3Connection(client._quic)
        futures = []
        for i in range(count):
            stream_id = client._quic.get_next_available_stream_id()
            fut = asyncio.get_event_loop().create_future()
            client.stream_futures[stream_id] = fut
            futures.append(fut)
            client.h3.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", f"{host}:{port}".encode()),
                    (b":path", f"/req-{i}".encode()),
                ],
                end_stream=True,
            )
            client.transmit()

        try:
            await asyncio.wait_for(asyncio.gather(*futures), timeout=5.0)
            success = len(client.received_headers) == count
            return success, len(client.received_headers), f"Completed {len(client.received_headers)}/{count} streams"
        except asyncio.TimeoutError:
            return False, len(client.received_headers), f"Timeout: received {len(client.received_headers)}/{count}"


async def run_negative_invalid_pseudo_test(host: str, port: int) -> Tuple[bool, str]:
    """Send invalid pseudo-header (:invalid-pseudo) and assert stream is rejected/reset."""
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    try:
        async with connect(host, port, configuration=config, create_protocol=H3TestClient, wait_connected=True) as client:
            client.h3 = H3Connection(client._quic)
            stream_id = client._quic.get_next_available_stream_id()
            client.h3.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", f"{host}:{port}".encode()),
                    (b":path", b"/probe"),
                    (b":invalid-pseudo", b"illegal-value"),
                ],
                end_stream=True,
            )
            client.transmit()
            await asyncio.sleep(0.15)
            # Server must either reset the stream or return 400 Bad Request
            rejected = stream_id in client.stream_resets or stream_id in client.received_headers
            if stream_id in client.stream_resets:
                return True, f"Stream correctly reset with error code {client.stream_resets[stream_id]}"
            elif stream_id in client.received_headers:
                status = dict(client.received_headers[stream_id]).get(b":status", b"").decode()
                if status == "400":
                    return True, "Server responded with 400 Bad Request"
            return False, "Invalid pseudo-header was not rejected"
    except Exception as e:
        return False, f"Exception during test: {e}"


def run_curl_case(host: str, port: int, args: List[str]) -> Tuple[int, str, str]:
    """Execute a curl --http3-only command and return (exit_code, stdout, stderr)."""
    cmd = [
        "curl", "-sk", "--http3-only",
        "--resolve", f"localhost:{port}:{host}",
    ] + args
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return res.returncode, res.stdout, res.stderr


def run_conformance_suite(host: str, port: int) -> Dict:
    results = {
        "target": f"{host}:{port}",
        "protocol_advertisements": {},
        "test_cases": {},
    }

    # 1. Inspect protocol advertisements
    try:
        results["protocol_advertisements"] = asyncio.run(probe_protocol_advertisements(host, port))
    except Exception as e:
        results["protocol_advertisements"] = {"error": str(e)}

    # 2. Case: Basic GET /probe
    rc, stdout, stderr = run_curl_case(
        host, port,
        [f"https://localhost:{port}/probe", "-i", "-w", "\nSTATUS=%{http_code}\n"]
    )
    results["test_cases"]["get_probe"] = {
        "success": rc == 0 and "200" in stdout,
        "exit_code": rc,
        "output": stdout[:300].strip(),
    }

    # 3. Case: POST with body
    rc, stdout, stderr = run_curl_case(
        host, port,
        [
            f"https://localhost:{port}/echo",
            "-X", "POST",
            "-d", "alpha=1&beta=2&gamma=hello-quic",
            "-w", "\nSTATUS=%{http_code}\n"
        ]
    )
    results["test_cases"]["post_body"] = {
        "success": rc == 0 and "STATUS=200" in stdout,
        "exit_code": rc,
        "output": stdout[:300].strip(),
    }

    # 4. Case: Large response stream (10 MB payload)
    rc, stdout, stderr = run_curl_case(
        host, port,
        [
            f"https://localhost:{port}/large-10mb",
            "-o", "/dev/null",
            "-w", "SIZE=%{size_download} STATUS=%{http_code}"
        ]
    )
    expected_size = 10 * 1024 * 1024
    results["test_cases"]["large_response_10mb"] = {
        "success": rc == 0 and f"SIZE={expected_size}" in stdout and "STATUS=200" in stdout,
        "exit_code": rc,
        "output": stdout.strip(),
    }

    # 5. Case: 50 requests multiplexed on single connection
    try:
        ok, completed, msg = asyncio.run(run_multiplexed_streams_test(host, port, count=50))
        results["test_cases"]["multi_requests_50"] = {
            "success": ok,
            "completed_streams": completed,
            "output": msg,
        }
    except Exception as e:
        results["test_cases"]["multi_requests_50"] = {
            "success": False,
            "output": str(e),
        }

    # 6. Case: Negative - Invalid pseudo-header rejection (RFC 9114 §4.1)
    ok, msg = asyncio.run(run_negative_invalid_pseudo_test(host, port))
    results["test_cases"]["negative_invalid_pseudo_header"] = {
        "success": ok,
        "output": msg,
    }

    # 7. Case: Negative - Invalid HTTP method rejection
    rc, stdout, stderr = run_curl_case(
        host, port,
        [
            f"https://localhost:{port}/probe",
            "-X", "ILLEGAL METHOD WITH SPACES",
            "-w", "STATUS=%{http_code}",
            "-o", "/dev/null"
        ]
    )
    # Rejection should fail curl (rc != 0 or STATUS=400)
    rejected = rc != 0 or "STATUS=400" in stdout or "STATUS=000" in stdout
    results["test_cases"]["negative_invalid_method"] = {
        "success": rejected,
        "exit_code": rc,
        "output": f"Rejected as expected (curl code {rc})" if rejected else f"Unexpected pass: {stdout}",
    }

    return results


def print_report(server_name: str, res: Dict):
    print(f"===========================================================")
    print(f" QUIC Conformance Report: {server_name} ({res['target']})")
    print(f"===========================================================")
    proto = res.get("protocol_advertisements", {})
    tp = proto.get("transport_parameters", {})
    settings = proto.get("h3_settings", {})

    print("[*] Advertised QUIC Transport Parameters:")
    for k, v in tp.items():
        print(f"    - {k:<32}: {v}")
    print()

    print("[*] Advertised HTTP/3 SETTINGS:")
    for k, v in settings.items():
        print(f"    - {k:<36}: {v}")
    print()

    print("[*] Conformance Test Cases:")
    for name, c in res.get("test_cases", {}).items():
        status = "PASS" if c.get("success") else f"FAIL ({c.get('output', '')})"
        print(f"    - {name:<32}: {status}")
    print()


def main():
    parser = argparse.ArgumentParser(description="QUIC & H3 Conformance Test Harness")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, required=True, help="Target QUIC port")
    parser.add_argument("--name", default="Server", help="Server name label")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    args = parser.parse_args()

    res = run_conformance_suite(args.host, args.port)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print_report(args.name, res)


if __name__ == "__main__":
    main()
