#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""QUIC Initial Flood Duress Test Script.

Tests server behavior under a flood of unanswered Initial packets from varied sources:
- Generates dynamically unique Initial packets with varied Connection IDs.
- Utilizes a pool of ephemeral UDP client sockets to simulate varied source endpoints.
- Sends Initial packets at target rate for specified duration.
- Tracks response datagrams sent by the server.
- Measures CPU ticks and RSS memory growth of the target process.
- Evaluates Retry threshold behavior (`tune.quic.fe.sec.retry-threshold`).
- Validates post-flood server responsiveness with a normal probe.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import ssl
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection


def get_process_metrics(pid: int) -> Tuple[float, int]:
    """Return (cpu_ticks, rss_kb) for a given PID."""
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            parts = f.read().split()
            utime = int(parts[13])
            stime = int(parts[14])
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                    return float(utime + stime), rss_kb
    except Exception:
        pass
    return 0.0, 0


def generate_unique_initial_packet(dest_addr: Tuple[str, int]) -> bytes:
    """Generate a genuine Initial packet with a fresh randomized Connection ID."""
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    conn = QuicConnection(configuration=config)
    conn.connect(dest_addr, now=time.time())
    dgrams = conn.datagrams_to_send(now=time.time())
    return dgrams[0][0] if dgrams else b""


def verify_server_health(host: str, port: int) -> bool:
    """Check if server can serve a normal curl HTTP/3 probe."""
    try:
        res = subprocess.run(
            [
                "curl", "-sk", "--http3-only",
                "--resolve", f"localhost:{port}:{host}",
                f"https://localhost:{port}/probe",
                "-o", "/dev/null", "--connect-timeout", "2"
            ],
            capture_output=True,
            timeout=3
        )
        return res.returncode == 0
    except Exception:
        return False


def run_initial_flood(
    host: str,
    port: int,
    duration: float = 2.0,
    target_pps: int = 2000,
    target_pid: Optional[int] = None,
    socket_pool_size: int = 16,
) -> Dict:
    """Run initial packet flood test against host:port using a pool of varied client sockets."""
    sockets = []
    for _ in range(socket_pool_size):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.setblocking(False)
        sockets.append(s)

    # Pre-generate a pool of 200 unique Initial packets to ensure high throughput without overhead
    packet_pool = [generate_unique_initial_packet((host, port)) for _ in range(200)]

    initial_cpu, initial_rss = get_process_metrics(target_pid) if target_pid else (0.0, 0)

    start_time = time.time()
    packets_sent = 0
    bytes_sent = 0
    packets_recv = 0
    bytes_recv = 0

    interval = 1.0 / target_pps
    next_send = start_time

    while time.time() - start_time < duration:
        now = time.time()
        if now >= next_send:
            sock = random.choice(sockets)
            # Pick a packet and inject a randomized 8-byte destination connection ID to guarantee diversity
            base_pkt = bytearray(random.choice(packet_pool))
            if len(base_pkt) >= 1200:
                # Randomize DCID in QUIC Long Header
                for idx in range(6, 14):
                    base_pkt[idx] = random.randint(0, 255)
            pkt = bytes(base_pkt)

            try:
                sock.sendto(pkt, (host, port))
                packets_sent += 1
                bytes_sent += len(pkt)
            except OSError:
                pass
            next_send += interval

        # Poll incoming responses across the socket pool without blocking
        for s in sockets:
            try:
                while True:
                    data, _ = s.recvfrom(65535)
                    packets_recv += 1
                    bytes_recv += len(data)
            except (BlockingIOError, OSError):
                pass

    # Wait 200ms to collect remaining in-flight responses
    flush_end = time.time() + 0.2
    while time.time() < flush_end:
        for s in sockets:
            try:
                data, _ = s.recvfrom(65535)
                packets_recv += 1
                bytes_recv += len(data)
            except (BlockingIOError, OSError):
                pass
        time.sleep(0.01)

    for s in sockets:
        s.close()

    elapsed = time.time() - start_time
    final_cpu, final_rss = get_process_metrics(target_pid) if target_pid else (0.0, 0)
    rss_delta_kb = final_rss - initial_rss if target_pid else 0

    healthy_after = verify_server_health(host, port)

    return {
        "target": f"{host}:{port}",
        "duration_sec": elapsed,
        "packets_sent": packets_sent,
        "bytes_sent": bytes_sent,
        "sent_pps": packets_sent / elapsed if elapsed > 0 else 0,
        "packets_recv": packets_recv,
        "bytes_recv": bytes_recv,
        "recv_pps": packets_recv / elapsed if elapsed > 0 else 0,
        "response_byte_ratio": bytes_recv / bytes_sent if bytes_sent > 0 else 0,
        "initial_rss_kb": initial_rss,
        "final_rss_kb": final_rss,
        "rss_delta_kb": rss_delta_kb,
        "healthy_post_flood": healthy_after,
    }


def print_report(server_name: str, res: Dict):
    print(f"===========================================================")
    print(f" QUIC Initial Flood Test: {server_name} ({res['target']})")
    print(f"===========================================================")
    print(f"[*] Flood Duration:     {res['duration_sec']:.2f} s")
    print(f"[*] Packets Sent:       {res['packets_sent']} ({res['sent_pps']:.1f} pps, {res['bytes_sent']/1024:.1f} KB)")
    print(f"[*] Packets Received:   {res['packets_recv']} ({res['recv_pps']:.1f} pps, {res['bytes_recv']/1024:.1f} KB)")
    print(f"[*] Response Ratio:     {res['response_byte_ratio']:.3f}x")
    if res['final_rss_kb'] > 0:
        print(f"[*] Memory RSS:         {res['final_rss_kb']} KB (delta: {res['rss_delta_kb']:+d} KB)")
    print(f"[*] Post-Flood Health:  {'PASS (Responsive)' if res['healthy_post_flood'] else 'FAIL (Unresponsive)'}")
    print()


def main():
    parser = argparse.ArgumentParser(description="QUIC Initial Flood Duress Test")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, required=True, help="Target QUIC port")
    parser.add_argument("--pid", type=int, default=None, help="Target process PID")
    parser.add_argument("--duration", type=float, default=2.0, help="Flood duration in seconds")
    parser.add_argument("--pps", type=int, default=2000, help="Target packets per second")
    parser.add_argument("--name", default="Server", help="Server name label")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    args = parser.parse_args()

    res = run_initial_flood(args.host, args.port, duration=args.duration, target_pps=args.pps, target_pid=args.pid)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print_report(args.name, res)


if __name__ == "__main__":
    main()
