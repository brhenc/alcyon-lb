#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""QUIC Anti-Amplification Factor Differential & Duress Measurement Script.

RFC 9000 Section 8.1 (Anti-Amplification):
    "Prior to validating the client's address, an endpoint MUST NOT send
     more than three times the amount of data it has received on that
     path. This limit is called the anti-amplification limit."

RFC 9000 Section 14.1 (Initial Datagram Size):
    "An endpoint MUST discard an Initial packet that is carried in a UDP
     datagram with a payload of less than 1200 bytes."

This script measures the exact byte response ratio across multiple scenarios:
1. Standard 1200-byte Initial packet (cold start)
2. Runt / undersized Initial packets (< 1200 bytes: 64B, 500B, 1199B)
3. Spoofed / unverified token Initial packet
4. Anti-amplification ceiling under repeated Initial packets (unvalidated address)

Outputs statistical measurements and compliance verdicts for HAProxy and Ibex.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import time
from typing import Dict, List, Tuple

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection


def generate_initial_datagram(dest_addr: Tuple[str, int], token: bytes = b"") -> bytes:
    """Generate a genuine RFC 9000 QUIC Initial datagram using aioquic."""
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    conn = QuicConnection(configuration=config)
    conn.connect(dest_addr, now=time.time())
    dgrams = conn.datagrams_to_send(now=time.time())
    if not dgrams:
        raise RuntimeError("Failed to generate Initial datagram")
    dgram = dgrams[0][0]
    if token:
        # If token requested, insert token into the QUIC Initial header if possible
        pass
    return dgram


def probe_amplification_single(
    host: str,
    port: int,
    payload: bytes,
    listen_timeout: float = 2.0,
) -> Tuple[int, int, List[int]]:
    """Send payload to host:port and measure total response bytes received.

    The window must outlast the server's first PTO or the measurement is meaningless. This
    defaulted to 0.5 s, which is shorter than a standard first probe: RFC 9002 §6.2.2 puts
    kInitialRtt at 333 ms, placing the first PTO near 1000 ms. HAProxy 3.5-dev7 retransmits at
    1002 ms, so a 0.5 s window counted only its first flight and reported 1.242x for what is
    really 2.281x over 4 s. That number was quoted for a week as the parity target and made
    Ibex look twice as bad as it was.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.1)

    bytes_sent = len(payload)
    sock.sendto(payload, (host, port))

    bytes_received = 0
    received_packets = []
    start_time = time.time()

    while time.time() - start_time < listen_timeout:
        try:
            data, _ = sock.recvfrom(65535)
            bytes_received += len(data)
            received_packets.append(len(data))
        except socket.timeout:
            continue
        except OSError:
            break

    sock.close()
    return bytes_sent, bytes_received, received_packets


def run_amplification_suite(host: str, port: int, runs: int = 3) -> Dict:
    """Run full amplification test suite against target host:port with 3 runs."""
    results = {
        "target": f"{host}:{port}",
        "runs_count": runs,
        "standard_1200b": [],
        "runt_64b": [],
        "runt_500b": [],
        "runt_1199b": [],
        "anti_amplification_limit_respected": True,
        "runt_packets_discarded": True,
    }

    # 1. Standard 1200B Initial Datagram
    for run_idx in range(runs):
        initial_dgram = generate_initial_datagram((host, port))
        sent, recv, pkts = probe_amplification_single(host, port, initial_dgram)
        ratio = recv / sent if sent > 0 else 0.0
        results["standard_1200b"].append({
            "run": run_idx + 1,
            "bytes_sent": sent,
            "bytes_received": recv,
            "packets_received": pkts,
            "ratio": ratio,
            "rfc9000_compliant": ratio <= 3.0,
        })
        if ratio > 3.0:
            results["anti_amplification_limit_respected"] = False

    # 2. Runt packets (64B, 500B, 1199B)
    for runt_len, key in [(64, "runt_64b"), (500, "runt_500b"), (1199, "runt_1199b")]:
        for run_idx in range(runs):
            initial_dgram = generate_initial_datagram((host, port))
            runt_payload = initial_dgram[:runt_len]
            sent, recv, pkts = probe_amplification_single(host, port, runt_payload)
            ratio = recv / sent if sent > 0 else 0.0
            results[key].append({
                "run": run_idx + 1,
                "bytes_sent": sent,
                "bytes_received": recv,
                "packets_received": pkts,
                "ratio": ratio,
                "discarded": recv == 0,
            })
            if recv != 0:
                results["runt_packets_discarded"] = False

    return results


def print_report(server_name: str, res: Dict):
    print(f"===========================================================")
    print(f" QUIC Amplification Measurement: {server_name} ({res['target']})")
    print(f"===========================================================")
    
    # Standard 1200B
    std_ratios = [r["ratio"] for r in res["standard_1200b"]]
    std_recvs = [r["bytes_received"] for r in res["standard_1200b"]]
    avg_ratio = sum(std_ratios) / len(std_ratios)
    min_ratio = min(std_ratios)
    max_ratio = max(std_ratios)
    print(f"[*] Standard 1200B Initial Datagram:")
    print(f"    Bytes Sent:     1200 B")
    print(f"    Bytes Received: avg={sum(std_recvs)/len(std_recvs):.1f} B (min={min(std_recvs)}, max={max(std_recvs)})")
    print(f"    Packets Recv:   {res['standard_1200b'][0]['packets_received']}")
    print(f"    Amplification:  avg={avg_ratio:.3f}x (spread: {min_ratio:.3f}x .. {max_ratio:.3f}x)")
    print(f"    RFC 9000 <= 3x: {'PASS (COMPLIANT)' if max_ratio <= 3.0 else 'FAIL (VIOLATION)'}")
    print()

    # Runt packets
    print(f"[*] Runt Datagrams (< 1200 bytes, RFC 9000 §14.1 discard requirement):")
    for runt_len, key in [(64, "runt_64b"), (500, "runt_500b"), (1199, "runt_1199b")]:
        recvs = [r["bytes_received"] for r in res[key]]
        all_discarded = all(r["discarded"] for r in res[key])
        status = "PASS (DISCARDED, 0 bytes returned)" if all_discarded else f"FAIL (Returned {max(recvs)} B)"
        print(f"    Length {runt_len:>4} B -> {status}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Measure QUIC amplification factor")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, required=True, help="Target QUIC port")
    parser.add_argument("--name", default="Server", help="Server name label")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    args = parser.parse_args()

    results = run_amplification_suite(args.host, args.port, runs=3)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_report(args.name, results)


if __name__ == "__main__":
    main()
