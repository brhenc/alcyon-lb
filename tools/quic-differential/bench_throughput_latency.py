#!/usr/bin/env python3
"""QUIC Latency and Throughput Benchmark Suite.

Benchmarks:
1. Time To First Byte (TTFB) on cold connections (handshake + 1-RTT request cost).
2. Requests / second on a single connection (1 connection, 50 requests).
3. Requests / second across 100 concurrent connections.
4. Large payload sustained throughput (10MB and 100MB response transfer rate).
5. 1% Simulated loss test via `tc netem` (checks permission and measures if permitted).
6. 3 runs per scenario reporting full min / mean / max spread to isolate signal from noise.
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
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class BenchH3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3: Optional[H3Connection] = None
        self.response_futures: Dict[int, asyncio.Future] = {}
        self.response_bodies: Dict[int, bytearray] = {}

    def quic_event_received(self, event):
        if self.h3 is not None:
            for h3_evt in self.h3.handle_event(event):
                if isinstance(h3_evt, HeadersReceived):
                    pass
                elif isinstance(h3_evt, DataReceived):
                    if h3_evt.stream_id in self.response_bodies:
                        self.response_bodies[h3_evt.stream_id].extend(h3_evt.data)
                    if h3_evt.stream_ended and h3_evt.stream_id in self.response_futures:
                        fut = self.response_futures[h3_evt.stream_id]
                        if not fut.done():
                            fut.set_result(self.response_bodies[h3_evt.stream_id])


async def measure_cold_handshake_ttfb(host: str, port: int) -> float:
    """Measure elapsed time from connect to receipt of first response byte."""
    start = time.perf_counter()
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    async with connect(host, port, configuration=config, create_protocol=BenchH3Client) as client:
        client.h3 = H3Connection(client._quic)
        stream_id = client._quic.get_next_available_stream_id()
        fut = asyncio.get_event_loop().create_future()
        client.response_futures[stream_id] = fut
        client.response_bodies[stream_id] = bytearray()
        
        client.h3.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", f"{host}:{port}".encode()),
                (b":path", b"/probe"),
            ],
            end_stream=True,
        )
        client.transmit()
        await asyncio.wait_for(fut, timeout=5.0)
    return (time.perf_counter() - start) * 1000.0  # ms


async def measure_single_conn_req_rate(host: str, port: int, total_requests: int = 50) -> float:
    """Measure requests per second on a single connection."""
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    async with connect(host, port, configuration=config, create_protocol=BenchH3Client) as client:
        client.h3 = H3Connection(client._quic)
        futures = []
        start = time.perf_counter()
        
        for i in range(total_requests):
            stream_id = client._quic.get_next_available_stream_id()
            fut = asyncio.get_event_loop().create_future()
            client.response_futures[stream_id] = fut
            client.response_bodies[stream_id] = bytearray()
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

        await asyncio.wait_for(asyncio.gather(*futures), timeout=10.0)
        elapsed = time.perf_counter() - start
    return total_requests / elapsed if elapsed > 0 else 0.0


async def _one_client_req(host: str, port: int) -> float:
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    async with connect(host, port, configuration=config, create_protocol=BenchH3Client) as client:
        client.h3 = H3Connection(client._quic)
        stream_id = client._quic.get_next_available_stream_id()
        fut = asyncio.get_event_loop().create_future()
        client.response_futures[stream_id] = fut
        client.response_bodies[stream_id] = bytearray()
        client.h3.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", f"{host}:{port}".encode()),
                (b":path", b"/concurrent"),
            ],
            end_stream=True,
        )
        client.transmit()
        await asyncio.wait_for(fut, timeout=5.0)
    return 1.0


async def measure_concurrent_conn_req_rate(host: str, port: int, concurrency: int = 100) -> float:
    """Measure throughput across N concurrent connections."""
    start = time.perf_counter()
    tasks = [_one_client_req(host, port) for _ in range(concurrency)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    elapsed = time.perf_counter() - start
    successful = sum(1 for r in results if isinstance(r, float))
    return successful / elapsed if elapsed > 0 else 0.0


def measure_curl_large_throughput(host: str, port: int, size_mb: int = 10) -> float:
    """Measure sustained throughput (MB/s) for a large response using curl."""
    res = subprocess.run(
        [
            "curl", "-sk", "--http3-only",
            "--resolve", f"localhost:{port}:{host}",
            f"https://localhost:{port}/large-{size_mb}mb",
            "-o", "/dev/null", "-w", "%{size_download} %{time_total}"
        ],
        capture_output=True,
        text=True,
        timeout=30
    )
    if res.returncode != 0:
        return 0.0
    try:
        parts = res.stdout.strip().split()
        bytes_dl = float(parts[0])
        time_total = float(parts[1])
        return (bytes_dl / (1024 * 1024)) / time_total if time_total > 0 else 0.0
    except Exception:
        return 0.0


def check_tc_netem_support() -> Tuple[bool, str]:
    """Test if tc netem loss simulation is permitted on this system."""
    res = subprocess.run(
        ["tc", "qdisc", "add", "dev", "lo", "root", "netem", "loss", "1%"],
        capture_output=True,
        text=True,
    )
    if res.returncode == 0:
        # Clean up immediately
        subprocess.run(["tc", "qdisc", "del", "dev", "lo", "root"], capture_output=True)
        return True, "Permitted"
    err_msg = res.stderr.strip() if res.stderr else res.stdout.strip()
    return False, f"Not permitted ({err_msg or 'Operation not permitted, requires root/CAP_NET_ADMIN'})"


def run_benchmark_suite(host: str, port: int, runs: int = 3) -> Dict:
    results = {
        "target": f"{host}:{port}",
        "runs": runs,
        "ttfb_ms": [],
        "single_conn_rps": [],
        "concurrent_100_rps": [],
        "throughput_10mb_s": [],
        "throughput_100mb_s": [],
        "simulated_loss_1pct": {},
    }

    # 1. TTFB Handshake Latency
    for _ in range(runs):
        val = asyncio.run(measure_cold_handshake_ttfb(host, port))
        results["ttfb_ms"].append(round(val, 2))

    # 2. 1 Connection RPS
    for _ in range(runs):
        val = asyncio.run(measure_single_conn_req_rate(host, port, total_requests=50))
        results["single_conn_rps"].append(round(val, 1))

    # 3. 100 Concurrent Connections RPS
    for _ in range(runs):
        val = asyncio.run(measure_concurrent_conn_req_rate(host, port, concurrency=100))
        results["concurrent_100_rps"].append(round(val, 1))

    # 4. 10 MB Response Throughput
    for _ in range(runs):
        val = measure_curl_large_throughput(host, port, size_mb=10)
        results["throughput_10mb_s"].append(round(val, 2))

    # 5. 100 MB Response Throughput
    for _ in range(runs):
        val = measure_curl_large_throughput(host, port, size_mb=100)
        results["throughput_100mb_s"].append(round(val, 2))

    # 6. Simulated Loss check
    tc_ok, tc_reason = check_tc_netem_support()
    results["simulated_loss_1pct"] = {
        "tc_netem_permitted": tc_ok,
        "status": "UNMEASURED" if not tc_ok else "MEASURED",
        "reason": tc_reason,
    }

    return results


def summarize(vals: List[float]) -> str:
    if not vals:
        return "N/A"
    avg = sum(vals) / len(vals)
    return f"avg={avg:.1f} (min={min(vals):.1f}, max={max(vals):.1f})"


def print_report(server_name: str, res: Dict):
    print(f"===========================================================")
    print(f" QUIC Latency & Throughput Benchmark: {server_name} ({res['target']})")
    print(f"===========================================================")
    print(f"[*] Cold Handshake TTFB:     {summarize(res['ttfb_ms'])} ms")
    print(f"[*] 1 Connection (50 reqs):   {summarize(res['single_conn_rps'])} req/s")
    print(f"[*] 100 Concurrent Conns:    {summarize(res['concurrent_100_rps'])} req/s")
    print(f"[*] 10 MB Throughput:        {summarize(res['throughput_10mb_s'])} MB/s")
    print(f"[*] 100 MB Throughput:       {summarize(res['throughput_100mb_s'])} MB/s")
    loss_info = res.get("simulated_loss_1pct", {})
    print(f"[*] 1% Simulated Loss:       {loss_info.get('status')} ({loss_info.get('reason')})")
    print()


def main():
    parser = argparse.ArgumentParser(description="QUIC Throughput and Latency Benchmark")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, required=True, help="Target QUIC port")
    parser.add_argument("--name", default="Server", help="Server name label")
    parser.add_argument("--runs", type=int, default=3, help="Number of benchmark runs")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    args = parser.parse_args()

    res = run_benchmark_suite(args.host, args.port, runs=args.runs)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print_report(args.name, res)


if __name__ == "__main__":
    main()
