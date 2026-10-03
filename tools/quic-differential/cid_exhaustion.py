#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""QUIC Connection ID Exhaustion and Rapid Retirement Duress Test Script.

Tests server resilience under rapid Connection ID (CID) rotation and retirement:
- Connects to QUIC endpoint and establishes 1-RTT connection.
- Receives peer-issued NEW_CONNECTION_ID frames.
- Rapidly issues RETIRE_CONNECTION_ID frames and consumes next available CIDs.
- Tests multiple concurrent connections cycling CIDs.
- Measures rotation throughput, connection survival, memory RSS delta, and error codes.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
import time
from typing import Dict, List, Optional, Tuple

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated


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


class CIDClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connection_closed = False
        self.close_error_code: Optional[int] = None
        self.close_reason = ""

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self.connection_closed = True
            self.close_error_code = event.error_code
            self.close_reason = event.reason_phrase


async def run_single_conn_cid_rotations(
    host: str,
    port: int,
    target_rotations: int = 50,
    max_duration: float = 5.0,
) -> Tuple[int, bool, Optional[int], str]:
    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
        verify_mode=ssl.CERT_NONE,
    )

    rotations_done = 0
    start_time = time.time()

    try:
        async with connect(
            host, port,
            configuration=config,
            create_protocol=CIDClient,
            wait_connected=True,
        ) as client:
            # Yield to receive initial NEW_CONNECTION_ID frames
            await asyncio.sleep(0.05)

            while rotations_done < target_rotations and not client.connection_closed and (time.time() - start_time) < max_duration:
                if client._quic._peer_cid_available:
                    client._quic.change_connection_id()
                    client.transmit()
                    rotations_done += 1
                    await asyncio.sleep(0.005)
                else:
                    client.transmit()
                    await asyncio.sleep(0.01)

            client.transmit()
            await asyncio.sleep(0.1)

            survived = not client.connection_closed
            return rotations_done, survived, client.close_error_code, client.close_reason
    except Exception as e:
        return rotations_done, False, None, str(e)


async def run_cid_exhaustion_test(
    host: str,
    port: int,
    rotations: int = 200,
    concurrency: int = 4,
    target_pid: Optional[int] = None,
) -> Dict:
    initial_cpu, initial_rss = get_process_metrics(target_pid) if target_pid else (0.0, 0)
    start_time = time.time()

    rotations_per_conn = max(1, rotations // concurrency)
    tasks = [
        run_single_conn_cid_rotations(host, port, target_rotations=rotations_per_conn)
        for _ in range(concurrency)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    elapsed = time.time() - start_time
    total_rotations = 0
    all_survived = True
    errors = []

    for r in results:
        if isinstance(r, tuple):
            rot_done, survived, err_code, reason = r
            total_rotations += rot_done
            if not survived:
                all_survived = False
                errors.append(f"code={err_code} reason={reason}")
        else:
            all_survived = False
            errors.append(str(r))

    final_cpu, final_rss = get_process_metrics(target_pid) if target_pid else (0.0, 0)
    rss_delta_kb = final_rss - initial_rss if target_pid else 0

    return {
        "target": f"{host}:{port}",
        "target_rotations": rotations,
        "concurrency": concurrency,
        "rotations_completed": total_rotations,
        "elapsed_sec": elapsed,
        "rotations_per_sec": total_rotations / elapsed if elapsed > 0 else 0,
        "connections_survived": all_survived,
        "errors": errors,
        "initial_rss_kb": initial_rss,
        "final_rss_kb": final_rss,
        "rss_delta_kb": rss_delta_kb,
    }


def print_report(server_name: str, res: Dict):
    print(f"===========================================================")
    print(f" QUIC CID Exhaustion / Rotation Test: {server_name} ({res['target']})")
    print(f"===========================================================")
    print(f"[*] Rotations Completed:{res['rotations_completed']} / {res['target_rotations']} ({res['concurrency']} concurrent conns)")
    print(f"[*] Elapsed Time:       {res['elapsed_sec']:.3f} s ({res['rotations_per_sec']:.1f} rotations/s)")
    print(f"[*] Conns Survived:     {res['connections_survived']}")
    if res['errors']:
        print(f"[*] Errors Encountered: {', '.join(res['errors'])}")
    if res['final_rss_kb'] > 0:
        print(f"[*] Memory RSS:         {res['final_rss_kb']} KB (delta: {res['rss_delta_kb']:+d} KB)")
    print()


def main():
    parser = argparse.ArgumentParser(description="QUIC CID Exhaustion Duress Test")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, required=True, help="Target QUIC port")
    parser.add_argument("--pid", type=int, default=None, help="Target process PID")
    parser.add_argument("--rotations", type=int, default=200, help="Total CID rotations to execute")
    parser.add_argument("--concurrency", type=int, default=4, help="Concurrent connections")
    parser.add_argument("--name", default="Server", help="Server name label")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    args = parser.parse_args()

    res = asyncio.run(run_cid_exhaustion_test(
        args.host, args.port, rotations=args.rotations, concurrency=args.concurrency, target_pid=args.pid
    ))
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print_report(args.name, res)


if __name__ == "__main__":
    main()
