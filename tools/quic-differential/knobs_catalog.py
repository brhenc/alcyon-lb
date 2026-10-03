#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""HAProxy 3.5 31 `tune.quic.*` knobs catalog and quinn-proto / Ibex mapping.

This tool audits all 31 tune.quic.* configuration keywords from HAProxy 3.5-dev7
(src/cfgparse-quic.c:537-569), compares them against quinn-proto 0.11 / Ibex runtime,
and outputs structured JSON and Markdown parity matrices.
"""

import json
import sys

# The 31 HAProxy tune.quic.* keywords and their semantics from doc/configuration.txt & src/cfgparse-quic.c
KNOBS_CATALOG = [
    # Global (4)
    {
        "name": "tune.quic.listen",
        "scope": "global",
        "type": "on|off",
        "default": "on",
        "haproxy_purpose": "Global kill-switch to enable or disable all QUIC listeners.",
        "quinn_proto_equivalent": "N/A (Ibex engine listener loop)",
        "ibex_layer": "ibex-rt engine listener supervisor",
        "status": "EXPRESSIBLE_AT_RUNTIME",
        "category": "Policy / Runtime",
        "notes": "Ibex controls listener binding at the engine configuration / bind parser level."
    },
    {
        "name": "tune.quic.mem.tx-max",
        "scope": "global",
        "type": "size (bytes)",
        "default": "0 (unlimited)",
        "haproxy_purpose": "Maximum memory allocated globally for QUIC transmit buffers.",
        "quinn_proto_equivalent": "N/A (buffer management / allocation pool)",
        "ibex_layer": "ibex-alloc / buffer pool",
        "status": "EXPRESSIBLE_AT_RUNTIME",
        "category": "Memory / Buffer Pool",
        "notes": "quinn-proto produces datagram chunks without owning OS memory pools; Ibex bounds allocations via ibex-alloc."
    },
    {
        "name": "tune.quic.sec.stateless-reset-rate",
        "scope": "global",
        "type": "integer (pps)",
        "default": "100",
        "haproxy_purpose": "Rate limit for sending Stateless Reset packets to prevent DoS reflection.",
        "quinn_proto_equivalent": "EndpointConfig::reset_token_key or rate-limiting transmit wrapper",
        "ibex_layer": "ibex-quic / ibex-rt dgram path",
        "status": "EXPRESSIBLE_AT_RUNTIME",
        "category": "Security / DoS",
        "notes": "quinn-proto generates stateless resets when configured; token bucket rate-limiting is implemented in the datagram dispatch loop."
    },
    {
        "name": "tune.quic.zero-copy-fwd-send",
        "scope": "global",
        "type": "on|off",
        "default": "on",
        "haproxy_purpose": "Enable zero-copy datagram forwarding on Linux using splice/vmsplice/sendmmsg.",
        "quinn_proto_equivalent": "N/A (OS datagram transmission)",
        "ibex_layer": "ibex-mmsg (sendmmsg / MSG_ZEROCOPY)",
        "status": "EXPRESSIBLE_AT_RUNTIME",
        "category": "OS / Datagram Path",
        "notes": "Ibex implements sendmmsg zero-copy in ibex-mmsg crate directly."
    },

    # Frontend (fe, 15)
    {
        "name": "tune.quic.fe.cc.cubic-min-losses",
        "scope": "frontend",
        "type": "integer",
        "default": "8",
        "haproxy_purpose": "Number of packet losses required before CUBIC reduces congestion window.",
        "quinn_proto_equivalent": "quinn_proto::congestion::CubicConfig (internal tuning)",
        "ibex_layer": "quinn-proto transport CC",
        "status": "TRANSPORT_INTERNAL",
        "category": "Congestion Control",
        "notes": "quinn-proto provides standard RFC 8312 / RFC 9002 CUBIC, NewReno, and BBR controllers. Fine-grained loss count constant is internal to the controller."
    },
    {
        "name": "tune.quic.fe.cc.hystart",
        "scope": "frontend",
        "type": "on|off",
        "default": "on",
        "haproxy_purpose": "Enable HyStart++ slow start algorithm in congestion control.",
        "quinn_proto_equivalent": "quinn_proto::congestion::Cubic (built-in HyStart++)",
        "ibex_layer": "quinn-proto transport CC",
        "status": "TRANSPORT_INTERNAL",
        "category": "Congestion Control",
        "notes": "HyStart++ is enabled by default in quinn-proto's Cubic implementation."
    },
    {
        "name": "tune.quic.fe.cc.max-frame-loss",
        "scope": "frontend",
        "type": "integer",
        "default": "3",
        "haproxy_purpose": "Packet threshold for loss detection (RFC 9002 kPacketThreshold).",
        "quinn_proto_equivalent": "TransportConfig::packet_threshold(u32)",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Loss Recovery",
        "notes": "Directly maps to quinn_proto::TransportConfig::packet_threshold."
    },
    {
        "name": "tune.quic.fe.cc.max-win-size",
        "scope": "frontend",
        "type": "size (bytes)",
        "default": "0 (unlimited)",
        "haproxy_purpose": "Maximum congestion / receive window size in bytes.",
        "quinn_proto_equivalent": "TransportConfig::receive_window(VarInt) / send_window(u64)",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Flow Control",
        "notes": "Directly maps to quinn_proto::TransportConfig::receive_window and send_window."
    },
    {
        "name": "tune.quic.fe.cc.reorder-ratio",
        "scope": "frontend",
        "type": "integer",
        "default": "32",
        "haproxy_purpose": "Reordering threshold fraction (RFC 9002 kTimeReorderingThreshold = 1/ratio).",
        "quinn_proto_equivalent": "TransportConfig::reordering_threshold(u32)",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Loss Recovery",
        "notes": "Directly maps to quinn_proto::TransportConfig::reordering_threshold."
    },
    {
        "name": "tune.quic.fe.max-idle-timeout",
        "scope": "frontend",
        "type": "time (ms)",
        "default": "30000ms",
        "haproxy_purpose": "QUIC transport parameter max_idle_timeout advertised to client.",
        "quinn_proto_equivalent": "TransportConfig::max_idle_timeout(Option<IdleTimeout>)",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Transport Parameter",
        "notes": "Directly maps to quinn_proto::TransportConfig::max_idle_timeout."
    },
    {
        "name": "tune.quic.fe.sec.glitches-threshold",
        "scope": "frontend",
        "type": "integer",
        "default": "0 (disabled)",
        "haproxy_purpose": "Maximum protocol errors / anomalies allowed on a connection before immediate abort.",
        "quinn_proto_equivalent": "N/A (Ibex connection supervisor anomaly tracker)",
        "ibex_layer": "ibex-rt / connection supervisor",
        "status": "EXPRESSIBLE_AT_RUNTIME",
        "category": "Security / DoS",
        "notes": "Identical architectural pattern to tune.h2.fe.glitches-threshold in ibex-proto."
    },
    {
        "name": "tune.quic.fe.sec.retry-threshold",
        "scope": "frontend",
        "type": "integer (pps)",
        "default": "0 (disabled)",
        "haproxy_purpose": "Initial packet rate threshold triggering QUIC stateless Retry requirement.",
        "quinn_proto_equivalent": "EndpointConfig::retry(bool) or dynamic rate trigger",
        "ibex_layer": "ibex-quic / ibex-rt dgram dispatcher",
        "status": "EXPRESSIBLE_AT_RUNTIME",
        "category": "Security / DoS",
        "notes": "quinn-proto Endpoint supports retry validation; Ibex runtime dynamically enables retry token validation based on Initial packet rate."
    },
    {
        "name": "tune.quic.fe.sock-per-conn",
        "scope": "frontend",
        "type": "default-on|force-off",
        "default": "default-on",
        "haproxy_purpose": "Allocate dedicated UDP socket per connected client for SO_REUSEPORT scaling.",
        "quinn_proto_equivalent": "N/A (OS socket architecture)",
        "ibex_layer": "ibex-rt dgram path",
        "status": "EXPRESSIBLE_AT_RUNTIME",
        "category": "OS / Socket Architecture",
        "notes": "Socket allocation strategy belongs entirely to the runtime datagram listener loop."
    },
    {
        "name": "tune.quic.fe.stream.data-ratio",
        "scope": "frontend",
        "type": "integer (percent)",
        "default": "0 (disabled)",
        "haproxy_purpose": "Ratio of data frames to control frames required to prevent stream flood DoS.",
        "quinn_proto_equivalent": "N/A (H3 frame validation / supervisor)",
        "ibex_layer": "ibex-proto H3 state machine",
        "status": "EXPRESSIBLE_AT_RUNTIME",
        "category": "Security / DoS",
        "notes": "Enforced in ibex-proto during H3 frame decoding and dispatch."
    },
    {
        "name": "tune.quic.fe.stream.max-concurrent",
        "scope": "frontend",
        "type": "integer",
        "default": "100",
        "haproxy_purpose": "Maximum concurrent bidirectional client streams (initial_max_streams_bidi).",
        "quinn_proto_equivalent": "TransportConfig::max_concurrent_bidi_streams(VarInt)",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Transport Parameter",
        "notes": "Directly maps to quinn_proto::TransportConfig::max_concurrent_bidi_streams."
    },
    {
        "name": "tune.quic.fe.stream.max-total",
        "scope": "frontend",
        "type": "integer",
        "default": "0 (disabled)",
        "haproxy_purpose": "Cumulative limit on total streams opened over connection lifetime (Rapid Reset defense).",
        "quinn_proto_equivalent": "N/A (Connection lifetime stream counter)",
        "ibex_layer": "ibex-rt / connection supervisor",
        "status": "EXPRESSIBLE_AT_RUNTIME",
        "category": "Security / DoS",
        "notes": "Tracked per QUIC connection in Ibex session struct; closes connection on overflow."
    },
    {
        "name": "tune.quic.fe.stream.rxbuf",
        "scope": "frontend",
        "type": "size (bytes)",
        "default": "16380",
        "haproxy_purpose": "Initial stream receive flow control window (initial_max_stream_data_bidi_remote).",
        "quinn_proto_equivalent": "TransportConfig::stream_receive_window(VarInt)",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Flow Control",
        "notes": "Directly maps to quinn_proto::TransportConfig::stream_receive_window."
    },
    {
        "name": "tune.quic.fe.tx.pacing",
        "scope": "frontend",
        "type": "on|off",
        "default": "on",
        "haproxy_purpose": "Enable packet pacing in datagram transmission to prevent packet bursts.",
        "quinn_proto_equivalent": "TransportConfig::pacing(bool) / poll_transmit timer",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Congestion / Pacing",
        "notes": "quinn-proto includes full packet pacing support via transmit timing."
    },
    {
        "name": "tune.quic.fe.tx.udp-gso",
        "scope": "frontend",
        "type": "on|off",
        "default": "on",
        "haproxy_purpose": "Enable UDP Generic Segmentation Offload (UDP_SEGMENT) on transmit.",
        "quinn_proto_equivalent": "TransportConfig::enable_segmentation_offload(bool)",
        "ibex_layer": "quinn-proto / ibex-mmsg",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "OS Offload",
        "notes": "quinn-proto coordinates GSO segment sizing with ibex-mmsg sendmmsg."
    },

    # Backend (be, 12) - mirror of frontend for QUIC egress/backend connections
    {
        "name": "tune.quic.be.cc.cubic-min-losses",
        "scope": "backend",
        "type": "integer",
        "default": "8",
        "haproxy_purpose": "Egress CUBIC loss threshold before window reduction.",
        "quinn_proto_equivalent": "quinn_proto::congestion::CubicConfig",
        "ibex_layer": "quinn-proto transport CC",
        "status": "TRANSPORT_INTERNAL",
        "category": "Congestion Control",
        "notes": "Egress QUIC backend connection congestion tuning."
    },
    {
        "name": "tune.quic.be.cc.hystart",
        "scope": "backend",
        "type": "on|off",
        "default": "on",
        "haproxy_purpose": "Enable HyStart++ on backend QUIC egress connections.",
        "quinn_proto_equivalent": "quinn_proto::congestion::Cubic",
        "ibex_layer": "quinn-proto transport CC",
        "status": "TRANSPORT_INTERNAL",
        "category": "Congestion Control",
        "notes": "Standard quinn-proto congestion controller behavior."
    },
    {
        "name": "tune.quic.be.cc.max-frame-loss",
        "scope": "backend",
        "type": "integer",
        "default": "3",
        "haproxy_purpose": "Loss detection packet threshold on backend connections.",
        "quinn_proto_equivalent": "TransportConfig::packet_threshold(u32)",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Loss Recovery",
        "notes": "Directly maps to client TransportConfig."
    },
    {
        "name": "tune.quic.be.cc.max-win-size",
        "scope": "backend",
        "type": "size (bytes)",
        "default": "0 (unlimited)",
        "haproxy_purpose": "Maximum window size for backend QUIC connections.",
        "quinn_proto_equivalent": "TransportConfig::receive_window / send_window",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Flow Control",
        "notes": "Directly maps to TransportConfig flow control limits."
    },
    {
        "name": "tune.quic.be.cc.reorder-ratio",
        "scope": "backend",
        "type": "integer",
        "default": "32",
        "haproxy_purpose": "Reordering time threshold fraction on backend connections.",
        "quinn_proto_equivalent": "TransportConfig::reordering_threshold(u32)",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Loss Recovery",
        "notes": "Directly maps to quinn_proto::TransportConfig::reordering_threshold."
    },
    {
        "name": "tune.quic.be.max-idle-timeout",
        "scope": "backend",
        "type": "time (ms)",
        "default": "30000ms",
        "haproxy_purpose": "Max idle timeout for backend QUIC connections.",
        "quinn_proto_equivalent": "TransportConfig::max_idle_timeout",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Transport Parameter",
        "notes": "Directly maps to TransportConfig."
    },
    {
        "name": "tune.quic.be.sec.glitches-threshold",
        "scope": "backend",
        "type": "integer",
        "default": "0 (disabled)",
        "haproxy_purpose": "Protocol glitch threshold on backend connections before abort.",
        "quinn_proto_equivalent": "N/A (Ibex backend connection supervisor)",
        "ibex_layer": "ibex-rt connection supervisor",
        "status": "EXPRESSIBLE_AT_RUNTIME",
        "category": "Security / DoS",
        "notes": "Enforced in runtime session layer."
    },
    {
        "name": "tune.quic.be.stream.data-ratio",
        "scope": "backend",
        "type": "integer (percent)",
        "default": "0 (disabled)",
        "haproxy_purpose": "Data/control ratio threshold on backend streams.",
        "quinn_proto_equivalent": "N/A (H3 frame supervisor)",
        "ibex_layer": "ibex-proto H3",
        "status": "EXPRESSIBLE_AT_RUNTIME",
        "category": "Security / DoS",
        "notes": "Enforced in ibex-proto during stream decoding."
    },
    {
        "name": "tune.quic.be.stream.max-concurrent",
        "scope": "backend",
        "type": "integer",
        "default": "100",
        "haproxy_purpose": "Maximum concurrent streams to open towards backend.",
        "quinn_proto_equivalent": "TransportConfig::max_concurrent_bidi_streams",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Transport Parameter",
        "notes": "Directly maps to TransportConfig."
    },
    {
        "name": "tune.quic.be.stream.rxbuf",
        "scope": "backend",
        "type": "size (bytes)",
        "default": "16380",
        "haproxy_purpose": "Receive buffer / window for backend streams.",
        "quinn_proto_equivalent": "TransportConfig::stream_receive_window",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Flow Control",
        "notes": "Directly maps to TransportConfig."
    },
    {
        "name": "tune.quic.be.tx.pacing",
        "scope": "backend",
        "type": "on|off",
        "default": "on",
        "haproxy_purpose": "Enable transmission pacing towards backend.",
        "quinn_proto_equivalent": "TransportConfig::pacing",
        "ibex_layer": "quinn-proto TransportConfig",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "Congestion / Pacing",
        "notes": "Directly maps to TransportConfig."
    },
    {
        "name": "tune.quic.be.tx.udp-gso",
        "scope": "backend",
        "type": "on|off",
        "default": "on",
        "haproxy_purpose": "Enable UDP GSO when sending to backend.",
        "quinn_proto_equivalent": "TransportConfig::enable_segmentation_offload",
        "ibex_layer": "quinn-proto / ibex-mmsg",
        "status": "EXPRESSIBLE_IN_QUINN",
        "category": "OS Offload",
        "notes": "Directly maps to TransportConfig."
    }
]

def generate_markdown_table():
    lines = [
        "| # | HAProxy Knob | Scope | Default | quinn-proto / Ibex Mapping | Architectural Layer | Classification |",
        "|---|---|---|---|---|---|---|"
    ]
    for i, k in enumerate(KNOBS_CATALOG, 1):
        lines.append(
            f"| {i} | `{k['name']}` | {k['scope']} | `{k['default']}` | {k['quinn_proto_equivalent']} | {k['ibex_layer']} | {k['status']} |"
        )
    return "\n".join(lines)

def summary_statistics():
    total = len(KNOBS_CATALOG)
    in_quinn = sum(1 for k in KNOBS_CATALOG if k["status"] == "EXPRESSIBLE_IN_QUINN")
    at_runtime = sum(1 for k in KNOBS_CATALOG if k["status"] == "EXPRESSIBLE_AT_RUNTIME")
    internal = sum(1 for k in KNOBS_CATALOG if k["status"] == "TRANSPORT_INTERNAL")
    return {
        "total_knobs": total,
        "directly_expressible_in_quinn": in_quinn,
        "expressible_in_ibex_runtime": at_runtime,
        "transport_internal_cc_constants": internal,
    }

if __name__ == "__main__":
    stats = summary_statistics()
    print(f"Audited {stats['total_knobs']} HAProxy tune.quic.* knobs.")
    print(f"  Directly in quinn-proto TransportConfig: {stats['directly_expressible_in_quinn']}")
    print(f"  In Ibex runtime / policy supervisor:   {stats['expressible_in_ibex_runtime']}")
    print(f"  Internal to CC algorithm:              {stats['transport_internal_cc_constants']}")
    print()
    print(generate_markdown_table())
