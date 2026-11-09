#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# Start HAProxy 3.5-dev with QUIC in front of a trivial HTTP/1 backend, and prove
# curl --http3 reaches it. Prints the QUIC port and leaves the daemon running.
#
# The stock $ALCYON_REFERENCE/haproxy/haproxy is built -QUIC and cannot serve
# HTTP/3. This uses the separate tree at $ALCYON_REFERENCE/haproxy-quic, built with
#
#   make -j64 TARGET=linux-glibc USE_OPENSSL=1 USE_QUIC=1 USE_ZLIB=1 USE_PCRE2=1 USE_THREAD=1
#
# against the system OpenSSL 3.5.8, whose native QUIC API needs neither quictls nor
# USE_QUIC_OPENSSL_COMPAT. Verified: +QUIC -QUIC_OPENSSL_COMPAT.
set -euo pipefail
HQ=${HQ:-${ALCYON_REFERENCE:?set ALCYON_REFERENCE (README, "Running the oracle tests") or HQ}/haproxy-quic/haproxy}
CRT=${CRT:-$(cd "$(dirname "$0")/../.." && pwd)/examples/certs/localhost.pem}
D=$(mktemp -d /tmp/quic-oracle.XXXXXX)

python3 "$(dirname "$0")/echo_backend.py" > "$D/be.port" 2> "$D/be.err" &
sleep 1
BE=$(head -1 "$D/be.port")
Q=$(python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")

{
  echo "defaults"
  printf '\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\ttimeout server 10s\n'
  echo "frontend fe"
  printf '\tbind quic4@127.0.0.1:%s ssl crt %s alpn h3\n\tdefault_backend be\n' "$Q" "$CRT"
  echo "backend be"
  printf '\tserver s1 127.0.0.1:%s\n' "$BE"
} > "$D/h3.cfg"

"$HQ" -f "$D/h3.cfg" -D -p "$D/hp.pid"
sleep 1
echo "QUIC_PORT=$Q BACKEND=$BE DIR=$D PID=$(cat "$D/hp.pid")"
curl -sk --http3-only --resolve "localhost:$Q:127.0.0.1" "https://localhost:$Q/probe" \
  -w 'oracle: http_version=%{http_version} code=%{http_code}\n' -o /dev/null
echo "stop with: kill \$(cat $D/hp.pid)"
