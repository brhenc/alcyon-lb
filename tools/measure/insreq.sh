#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Instructions per request (perf stat instructions:u) of one proxy binary on one scenario.
# Works for ibex and for haproxy, so the oracle can be measured with the same backend and client.
#
#   tools/measure/insreq.sh <label> <proxy-bin> <scenario.body> <client> <N> <rounds> <outdir>
#   client: mb50|ab1|ab1s|hs1|nc1|h2s1|h3c1|h3best|h3worst|h3fit
#
#   client mb50: measure-bench, 50 keep-alive connections, N requests (what the gate uses)
#   client ab1:  ab -k -c 1, N requests (one connection, the T447 figure)
#   client ab1s: ab1 over TLS (https://; the scenario's frontend binds with `ssl crt`, T460)
#   client hs1:  ab -c 1 over TLS without keep-alive: one TLS handshake per request (T460)
#   client nc1:  ab -c 1 without keep-alive: one new TCP connection per request (T459)
#   client h2s1: h2load -c 1 -m 1 over TLS with ALPN h2: one HTTP/2 connection, one stream at a time
#   client h3c1: h2load -c 1 -m 1 with ALPN h3 (QUIC). Not a result since T555: h2load's ACK-only
#                datagrams vary 1.12-1.91 per request between rounds, and Ibex pays ~6k per one.
#   client h3best, h3worst: tools/measure/h3bench (T555), one HTTP/3 connection, N sequential
#                GETs (IBEX_H3_METHOD=post: 32-byte POSTs), the client's ACK policy fixed. best
#                ACKs only with its next request (1.000 client datagrams/req); worst answers every
#                server datagram at once (~2.02/req, the realistic one: curl 8.18 sends 1.99/req
#                and h2load 1.96 to HAProxy dev10). Each round prints the client's datagrams/req.
#                The client sends each datagram >= 200 us after its previous one, sent or received
#                (H3BENCH_GAP_US), so the proxy takes each in a wakeup of its own.
#   client h3fit: THE h3 figure (user decision D6). Each round runs h3best then h3worst and fits
#                the line through the two points at IBEX_H3_FIT_RATE client datagrams/req (1.97,
#                h2load's steady rate to HAProxy); prints best, worst and fit per round and their
#                medians, and the fit's spread (max-min over median). min-of-rounds is retired
#                for h3. IBEX_MEASURE_JSONL=<file> appends one row (`"kind": "insreq-h3"`) with
#                all three; data/measurements.jsonl takes them (measure.py skips such rows).
#   The h3 scenario binds `quic4@` on the same port as its TCP `ssl` bind (h3.body).
#
# The scenario body is a config with @FE@ and @BE@ for the two ports (tools/measure/scenarios/),
# and @CRT@ for a certificate and key (IBEX_MEASURE_CRT, else a self-signed P-256 one made in
# <outdir>), and @TP@ for a third free port (a hop inside the proxy, as tlsbackend.body's TLS
# server, T538).
# The proxy under test is a `cargo build --profile release-perf --bin ibex` binary
# (target/release-perf/ibex, T518: the budget is judged on one fat-LTO layout, not `release`).
# Pins the proxy to CPU 4, the client to 5, the backend to 6 (as measure.py); IBEX_MEASURE_CPUS
# "a,b,c" overrides. Warms up with 2000 requests, then counts the proxy process's user-space
# instructions over each round and prints instructions per request. Takes no lock: hold
# `flock -x /tmp/ibex-load.lock` around a batch, and keep a batch under 15 minutes. Needs
# $HOME/ibex-targets/gate-slot1/release/measure-bench (MEASURE_BENCH overrides; for an h3 POST one
# built since T555, which frames a body that arrives in a read of its own), and for h3best,
# h3worst, h3fit $HOME/ibex-targets/h3bench/release/h3bench (H3BENCH overrides; built if missing).
set -u
if [ $# -ne 7 ]; then sed -n '5,46p' "$0"; exit 2; fi
LABEL=$1; BIN=$2; BODY=$3; CL=$4; N=$5; ROUNDS=$6; OUT=$7
mkdir -p "$OUT" || exit 1
BENCH=${MEASURE_BENCH:-$HOME/ibex-targets/gate-slot1/release/measure-bench}
H3BENCH=${H3BENCH:-$HOME/ibex-targets/h3bench/release/h3bench}
H3M=${IBEX_H3_METHOD:-get}
FIT_RATE=${IBEX_H3_FIT_RATE:-1.97}
case $CL in
  h3best|h3worst|h3fit)
    if [ ! -x "$H3BENCH" ]; then
      CARGO_TARGET_DIR=$(dirname "$(dirname "$H3BENCH")") cargo build -q --release --offline \
        --manifest-path "$(dirname "$0")/h3bench/Cargo.toml" || exit 1
    fi ;;
esac
IFS=, read -r CPU_P CPU_C CPU_B <<< "${IBEX_MEASURE_CPUS:-4,5,6}"
port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
FE=$(port); BE=$(port); TP=$(port)
CFG=$OUT/$LABEL.cfg
CRT=${IBEX_MEASURE_CRT:-$OUT/insreq-cert.pem}
if grep -q @CRT@ "$BODY" && [ ! -s "$CRT" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$CRT.key" -out "$CRT.crt" \
    -subj /CN=localhost -days 30 >/dev/null 2>&1 && cat "$CRT.crt" "$CRT.key" > "$CRT" || exit 1
fi
sed -e "s/@FE@/$FE/g; s/@BE@/$BE/g; s/@TP@/$TP/g; s#@CRT@#$CRT#g" "$BODY" > "$CFG" || exit 1
taskset -c "$CPU_B" "$BENCH" backend "$BE" >/dev/null 2>&1 & BEPID=$!
sleep 0.3
taskset -c "$CPU_P" "$BIN" -f "$CFG" > "$OUT/$LABEL.proxy.log" 2>&1 & P=$!
for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/"$FE") 2>/dev/null && break; sleep 0.1; done
client() {
  case $CL in
    mb50) taskset -c "$CPU_C" "$BENCH" fixed 127.0.0.1:"$FE" 50 "$1" ;;
    ab1)  taskset -c "$CPU_C" ab -k -q -c 1 -n "$1" "http://127.0.0.1:$FE/" ;;
    ab1s) taskset -c "$CPU_C" ab -k -q -c 1 -n "$1" "https://127.0.0.1:$FE/" ;;
    hs1)  taskset -c "$CPU_C" ab -q -c 1 -n "$1" "https://127.0.0.1:$FE/" ;;
    nc1)  taskset -c "$CPU_C" ab -q -c 1 -n "$1" "http://127.0.0.1:$FE/" ;;
    h2s1) taskset -c "$CPU_C" h2load -c 1 -m 1 --alpn-list=h2 -n "$1" "https://127.0.0.1:$FE/" ;;
    h3c1) taskset -c "$CPU_C" h2load -c 1 -m 1 --alpn-list=h3 -n "$1" "https://127.0.0.1:$FE/" ;;
    h3best)  taskset -c "$CPU_C" "$H3BENCH" 127.0.0.1:"$FE" "$1" best "$H3M" ;;
    h3worst) taskset -c "$CPU_C" "$H3BENCH" 127.0.0.1:"$FE" "$1" worst "$H3M" ;;
    *) echo "unknown client $CL" >&2; return 1 ;;
  esac
}
# One counted round of client $CL: "<instructions> <client datagrams/req or ->", files $OUT/$LABEL.$1.*
round() {
  perf stat -x, -e instructions:u -p "$P" -o "$OUT/$LABEL.$1.stat" -- \
    bash -c "$(declare -f client); BENCH=$BENCH H3BENCH=$H3BENCH H3M=$H3M CL=$CL FE=$FE CPU_C=$CPU_C; client $N" > "$OUT/$LABEL.$1.client" 2>&1
  INS=$(grep instructions "$OUT/$LABEL.$1.stat" | cut -d, -f1)
  if grep -q '^requests:' "$OUT/$LABEL.$1.client" && ! grep -q "requests: $N total, $N started, $N done, $N succeeded" "$OUT/$LABEL.$1.client"; then
    echo "$LABEL $1: the client did not complete every request: $(grep '^requests:' "$OUT/$LABEL.$1.client")" >&2
  fi
  D=$(sed -n 's/^h3bench: .* client \([0-9.]*\) datagrams\/req.*/\1/p' "$OUT/$LABEL.$1.client")
  echo "$INS ${D:--}"
}
if [ "$CL" = h3fit ]; then
  CL=h3best client 2000 > "$OUT/$LABEL.warm-best.out" 2>&1
  CL=h3worst client 2000 > "$OUT/$LABEL.warm-worst.out" 2>&1
  : > "$OUT/$LABEL.fit"
  for r in $(seq 1 "$ROUNDS"); do
    read -r IB DB < <(CL=h3best round "r$r.best")
    read -r IW DW < <(CL=h3worst round "r$r.worst")
    python3 - "$LABEL" "$r" "$N" "$IB" "$DB" "$IW" "$DW" "$FIT_RATE" <<'PY' | tee -a "$OUT/$LABEL.fit"
import sys
label, r, n, ib, db, iw, dw, rate = sys.argv[1:]
n = int(n); b = int(ib) / n; w = int(iw) / n; db = float(db); dw = float(dw); rate = float(rate)
fit = b + (w - b) * (rate - db) / (dw - db)
print(f"{label} round {r}: best {b:.0f} ins/req at {db:.4f} dgrams/req, worst {w:.0f} at {dw:.4f}, "
      f"fit {fit:.0f} ins/req at {rate}")
PY
  done
  python3 - "$LABEL" "$OUT/$LABEL.fit" "$FIT_RATE" "$BIN" "$BODY" "$N" "${IBEX_MEASURE_JSONL:-}" "$H3M" "$(dirname "$0")" <<'PY'
import json, re, statistics, subprocess, sys, datetime, os
label, path, rate, binp, body, n, jsonl, method, here = sys.argv[1:]
rows = [list(map(float, re.findall(r"best (\d+) ins/req at ([\d.]+) dgrams/req, worst (\d+) at ([\d.]+), fit (\d+)", l)[0]))
        for l in open(path) if " fit " in l]
med = lambda i: statistics.median(r[i] for r in rows)
fits = [r[4] for r in rows]
spread = (max(fits) - min(fits)) / statistics.median(fits) * 100
print(f"{label} h3fit: fit {med(4):.0f} ins/req at {rate} client dgrams/req (median of {len(rows)}, spread "
      f"{spread:.2f}%); best {med(0):.0f} at {med(1):.4f}, worst {med(2):.0f} at {med(3):.4f}")
if jsonl:
    # The tree the measurement was made from (IBEX_MEASURE_SHA names the build's own commit).
    sha = os.environ.get("IBEX_MEASURE_SHA") or subprocess.run(
        ["git", "-C", here, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    row = {"kind": "insreq-h3", "sha": sha, "label": label, "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "binary": binp, "scenario": os.path.basename(body), "method": method, "requests": int(n), "rounds": len(rows),
           "fit_rate": float(rate), "h3_fit": round(med(4)), "h3_fit_spread_pct": round(spread, 3),
           "h3_best": round(med(0)), "h3_best_dgrams": med(1), "h3_worst": round(med(2)), "h3_worst_dgrams": med(3),
           "h3_fit_samples": [round(f) for f in fits]}
    with open(jsonl, "a") as f:
        f.write(json.dumps(row) + "\n")
PY
else
  client 2000 > "$OUT/$LABEL.warm.out" 2>&1
  for r in $(seq 1 "$ROUNDS"); do
    read -r INS D < <(round "r$r")
    if [ "$D" = - ]; then
      echo "$LABEL round $r: $INS instructions, $((INS / N)) ins/req"
    else
      echo "$LABEL round $r: $INS instructions, $((INS / N)) ins/req, $D client dgrams/req"
    fi
  done
fi
kill "$P"; wait "$P" 2>/dev/null; kill "$BEPID"; wait "$BEPID" 2>/dev/null
echo "$LABEL done (proxy pid $P and backend pid $BEPID stopped)"
