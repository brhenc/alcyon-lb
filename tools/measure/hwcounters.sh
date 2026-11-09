#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# T603: hardware counters per request and throughput of one proxy binary, same rig as insreq.sh
# (same backend, client, pinning: proxy CPU a, client b, backend c from ALCYON_MEASURE_CPUS, default 4,5,6).
#
#   tools/measure/hwcounters.sh <label> <proxy-bin> <scenario.body> <ab1|h2s1|tp1|tp50> <N> <rounds> <outdir>
#
#   ab1, h2s1  perf stat -p <proxy> per round, in two event groups (so the PMU does not multiplex):
#              A = cycles:u instructions:u cycles:k instructions:k
#              B = L1-dcache-load-misses L1-icache-load-misses branch-misses l2_cache_req_stat.ic_dc_miss_in_l2
#              (LLC-load-misses is <not supported> on this CPU, AMD; the L2 event is the nearest)
#              Prints per request: medians over the rounds of each count, IPC user and kernel.
#   tp1, tp50  throughput, requests/s (ab -k -c 1; measure-bench fixed, 50 keep-alive connections), median of
#              rounds, with the load average at start and end. A timing claim: hold the slot, no game running.
#
# Takes no lock: wrap in `flock -x /tmp/alcyon-load.lock`, and check wwm.exe and the governor before and after.
set -u
[ $# -eq 7 ] || { sed -n 5,19p "$0"; exit 2; }
LABEL=$1; BIN=$2; BODY=$3; CL=$4; N=$5; ROUNDS=$6; OUT=$7
mkdir -p "$OUT" || exit 1
BENCH=${MEASURE_BENCH:-${ALCYON_TARGETS:-${XDG_CACHE_HOME:-$HOME/.cache}/alcyon/targets}/gate-slot1/release/measure-bench}
IFS=, read -r CPU_P CPU_C CPU_B <<< "${ALCYON_MEASURE_CPUS:-4,5,6}"
port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
FE=$(port); BE=$(port); TP=$(port)
CFG=$OUT/$LABEL.$CL.cfg
CRT=${ALCYON_MEASURE_CRT:-$OUT/insreq-cert.pem}
if grep -q @CRT@ "$BODY" && [ ! -s "$CRT" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$CRT.key" -out "$CRT.crt" \
    -subj /CN=localhost -days 30 >/dev/null 2>&1 && cat "$CRT.crt" "$CRT.key" > "$CRT" || exit 1
fi
sed -e "s/@FE@/$FE/g; s/@BE@/$BE/g; s/@TP@/$TP/g; s#@CRT@#$CRT#g" "$BODY" > "$CFG" || exit 1
taskset -c "$CPU_B" "$BENCH" backend "$BE" >/dev/null 2>&1 & BEPID=$!
sleep 0.3
taskset -c "$CPU_P" "$BIN" -f "$CFG" > "$OUT/$LABEL.$CL.proxy.log" 2>&1 & P=$!
for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/"$FE") 2>/dev/null && break; sleep 0.1; done
client() {
  case $CL in
    ab1|tp1) taskset -c "$CPU_C" ab -k -q -c 1 -n "$1" "http://127.0.0.1:$FE/" ;;
    tp50)    taskset -c "$CPU_C" "$BENCH" fixed 127.0.0.1:"$FE" 50 "$1" ;;
    h2s1)    taskset -c "$CPU_C" h2load -c 1 -m 1 --alpn-list=h2 -n "$1" "https://127.0.0.1:$FE/" ;;
  esac
}
# tp50 runs on three client CPUs would not be the insreq shape; one client CPU, as everywhere else.
client 2000 >/dev/null 2>&1
EVA=cycles:u,instructions:u,cycles:k,instructions:k
EVB=L1-dcache-load-misses,L1-icache-load-misses,branch-misses,l2_cache_req_stat.ic_dc_miss_in_l2
case $CL in
  ab1|h2s1)
    for g in A B; do
      EV=$EVA; [ $g = B ] && EV=$EVB
      : > "$OUT/$LABEL.$CL.$g"
      for r in $(seq 1 "$ROUNDS"); do
        perf stat -x, -e "$EV" -p "$P" -o "$OUT/$LABEL.$CL.$g.r$r.stat" -- \
          bash -c "$(declare -f client); BENCH=$BENCH CL=$CL FE=$FE CPU_C=$CPU_C; client $N" > "$OUT/$LABEL.$CL.$g.r$r.client" 2>&1
        python3 - "$OUT/$LABEL.$CL.$g.r$r.stat" "$N" >> "$OUT/$LABEL.$CL.$g" <<'PY'
import sys
n = int(sys.argv[2]); row = {}; mux = 100.0
for l in open(sys.argv[1]):
    f = l.split(",")
    if len(f) > 5 and f[0].strip().isdigit():
        row[f[2]] = int(f[0]); mux = min(mux, float(f[4] or 100) if f[4].replace(".", "").isdigit() else 100.0)
print(" ".join(f"{k}={v}" for k, v in row.items()), f"n={n}", f"minrun%={mux}")
PY
      done
    done
    python3 - "$LABEL" "$CL" "$OUT" <<'PY'
import statistics, sys
label, cl, out = sys.argv[1:]
med = {}; n = None; mux = 100.0
for g in "AB":
    for l in open(f"{out}/{label}.{cl}.{g}"):
        d = dict(x.split("=") for x in l.split())
        n = int(d.pop("n")); mux = min(mux, float(d.pop("minrun%")))
        for k, v in d.items():
            med.setdefault(k, []).append(int(v))
m = {k: statistics.median(v) / n for k, v in med.items()}
print(f"{label} {cl} per request (median of rounds, min PMU run {mux}%):")
for k, v in m.items():
    print(f"  {k:<40}{v:>12.1f}")
print(f"  IPC user {m['instructions:u']/m['cycles:u']:.3f}  IPC kernel {m['instructions:k']/m['cycles:k']:.3f}  "
      f"cycles/req user {m['cycles:u']:.0f} kernel {m['cycles:k']:.0f}")
PY
    ;;
  tp1|tp50)
    echo "$LABEL $CL load-start $(cut -d' ' -f1-3 /proc/loadavg)"
    for r in $(seq 1 "$ROUNDS"); do
      T0=$(date +%s.%N)
      client "$N" > "$OUT/$LABEL.$CL.r$r.client" 2>&1
      T1=$(date +%s.%N)
      case $CL in
        tp1)  sed -n 's/^Requests per second: *\([0-9.]*\).*/\1/p' "$OUT/$LABEL.$CL.r$r.client" ;;
        # measure-bench fixed prints no rate: N over the wall time of the whole client run
        tp50) python3 -c "print($N / ($T1 - $T0))" ;;
      esac
    done | tee "$OUT/$LABEL.$CL.rps" | python3 -c "
import statistics, sys
v = [float(x) for x in sys.stdin.read().split()]
print('$LABEL $CL requests/s: median', round(statistics.median(v)), 'min', round(min(v)), 'max', round(max(v)), 'of', len(v), v)
"
    echo "$LABEL $CL load-end $(cut -d' ' -f1-3 /proc/loadavg)"
    ;;
esac
kill "$P"; wait "$P" 2>/dev/null; kill "$BEPID"; wait "$BEPID" 2>/dev/null
exit 0
