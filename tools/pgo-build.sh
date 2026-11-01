#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Build a PGO-optimised ibex (profile `release-perf`).
#   1. build an instrumented ibex            (-Cprofile-generate)
#   2. run a mixed training load against it  (tools/pgo/train.cfg)
#   3. merge the raw profiles                (llvm-profdata)
#   4. build the final binary                (-Cprofile-use)
#   5. with --bolt: reorder-only BOLT from an instrumented run
# The profile is NOT checked in: it goes stale with every change, regenerate it per release.
#
# Usage: tools/pgo-build.sh [--target-dir DIR] [--out FILE] [--bolt] [--keep]
#   --target-dir DIR  cargo target root; the instrumented build goes to DIR/pgo-gen and the
#                     final one to DIR/pgo-use. Default: <repo>/target (or $PGO_TARGET_DIR).
#   --out FILE        also copy the final binary to FILE
#   --bolt            add llvm-bolt reordering (needs llvm-bolt; off by default)
#   --keep            keep the work directory under /tmp
# The training covers h1 (plain, TLS), h2 (TLS, h2c), h3 (h3bench and h2load -m 10), rules, errors.
# Needs: rustc and llvm-profdata with the same LLVM major version, h2load, socat, openssl, curl, nc.
# Environment: CARGO_BUILD_PREFIX (e.g. "nice -n 19 taskset -c 0-47") is put in front of cargo.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd) || exit 1
cd "$ROOT" || exit 1
TD=${PGO_TARGET_DIR:-$ROOT/target}; OUT=""; BOLT=0; KEEP=0
while [ $# -gt 0 ]; do
  case $1 in
    --target-dir) TD=$2; shift 2;;
    --out) OUT=$2; shift 2;;
    --bolt) BOLT=1; shift;;
    --keep) KEEP=1; shift;;
    -h|--help) sed -n 2,20p "$0"; exit 0;;
    *) echo "pgo-build: unknown option $1" >&2; exit 2;;
  esac
done
T0=$(date +%s)
log() { echo "pgo-build [$(( $(date +%s) - T0 ))s]: $*" >&2; }
die() { echo "pgo-build: $*" >&2; exit 1; }

# 0. Toolchain check: a profile written by one LLVM cannot be read by another.
for t in rustc cargo llvm-profdata h2load socat openssl curl nc; do
  command -v "$t" >/dev/null || die "missing tool: $t"
done
RL=$(rustc -vV | sed -n 's/^LLVM version: *//p' | cut -d. -f1)
PL=$(llvm-profdata --version | sed -n 's/.*LLVM version *//p' | head -1 | cut -d. -f1)
[ -n "$RL" ] && [ "$RL" = "$PL" ] || die "LLVM mismatch: rustc uses LLVM '${RL:-?}', llvm-profdata is '${PL:-?}'. Install a matching llvm-profdata (or rustup component add llvm-tools and use its llvm-profdata)."
if [ "$BOLT" = 1 ]; then command -v llvm-bolt >/dev/null || die "--bolt: llvm-bolt not found"; fi

W=$(mktemp -d /tmp/pgo-build.XXXXXX) || exit 1
PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  if [ "$KEEP" = 1 ]; then log "work dir kept: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
PFX=${CARGO_BUILD_PREFIX:-}
export CARGO_INCREMENTAL=0

# 1. Instrumented build.
# A fixed raw-profile dir: it is part of RUSTFLAGS, so a per-run path would rebuild everything each time.
PGDIR=$TD/pgo-raw
log "building instrumented ibex in $TD/pgo-gen"
RUSTFLAGS="-Cprofile-generate=$PGDIR" CARGO_TARGET_DIR="$TD/pgo-gen" $PFX cargo build --profile release-perf -p ibex-rt --bin ibex >"$W/build-gen.log" 2>&1 \
  || { tail -20 "$W/build-gen.log" >&2; die "instrumented build failed (log $W/build-gen.log)"; }
GEN=$TD/pgo-gen/release-perf/ibex
BENCH_TD=$TD/pgo-bench
log "building measure-bench"
(cd "$ROOT/tools/measure/bench" || exit 1; CARGO_TARGET_DIR="$BENCH_TD" $PFX cargo build --release >"$W/build-bench.log" 2>&1) \
  || { tail -20 "$W/build-bench.log" >&2; die "measure-bench build failed"; }
BENCH=$BENCH_TD/release/measure-bench
[ -x "$BENCH" ] || die "measure-bench not found at $BENCH"
# h3bench: the deterministic HTTP/3 client (T555), for the QUIC part of the training.
log "building h3bench"
(cd "$ROOT/tools/measure/h3bench" || exit 1; CARGO_TARGET_DIR="$BENCH_TD" $PFX cargo build --release --offline >"$W/build-h3bench.log" 2>&1) \
  || { tail -20 "$W/build-h3bench.log" >&2; die "h3bench build failed"; }
H3BENCH=$BENCH_TD/release/h3bench
[ -x "$H3BENCH" ] || die "h3bench not found at $H3BENCH"

# 2. Training load.
# train <ibex-binary> <label>: start backend + log sink + proxy, drive the load, stop the proxy
# with SIGUSR1 (graceful, so the profile is written at exit) and wait for it.
train() {
  local BIN=$1 LABEL=$2
  local P_LOG P_H1 P_TLS P_H2C P_H3 P_BE P_DEAD
  P_LOG=$(port); P_H1=$(port); P_TLS=$(port); P_H2C=$(port); P_H3=$(port); P_BE=$(port); P_DEAD=$(port)
  if [ ! -f "$W/cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/cert.pem" -out "$W/crt.pem" -subj /CN=localhost -days 1 2>/dev/null \
      && cat "$W/crt.pem" >> "$W/cert.pem" || die "openssl cert generation failed"
  fi
  sed -e "s/@P_LOG@/$P_LOG/;s/@P_H1@/$P_H1/;s/@P_TLS@/$P_TLS/;s/@P_H2C@/$P_H2C/;s/@P_H3@/$P_H3/;s/@P_BE@/$P_BE/;s/@P_DEAD@/$P_DEAD/" \
      -e "s#@CERT@#$W/cert.pem#" "$ROOT/tools/pgo/train.cfg" > "$W/train.cfg"

  "$BENCH" backend "$P_BE" >/dev/null 2>&1 & local BEP=$!; PIDS+=("$BEP")
  socat -u "UDP-RECV:$P_LOG,bind=127.0.0.1" /dev/null 2>/dev/null & local SOP=$!; PIDS+=("$SOP")
  LLVM_PROFILE_FILE="$PGDIR/ibex-%p-%m.profraw" "$BIN" -db -f "$W/train.cfg" >"$W/ibex-$LABEL.log" 2>&1 & local IP=$!; PIDS+=("$IP")
  local i
  for i in $(seq 1 100); do
    (exec 3<>"/dev/tcp/127.0.0.1/$P_H1") 2>/dev/null && break
    kill -0 "$IP" 2>/dev/null || { cat "$W/ibex-$LABEL.log" >&2; die "ibex exited at startup"; }
    sleep 0.1
  done
  local H1=127.0.0.1:$P_H1 TLS=127.0.0.1:$P_TLS H2C=127.0.0.1:$P_H2C
  log "[$LABEL] HTTP/1 keep-alive"
  "$BENCH" fixed "$H1" 20 100000 >/dev/null
  log "[$LABEL] HTTP/1 connection: close"
  h2load --h1 -H 'Connection: close' -n 8000 -c 10 "http://$H1/" >/dev/null 2>&1
  log "[$LABEL] rules (set-header, del-header, regex ACL, redirect)"
  h2load --h1 -H 'X-Debug: 1' -n 20000 -c 10 "http://$H1/rule" >/dev/null 2>&1
  h2load --h1 -n 5000 -c 5 "http://$H1/private/123" >/dev/null 2>&1
  h2load --h1 -n 5000 -c 5 "http://$H1/old" >/dev/null 2>&1
  log "[$LABEL] error paths (404 return, 403 deny, 503 no server, malformed)"
  h2load --h1 -n 10000 -c 10 "http://$H1/missing" >/dev/null 2>&1
  h2load --h1 -n 2000 -c 5 "http://$H1/down" >/dev/null 2>&1
  for i in $(seq 1 300); do
    printf 'GARBAGE\r\n\r\n' | nc -w 1 127.0.0.1 "$P_H1" >/dev/null 2>&1
    printf 'GET / HTTP/1.1\r\nBad Header\r\n\r\n' | nc -w 1 127.0.0.1 "$P_H1" >/dev/null 2>&1
  done
  log "[$LABEL] TLS HTTP/1.1 (one connection, then ten)"
  h2load --h1 -n 5000 -c 1 "https://$TLS/" >/dev/null 2>&1
  h2load --h1 -n 20000 -c 10 "https://$TLS/" >/dev/null 2>&1
  curl -sk --http1.1 -o /dev/null -w '' "https://$TLS/old" 2>/dev/null
  log "[$LABEL] TLS + h2 (ALPN): one stream at a time, then -m 10"
  h2load -n 10000 -c 1 -m 1 "https://$TLS/" >/dev/null 2>&1
  h2load -n 100000 -c 10 -m 10 "https://$TLS/" >/dev/null 2>&1
  h2load -n 5000 -c 5 -m 5 "https://$TLS/old" >/dev/null 2>&1
  log "[$LABEL] h2c"
  h2load -n 50000 -c 10 -m 10 "http://$H2C/" >/dev/null 2>&1
  # HTTP/3: h3bench keeps the ACK path in both policies (the h3fit shape), h2load adds
  # concurrent connections and streams (-m 10) and a POST with a 4 KB body (QPACK, DATA framing).
  local H3=127.0.0.1:$P_H3
  head -c 4096 /dev/zero | tr '\0' 'x' > "$W/body4k"
  log "[$LABEL] HTTP/3 h3bench best/worst, GET and POST"
  "$H3BENCH" "$H3" 20000 best get >/dev/null 2>&1
  "$H3BENCH" "$H3" 20000 worst get >/dev/null 2>&1
  "$H3BENCH" "$H3" 5000 best post >/dev/null 2>&1
  "$H3BENCH" "$H3" 5000 worst post >/dev/null 2>&1
  log "[$LABEL] HTTP/3 h2load: -c 10 -m 1, -c 50, -m 10, POST 4 KB, /old redirect"
  h2load --alpn-list=h3 -n 20000 -c 10 -m 1 "https://$H3/" >/dev/null 2>&1
  h2load --alpn-list=h3 -n 10000 -c 50 -m 1 "https://$H3/" >/dev/null 2>&1
  h2load --alpn-list=h3 -n 30000 -c 10 -m 10 "https://$H3/" >/dev/null 2>&1
  h2load --alpn-list=h3 -n 5000 -c 10 -m 1 -d "$W/body4k" "https://$H3/" >/dev/null 2>&1
  h2load --alpn-list=h3 -n 3000 -c 5 -m 1 "https://$H3/old" >/dev/null 2>&1
  kill -USR1 "$IP" 2>/dev/null
  for i in $(seq 1 100); do kill -0 "$IP" 2>/dev/null || break; sleep 0.1; done
  kill -0 "$IP" 2>/dev/null && { log "[$LABEL] ibex ignored SIGUSR1, killing"; kill "$IP" 2>/dev/null; }
  wait "$IP" 2>/dev/null
  kill "$BEP" "$SOP" 2>/dev/null; wait "$BEP" "$SOP" 2>/dev/null
  PIDS=()
}

rm -rf "$PGDIR"; mkdir -p "$PGDIR" || die "cannot create $PGDIR"
log "training"
train "${PGO_TRAIN_BIN:-$GEN}" pgo
ls "$PGDIR"/*.profraw >/dev/null 2>&1 || die "no .profraw written (ibex did not exit cleanly?); see $W/ibex-pgo.log"

# 3. Merge.
llvm-profdata merge -o "$W/ibex.profdata" "$PGDIR"/*.profraw || die "llvm-profdata merge failed"
log "merged profile: $(du -h "$W/ibex.profdata" | cut -f1)"

# 4. Final build. A profile mismatch is a warning, not an error.
RF="-Cprofile-use=$W/ibex.profdata"
[ "$BOLT" = 1 ] && RF="$RF -Clink-arg=-Wl,--emit-relocs"
log "building final binary in $TD/pgo-use"
RUSTFLAGS="$RF" CARGO_TARGET_DIR="$TD/pgo-use" $PFX cargo build --profile release-perf -p ibex-rt --bin ibex >"$W/build-use.log" 2>&1 \
  || { tail -20 "$W/build-use.log" >&2; die "final build failed (log $W/build-use.log)"; }
FINAL=$TD/pgo-use/release-perf/ibex

# 5. Optional BOLT: instrument, train again, reorder only.
if [ "$BOLT" = 1 ]; then
  log "BOLT: instrumenting"
  BF=$W/bolt.fdata
  llvm-bolt "$FINAL" -instrument -instrumentation-file="$BF" -instrumentation-file-append-pid=0 -o "$W/ibex.inst" >"$W/bolt-inst.log" 2>&1 \
    || { tail -5 "$W/bolt-inst.log" >&2; die "llvm-bolt -instrument failed"; }
  train "$W/ibex.inst" bolt
  [ -s "$BF" ] || die "BOLT profile $BF not written"
  llvm-bolt "$FINAL" -o "$TD/pgo-use/release-perf/ibex.bolt" -data "$BF" -reorder-blocks=ext-tsp -reorder-functions=cdsort >"$W/bolt-opt.log" 2>&1 \
    || { tail -5 "$W/bolt-opt.log" >&2; die "llvm-bolt optimisation failed"; }
  FINAL=$TD/pgo-use/release-perf/ibex.bolt
fi

if [ -n "$OUT" ]; then cp "$FINAL" "$OUT" || die "cannot copy to $OUT"; FINAL=$OUT; fi
log "done"
echo "$FINAL"
