#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# T603: build HAProxy the ways Alcyon is built (o2, lto, pgo, pgo-lto) from COPIES of the oracle
# sources, train the pgo builds with the same request mix as tools/pgo-build.sh, and measure.
# The oracle trees and binaries under ~/reference are never touched (git archive reads them).
#
#   tools/measure/haproxy-variants.sh build  <d8|q10> [variant...]   o2 lto pgo pgo-lto (default all)
#   tools/measure/haproxy-variants.sh check  <d8|q10>                -vv CFLAGS line, .gcda count
#
#   d8  = ~/reference/haproxy      (3.5-dev8, h1/h2: USE_OPENSSL USE_ZLIB USE_PCRE2, as its -vv)
#   q10 = ~/reference/haproxy-quic (3.5-dev10, h3fit: + USE_THREAD USE_QUIC USE_PROMEX)
#
# Root: $HAPV_ROOT (default ~/ibex-targets/t603): src/<set>, <set>/<variant>/haproxy.
# Training: the mix of tools/pgo-build.sh train(), the same requests in the same order; q10 gets
# the HTTP/3 part and the fe_h3 frontend of tools/pgo/train.cfg, d8 (no QUIC) does not.
# Needs the same tools as pgo-build.sh (h2load, socat, openssl, curl, nc) and its measure-bench/h3bench
# (HAPV_BENCH_DIR, default ~/ibex-targets/t603-alcyon/pgo-bench/release). Training runs under
# flock -x /tmp/alcyon-load.lock (a synthetic load), builds run niced on CPUs 16-47.
set -u
ROOT=${HAPV_ROOT:-$HOME/ibex-targets/t603}
HERE=$(cd "$(dirname "$0")/../.." && pwd) || exit 1
BENCHD=${HAPV_BENCH_DIR:-$HOME/ibex-targets/t603-alcyon/pgo-bench/release}
BUILDCPUS=${HAPV_BUILD_CPUS:-16-47}
log() { echo "haproxy-variants [$(date +%H:%M:%S)]: $*" >&2; }
die() { echo "haproxy-variants: $*" >&2; exit 1; }
opts_for() { # set -> USE_* options of the oracle's -vv
  case $1 in
    d8)  echo "USE_OPENSSL=1 USE_ZLIB=1 USE_PCRE2=1";;
    q10) echo "USE_THREAD=1 USE_OPENSSL=1 USE_ZLIB=1 USE_QUIC=1 USE_PROMEX=1 USE_PCRE2=1";;
    *) die "unknown set $1";;
  esac
}
mk() { # dir optcflags ldflags set
  (cd "$1" && nice -n 19 taskset -c "$BUILDCPUS" make -j24 TARGET=linux-glibc $(opts_for "$4") \
     OPT_CFLAGS="$2" LDFLAGS="$3" >"$1/build.log" 2>&1) || { tail -20 "$1/build.log" >&2; die "build failed in $1"; }
}
clean_objs() { find "$1" -name '*.o' -delete; rm -f "$1/haproxy" "$1"/*.a "$1"/src/*.a 2>/dev/null; }
port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

# train <set> <haproxy-bin> <workdir>: the pgo-build.sh load, then SIGUSR1 so the profile is written.
train() {
  local SET=$1 BIN=$2 W=$3 i
  local B=$BENCHD/measure-bench H3B=$BENCHD/h3bench
  [ -x "$B" ] || die "no $B (run tools/pgo-build.sh first, or set HAPV_BENCH_DIR)"
  mkdir -p "$W"
  local P_LOG P_H1 P_TLS P_H2C P_H3 P_BE P_DEAD
  P_LOG=$(port); P_H1=$(port); P_TLS=$(port); P_H2C=$(port); P_H3=$(port); P_BE=$(port); P_DEAD=$(port)
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/cert.pem" -out "$W/crt.pem" -subj /CN=localhost -days 1 2>/dev/null \
    && cat "$W/crt.pem" >> "$W/cert.pem" || die "cert"
  sed -e "s/@P_LOG@/$P_LOG/;s/@P_H1@/$P_H1/;s/@P_TLS@/$P_TLS/;s/@P_H2C@/$P_H2C/;s/@P_H3@/$P_H3/;s/@P_BE@/$P_BE/;s/@P_DEAD@/$P_DEAD/" \
      -e "s#@CERT@#$W/cert.pem#" "$HERE/tools/pgo/train.cfg" > "$W/train.full"
  # HAProxy jails itself in an empty chroot by default, where the profile cannot be written at exit:
  # "chroot /" (the documented way to say no jail) is the one line the training config adds.
  sed -i 's/^global$/global\n    chroot \//' "$W/train.full"
  if [ "$SET" = d8 ]; then # no QUIC in dev8: drop the fe_h3 frontend (4 lines after its comment)
    awk '/^# HTTP\/3 over QUIC/{skip=1} skip&&/^# Cleartext HTTP\/2/{skip=0} !skip' "$W/train.full" > "$W/train.cfg"
  else cp "$W/train.full" "$W/train.cfg"; fi
  "$B" backend "$P_BE" >/dev/null 2>&1 & local BEP=$!
  socat -u "UDP-RECV:$P_LOG,bind=127.0.0.1" /dev/null 2>/dev/null & local SOP=$!
  "$BIN" -db -f "$W/train.cfg" >"$W/proxy.log" 2>&1 & local HP=$!
  for i in $(seq 1 100); do
    (exec 3<>"/dev/tcp/127.0.0.1/$P_H1") 2>/dev/null && break
    kill -0 "$HP" 2>/dev/null || { cat "$W/proxy.log" >&2; kill "$BEP" "$SOP" 2>/dev/null; die "haproxy exited at startup"; }
    sleep 0.1
  done
  local H1=127.0.0.1:$P_H1 TLS=127.0.0.1:$P_TLS H2C=127.0.0.1:$P_H2C
  "$B" fixed "$H1" 20 100000 >/dev/null
  h2load --h1 -H 'Connection: close' -n 8000 -c 10 "http://$H1/" >/dev/null 2>&1
  h2load --h1 -H 'X-Debug: 1' -n 20000 -c 10 "http://$H1/rule" >/dev/null 2>&1
  h2load --h1 -n 5000 -c 5 "http://$H1/private/123" >/dev/null 2>&1
  h2load --h1 -n 5000 -c 5 "http://$H1/old" >/dev/null 2>&1
  h2load --h1 -n 10000 -c 10 "http://$H1/missing" >/dev/null 2>&1
  h2load --h1 -n 2000 -c 5 "http://$H1/down" >/dev/null 2>&1
  for i in $(seq 1 300); do
    printf 'GARBAGE\r\n\r\n' | nc -w 1 127.0.0.1 "$P_H1" >/dev/null 2>&1
    printf 'GET / HTTP/1.1\r\nBad Header\r\n\r\n' | nc -w 1 127.0.0.1 "$P_H1" >/dev/null 2>&1
  done
  h2load --h1 -n 5000 -c 1 "https://$TLS/" >/dev/null 2>&1
  h2load --h1 -n 20000 -c 10 "https://$TLS/" >/dev/null 2>&1
  curl -sk --http1.1 -o /dev/null -w '' "https://$TLS/old" 2>/dev/null
  h2load -n 10000 -c 1 -m 1 "https://$TLS/" >/dev/null 2>&1
  h2load -n 100000 -c 10 -m 10 "https://$TLS/" >/dev/null 2>&1
  h2load -n 5000 -c 5 -m 5 "https://$TLS/old" >/dev/null 2>&1
  h2load -n 50000 -c 10 -m 10 "http://$H2C/" >/dev/null 2>&1
  if [ "$SET" != d8 ]; then
    local H3=127.0.0.1:$P_H3
    head -c 4096 /dev/zero | tr '\0' 'x' > "$W/body4k"
    "$H3B" "$H3" 20000 best get >/dev/null 2>&1
    "$H3B" "$H3" 20000 worst get >/dev/null 2>&1
    "$H3B" "$H3" 5000 best post >/dev/null 2>&1
    "$H3B" "$H3" 5000 worst post >/dev/null 2>&1
    h2load --alpn-list=h3 -n 20000 -c 10 -m 1 "https://$H3/" >/dev/null 2>&1
    h2load --alpn-list=h3 -n 10000 -c 50 -m 1 "https://$H3/" >/dev/null 2>&1
    h2load --alpn-list=h3 -n 30000 -c 10 -m 10 "https://$H3/" >/dev/null 2>&1
    h2load --alpn-list=h3 -n 5000 -c 10 -m 1 -d "$W/body4k" "https://$H3/" >/dev/null 2>&1
    h2load --alpn-list=h3 -n 3000 -c 5 -m 1 "https://$H3/old" >/dev/null 2>&1
  fi
  kill -USR1 "$HP" 2>/dev/null
  for i in $(seq 1 150); do kill -0 "$HP" 2>/dev/null || break; sleep 0.1; done
  kill -0 "$HP" 2>/dev/null && { log "haproxy ignored SIGUSR1, killing"; kill "$HP" 2>/dev/null; }
  wait "$HP" 2>/dev/null
  kill "$BEP" "$SOP" 2>/dev/null; wait "$BEP" "$SOP" 2>/dev/null
  return 0
}

cmd_build() {
  local SET=$1; shift
  local V=${*:-o2 lto pgo pgo-lto} v
  local SRC=$ROOT/src/$SET
  [ -d "$SRC" ] || { mkdir -p "$SRC"; git -C "$HOME/reference/$([ "$SET" = d8 ] && echo haproxy || echo haproxy-quic)" archive HEAD | tar -x -C "$SRC"; }
  local O2="-O2" LT="-O2 -flto=auto"
  for v in $V; do
    local D=$ROOT/$SET/$v
    case $v in
      o2)  rm -rf "$D"; mkdir -p "$ROOT/$SET"; cp -a "$SRC" "$D"; log "$SET o2"; mk "$D" "$O2" "" "$SET";;
      lto) rm -rf "$D"; mkdir -p "$ROOT/$SET"; cp -a "$SRC" "$D"; log "$SET lto"; mk "$D" "$LT" "-O2 -flto=auto" "$SET";;
      pgo|pgo-lto)
        if [ "$v" = pgo ]; then
          rm -rf "$D" "$ROOT/$SET/pgo-lto" "$ROOT/$SET/pgo-gen"; mkdir -p "$ROOT/$SET"; cp -a "$SRC" "$D"
          log "$SET pgo: instrumented build"
          mk "$D" "-O2 -fprofile-generate -fprofile-update=atomic" "-fprofile-generate -fprofile-update=atomic" "$SET"
          cp "$D/haproxy" "$ROOT/$SET/haproxy-pgo-gen"
          log "$SET pgo: training (flock -x /tmp/alcyon-load.lock)"
          flock -x /tmp/alcyon-load.lock bash -c "$(declare -f train port log die); BENCHD=$BENCHD HERE=$HERE; train $SET $D/haproxy $ROOT/$SET/train-work" \
            || die "training failed"
          log "$SET pgo: $(find "$D" -name '*.gcda' | wc -l) .gcda files"
          rm -rf "$ROOT/$SET/pgo-lto"; cp -a "$D" "$ROOT/$SET/pgo-lto"
        fi
        # use build: pgo uses the profile as is; pgo-lto is a copy of the trained tree.
        local U="-O2 -fprofile-use -fprofile-partial-training -Wno-missing-profile" LD="-O2"
        [ "$v" = pgo-lto ] && { U="$U -flto=auto"; LD="-O2 -flto=auto"; }
        [ -d "$D" ] || die "$D missing: build pgo first"
        clean_objs "$D"; log "$SET $v: use build"; mk "$D" "$U" "$LD" "$SET";;
      *) die "unknown variant $v";;
    esac
    [ -x "$D/haproxy" ] || die "no binary for $SET $v"
  done
}

cmd_check() {
  local SET=$1 v
  for v in o2 lto pgo pgo-lto; do
    local D=$ROOT/$SET/$v
    echo "== $SET $v: $(find "$D" -name '*.gcda' 2>/dev/null | wc -l) .gcda"
    "$D/haproxy" -vv 2>&1 | grep -E 'HAProxy version|CFLAGS|OPTIONS|compiler'
  done
}

case ${1:-} in
  build) shift; [ $# -ge 1 ] || die "usage: build <d8|q10> [variant...]"; cmd_build "$@";;
  check) shift; cmd_check "$1";;
  *) sed -n 5,20p "$0"; exit 2;;
esac
