#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# dpbench-style proxy comparison (github.com/dpbench/dpbench, howtos/): h1load and httpterm from
# dpbench's bin/, the forwarder configuration of config/haproxy-forwarder-basic.conf (8 servers,
# balance random), an empty GET to `/?s=0`. Every proxy gets the same configuration file.
#
#   DPBENCH_BIN=<dpbench>/bin tools/measure/dpbench.sh <outdir> <label>=<binary> [<label>=<binary>...]
#
# For nbthread 1 and then 4:
#   1. max    each proxy under h1load -t 8 -c 400 -d 20 -s 2; req/s over seconds 4..19
#   2. fixed  each proxy at R = 80% of the weakest proxy's max for 30 s, with a probe client
#             (h1load -c 4 -R R/100 -A -P) whose percentiles are the latency figures
# CPU is reported twice: the proxy process (utime+stime) and the proxy CPUs' busy time from
# /proc/stat, which includes the loopback softirq work the kernel does not charge to the process.
# DPB_BALANCE=roundrobin (default random, as dpbench) changes the balance algorithm.
# CPUs (one EPYC 7542 CCX each): proxy 8 (or 8-11), servers 16-23, load 24-31, probe 0-1. Override
# with DPB_PROXY_CPU0, DPB_SRV_CPUS, DPB_LOAD_CPUS, DPB_PROBE_CPUS. Take the measurement locks
# yourself (flock -x /tmp/alcyon-load.lock flock -x /tmp/alcyon-load-n1.lock ...).
set -u
[ $# -ge 2 ] || { sed -n '5,20p' "$0"; exit 2; }
O=$1; shift; mkdir -p "$O"
B=${DPBENCH_BIN:?set DPBENCH_BIN to the dpbench bin directory (h1load, httpterm)}
C0=${DPB_PROXY_CPU0:-8}; SRVC=${DPB_SRV_CPUS:-16-23}; LOADC=${DPB_LOAD_CPUS:-24-31}; PROBEC=${DPB_PROBE_CPUS:-0-1}
declare -A BIN; ORDER=""
for a in "$@"; do BIN[${a%%=*}]=${a#*=}; ORDER="$ORDER ${a%%=*}"; [ -x "${a#*=}" ] || { echo "not executable: ${a#*=}"; exit 2; }; done
BAL=${DPB_BALANCE:-random}; FE=18000; SV=18100; URL=http://127.0.0.1:$FE/?s=0

parse() { python3 -I "$(dirname "$0")/dpbench_parse.py" "$@"; }

pids=(); i=0
for c in $(seq ${SRVC%-*} ${SRVC#*-}); do
  [ $i -lt 8 ] || break
  # -dS: no vmsplice; without it, httpterm runs into the per-user pipe buffer limit and exits
  taskset -c $c "$B/httpterm" -db -dS -L 127.0.0.1:$((SV+i)) >/dev/null 2>&1 & pids+=($!); i=$((i+1))
done
sleep 1
for p in "${pids[@]}"; do kill -0 $p 2>/dev/null || { echo "an httpterm exited at startup"; kill "${pids[@]}" 2>/dev/null; exit 1; }; done

cfg() { printf 'global\n   strict-limits\n   nbthread %s\n   maxconn 10000\ndefaults\n   mode http\n   balance %s\n   timeout client 60s\n   timeout server 60s\n   timeout connect 1s\nlisten p\n   bind 127.0.0.1:%s\n' $1 $BAL $FE
  for i in 0 1 2 3 4 5 6 7; do printf '   server s%s 127.0.0.1:%s\n' $i $((SV+i)); done; }
cpus() { [ $1 = 1 ] && echo $C0 || echo $C0-$((C0+$1-1)); }
ticks() { awk '{print $14+$15}' /proc/$1/stat; }
busy() { local t=0 c; for c in $(seq $C0 $((C0+$1-1))); do t=$((t + $(awk -v c=cpu$c '$1==c{print $2+$3+$4+$7+$8+$9}' /proc/stat))); done; echo $t; }
cores() { echo "scale=2; ($2-$1)/$(getconf CLK_TCK)/($4-$3)" | bc -l; }
start() { cfg $2 > "$O/p-$2.cfg"; taskset -c $(cpus $2) "${BIN[$1]}" -db -f "$O/p-$2.cfg" >"$O/$1-$2.proxy.log" 2>&1 & PROXY=$!
  for i in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$FE) 2>/dev/null && return; sleep 0.1; done; echo "$1 did not start"; }
stop() { kill -USR1 $PROXY 2>/dev/null; for i in $(seq 50); do kill -0 $PROXY 2>/dev/null || break; sleep 0.1; done; kill $PROXY 2>/dev/null; wait $PROXY 2>/dev/null; }
mark() { t0=$(ticks $PROXY); b0=$(busy $1); s0=$(date +%s.%N); }
cpu() { local t1 b1 s1; t1=$(ticks $PROXY); b1=$(busy $1); s1=$(date +%s.%N)
  echo "cpu $(cores $t0 $t1 $s0 $s1) cores (process), $(cores $b0 $b1 $s0 $s1) cores (CPUs incl. softirq)"; }

echo "start $(date +%T) gov=$(cat /sys/devices/system/cpu/cpu$C0/cpufreq/scaling_governor 2>/dev/null) load=$(cut -d' ' -f1 /proc/loadavg)"
for nb in 1 4; do
  min=0
  for p in $ORDER; do
    start $p $nb; mark $nb
    taskset -c $LOADC "$B/h1load" -t 8 -c 400 -d 20 -s 2 $URL > "$O/$p-$nb.max.out" 2>&1
    c=$(cpu $nb); stop
    r=$(parse rps "$O/$p-$nb.max.out")
    echo "nb$nb $p max: $r req/s, $c"
    { [ $min = 0 ] || [ $r -lt $min ]; } && min=$r
  done
  R=$(( min * 8 / 10 / 1000 * 1000 )); PR=$(( R / 100 ))
  echo "nb$nb fixed rate R=$R req/s (80% of the weakest max $min), probe $PR req/s"
  for p in $ORDER; do
    start $p $nb; mark $nb
    taskset -c $LOADC "$B/h1load" -t 8 -c 400 -d 30 -s 2 -R $R $URL > "$O/$p-$nb.fixed.out" 2>&1 &
    L=$!; sleep 3
    taskset -c $PROBEC "$B/h1load" -t 1 -c 4 -d 25 -R $PR -A -P $URL > "$O/$p-$nb.probe.out" 2>&1
    wait $L; c=$(cpu $nb); stop
    echo "nb$nb $p at $R: load $(parse rps "$O/$p-$nb.fixed.out") req/s, $c; probe $(parse pctl "$O/$p-$nb.probe.out")"
  done
done
kill "${pids[@]}"
echo "end $(date +%T) load=$(cut -d' ' -f1 /proc/loadavg)"
