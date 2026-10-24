#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# T452 night run: what puts the gate's 1-connection A/B samples in the ~15k or the ~19k
# cluster. One variable per batch, each against the gate's baseline (proxy;client;backend
# on CPUs 4;5;6, nbthread 1, the 50-connection phase after each sample). Every batch is 16
# rounds; two labels alternate ABBA as measure_ab does, an A/A repeats one binary.
#
#   tools/measure/t452_night.sh            # all batches, ~75 min on a quiet host, cap 150 min
#   T452_ONLY=base-aa-cand T452_ROUNDS=1 tools/measure/t452_night.sh   # smoke test
#   T452_TAG_SUFFIX=-perfgov tools/measure/t452_night.sh   # again after a root setting change
#
# Per batch, holding `flock -x /tmp/ibex-load.lock` (waits up to 20 min, then skips):
# checks wwm.exe, running VMs, llama-server CPU and busy CPUs over 3 s, and skips the batch
# with the reason logged if the host is busy. Samples go to $T452_OUT (one JSON line each,
# from t452_ab.py); batch records ("kind": "batch") say what ran or why it was skipped.
# Read the result with tools/measure/t452_report.py /tmp/t452/results.jsonl.
#
# Needs: the binaries in $T452_TARGET (release/ibex = candidate, measure-ref/ibex-<sha>,
# release/measure-bench), copies in /tmp/t452/bins, `sudo -n` for perf stat (counting only).
# Changes no system setting.

set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
OUT=${T452_OUT:-/tmp/t452/results.jsonl}
LOG=${T452_LOG:-/tmp/t452/night.log}
ROUNDS=${T452_ROUNDS:-16}
ONLY=${T452_ONLY:-}
SUFFIX=${T452_TAG_SUFFIX:-}
BUSY_MAX=${T452_BUSY_MAX:-2.0}       # busy CPUs (of 64) allowed before a batch, besides us
DEADLINE=$(( $(date +%s) + ${T452_MAX_MINUTES:-150} * 60 ))
MUSE=$HOME/ibex-worktrees/qwen/muse-pause
REF=95f4f5cc RC2REF=5bcdce4b
mkdir -p /tmp/t452
exec > >(tee -a "$LOG") 2>&1

log() { echo "$(date '+%F %T') $*"; }

batch_record() {  # tag status reason host-json
    python3 -c 'import json,sys,time; print(json.dumps({"kind":"batch","tag":sys.argv[1],"status":sys.argv[2],"reason":sys.argv[3],"host":json.loads(sys.argv[4]),"time":time.time()}))' \
        "$1" "$2" "$3" "$4" >> "$OUT"
}

# Host state as JSON on stdout; exit 1 (with the reason in .reason) if it is too busy.
host_state() {
    python3 - "$BUSY_MAX" <<'EOF'
import json, os, subprocess, sys, time
def stat():
    t = {}
    for l in open("/proc/stat"):
        f = l.split()
        if f[0].startswith("cpu") and f[0] != "cpu":
            v = list(map(int, f[1:])); t[int(f[0][3:])] = (sum(v) - v[3] - v[4], sum(v))
    return t
def llama():
    tot = 0
    for pid in subprocess.run(["pgrep", "-x", "llama-server"], capture_output=True, text=True).stdout.split():
        try:
            f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split(); tot += int(f[11]) + int(f[12])
        except OSError:
            pass
    return tot
a, la = stat(), llama(); time.sleep(3); b, lb = stat(), llama()
busy = {c: (b[c][0] - a[c][0]) / max(1, b[c][1] - a[c][1]) for c in a}
st = {
    "load": open("/proc/loadavg").read().split()[:3],
    "wwm": subprocess.run(["pgrep", "-x", "wwm.exe"], capture_output=True).returncode == 0,
    "vms": subprocess.run(["sudo", "-n", "virsh", "list", "--state-running", "--name"],
                          capture_output=True, text=True).stdout.split(),
    "busy_cpus": round(sum(busy.values()), 2),
    "busy_ccx4": {c: round(100 * busy[c]) for c in (4, 5, 6, 7, 36, 37, 38, 39)},
    "llama_pct": round((lb - la) / os.sysconf("SC_CLK_TCK") / 3 * 100),
    "governor": open("/sys/devices/system/cpu/cpu4/cpufreq/scaling_governor").read().strip(),
    "boost": open("/sys/devices/system/cpu/cpufreq/boost").read().strip(),
    "c2_disabled": open("/sys/devices/system/cpu/cpu4/cpuidle/state2/disable").read().strip(),
}
why = []
if st["wwm"]: why.append("wwm.exe running")
if st["vms"] and not os.environ.get("T452_ALLOW_VMS"): why.append("VMs running: " + ",".join(st["vms"]))
if st["busy_cpus"] > float(sys.argv[1]): why.append(f"{st['busy_cpus']} CPUs busy")
st["reason"] = "; ".join(why)
print(json.dumps(st))
sys.exit(1 if why else 0)
EOF
}

SPIN_PIDS=()
spin_on() { for c in "$@"; do taskset -c "$c" python3 -c 'while 1: pass' & SPIN_PIDS+=($!); done; }
spin_off() { for p in "${SPIN_PIDS[@]}"; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done; SPIN_PIDS=(); }
trap 'spin_off' EXIT

# batch TAG [spin CPUS] -- t452_ab.py args
batch() {
    local tag=$1$SUFFIX; shift
    local spin=()
    if [ "${1:-}" = spin ]; then IFS=, read -ra spin <<< "$2"; shift 2; fi
    [ "${1:-}" = -- ] && shift
    if [ -n "$ONLY" ] && [[ ",$ONLY," != *",${tag%"$SUFFIX"},"* ]]; then return; fi
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        log "SKIP $tag: past the deadline"; batch_record "$tag" skip deadline '{}'; return
    fi
    (
        if ! flock -x -w 1200 9; then
            log "SKIP $tag: /tmp/ibex-load.lock busy for 20 min"; batch_record "$tag" skip "lock busy" '{}'; exit 0
        fi
        local pause=""
        [ -x "$MUSE" ] && pause=$("$MUSE" on --reason "T452 $tag" --max-minutes 20 --wait-seconds 120 2>/dev/null)
        local st
        if ! st=$(host_state); then
            log "SKIP $tag: $(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["reason"])' "$st")"
            batch_record "$tag" skip busy "$st"
        else
            log "RUN  $tag: host $st"
            batch_record "$tag" start "" "$st"
            [ ${#spin[@]} -gt 0 ] && spin_on "${spin[@]}"
            python3 "$HERE/t452_ab.py" --tag "$tag" --rounds "$ROUNDS" --out "$OUT" "$@" \
                || log "FAIL $tag: t452_ab.py exited $?"
            spin_off
            st=$(host_state)
            batch_record "$tag" end "" "$st"
            log "END  $tag: host $st"
        fi
        [ -n "$pause" ] && "$MUSE" off --id "$pause" >/dev/null 2>&1
    ) 9>/tmp/ibex-load.lock
}

log "T452 night run: rounds $ROUNDS, out $OUT, only '${ONLY}', suffix '${SUFFIX}'"
G=(--load)   # the gate's sample: 1-conn phase, then 50 connections
# Baseline as the gate measures it. The A/A of the candidate runs at the start, the middle
# and the end, to show the drift over the night.
batch base-aa-cand    -- "${G[@]}" --bins cand,cand
batch base-aa-ref     -- "${G[@]}" --bins $REF,$REF
batch base-ab         -- "${G[@]}" --bins cand,$REF
batch base-ba         -- "${G[@]}" --bins $REF,cand          # order swapped
batch rebuild-aa      -- "${G[@]}" --bins $REF,gate95f4      # same commit, gate's build vs ours
batch rc2-ab          -- "${G[@]}" --bins $REF,$RC2REF       # rc2 vs its gate reference
batch rc2-ba          -- "${G[@]}" --bins $RC2REF,$REF
batch noperf-aa-cand  -- "${G[@]}" --bins cand,cand --no-perf   # does perf itself move it
batch noload-aa-cand  -- --bins cand,cand                      # without the 50-conn phase
# Memory placement (node0 = CPUs 0-7,32-39).
batch membind0-aa     -- "${G[@]}" --bins cand,cand --wrap "numactl --membind=0"
batch membind0-ab     -- "${G[@]}" --bins cand,$REF --wrap "numactl --membind=0"
batch interleave-aa   -- "${G[@]}" --bins cand,cand --wrap "numactl --interleave=all"
batch base-aa-cand-2  -- "${G[@]}" --bins cand,cand
# Neighbours: SMT siblings of 4,5,6 busy (also keeps those cores out of C2), the rest of the CCX busy.
batch smtbusy-aa  spin 36,37,38 -- "${G[@]}" --bins cand,cand
batch smtbusy-ab  spin 36,37,38 -- "${G[@]}" --bins cand,$REF
batch ccxbusy-aa  spin 7,39     -- "${G[@]}" --bins cand,cand
# Placement: proxy and client on SMT siblings; across L3 and node; another node's CCX.
batch smtpair-aa  -- "${G[@]}" --bins cand,cand --cpus "4;36;5"
batch crossl3-aa  -- "${G[@]}" --bins cand,cand --cpus "4;8;12"
batch node1-aa    -- "${G[@]}" --bins cand,cand --cpus "12;13;14"
batch node1-ab    -- "${G[@]}" --bins cand,$REF --cpus "12;13;14"
# Threads: nbthread 2 inside one CPU, and with a CPU of its own for the second thread.
batch nbt2-1cpu-aa -- "${G[@]}" --bins cand,cand --nbthread 2 --cpus "4;5;6"
batch nbt2-2cpu-aa -- "${G[@]}" --bins cand,cand --nbthread 2 --cpus "4,7;5;6"
batch base-aa-cand-3 -- "${G[@]}" --bins cand,cand
log "T452 night run done"
