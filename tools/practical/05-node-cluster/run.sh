#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Practical topology 05:  3 x node.js behind the proxy, roundrobin + HTTP health checks
#
#   ./run.sh              run against Alcyon
#   ./run.sh --haproxy    run against HAProxy (the oracle)
#
# Phases: kill one node under load / start it again / rolling restart of all three /
# cookie persistence (SRV insert indirect nocache). Everything is started by this
# script and killed by PID at the end. Override any variable from the environment.

# ---- settings you may want to change ---------------------------------------
ALCYON_BIN=${ALCYON_BIN:-${ALCYON_TARGETS:-${XDG_CACHE_HOME:-$HOME/.cache}/alcyon/targets}/t181/release/alcyon}
HAPROXY_BIN=${HAPROXY_BIN:-${ALCYON_REFERENCE:?set ALCYON_REFERENCE (README, "Running the oracle tests") or HAPROXY_BIN}/haproxy/haproxy}
PROXY_PORT=${PROXY_PORT:-23080}     # plain (round-robin) frontend
STICKY_PORT=${STICKY_PORT:-23081}   # cookie persistence frontend
APP_PORT1=${APP_PORT1:-23001}       # the three node.js instances
APP_PORT2=${APP_PORT2:-23002}
APP_PORT3=${APP_PORT3:-23003}
CLIENTS=${CLIENTS:-8}               # concurrent keep-alive load clients
INTER_MS=500                        # must match proxy.cfg: inter 500ms fall 2 rise 2
FALL=2
RISE=2
SLACK_MS=${SLACK_MS:-500}           # allowed over inter*fall (one check may be in flight)
# -----------------------------------------------------------------------------

HERE=$(cd "$(dirname "$0")" && pwd)
PROXY=alcyon
[ "$1" = "--haproxy" ] && PROXY=haproxy
if [ "$PROXY" = alcyon ]; then PROXY_BIN=$ALCYON_BIN; else PROXY_BIN=$HAPROXY_BIN; fi

WORK=$(mktemp -d /tmp/practical05-XXXXXX)
SOCK=$WORK/stats.sock
PIDS=""
RESULTS=()
FAILS=0
declare -A APID     # node name -> pid
DOWN_MAX=$((INTER_MS * FALL + SLACK_MS))
UP_MAX=$((INTER_MS * RISE + SLACK_MS))

cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

record() {   # record NAME OK(0/1) DETAIL
    if [ "$2" = 0 ]; then RESULTS+=("PASS  $1  $3"); else RESULTS+=("FAIL  $1  $3"); FAILS=$((FAILS+1)); fi
}
now_ms() { date +%s%3N; }
wait_port() {   # wait_port PORT : up to 10 s
    for _ in $(seq 100); do
        (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}
port_of() { eval echo \$APP_PORT"${1#n}"; }
start_node() {   # start_node n1
    node "$HERE/app.js" "$(port_of "$1")" "$1" >> "$WORK/app.log" 2>&1 &
    APID[$1]=$!; PIDS="$PIDS $!"
    wait_port "$(port_of "$1")" || { echo "$1 did not start"; exit 2; }
}
kill_node() { kill "${APID[$1]}" 2>/dev/null; wait "${APID[$1]}" 2>/dev/null; }
stat_of() {   # stat_of BACKEND SERVER -> status column of "show stat"
    echo "show stat" | socat - "UNIX-CONNECT:$SOCK" 2>/dev/null \
        | awk -F, -v b="$1" -v s="$2" '$1==b && $2==s {print $18}'
}
wait_status() {   # wait_status BACKEND SERVER UP|DOWN -> echoes ms waited, rc 1 on 15 s timeout
    local t0 st; t0=$(now_ms)
    while [ $(( $(now_ms) - t0 )) -lt 15000 ]; do
        st=$(stat_of "$1" "$2")
        [ "${st%% *}" = "$3" ] && [ "$st" = "$3" ] && { echo $(( $(now_ms) - t0 )); return 0; }
        sleep 0.05
    done
    echo 15000; return 1
}
# window FILE FROM_MS TO_MS -> "N requests, E errors" (non-2xx counted as errors)
errs() { awk -v a="$2" -v b="$3" '$1>=a && $1<=b && $2!=200 {n++} END{print n+0}' "$1"; }
reqs() { awk -v a="$2" -v b="$3" '$1>=a && $1<=b {n++} END{print n+0}' "$1"; }
last_err() { awk -v a="$2" '$1>=a && $2!=200 {t=$1} END{print t+0}' "$1"; }

# ---- start the nodes and the proxy -------------------------------------------
for n in n1 n2 n3; do start_node $n; done
sed -e "s/@PROXY_PORT@/$PROXY_PORT/" -e "s/@STICKY_PORT@/$STICKY_PORT/" \
    -e "s/@APP_PORT1@/$APP_PORT1/" -e "s/@APP_PORT2@/$APP_PORT2/" -e "s/@APP_PORT3@/$APP_PORT3/" \
    -e "s#@SOCK@#$SOCK#" "$HERE/proxy.cfg" > "$WORK/proxy.cfg"
"$PROXY_BIN" -c -f "$WORK/proxy.cfg" > "$WORK/check.log" 2>&1 \
    || { echo "$PROXY config check failed:"; cat "$WORK/check.log"; exit 2; }
"$PROXY_BIN" -f "$WORK/proxy.cfg" > "$WORK/proxy.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$PROXY_PORT" || { echo "$PROXY did not start"; cat "$WORK/proxy.log"; exit 2; }
echo "== topology 05 via $PROXY ($PROXY_BIN), work dir $WORK"
for b in be be_sticky; do for n in n1 n2 n3; do
    wait_status $b $n UP > /dev/null || { echo "$b/$n never UP"; exit 2; }
done; done

# background status poller: "epoch_ms be/n1 be/n2 be/n3" every 100 ms, for the timeline
( while :; do
    echo "show stat" | socat - "UNIX-CONNECT:$SOCK" 2>/dev/null | awk -F, -v t="$(now_ms)" \
        '$1=="be" && $2 ~ /^n[123]$/ {s=s "|" $2 "=" $18} END{print t s}' >> "$WORK/status.log"
    sleep 0.1
  done ) &
PIDS="$PIDS $!"

# ---- phase 1: baseline under load --------------------------------------------
LOG=$WORK/load.log
node "$HERE/load.js" "http://127.0.0.1:$PROXY_PORT/" "$CLIENTS" "$LOG" &
LOADPID=$!; PIDS="$PIDS $LOADPID"
sleep 2
t1=$(now_ms)
n=$(reqs "$LOG" 0 "$t1"); e=$(errs "$LOG" 0 "$t1")
srvs=$(awk '$2==200 {print $3}' "$LOG" | sort -u | tr '\n' ' ')
[ "$e" = 0 ] && [ "$srvs" = "n1 n2 n3 " ] && record baseline 0 "$n requests, $e errors, servers: $srvs" \
    || record baseline 1 "$n requests, $e errors, servers: $srvs (want n1 n2 n3, 0 errors)"

# ---- phase 2: kill n2 under load ---------------------------------------------
tk=$(now_ms); kill_node n2
down_ms=$(wait_status be n2 DOWN); rc=$?
td=$(( tk + down_ms ))
sleep 2
t2=$(now_ms)
last=$(last_err "$LOG" "$tk"); [ "$last" = 0 ] && lerr=none || lerr="$((last - tk)) ms after kill"
late=$(errs "$LOG" $((tk + DOWN_MAX)) "$t2")
ne=$(errs "$LOG" "$tk" "$t2")
[ $rc = 0 ] && [ "$down_ms" -le "$DOWN_MAX" ] && record kill-detect 0 "n2 DOWN in ${down_ms} ms (limit $DOWN_MAX)" \
    || record kill-detect 1 "n2 DOWN after ${down_ms} ms (limit $DOWN_MAX, rc $rc)"
[ "$late" = 0 ] && record kill-no-errors-after-detect 0 "$ne errors in the window, last: $lerr, 0 after ${DOWN_MAX} ms" \
    || record kill-no-errors-after-detect 1 "$late errors after ${DOWN_MAX} ms ($ne in window, last $lerr)"
s=$(awk -v a="$((tk + DOWN_MAX))" '$1>=a && $2==200 {print $3}' "$LOG" | sort -u | tr '\n' ' ')
[ "$s" = "n1 n3 " ] && record kill-traffic-moved 0 "after detection only: $s" \
    || record kill-traffic-moved 1 "after detection servers: '$s' (want n1 n3)"

# ---- phase 3: start n2 again ---------------------------------------------------
tu=$(now_ms); start_node n2
up_ms=$(wait_status be n2 UP); rc=$?
tU=$(( tu + up_ms ))
sleep 2
t3=$(now_ms)
first=$(awk -v a="$tu" '$1>=a && $2==200 && $3=="n2" {print $1; exit}' "$LOG")
[ -z "$first" ] && first=0
[ $rc = 0 ] && [ "$up_ms" -le "$UP_MAX" ] && record rise-detect 0 "n2 UP ${up_ms} ms after start (limit $UP_MAX)" \
    || record rise-detect 1 "n2 UP after ${up_ms} ms (limit $UP_MAX, rc $rc)"
[ "$first" != 0 ] && [ "$first" -ge $((tU - 150)) ] && record rise-no-early-traffic 0 "first n2 response $((first - tu)) ms after start, UP seen at $up_ms ms" \
    || record rise-no-early-traffic 1 "first n2 response at $((first - tu)) ms after start (UP seen at $up_ms ms)"
e=$(errs "$LOG" "$tu" "$t3")
[ "$e" = 0 ] && record rise-no-errors 0 "0 errors while n2 came back" || record rise-no-errors 1 "$e errors while n2 came back"

# ---- phase 4: rolling restart n1, n2, n3 ---------------------------------------
r0=$(now_ms); detail=""; bad=0
for n in n1 n2 n3; do
    tk=$(now_ms); kill_node $n
    d=$(wait_status be $n DOWN) || bad=1
    late=$(errs "$LOG" $((tk + DOWN_MAX)) $((tk + DOWN_MAX + 1000)))
    sleep 1
    tu=$(now_ms); start_node $n
    u=$(wait_status be $n UP) || bad=1
    sleep 1
    [ "$d" -gt "$DOWN_MAX" ] || [ "$u" -gt "$UP_MAX" ] || [ "$late" != 0 ] && bad=1
    detail="$detail $n:down=${d}ms,up=${u}ms,late-errs=$late"
done
r1=$(now_ms)
tot=$(reqs "$LOG" "$r0" "$r1"); ne=$(errs "$LOG" "$r0" "$r1")
[ "$bad" = 0 ] && record rolling 0 "$detail" || record rolling 1 "$detail"
record rolling-info 0 "$tot requests, $ne non-200 in the whole rolling window"
s=$(awk -v a="$r1" '$1>=a-1000 && $1<=a && $2==200 {print $3}' "$LOG" | sort -u | tr '\n' ' ')
[ "$s" = "n1 n2 n3 " ] && record rolling-final 0 "all three serving again" || record rolling-final 1 "servers in last second: '$s'"
kill "$LOADPID" 2>/dev/null; sleep 0.3; [ -n "$KEEP" ] && cp "$LOG" "$KEEP"

# ---- phase 5: cookie persistence -------------------------------------------------
# 9 sessions (cookie jars); round-robin spreads them over the servers, the exact split
# does not matter. Each session must stay on its first server while that server is up.
SB=http://127.0.0.1:$STICKY_PORT/
SESS="1 2 3 4 5 6 7 8 9"
srv_of() { curl -s -b "$WORK/$1.jar" -c "$WORK/$1.jar" "$SB" | tr -d '\n'; }
for s in $SESS; do : > "$WORK/$s.jar"; srv_of $s > "$WORK/$s.first"; done
split=$(for s in $SESS; do cat "$WORK/$s.first"; echo; done | sort | uniq -c | tr -s ' ' | tr '\n' ',')
stay=1
for i in 1 2 3 4 5; do for s in $SESS; do
    [ "$(srv_of $s)" = "$(cat "$WORK/$s.first")" ] || stay=0
done; done
[ "$stay" = 1 ] && record cookie-sticks 0 "9 sessions over servers [$split], 5 more requests each, none moved" \
    || record cookie-sticks 1 "a session changed server while all were up (split [$split])"
hdr=$(curl -s -D - -o /dev/null "$SB" | tr -d '\r' | grep -i '^\(set-cookie\|cache-control\)' | tr '\n' '|')
echo "$hdr" | grep -qi 'set-cookie: SRV=n[123]' \
    && record cookie-header 0 "$hdr" || record cookie-header 1 "$hdr (want Set-Cookie SRV=nX)"
hdr2=$(curl -s -D - -o /dev/null -b "SRV=n1" "$SB" | tr -d '\r' | grep -ic '^set-cookie')
[ "$hdr2" = 0 ] && record cookie-not-reset 0 "request carrying SRV=n1 gets no Set-Cookie" || record cookie-not-reset 1 "got $hdr2 Set-Cookie on a request that carried a valid cookie"
# kill the server of session 1: its sessions must move (once, then stay), the others stay
X=$(cat "$WORK/1.first"); kill_node "$X"; wait_status be_sticky "$X" DOWN > /dev/null
bad=""; moved=0
for s in $SESS; do
    f=$(cat "$WORK/$s.first"); a=$(srv_of $s); b=$(srv_of $s); c=$(srv_of $s)
    ck=$(grep -o "SRV[[:space:]]*n[0-9]" "$WORK/$s.jar" | awk '{print $2}')
    if [ "$f" = "$X" ]; then
        moved=$((moved+1))
        { [ "$a" != "$X" ] && [ -n "$a" ] && [ "$a" = "$b" ] && [ "$b" = "$c" ] && [ "$ck" = "$a" ]; } || bad="$bad s$s:$f->$a,$b,$c,cookie=$ck"
        echo "$a" > "$WORK/$s.now"
    else
        { [ "$a" = "$f" ] && [ "$b" = "$f" ] && [ "$c" = "$f" ]; } || bad="$bad s$s:$f->$a,$b,$c"
        echo "$f" > "$WORK/$s.now"
    fi
done
[ -z "$bad" ] && record cookie-moves-when-down 0 "$X down: its $moved sessions moved once and stayed, cookie updated; others unmoved" \
    || record cookie-moves-when-down 1 "after $X down:$bad"
# server comes back: moved sessions stay where they are, new sessions use it again
start_node "$X"; wait_status be_sticky "$X" UP > /dev/null
sleep 0.2
bad=""
for s in $SESS; do [ "$(srv_of $s)" = "$(cat "$WORK/$s.now")" ] || bad="$bad s$s"; done
seen=""
for i in $(seq 12); do : > "$WORK/N$i.jar"; seen="$seen $(srv_of N$i)"; done
[ -z "$bad" ] && echo "$seen" | grep -q "$X" && record cookie-after-return 0 "no session moved back; new sessions got:$seen" \
    || record cookie-after-return 1 "moved:$bad; new sessions got:$seen (want $X among them)"

# ---- status timeline (show stat, be/n1..n3, transitions only) ---------------------
echo
echo "STATUS TIMELINE ($PROXY, ms from first sample)"
awk -F'|' 'NR==1 {t0=$1} { s=$2 "  " $3 "  " $4; if (s != prev) { printf "%6d  %s\n", $1 - t0, s; prev = s } }' "$WORK/status.log"

# ---- results ----------------------------------------------------------------------
echo
echo "RESULTS ($PROXY)"
printf '%s\n' "${RESULTS[@]}"
echo "$FAILS failed"
rm -rf "$WORK"
[ "$FAILS" = 0 ]
