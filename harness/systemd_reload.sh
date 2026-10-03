#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# End-to-end hitless reload under a real systemd, using admin/systemd/ibex.service.
#
# Starts Ibex as a user unit, keeps opening fresh connections against it the whole time,
# and in the middle: reloads it several times, reloads it onto a broken configuration,
# then stops it. Reports every request that did not get a 200, and what systemd believed
# at each step. A reload that drops anything, or that systemd reads as the service
# stopping, shows up here.
#
# Needs a systemd user manager (`systemctl --user is-system-running`). Takes ~15s.
#
#   harness/systemd_reload.sh [path/to/ibex]
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

BIN=$(realpath "${1:-target/debug/ibex}")
TMP=$(mktemp -d /tmp/ibex-sd.XXXXXX)
UNIT="ibex-e2e-$$"
UNITFILE="$HOME/.config/systemd/user/$UNIT.service"
port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
FE=$(port); BE=$(port)
FAIL=0
note_fail() { echo "!! FAIL: $*"; FAIL=1; }
show() { systemctl --user show "$UNIT" -p "$1" --value; }

cleanup() {
  systemctl --user stop "$UNIT" >/dev/null 2>&1
  rm -f "$UNITFILE"; systemctl --user daemon-reload
  [ -n "${LOADPID:-}" ] && kill "$LOADPID" 2>/dev/null
  [ -n "${BEPID:-}" ] && kill "$BEPID" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

python3 -m http.server "$BE" --bind 127.0.0.1 -d "$TMP" >/dev/null 2>&1 &
BEPID=$!
mkdir -p "$TMP/conf.d" "$(dirname "$UNITFILE")"
good_cfg() {
  cat > "$TMP/ibex.cfg" <<EOF
defaults
  mode http
  timeout connect 2s
  timeout client 10s
  timeout server 10s
frontend fe
  bind 127.0.0.1:$FE
  default_backend be
backend be
  server s1 127.0.0.1:$BE
EOF
}
good_cfg

sed -e "s|/usr/local/sbin/ibex|$BIN|g" \
    -e "s|CONFIG=/etc/ibex/ibex.cfg|CONFIG=$TMP/ibex.cfg|" \
    -e "s|PIDFILE=/run/ibex.pid|PIDFILE=$TMP/ibex.pid|" \
    -e "s|CFGDIR=/etc/ibex/conf.d|CFGDIR=$TMP/conf.d|" \
    -e "/^EnvironmentFile=/d" \
    admin/systemd/ibex.service > "$UNITFILE"
systemctl --user daemon-reload

echo "=== start ==="
systemctl --user start "$UNIT" || note_fail "start"
A=$(show MainPID)
echo "state=$(show ActiveState)/$(show SubState) MainPID=$A status='$(show StatusText)'"
[ "$(show SubState)" = running ] || note_fail "not running after start"

# Fresh connection per request for the whole run: every one of them must get a 200.
cat > "$TMP/load.py" <<'EOF'
import socket, sys, time
port, stop_file, out = int(sys.argv[1]), sys.argv[2], sys.argv[3]
ok = bad = 0; errors = {}
import os
while not os.path.exists(stop_file):
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=3)
        c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        d = b""
        while True:
            x = c.recv(65536)
            if not x: break
            d += x
        c.close()
        if d.startswith(b"HTTP/1.1 200") or d.startswith(b"HTTP/1.0 200"): ok += 1
        else:
            bad += 1; k = repr(d[:40]); errors[k] = errors.get(k, 0) + 1
    except Exception as e:
        bad += 1; k = type(e).__name__ + ": " + str(e)[:40]; errors[k] = errors.get(k, 0) + 1
open(out, "w").write(f"{ok} {bad} {errors}\n")
EOF
python3 "$TMP/load.py" "$FE" "$TMP/stop" "$TMP/load.out" &
LOADPID=$!
sleep 1

prev=$A
for i in 1 2 3; do
  echo "=== reload $i ==="
  systemctl --user reload "$UNIT" || note_fail "reload $i returned non-zero"
  sleep 1
  now=$(show MainPID)
  echo "state=$(show ActiveState)/$(show SubState) MainPID=$now status='$(show StatusText)'"
  [ "$(show SubState)" = running ] || note_fail "not running after reload $i"
  [ "$now" != "$prev" ] || note_fail "MainPID did not change on reload $i"
  kill -0 "$prev" 2>/dev/null && note_fail "old process $prev still alive after reload $i"
  prev=$now
done

echo "=== reload onto a broken configuration ==="
cp "$TMP/ibex.cfg" "$TMP/ibex.cfg.good"
printf 'frontend fe\n  this-is-not-a-keyword\n' > "$TMP/ibex.cfg"
if systemctl --user reload "$UNIT" 2>/dev/null; then
  note_fail "systemctl reload succeeded on a broken configuration"
else
  echo "systemctl reload refused it (ExecReload's -c check), as it should"
fi
# And the path that skips ExecReload's check: SIGUSR2 straight to the process.
kill -USR2 "$prev"; sleep 1.5
echo "state=$(show ActiveState)/$(show SubState) MainPID=$(show MainPID) status='$(show StatusText)'"
[ "$(show MainPID)" = "$prev" ] || note_fail "MainPID changed on a failed reload"
[ "$(show SubState)" = running ] || note_fail "not running after a failed reload"
case "$(show StatusText)" in *"Reload failed"*) ;; *) note_fail "systemd was not told the reload failed" ;; esac
cp "$TMP/ibex.cfg.good" "$TMP/ibex.cfg"

echo "=== reload after the failure ==="
systemctl --user reload "$UNIT" || note_fail "reload after failure"
sleep 1
echo "state=$(show ActiveState)/$(show SubState) MainPID=$(show MainPID) status='$(show StatusText)'"
[ "$(show MainPID)" != "$prev" ] || note_fail "MainPID did not change on the recovering reload"

touch "$TMP/stop"; wait "$LOADPID"; LOADPID=
read -r OK BAD ERR < "$TMP/load.out"
echo "=== load across all of the above: $OK ok, $BAD failed ${ERR} ==="
[ "$BAD" = 0 ] || note_fail "$BAD requests failed"

echo "=== stop ==="
systemctl --user stop "$UNIT"
echo "state=$(show ActiveState)/$(show SubState)"
[ "$(show ActiveState)" = inactive ] || note_fail "not inactive after stop"

echo
[ "$FAIL" = 0 ] && echo "systemd_reload: PASS" || echo "systemd_reload: FAIL"
exit "$FAIL"
