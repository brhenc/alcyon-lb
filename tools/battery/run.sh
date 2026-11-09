#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# Hostile-client battery driver, run from a checkout. Usage:
#   tools/battery/run.sh ALCYON_BINARY [SECONDS=60] [scenario ...]
# BATTERY_ENV="CAPTURE=1" passes environment to the remote battery.py (CAPTURE=1 adds the httplog
# sink and the stats-socket CurrConns poll, keys cap_* in the json).
# Copies the battery and the binary to devtest7, runs Alcyon and HAProxy one after the
# other (same config), prints the table, leaves results in tools/battery/results/.
set -eu
ALCYON=$1; SECS=${2:-60}; shift 2 || true
HOST=${BATTERY_HOST:-root@192.168.122.139}
# VM ssh without the host's YubiKey agent (user rule 2026-10-12): the VMs accept ~/.ssh/id_ed25519.
SSH="ssh -o IdentityAgent=none -i $HOME/.ssh/id_ed25519"; SCP="scp -o IdentityAgent=none -i $HOME/.ssh/id_ed25519"
REMOTE=/root/battery
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/results/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
$SSH "$HOST" "rm -rf $REMOTE/out; mkdir -p $REMOTE"
$SCP -q "$HERE/battery.py" "$HERE/clients.py" "$HOST:$REMOTE/"
$SCP -q "$ALCYON" "$HOST:$REMOTE/alcyon"
for P in alcyon haproxy; do
  BIN=$REMOTE/alcyon; [ $P = haproxy ] && BIN=${HAPROXY_REMOTE:-${ALCYON_LAB_DIR:-/root/alcyon-test}/haproxy}
  $SSH "$HOST" "${BATTERY_ENV:-} python3 $REMOTE/battery.py run $BIN $P $REMOTE/out $SECS $*" | tee -a "$OUT/raw.jsonl"
done
$SCP -q "$HOST:$REMOTE/out/*.json" "$OUT/"
python3 "$HERE/battery.py" table "$OUT" | tee "$OUT/table.md"
