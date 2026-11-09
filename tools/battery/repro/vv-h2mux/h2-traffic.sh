#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# h2 multiplexing traffic for the soak: per proxy one large-body backend (bigapp.js on
# <base>05) and one h2mux.py driver against fe_h2 (<base>44). Stops both at the end.
#   h2-traffic.sh DURATION_SECONDS LOGDIR
set -u
HERE=$(cd "$(dirname "$0")" && pwd); DUR=$1; D=$2; pids=()
for side in alcyon:31 haproxy:32; do
  name=${side%%:*}; base=${side##*:}
  node "$HERE/bigapp.js" "${base}05" "$D/bigapp-$name.log" >> "$D/bigapp-$name.err" 2>&1 & pids+=($!)
done
sleep 1
for side in alcyon:31 haproxy:32; do
  name=${side%%:*}; base=${side##*:}
  python3 "$HERE/h2mux.py" "$DUR" "$D" "$name" "${base}44" >> "$D/h2mux-$name.err" 2>&1 & pids+=($!)
done
sleep "$DUR"; sleep 20
kill "${pids[@]}" 2>/dev/null; wait
