#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# sample.sh SECS: every 5 s, the proxy on :19960's fds, backend sockets by state, client conns
end=$((SECONDS+$1))
while [ $SECONDS -lt $end ]; do
  pid=$(ss -ltnpH 'sport = :19960' | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
  if [ -n "$pid" ]; then
    f=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
    syn=$(ss -tnH state syn-sent '( dport = :8891 )' | wc -l)
    est=$(ss -tnH state established '( dport = :8891 )' | wc -l)
    cli=$(ss -tnH state established '( sport = :19960 )' | wc -l)
    tw=$(ss -tanH '( dport = :8891 )' | awk '{print $1}' | sort | uniq -c | tr '\n' ' ')
    echo "$(date +%T) pid=$pid fds=$f be-synsent=$syn be-est=$est clients=$cli be-states: $tw"
  fi
  sleep 5
done
