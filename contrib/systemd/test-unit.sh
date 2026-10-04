#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# Checks contrib/systemd/ibex.service: it carries the directives a Type=notify,
# SIGUSR2-reload service needs, and passes `systemd-analyze verify`.
# The verify step is skipped (not failed) when systemd-analyze is not installed.
set -u
here=$(cd "$(dirname "$0")" && pwd)
unit=$here/ibex.service
fail=0
for want in 'Type=notify' ' -Ws ' 'ExecReload=.*-c' 'ExecReload=/bin/kill -USR2 \$MAINPID' \
            'KillMode=mixed'; do
    grep -Eq -- "$want" "$unit" || { echo "FAIL: ibex.service lacks /$want/"; fail=1; }
done
# SIGTERM exits 0 under -Ws, as HAProxy's master does; the unit must not paper over a status.
if grep -q '^SuccessExitStatus' "$unit"; then echo "FAIL: ibex.service carries SuccessExitStatus"; fail=1; fi
if command -v systemd-analyze >/dev/null 2>&1; then
    # verify wants ExecStart to exist: point a copy of the unit at a stub binary.
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    stub=$tmp/ibex
    printf '#!/bin/sh\n' > "$stub"
    chmod +x "$stub"
    sed "s#/usr/local/sbin/ibex#$stub#g" "$unit" > "$tmp/ibex.service"
    if out=$(systemd-analyze verify "$tmp/ibex.service" 2>&1); then
        echo "ok: systemd-analyze verify"
    else
        echo "FAIL: systemd-analyze verify:"
        echo "$out"
        fail=1
    fi
else
    echo "skip: systemd-analyze not installed"
fi
exit $fail
