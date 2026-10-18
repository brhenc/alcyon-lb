#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# VV-17: `stats auth` in defaults is dropped. Config valid on HAProxy (stats + auth in defaults,
# `stats admin if TRUE` in the frontend): HAProxy 401 on GET and on the admin POST; an Ibex that
# drops the auth serves the page and lets an unauthenticated POST put s1 into MAINT.
#   vv17.sh BIN [PORT=19970]     prints: GET no creds, POST maint no creds, s1 status after
set -u
BIN=$1; P=${2:-19970}; D=$(mktemp -d /tmp/vv17-XXXX)
cat > "$D/c.cfg" <<EOC
global
    nbthread 1
defaults
    mode http
    timeout client 2s
    timeout server 2s
    timeout connect 1s
    stats enable
    stats uri /st
    stats auth u:p
frontend f
    bind 127.0.0.1:$P
    stats admin if TRUE
    default_backend app
backend app
    server s1 127.0.0.1:$((P + 1))
EOC
"$BIN" -f "$D/c.cfg" > "$D/log" 2>&1 & X=$!
sleep 0.6
g=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/st")
p=$(curl -s -o /dev/null -w '%{http_code}' -d 's=s1&action=maint&b=app' "http://127.0.0.1:$P/st")
s=$(curl -s -u u:p "http://127.0.0.1:$P/st;csv" | grep '^app,s1' | cut -d, -f18)
echo "GET /st no creds $g; POST action=maint no creds $p; s1 status ${s:-?}"
kill "$X"; wait "$X" 2>/dev/null
exit 0
