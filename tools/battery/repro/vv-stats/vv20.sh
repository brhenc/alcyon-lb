#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# VV-20: a cross-site GET /st?b=app&s=s1&action=maint puts s1 into MAINT (Alcyon-only admin query API,
# no same-origin check). HAProxy has no GET admin action: s1 stays as it is.
# vv20.sh BIN [PORT]   prints the GET's status and s1's status from ;csv, per Origin/Referer variant.
B=$1; P=${2:-19970}; D=$(mktemp -d /tmp/vv-20.XXXXXX)
printf 'global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 2s\n    timeout server 2s\n    timeout connect 1s\nfrontend f\n    bind 127.0.0.1:%s\n    stats enable\n    stats uri /st\n    stats auth u:p\n    stats admin if TRUE\n    default_backend app\nbackend app\n    server s1 127.0.0.1:%s\n' $P $((P+1)) > $D/c.cfg
U="http://127.0.0.1:$P/st?b=app&s=s1&action=maint"
for v in "none" "Origin: http://evil.example" "Referer: http://evil.example/"; do
  taskset -c 48-49 $B -f $D/c.cfg > $D/log 2>&1 & X=$!
  for i in $(seq 50); do curl -s -o /dev/null http://127.0.0.1:$P/x && break; sleep 0.05; done
  H=(); [ "$v" != none ] && H=(-H "$v")
  st=$(curl -s -o /dev/null -w '%{http_code}' -u u:p "${H[@]}" "$U")
  s1=$(curl -s -u u:p "http://127.0.0.1:$P/st;csv" | awk -F, 'NR==1{for(i=1;i<=NF;i++)if($i=="status")c=i} $2=="s1"{print $c}')
  echo "GET ?action=maint, $v: $st; s1 $s1"
  kill $X; wait $X 2>/dev/null
done
exit 0
