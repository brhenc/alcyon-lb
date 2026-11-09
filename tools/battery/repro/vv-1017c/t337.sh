#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# T337 occurrence semantics: t337.sh BIN PORT (uses PORT and PORT+1); compare Alcyon vs HAProxy output.
# t337.sh BIN PORT: print fetch results for a set of requests
B=$1; P=$2; S=$(cd "$(dirname "$0")" && pwd); D=$(mktemp -d /tmp/vv-t337-XXXX)
sed "s/@P@/$P/; s/@BE@/$((P+1))/g" $S/t337.cfg > $D/t337-$P.cfg
$B -f $D/t337-$P.cfg > $D/t337-$P.log 2>&1 & X=$!; sleep 0.8
r(){ curl -s --max-time 2 "$@"; }
echo "1 $(r -H 'X: a, b' -H 'X: c' 'http://127.0.0.1:'$P'/?a=1&a=2')"
echo "2 $(r -H 'X: a, b' 'http://127.0.0.1:'$P'/?b=1;a=5&A=7')"
echo "3 $(r -H 'Cookie: a=1; b=2; a=3' -H 'Cookie: a=4' 'http://127.0.0.1:'$P'/x;a=9?a=')"
echo "4 $(r -H 'Cookie: a="q;w"; a=2' 'http://127.0.0.1:'$P'/?A=up&a=low')"
echo "5 acl X:a,b -> $(r -H 'X: a, b' http://127.0.0.1:$P/acl)"
echo "6 acl X:b,c X:d -> $(r -H 'X: b, c' -H 'X: d' http://127.0.0.1:$P/acl)"
echo "7 acl Cookie a=0;a=1 -> $(r -H 'Cookie: a=0; a=1' http://127.0.0.1:$P/acl)"
echo "8 acl ?a=1&a=2 -> $(r 'http://127.0.0.1:'$P'/acl?a=1&a=2')"
echo "9 resp $(r -sD - -o /dev/null http://127.0.0.1:$P/resp | grep -i '^y:' | tr -d '\r')"
kill $X; wait $X 2>/dev/null
grep -iE 'alert|panic' $D/t337-$P.log | head -3
