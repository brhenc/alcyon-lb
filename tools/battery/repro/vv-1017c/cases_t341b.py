# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# cases for cfgcmp.py (python3 cfgcmp.py IBEX t341b.py)
CASES = [
 ("hr-ipmask-badarg",   'http-request set-header X %[src,ipmask(abc)]'),
 ("lf-ipmask-badarg",   'log-format "%[src,ipmask(abc)]"'),
 ("lf-ipmask-badarg-q", "log-format '%[src,ipmask(abc)]'"),
 ("lf-regsub-badre",    'log-format "%[str(a),regsub(a**,b)]"'),
 ("lf-bytes-badarg",    'log-format "%[str(a),bytes(x)]"'),
 ("lf-field-badarg",    'log-format "%[str(a),field(x,:)]"'),
 ("lf-word-noarg",      'log-format "%[str(a),word]"'),
 ("lf-unknown-conv",    'log-format "%[str(a),nosuchconv]"'),
 ("lf-strcmp-literal",  'log-format "%[str(a),strcmp(abc)]"'),
 ("lf-map-nofile",      'log-format "%[str(a),map(/nonexistent/x.map)]"'),
 ("uid-bytes-badarg",   'unique-id-format "%[str(a),bytes(x)]"'),
 ("hr-bytes-badarg",    'http-request set-header X %[str(a),bytes(x)]'),
 ("lf-fetch-badarg",    'log-format "%[int(x)]"'),
 ("hr-src-bool",        'http-request set-header X %[src,bool]'),
 ("hr-src-hex2i",       'http-request set-header X %[src,hex2i]'),
 ("hr-src-lower",       'http-request set-header X %[src,lower]'),
 ("hr-int-ipmask",      'http-request set-header X %[int(1),ipmask(24)]'),
 ("q-blank-int",        'http-request set-header X "%[int( 1)]"'),
 ("q-blank-int2",       'http-request set-header X "%[int(1 )]"'),
 ("q-blank-ipmask",     'http-request set-header X "%[src,ipmask( 24)]"'),
 ("q-blank-str",        'http-request set-header X "%[str( a b )]"'),
 ("q-blank-field",      'http-request set-header X "%[str(a:b),field(1, :)]"'),
 ("uq-blank-int",       'http-request set-header X %[int( 1)]'),
]
