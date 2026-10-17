# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# cases for cfgcmp.py (python3 cfgcmp.py IBEX t341.py)
CASES = [
 # converter args in log-format family
 ("lf-conv-badarg",   'log-format "%[src,ipmask(abc)]"'),
 ("uid-conv-badarg",  'unique-id-format "%[src,ipmask(abc)]"'),
 ("elf-conv-badarg",  'error-log-format "%[src,ipmask(abc)]"'),
 ("lfsd-conv-badarg", 'log-format-sd "%[src,ipmask(abc)]"'),
 ("lf-conv-ok",       'log-format "%[src,ipmask(24)]"'),
 # strcmp / secure_memcmp need a variable
 ("strcmp-literal",   'http-request set-header X %[str(a),strcmp(abc)]'),
 ("strcmp-var",       'http-request set-header X %[str(a),strcmp(txn.x)]'),
 ("secmemcmp-literal",'http-request set-header X %[str(a),secure_memcmp(abc)]'),
 ("secmemcmp-var",    'http-request set-header X %[str(a),secure_memcmp(txn.x)]'),
 # extra args
 ("srv_conn-extra",   'http-request set-header X %[srv_conn(b/s,x)]'),
 ("srv_conn-ok",      'http-request set-header X %[srv_conn(b/s)]'),
 ("nbsrv-extra",      'http-request set-header X %[nbsrv(b,x)]'),
 ("be_conn-extra",    'http-request set-header X %[be_conn(b,x)]'),
 ("fe_conn-extra",    'http-request set-header X %[fe_conn(f,x)]'),
 ("table_cnt-extra",  'http-request set-header X %[table_cnt(t,x)]'),
 ("table_cnt-ok",     'http-request set-header X %[table_cnt(t)]'),
 ("srv_id-arg",       'log-format "%[srv_id(x)]"'),
 ("srv_name-arg",     'log-format "%[srv_name(x)]"'),
 ("srv_id-noarg-lf",  'log-format "%[srv_id]"'),
 # server / server-connection fetches where unavailable
 ("srv_id-in-req",    'http-request set-header X %[srv_id]'),
 ("srv_name-in-req",  'http-request set-header X %[srv_name]'),
 ("bc_src-in-req",    'http-request set-header X %[bc_src]'),
 ("srv_id-in-uid",    'unique-id-format "%[srv_id]"'),
 ("bc_src-in-uid",    'unique-id-format "%[bc_src]"'),
 ("srv_id-in-resp",   'http-response set-header X %[srv_id]'),
 # body without content-type
 ("return-str-noct",  'http-request return status 200 string hello'),
 ("return-str-ct",    'http-request return status 200 content-type text/plain string hello'),
 ("return-lf-noct",   'http-request return status 200 lf-string hello'),
 ("return-noBody",    'http-request return status 204'),
 ("deny-str-noct",    'http-request deny deny_status 403 string nope'),
 ("tarpit-str-noct",  'http-request tarpit deny_status 403 string nope'),
 ("deny-str-ct",      'http-request deny deny_status 403 content-type text/plain string nope'),
 ("httperror-noct",   '', 'http-error status 503 string down'),
 ("httperror-ct",     '', 'http-error status 503 content-type text/plain string down'),
 # ip.fp and input-type chain
 ("ipfp-badarg",      'http-request set-header X %[ip.fp(x)]'),
 ("ipfp-ok",          'http-request set-header X %[ip.fp(1)]'),
 ("ipfp-toomany",     'http-request set-header X %[ip.fp(1,2)]'),
 ("bool-on-str",      'http-request set-header X %[str(a),bool]'),
 ("bool-on-int",      'http-request set-header X %[int(1),bool]'),
 ("ipmask-on-str",    'http-request set-header X %[str(a),ipmask(24)]'),
 ("hex2i-on-int",     'http-request set-header X %[int(1),hex2i]'),
 # commas
 ("commas-run",       'http-request set-header X %[str(a),,,lower]'),
 ("comma-trailing-hr",'http-request set-header X %[str(a),]'),
 ("comma-trailing-lf",'log-format "%[str(a),]"'),
 ("comma-leading",    'http-request set-header X %[,str(a)]'),
 # blanks in args (make_arg_list keeps them)
 ("blank-arg-int",    'http-request set-header X %[int( 1)]'),
 ("blank-arg-ipmask", 'http-request set-header X %[src,ipmask( 24)]'),
 ("blank-arg-str",    'http-request set-header X %[str( a b )]'),
]
