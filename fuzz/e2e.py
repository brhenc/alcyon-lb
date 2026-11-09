# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""End-to-end check of the differential harness's findings.

usage: e2e.py <dir-of-.bin-inputs> [alcyon-binary]

Starts the reference HAProxy and a real Alcyon (default $CARGO_TARGET_DIR/release/alcyon, build with
`cargo build --release -p alcyon-rt --bin alcyon`) with the same config, each in front of its own
recording backend, sends every input over a raw socket (no half-close: a client FIN makes both
proxies answer 400), and prints SAME/DIFF on the status lines plus the bytes the backend got.
The harness itself compares parsers, not proxies; confirm a finding here before filing it.
"""
import os
import socket,threading,subprocess,sys,time,glob,re
HA=os.path.join(os.environ['ALCYON_REFERENCE'],'haproxy/haproxy')  # T630: KeyError names the variable
IB=sys.argv[2] if len(sys.argv)>2 else os.path.join(os.environ.get('CARGO_TARGET_DIR','target'),'release','alcyon')
TMP=__import__('tempfile').mkdtemp(prefix='alcyon-fuzz-e2e-')
def free():
    s=socket.socket();s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p
class Backend:
    def __init__(s):
        s.port=free();s.log=[];s.l=socket.socket();s.l.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.l.bind(('127.0.0.1',s.port));s.l.listen(50);threading.Thread(target=s.run,daemon=True).start()
    def run(s):
        while True:
            c,_=s.l.accept();threading.Thread(target=s.h,args=(c,),daemon=True).start()
    def h(s,c):
        data=b'';c.settimeout(0.4);sent=False
        try:
            while True:
                d=c.recv(65536)
                if not d:break
                data+=d
                if not sent and (b'\r\n\r\n' in data or b'\n\n' in data):
                    c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');sent=True;c.settimeout(0.15)
        except Exception:pass
        s.log.append(data);c.close()
def cfg(fe,be):
    return f"""global
  tune.bufsize 32768
defaults
  mode http
  timeout connect 500ms
  timeout client 1000ms
  timeout server 1000ms
  timeout http-request 1000ms
frontend fe
  bind 127.0.0.1:{fe}
  default_backend be
backend be
  server s1 127.0.0.1:{be}
"""
def start(binp,name):
    fe=free();be=Backend()
    f=TMP+f'/{name}.cfg';open(f,'w').write(cfg(fe,be.port))
    p=subprocess.Popen([binp,'-f',f],stdout=open(TMP+f'/{name}.log','w'),stderr=subprocess.STDOUT)
    for _ in range(100):
        try:socket.create_connection(('127.0.0.1',fe),0.2).close();break
        except Exception:time.sleep(0.1)
    return p,fe,be
def send(fe,be,raw):
    n=len(be.log)
    c=socket.create_connection(('127.0.0.1',fe));c.settimeout(1.5);c.sendall(raw)
    try:pass
    except Exception:pass
    resp=b''
    try:
        while True:
            d=c.recv(65536)
            if not d:break
            resp+=d
    except Exception:pass
    c.close();time.sleep(1.0)
    return resp,b'|'.join(be.log[n:])
RAW={}
procs={}
for nm,b in (('haproxy',HA),('alcyon',IB)):procs[nm]=start(b,nm)
try:
    files=sorted(glob.glob(sys.argv[1]+'/*.bin'))
    for f in files:
        raw=open(f,'rb').read();out={}
        for nm,(p,fe,be) in procs.items():
            r,b=send(fe,be,raw)
            st=re.findall(rb'HTTP/1\.[01] (\d+)',r)
            out[nm]=(st,b);RAW[nm]=r
        same=out['haproxy']==out['alcyon']
        print(('SAME ' if same else 'DIFF ')+os.path.basename(f),len(raw))
        if not same:
            for nm in out:print('   ',nm,RAW[nm][:90],[x.decode() for x in out[nm][0]],'fwd=',out[nm][1][:300])
            print('    raw=',raw[:200])
finally:
    for p,_,_ in procs.values():p.kill()
