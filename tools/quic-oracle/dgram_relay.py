import socket,threading,json,time,sys
UP=("127.0.0.1",41579)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("127.0.0.1",0))
print(s.getsockname()[1],flush=True)
log=[];t0=time.time();peers={}
def up_reader(us,cli):
    while True:
        try: d,_=us.recvfrom(65535)
        except OSError: return
        log.append({"dir":"s2c","t":round(time.time()-t0,4),"len":len(d),"hex":d[:64].hex()})
        s.sendto(d,cli)
while True:
    d,cli=s.recvfrom(65535)
    if cli not in peers:
        us=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); us.connect(UP)
        peers[cli]=us; threading.Thread(target=up_reader,args=(us,cli),daemon=True).start()
    log.append({"dir":"c2s","t":round(time.time()-t0,4),"len":len(d),"hex":d[:64].hex()})
    peers[cli].send(d)
    json.dump(log,open("/tmp/claude-1000/-home-bhenc-project-ibex/2c9bb267-2e19-4881-8a74-ff955698230a/scratchpad/h3/datagrams.json","w"),indent=1)
