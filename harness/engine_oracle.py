#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

import asyncio
import argparse
import json
import subprocess
import tempfile
import os
import sys
import hashlib
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = os.path.join(REPO, "target", "debug", "ibex")

def get_free_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p

class SyslogServer:
    def __init__(self, port):
        self.port = port
        self.logs = []
        self.transport = None

    class Protocol(asyncio.DatagramProtocol):
        def __init__(self, logs):
            self.logs = logs
        def datagram_received(self, data, addr):
            self.logs.append(data.decode('utf-8', errors='replace'))

    async def start(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self.Protocol(self.logs),
            local_addr=('127.0.0.1', self.port)
        )

    def stop(self):
        if self.transport:
            self.transport.close()

class MockBackend:
    def __init__(self, port, name, delay=0.0, drop=False, respond=True):
        self.port = port
        self.name = name
        self.delay = delay
        self.drop = drop
        self.respond = respond
        self.server = None
        self.requests_received = []
        self.client_tasks = []

    async def handle_client(self, reader, writer):
        if self.drop:
            writer.close()
            return
        
        data = b""
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=0.1)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
            
        self.requests_received.append(data)

        if self.delay > 0:
            await asyncio.sleep(self.delay)

        if self.respond:
            resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
            try:
                writer.write(resp)
                await writer.drain()
            except Exception:
                pass
        
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    def accept_client(self, reader, writer):
        task = asyncio.create_task(self.handle_client(reader, writer))
        self.client_tasks.append(task)

    async def start(self):
        self.server = await asyncio.start_server(self.accept_client, '127.0.0.1', self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for task in self.client_tasks:
            task.cancel()

class Probe:
    def __init__(self, request_data, delay_before=0.0, slow_send=False):
        self.request_data = request_data
        self.delay_before = delay_before
        self.slow_send = slow_send
        self.response = None
        self.error = None

    async def run(self, proxy_port):
        if self.delay_before > 0:
            await asyncio.sleep(self.delay_before)
        
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
            if self.slow_send:
                half = len(self.request_data) // 2
                writer.write(self.request_data[:half])
                await writer.drain()
                await asyncio.sleep(0.2)
                writer.write(self.request_data[half:])
                await writer.drain()
            else:
                writer.write(self.request_data)
                await writer.drain()

            resp_data = b""
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=0.5)
                    if not chunk:
                        break
                    resp_data += chunk
                except asyncio.TimeoutError:
                    break
            
            self.response = resp_data
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            self.error = str(type(e).__name__)

async def run_case(name, case_def):
    proxy_port = get_free_port()
    syslog_port = get_free_port()
    
    port_map = {
        proxy_port: "<proxy_port>",
        syslog_port: "<syslog_port>"
    }
    
    be_ports = []
    backends = []
    for i, bdef in enumerate(case_def.get("backends", [])):
        p = get_free_port()
        be_ports.append(p)
        port_map[p] = f"<be_port_{i}>"
        b = MockBackend(
            p, f"b{i}",
            delay=bdef.get("delay", 0.0),
            drop=bdef.get("drop", False),
            respond=bdef.get("respond", True)
        )
        backends.append(b)

    syslog = SyslogServer(syslog_port)
    await syslog.start()

    for b in backends:
        await b.start()

    config = case_def["config"].format(
        proxy_port=proxy_port,
        syslog_port=syslog_port,
        be_ports=be_ports
    )

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(config)
        cfg_path = f.name

    proc = await asyncio.create_subprocess_exec(
        BINARY, "-f", cfg_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    await asyncio.sleep(0.1)

    probes = case_def.get("probes", [])
    probe_results = []
    for p in probes:
        probe = Probe(p.get("send", b""), delay_before=p.get("delay", 0.0), slow_send=p.get("slow", False))
        await probe.run(proxy_port)
        
        resp = probe.response
        if probe.error:
            probe_results.append({"error": probe.error})
        elif not resp:
            probe_results.append({"error": "empty_response"})
        else:
            lines = resp.split(b"\r\n")
            if not lines:
                probe_results.append({"raw_response": resp.decode('latin1')})
            else:
                status_line = lines[0].decode('latin1')
                headers = []
                idx = 1
                while idx < len(lines) and lines[idx]:
                    headers.append(lines[idx].decode('latin1'))
                    idx += 1
                body = b"\r\n".join(lines[idx+1:])
                body_hash = hashlib.sha256(body).hexdigest()[:16] if body else None
                
                headers.sort()
                probe_results.append({
                    "status_line": sanitize_str(status_line, port_map),
                    "headers": [sanitize_str(h, port_map) for h in headers],
                    "body_hash": body_hash
                })

    await asyncio.sleep(case_def.get("run_time", 0.1))
    
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=1.0)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
    
    os.remove(cfg_path)

    for b in backends:
        await b.stop()
    syslog.stop()
    
    be_reqs = {}
    for b in backends:
        reqs = []
        for r in b.requests_received:
            lines = r.split(b"\r\n")
            if lines and lines[0]:
                status = lines[0].decode('latin1')
                hdrs = []
                for idx in range(1, len(lines)):
                    if not lines[idx]: break
                    hdrs.append(lines[idx].decode('latin1'))
                hdrs.sort()
                reqs.append({
                    "request_line": sanitize_str(status, port_map),
                    "headers": [sanitize_str(h, port_map) for h in hdrs]
                })
        be_reqs[b.name] = reqs
        
    sanitized_logs = []
    for l in syslog.logs:
        l = l.replace('\0', '')
        sanitized_logs.append(sanitize_str(l, port_map).strip())
    sanitized_logs.sort()
    
    return {
        "probe_results": probe_results,
        "backend_requests": be_reqs,
        "syslog": sanitized_logs
    }

def sanitize_str(text, port_map):
    for p_val, p_name in sorted(port_map.items(), key=lambda x: -len(str(x[0]))):
        text = text.replace(str(p_val), p_name)
    text = re.sub(r'<\d+>', '<FAC>', text)
    text = re.sub(r'\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}', '<DATE>', text)
    text = re.sub(r'\[\d+\]', '[<PID>]', text)
    text = re.sub(r'pid = \d+', 'pid = <PID>', text)
    text = re.sub(r'port \d+', 'port <PORT>', text)
    return text

CASES = {
    "backend_selection": {
        "config": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout client 5s
    timeout server 5s
    timeout connect 5s
    log global
    mode http
frontend fe
    bind 127.0.0.1:{proxy_port}
    use_backend b1 if {{ path_beg /b1 }}
    default_backend b2
backend b1
    server s1 127.0.0.1:{be_ports[0]}
backend b2
    server s2 127.0.0.1:{be_ports[1]}
""",
        "backends": [{"respond": True}, {"respond": True}],
        "probes": [
            {"send": b"GET /b1 HTTP/1.0\r\n\r\n"},
            {"send": b"GET / HTTP/1.0\r\n\r\n"}
        ]
    },
    "keep_alive": {
        "config": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout client 5s
    timeout server 5s
    timeout connect 5s
    log global
    mode http
frontend fe
    bind 127.0.0.1:{proxy_port}
    default_backend b1
backend b1
    server s1 127.0.0.1:{be_ports[0]}
""",
        "backends": [{"respond": True}],
        "probes": [
            {"send": b"GET / HTTP/1.1\r\nHost: loc\r\n\r\nGET / HTTP/1.1\r\nConnection: close\r\nHost: loc\r\n\r\n"}
        ]
    },
    "req_res_rule": {
        "config": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout client 5s
    timeout server 5s
    timeout connect 5s
    log global
    mode http
frontend fe
    bind 127.0.0.1:{proxy_port}
    http-request set-header X-Added-Req 1
    http-request deny if {{ path_beg /deny }}
    default_backend b1
backend b1
    http-response set-header X-Added-Res 1
    server s1 127.0.0.1:{be_ports[0]}
""",
        "backends": [{"respond": True}],
        "probes": [
            {"send": b"GET / HTTP/1.0\r\n\r\n"},
            {"send": b"GET /deny HTTP/1.0\r\n\r\n"}
        ]
    },
    "error_paths": {
        "config": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout client 5s
    timeout server 5s
    timeout connect 5s
    log global
    mode http
frontend fe
    bind 127.0.0.1:{proxy_port}
    default_backend b1
backend b1
    server s1 127.0.0.1:{be_ports[0]}
""",
        "backends": [{"drop": True}],
        "probes": [
            {"send": b"GET / HTTP/1.0\r\n\r\n"},
            {"send": b"INVALID REQUEST\r\n\r\n"}
        ]
    },
    "timeouts": {
        "config": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout client 100ms
    timeout server 100ms
    timeout connect 100ms
    log global
    mode http
frontend fe
    bind 127.0.0.1:{proxy_port}
    default_backend b1
backend b1
    server s1 127.0.0.1:{be_ports[0]}
""",
        "backends": [{"delay": 0.2, "respond": True}],
        "probes": [
            {"send": b"GET / HTT", "slow": True},
            {"send": b"GET / HTTP/1.0\r\n\r\n"}
        ]
    },
    "stick_table": {
        "config": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout client 5s
    timeout server 5s
    timeout connect 5s
    log global
    mode http
frontend fe
    bind 127.0.0.1:{proxy_port}
    default_backend b1
backend b1
    stick-table type ip size 100
    stick on src
    server s1 127.0.0.1:{be_ports[0]}
    server s2 127.0.0.1:{be_ports[1]}
""",
        "backends": [{"respond": True}, {"respond": True}],
        "probes": [
            {"send": b"GET / HTTP/1.0\r\n\r\n"},
            {"send": b"GET / HTTP/1.0\r\n\r\n"}
        ]
    },
    "health_check": {
        "config": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout client 5s
    timeout server 5s
    timeout connect 5s
    log global
    mode http
frontend fe
    bind 127.0.0.1:{proxy_port}
    default_backend b1
backend b1
    server s1 127.0.0.1:{be_ports[0]} check inter 100ms
""",
        "backends": [{"respond": True}],
        "run_time": 0.4
    }
}

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--diff", nargs=2, help="Diff two JSON fingerprint files")
    args = parser.parse_args()

    if args.diff:
        import subprocess
        import tempfile
        with open(args.diff[0]) as f1, open(args.diff[1]) as f2:
            d1 = json.load(f1)
            d2 = json.load(f2)
        fd1, f1_name = tempfile.mkstemp()
        fd2, f2_name = tempfile.mkstemp()
        with os.fdopen(fd1, "w") as f1_out, os.fdopen(fd2, "w") as f2_out:
            json.dump(d1, f1_out, sort_keys=True, indent=2)
            f1_out.write("\n")
            json.dump(d2, f2_out, sort_keys=True, indent=2)
            f2_out.write("\n")
        subprocess.run(["diff", "-u", f1_name, f2_name])
        os.remove(f1_name)
        os.remove(f2_name)
        sys.exit(0)

    # Fingerprint generation mode
    out = {}
    for name, cdef in CASES.items():
        out[name] = await run_case(name, cdef)
    
    print(json.dumps(out, sort_keys=True, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
