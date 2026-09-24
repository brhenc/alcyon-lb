#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess
import json
import socket
import threading
import time
import hashlib
import re
import tempfile

CONFIG_TEMPLATES = {
    "backend_selection": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout connect 1s
    timeout client 1s
    timeout server 1s
    mode http
    option httplog
frontend f1
    bind 127.0.0.1:{front_port}
    use_backend b2 if { path -m beg /b2 }
    default_backend b1
backend b1
    server s1 127.0.0.1:{back1_port}
backend b2
    server s2 127.0.0.1:{back2_port}
""",
    "keep_alive": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout connect 1s
    timeout client 1s
    timeout server 1s
    mode http
    option httplog
frontend f1
    bind 127.0.0.1:{front_port}
    default_backend b1
backend b1
    option http-keep-alive
    server s1 127.0.0.1:{back1_port}
""",
    "header_rewriting": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout connect 1s
    timeout client 1s
    timeout server 1s
    mode http
    option httplog
frontend f1
    bind 127.0.0.1:{front_port}
    http-request set-header X-Added-Front Front
    default_backend b1
backend b1
    http-request set-header X-Added-Back Back
    http-response set-header X-Added-Resp Resp
    server s1 127.0.0.1:{back1_port}
""",
    "error_paths": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout connect 1s
    timeout client 1s
    timeout server 1s
    mode http
    option httplog
frontend f1
    bind 127.0.0.1:{front_port}
    http-request deny if { path -m beg /deny }
    default_backend b1
backend b1
    server s1 127.0.0.1:{back1_port}
""",
    "timeouts": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout connect 100ms
    timeout client 100ms
    timeout server 100ms
    mode http
    option httplog
frontend f1
    bind 127.0.0.1:{front_port}
    default_backend b1
backend b1
    server s1 127.0.0.1:{back1_port}
""",
    "stick_table": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout connect 1s
    timeout client 1s
    timeout server 1s
    mode http
    option httplog
frontend f1
    bind 127.0.0.1:{front_port}
    default_backend b1
backend b1
    stick-table type ip size 1m
    stick on src
    server s1 127.0.0.1:{back1_port}
""",
    "no_server": """
global
defaults
    timeout connect 1s
    timeout client 1s
    timeout server 1s
    mode http
frontend f1
    bind 127.0.0.1:{front_port}
    default_backend b1
backend b1
""",
    "health_check": """
global
    log 127.0.0.1:{syslog_port} local0
defaults
    timeout connect 1s
    timeout client 1s
    timeout server 1s
    mode http
    option httplog
frontend f1
    bind 127.0.0.1:{front_port}
    default_backend b1
backend b1
    option httpchk GET /health
    server s1 127.0.0.1:{back1_port} check inter 100ms fall 1 rise 1
    server s2 127.0.0.1:{back2_port} check inter 100ms fall 1 rise 1
"""
}

PROBES = {
    "backend_selection": [
        {"path": "/"},
        {"path": "/b2"},
    ],
    "keep_alive": [
        {"path": "/", "headers": {"Connection": "keep-alive"}, "keep_open": True},
        {"path": "/second", "headers": {"Connection": "keep-alive"}},
    ],
    "header_rewriting": [
        {"path": "/"},
    ],
    "error_paths": [
        {"path": "/deny"},
        {"path": "/"},
    ],
    "timeouts": [
        {"path": "/timeout", "backend_delay": 0.5},
    ],
    "stick_table": [
        {"path": "/"},
        {"path": "/"},
    ],
    "no_server": [
        {"path": "/"},
    ],
    "health_check": [
        {"path": "/", "delay_before": 0.3},
    ]
}

def get_free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p

class MockBackend:
    def __init__(self, port, name):
        self.port = port
        self.name = name
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', port))
        self.sock.listen(5)
        self.running = True
        self.t = threading.Thread(target=self.run)
        self.t.start()
        
    def run(self):
        self.sock.settimeout(0.1)
        while self.running:
            try:
                conn, _ = self.sock.accept()
                conn.settimeout(0.5)
                threading.Thread(target=self.handle, args=(conn,)).start()
            except socket.timeout:
                pass
                
    def handle(self, conn):
        try:
            data = conn.recv(4096).decode('utf-8', errors='replace')
            if not data:
                return
                
            if "GET /timeout" in data:
                time.sleep(0.5)
                
            body = f"Hello from {self.name}"
            resp = (f"HTTP/1.1 200 OK\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{body}")
            conn.sendall(resp.encode('utf-8'))
        except:
            pass
        finally:
            conn.close()

    def stop(self):
        self.running = False
        self.t.join()
        self.sock.close()

class SyslogReceiver:
    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', port))
        self.sock.settimeout(0.1)
        self.logs = []
        self.running = True
        self.t = threading.Thread(target=self.run)
        self.t.start()
        
    def run(self):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(4096)
                self.logs.append(data.decode('utf-8', errors='replace').strip())
            except socket.timeout:
                pass
                
    def get_and_clear(self):
        res = self.logs[:]
        self.logs.clear()
        return res
        
    def stop(self):
        self.running = False
        self.t.join()
        self.sock.close()

def parse_response(raw):
    parts = raw.split("\r\n\r\n", 1)
    headers_part = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    lines = headers_part.split("\r\n")
    if not lines:
        return {"error": "Empty response"}
    status = lines[0]
    headers = [h for h in lines[1:] if not h.lower().startswith("date:") and not h.lower().startswith("server:")]
    headers.sort()
    return {
        "status": status,
        "headers": headers,
        "body_hash": hashlib.sha256(body.encode('utf-8')).hexdigest()[:16]
    }

def clean_syslog(lines, port_map):
    cleaned = []
    for line in lines:
        line = re.sub(r'^<\d+>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+', '', line)
        line = re.sub(r'^(ibex|haproxy)\[\d+\]:\s+', '', line)
        for actual, placeholder in port_map.items():
            line = line.replace(str(actual), placeholder)
        cleaned.append(line)
    return sorted(cleaned)

def run_probes(front_port, probes, port_map):
    results = []
    conn = None
    for p in probes:
        if p.get("delay_before"):
            time.sleep(p.get("delay_before"))
            
        if not conn:
            conn = socket.socket()
            conn.settimeout(1.0)
            try:
                conn.connect(('127.0.0.1', front_port))
            except Exception as e:
                results.append({"error": f"connect: {e}"})
                conn = None
                continue
                
        req = f"GET {p['path']} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        for k, v in p.get("headers", {}).items():
            req += f"{k}: {v}\r\n"
        req += "\r\n"
        
        try:
            conn.sendall(req.encode('utf-8'))
            resp = conn.recv(8192).decode('utf-8', errors='replace')
            if not resp:
                results.append({"error": "empty response"})
                conn.close()
                conn = None
            else:
                parsed = parse_response(resp)
                parsed_str = json.dumps(parsed)
                for actual, placeholder in port_map.items():
                    parsed_str = parsed_str.replace(str(actual), placeholder)
                results.append(json.loads(parsed_str))
                
                if not p.get("keep_open"):
                    conn.close()
                    conn = None
        except Exception as e:
            results.append({"error": f"req: {e}"})
            if conn:
                conn.close()
            conn = None
            
    if conn:
        conn.close()
    return results

def wait_for_port(port, timeout=2.0):
    start = time.time()
    while time.time() - start < timeout:
        s = socket.socket()
        s.settimeout(0.1)
        try:
            s.connect(('127.0.0.1', port))
            s.close()
            return True
        except:
            pass
        time.sleep(0.1)
    return False

def diff_dicts(d1, d2, path=""):
    diffs = []
    keys = sorted(set(d1.keys()) | set(d2.keys()))
    for k in keys:
        p = f"{path}.{k}" if path else k
        if k not in d1:
            diffs.append(f"+ {p}: {d2[k]}")
        elif k not in d2:
            diffs.append(f"- {p}: {d1[k]}")
        elif isinstance(d1[k], dict) and isinstance(d2[k], dict):
            diffs.extend(diff_dicts(d1[k], d2[k], p))
        elif isinstance(d1[k], list) and isinstance(d2[k], list):
            if d1[k] != d2[k]:
                diffs.append(f"~ {p}: {d1[k]} -> {d2[k]}")
        elif d1[k] != d2[k]:
            diffs.append(f"~ {p}: {d1[k]} -> {d2[k]}")
    return diffs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="./target/debug/ibex")
    ap.add_argument("--diff", nargs=2, help="Diff two JSON fingerprint files")
    args = ap.parse_args()
    
    if args.diff:
        with open(args.diff[0]) as f1, open(args.diff[1]) as f2:
            d1 = json.load(f1)
            d2 = json.load(f2)
            
        diffs = diff_dicts(d1, d2)
        if not diffs:
            print("No differences found.")
        else:
            for d in diffs:
                print(d)
        return

    if not os.path.exists(args.bin):
        print(f"Error: binary {args.bin} not found")
        sys.exit(1)

    out = {}
    
    for name, template in sorted(CONFIG_TEMPLATES.items()):
        syslog_port = get_free_port()
        front_port = get_free_port()
        back1_port = get_free_port()
        back2_port = get_free_port()
        
        port_map = {
            syslog_port: "<SYSLOG_PORT>",
            front_port: "<FRONT_PORT>",
            back1_port: "<BACK1_PORT>",
            back2_port: "<BACK2_PORT>"
        }
        
        cfg = template.replace("{syslog_port}", str(syslog_port)).replace("{front_port}", str(front_port)).replace("{back1_port}", str(back1_port)).replace("{back2_port}", str(back2_port))
        
        syslog = SyslogReceiver(syslog_port)
        b1 = MockBackend(back1_port, "b1")
        b2 = MockBackend(back2_port, "b2")
        
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(cfg)
            cfg_path = f.name
            
        proc = subprocess.Popen([args.bin, "-f", cfg_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        ready = wait_for_port(front_port)
        
        if not ready:
            out[name] = {"error": "proxy failed to start"}
        else:
            probes = PROBES.get(name, [])
            results = run_probes(front_port, probes, port_map)
            time.sleep(0.2)
            syslog_lines = syslog.get_and_clear()
            out[name] = {
                "results": results,
                "syslog": clean_syslog(syslog_lines, port_map)
            }
            
        proc.kill()
        proc.wait()
        os.remove(cfg_path)
        syslog.stop()
        b1.stop()
        b2.stop()

    print(json.dumps(out, sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
