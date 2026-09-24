#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess
import json
import re
import hashlib
from collections import defaultdict
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import smoke

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def normalize_whitespace(text):
    return " ".join(text.split())

def hash_body(text):
    norm = normalize_whitespace(text)
    return hashlib.sha256(norm.encode('utf-8')).hexdigest()[:16]

def get_parse_set():
    orig_run = subprocess.run
    results = []
    
    def fake_run(*args, **kwargs):
        res = orig_run(*args, **kwargs)
        if len(args) > 0 and type(args[0]) is list and "-c" in args[0]:
            results.append(res)
        elif "args" in kwargs and type(kwargs["args"]) is list and "-c" in kwargs["args"]:
            results.append(res)
        return res

    subprocess.run = fake_run
    ok, total, rejected = smoke.parse_gate()
    subprocess.run = orig_run
    
    keys = []
    for path in smoke._vtc_files():
        rel = os.path.relpath(path, smoke.REGTESTS)
        for i, _ in enumerate(smoke._configs_from(path)):
            keys.append(f"{rel}:{i}")
            
    out = {}
    for k, res in zip(keys, results):
        if res.returncode == 0:
            out[k] = "accepted"
        else:
            first = (res.stdout + res.stderr).strip().splitlines()
            out[k] = first[0][:110] if first else "(no message)"
            
    return out

def get_board():
    vtc_files = smoke._vtc_files()
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "r.json")
        subprocess.run([sys.executable, os.path.join(REPO, "harness", "vtc_runner.py"),
                        *vtc_files, "--json", out], capture_output=True, text=True)
        try:
            with open(out) as f:
                data = json.load(f)
        except Exception:
            return {}
        rows = data.get("results", []) if isinstance(data, dict) else data
        return {r.get("file_path", "").split("reg-tests/")[-1]: r.get("status") for r in rows if "file_path" in r}

def scan_rust_files():
    crates_dir = os.path.join(REPO, "crates")
    files = []
    for root, _, fnames in os.walk(crates_dir):
        for f in fnames:
            if f.endswith('.rs'):
                files.append(os.path.join(root, f))
    return sorted(files)

def parse_rust_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception:
        return [], []
        
    bodies = []
    idx = 0
    n = len(content)
    
    while idx < n:
        match = re.search(r'^(?:pub(?:\([^)]+\))?\s+)?(?:fn|struct|enum|impl|trait)\s+[^{;]*\{', content[idx:], re.MULTILINE)
        if not match:
            break
            
        start_idx = idx + match.end() - 1
        
        depth = 0
        j = start_idx
        while j < n:
            if content[j] == '{':
                depth += 1
            elif content[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
            
        if j < n:
            body = content[start_idx:j+1]
            bodies.append(body)
            idx = j + 1
        else:
            idx += match.end()

    api = []
    parts = path.split(os.sep)
    try:
        crates_idx = parts.index("crates")
        crate_name = parts[crates_idx+1].replace("-", "_")
    except ValueError:
        crate_name = "unknown"
        
    rel_path = path[path.find("src/")+4:]
    mod_path = rel_path.replace(".rs", "").replace("/mod", "").replace("/", "::")
    if mod_path:
        base_path = f"{crate_name}::{mod_path}"
    else:
        base_path = crate_name

    for m in re.finditer(r'^(?:pub(?:\([^)]+\))?\s+)(fn|struct|enum|trait|type|const|static)\s+([A-Za-z0-9_]+)', content, re.MULTILINE):
        item_name = m.group(2)
        api.append(f"{base_path}::{item_name}")

    return bodies, api

def get_bodies_and_api():
    all_bodies = []
    all_api = []
    for f in scan_rust_files():
        bodies, api = parse_rust_file(f)
        all_bodies.extend(bodies)
        all_api.extend(api)
    
    body_hashes = defaultdict(int)
    for b in all_bodies:
        body_hashes[hash_body(b)] += 1
        
    return dict(body_hashes), sorted(list(set(all_api)))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sections", default="parse,board,api,bodies")
    args = ap.parse_args()
    
    sections = args.sections.split(",")
    
    out = {}
    if "parse" in sections:
        out["parse"] = get_parse_set()
    if "board" in sections:
        out["board"] = get_board()
    
    if "api" in sections or "bodies" in sections:
        b, a = get_bodies_and_api()
        if "bodies" in sections:
            out["bodies"] = b
        if "api" in sections:
            out["api"] = a

    print(json.dumps(out, sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
