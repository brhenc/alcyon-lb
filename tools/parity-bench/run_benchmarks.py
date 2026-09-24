#!/usr/bin/env python3
"""
tools/parity-bench/run_benchmarks.py

Automated benchmark and profiling harness for T39 Performance Parity Investigation.
"""

import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PARITY_DIR = REPO_ROOT / "tools" / "parity-bench"
BENCH_BIN = Path("/tmp/t39-target/release/parity-bench")
IBEX_BIN = Path("/tmp/t39-target/release/ibex")
HAPROXY_BIN = Path("/home/bhenc/reference/haproxy-quic/haproxy")
PERF_SCRIPT_DIR = Path("/home/bhenc/.cargo/bin")

# Add cargo bin to PATH for inferno tools
os.environ["PATH"] = f"{PERF_SCRIPT_DIR}:{os.environ.get('PATH', '')}"


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get_free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_backend(port: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        [str(BENCH_BIN), "backend", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    line = proc.stdout.readline()
    if "READY" not in line:
        raise RuntimeError(f"Backend failed to start on port {port}")
    return proc


def start_udp_log_sink(port: int) -> tuple[socket.socket, subprocess.Popen]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.setblocking(False)
    return s


def make_configs(fe_port: int, be_port: int, log_port: int) -> dict[str, tuple[str, str]]:
    """Returns {config_name: (haproxy_cfg_text, ibex_cfg_text)}"""
    configs = {}

    # 1. Baseline
    h_baseline = f"""
global
    # default threading
defaults
    mode http
    timeout client 5s
    timeout connect 5s
    timeout server 5s

frontend fe
    bind 127.0.0.1:{fe_port}
    default_backend be

backend be
    server s1 127.0.0.1:{be_port}
"""
    i_baseline = f"""
defaults
    mode http
    timeout client 5s
    timeout connect 5s
    timeout server 5s

frontend fe
    bind 127.0.0.1:{fe_port}
    default_backend be

backend be
    server s1 127.0.0.1:{be_port}
"""
    configs["baseline"] = (h_baseline, i_baseline)

    # 2. + set-header
    h_sethdr = f"""
global
    # default threading
defaults
    mode http
    timeout client 5s
    timeout connect 5s
    timeout server 5s

frontend fe
    bind 127.0.0.1:{fe_port}
    http-request set-header X-Trace %[uuid()]
    default_backend be

backend be
    server s1 127.0.0.1:{be_port}
"""
    i_sethdr = f"""
defaults
    mode http
    timeout client 5s
    timeout connect 5s
    timeout server 5s

frontend fe
    bind 127.0.0.1:{fe_port}
    http-request set-header X-Trace %[uuid()]
    default_backend be

backend be
    server s1 127.0.0.1:{be_port}
"""
    configs["+ set-header"] = (h_sethdr, i_sethdr)

    # 3. + acl
    h_acl = f"""
global
    # default threading
defaults
    mode http
    timeout client 5s
    timeout connect 5s
    timeout server 5s

frontend fe
    bind 127.0.0.1:{fe_port}
    acl is_get method GET
    http-request set-var(txn.m) str(get) if is_get
    default_backend be

backend be
    server s1 127.0.0.1:{be_port}
"""
    i_acl = f"""
defaults
    mode http
    timeout client 5s
    timeout connect 5s
    timeout server 5s

frontend fe
    bind 127.0.0.1:{fe_port}
    acl is_get method GET
    http-request set-var(txn.m) str(get) if is_get
    default_backend be

backend be
    server s1 127.0.0.1:{be_port}
"""
    configs["+ acl"] = (h_acl, i_acl)

    # 4. + httplog
    h_httplog = f"""
global
    log 127.0.0.1:{log_port} local0
defaults
    mode http
    log global
    option httplog
    timeout client 5s
    timeout connect 5s
    timeout server 5s

frontend fe
    bind 127.0.0.1:{fe_port}
    default_backend be

backend be
    server s1 127.0.0.1:{be_port}
"""
    i_httplog = f"""
global
    log 127.0.0.1:{log_port} local0
defaults
    mode http
    log global
    option httplog
    timeout client 5s
    timeout connect 5s
    timeout server 5s

frontend fe
    bind 127.0.0.1:{fe_port}
    default_backend be

backend be
    server s1 127.0.0.1:{be_port}
"""
    configs["+ httplog"] = (h_httplog, i_httplog)

    return configs


def run_benchmark_run(target_addr: str, conns: int, duration_secs: int = 5) -> float:
    cmd = [str(BENCH_BIN), "client", target_addr, str(conns), str(duration_secs)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Client failed: {res.stderr}")
    m = re.search(r"rps:\s*([0-9.]+)", res.stdout)
    if not m:
        raise RuntimeError(f"Could not parse RPS from client output: {res.stdout}")
    return float(m.group(1))


def calc_stats(values: list[float]) -> dict:
    n = len(values)
    avg = sum(values) / n
    variance = sum((x - avg) ** 2 for x in values) / n if n > 1 else 0
    stddev = math.sqrt(variance)
    return {
        "runs": values,
        "avg": avg,
        "stddev": stddev,
        "min": min(values),
        "max": max(values),
    }


def run_strace(proxy_bin: Path, cfg_text: str, fe_port: int, be_port: int, log_port: int) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as f:
        f.write(cfg_text)
        cfg_file = f.name

    proxy_proc = subprocess.Popen(
        [str(proxy_bin), "-f", cfg_file, "-db"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.3)

    strace_file = f"/tmp/strace_{proxy_bin.name}.log"
    strace_proc = subprocess.Popen(
        ["strace", "-c", "-f", "-p", str(proxy_proc.pid), "-o", strace_file],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.3)

    # Run 10,000 requests
    fixed_cmd = [str(BENCH_BIN), "fixed", f"127.0.0.1:{fe_port}", "1", "10000"]
    subprocess.run(fixed_cmd, capture_output=True, text=True)

    strace_proc.terminate()
    strace_proc.wait()
    proxy_proc.terminate()
    proxy_proc.wait()
    os.unlink(cfg_file)

    syscalls = {}
    if os.path.exists(strace_file):
        with open(strace_file, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6 and parts[-1] not in ("syscall", "------", "total"):
                    sc_name = parts[-1]
                    try:
                        calls = int(parts[3])
                        syscalls[sc_name] = calls
                    except (ValueError, IndexError):
                        pass
        os.unlink(strace_file)

    return syscalls


def run_perf_profile(proxy_bin: Path, cfg_text: str, fe_port: int, be_port: int, svg_out: Path):
    with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as f:
        f.write(cfg_text)
        cfg_file = f.name

    proxy_proc = subprocess.Popen(
        [str(proxy_bin), "-f", cfg_file, "-db"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.3)

    # Start background client load
    client_proc = subprocess.Popen(
        [str(BENCH_BIN), "client", f"127.0.0.1:{fe_port}", "1", "25"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)

    perf_data = f"/tmp/perf_{proxy_bin.name}.data"
    perf_record = subprocess.run(
        ["perf", "record", "-F", "999", "-g", "-p", str(proxy_proc.pid), "-o", perf_data, "--", "sleep", "12"],
        capture_output=True,
    )

    client_proc.wait()
    proxy_proc.terminate()
    proxy_proc.wait()
    os.unlink(cfg_file)

    if os.path.exists(perf_data):
        script_proc = subprocess.Popen(
            ["perf", "script", "-i", perf_data],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        collapse_proc = subprocess.Popen(
            ["inferno-collapse-perf"],
            stdin=script_proc.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        flame_proc = subprocess.Popen(
            ["inferno-flamegraph"],
            stdin=collapse_proc.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        svg_content, _ = flame_proc.communicate()
        with open(svg_out, "wb") as f:
            f.write(svg_content)
        os.unlink(perf_data)


def run_noncanonical_diff(fe_port: int, be_port: int) -> dict[str, str]:
    raw_req = (
        b"GET / HTTP/1.1\r\n"
        b"Host:   localhost\r\n"
        b"X-Folded: line1\r\n"
        b"\tline2\r\n"
        b"MY-HEADER: v1\r\n"
        b"my-header: v2\r\n"
        b"\r\n"
    )

    results = {}
    for name, pbin in [("haproxy", HAPROXY_BIN), ("ibex", IBEX_BIN)]:
        be_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        be_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        be_sock.bind(("127.0.0.1", be_port))
        be_sock.listen(5)

        cfg_text = f"""
defaults
    mode http
    timeout client 5s
    timeout connect 5s
    timeout server 5s
frontend fe
    bind 127.0.0.1:{fe_port}
    default_backend be
backend be
    server s1 127.0.0.1:{be_port}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as f:
            f.write(cfg_text)
            cfg_file = f.name

        proc = subprocess.Popen([str(pbin), "-f", cfg_file, "-db"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.3)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", fe_port))
        client.sendall(raw_req)

        be_conn, _ = be_sock.accept()
        be_conn.settimeout(1.0)
        raw_received = be_conn.recv(4096)
        be_conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        be_conn.close()
        be_sock.close()
        client.close()

        proc.terminate()
        proc.wait()
        os.unlink(cfg_file)
        results[name] = raw_received.decode("latin1")

    return results


def main():
    print("=== T39 Benchmark & Parity Suite ===")
    agy_count = subprocess.run(["pgrep", "-c", "agy"], capture_output=True, text=True).stdout.strip() or "0"
    print(f"Active agy sessions: {agy_count}")

    fe_port = get_free_port()
    be_port = get_free_port()
    log_port = get_free_udp_port()

    be_proc = start_backend(be_port)
    log_sock = start_udp_log_sink(log_port)

    configs = make_configs(fe_port, be_port, log_port)
    bench_results = {}

    print("\n--- 1. Running 4-Configuration Benchmarks (3 runs each, 1-conn & 50-conn) ---")
    for cfg_name, (h_cfg, i_cfg) in configs.items():
        bench_results[cfg_name] = {}
        for proxy_name, proxy_bin, cfg_text in [("haproxy", HAPROXY_BIN, h_cfg), ("ibex", IBEX_BIN, i_cfg)]:
            print(f"\nEvaluating {proxy_name.upper()} on config '{cfg_name}'...")
            with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as f:
                f.write(cfg_text)
                cfg_file = f.name

            proxy_proc = subprocess.Popen(
                [str(proxy_bin), "-f", cfg_file, "-db"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.4)

            # 1-connection runs
            r1_list = []
            for run_i in range(3):
                rps1 = run_benchmark_run(f"127.0.0.1:{fe_port}", conns=1, duration_secs=4)
                r1_list.append(rps1)
                print(f"  1-conn run {run_i+1}: {rps1:.1f} rps")

            # 50-connection runs
            r50_list = []
            for run_i in range(3):
                rps50 = run_benchmark_run(f"127.0.0.1:{fe_port}", conns=50, duration_secs=4)
                r50_list.append(rps50)
                print(f"  50-conn run {run_i+1}: {rps50:.1f} rps")

            proxy_proc.terminate()
            proxy_proc.wait()
            os.unlink(cfg_file)

            bench_results[cfg_name][proxy_name] = {
                "1_conn": calc_stats(r1_list),
                "50_conn": calc_stats(r50_list),
            }

    print("\n--- 2. Syscall Counting via strace (10,000 requests) ---")
    h_baseline_cfg, i_baseline_cfg = configs["baseline"]
    h_syscalls = run_strace(HAPROXY_BIN, h_baseline_cfg, fe_port, be_port, log_port)
    i_syscalls = run_strace(IBEX_BIN, i_baseline_cfg, fe_port, be_port, log_port)

    print("HAProxy Syscalls (10k reqs):", h_syscalls)
    print("Ibex Syscalls (10k reqs):", i_syscalls)

    print("\n--- 3. Perf Profiling & Flamegraph Generation ---")
    PARITY_DIR.mkdir(parents=True, exist_ok=True)
    haproxy_svg = PARITY_DIR / "haproxy.svg"
    ibex_svg = PARITY_DIR / "ibex.svg"
    print("Capturing HAProxy perf flamegraph...")
    run_perf_profile(HAPROXY_BIN, h_baseline_cfg, fe_port, be_port, haproxy_svg)
    print(f"Saved {haproxy_svg} ({haproxy_svg.stat().st_size:,} bytes)")

    print("Capturing Ibex perf flamegraph...")
    run_perf_profile(IBEX_BIN, i_baseline_cfg, fe_port, be_port, ibex_svg)
    print(f"Saved {ibex_svg} ({ibex_svg.stat().st_size:,} bytes)")

    print("\n--- 4. Byte-for-Byte Differential Inspection ---")
    diff_results = run_noncanonical_diff(fe_port, be_port)
    print("HAProxy Backend Raw View:\n" + repr(diff_results["haproxy"]))
    print("Ibex Backend Raw View:\n" + repr(diff_results["ibex"]))

    be_proc.terminate()
    be_proc.wait()
    log_sock.close()

    summary_out = {
        "timestamp": time.time(),
        "active_agy_sessions": agy_count,
        "benchmarks": bench_results,
        "syscalls": {
            "haproxy": h_syscalls,
            "ibex": i_syscalls,
        },
        "non_canonical": diff_results,
    }

    with open("/tmp/t39_benchmark_summary.json", "w") as f:
        json.dump(summary_out, f, indent=2)

    print("\nBenchmark Suite Completed Successfully!")


if __name__ == "__main__":
    main()
