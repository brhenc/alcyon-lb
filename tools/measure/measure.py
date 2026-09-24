#!/usr/bin/env python3
"""
Ibex Continuous Measurement Suite (`tools/measure/measure.py`)

Automates tracking and regression detection for:
- Allocations per request (tools/allocprofile)
- 1-connection and 50-connection throughput (req/s) and CPU %
- HAProxy side-by-side throughput comparison
- VTC regression test board scores (harness/vtc_runner.py)
- Binary size and .text section size
- 60,000 backends memory footprint
- Load average and concurrent agy sessions
- Flamegraph generation with inferno and perf
"""

import argparse
import dataclasses
from enum import Enum
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = REPO_ROOT / "data"
MEASUREMENTS_JSONL = DATA_DIR / "measurements.jsonl"
HAPROXY_BIN = Path("/home/bhenc/reference/haproxy/haproxy")
VTC_TESTS_DIR = Path("/home/bhenc/reference/haproxy/reg-tests")
VTC_RUNNER = REPO_ROOT / "harness" / "vtc_runner.py"

# Ensure ~/.cargo/bin is in PATH for inferno tools
os.environ["PATH"] = f"{Path.home()}/.cargo/bin:{os.environ.get('PATH', '')}"


class Verdict(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BASELINE = "BASELINE"


@dataclasses.dataclass
class MetricDelta:
    name: str
    label: str
    current: Any
    previous: Any
    delta_str: str
    status: str
    is_regression: bool
    unit: str = ""
    details: str = ""


def get_free_port() -> int:
    """Allocate an ephemeral TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get_git_info() -> Dict[str, Any]:
    """Extract current git commit hash, dirty flag, and UTC timestamp."""
    sha = "unknown"
    dirty = False
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True)
        if res.returncode == 0:
            sha = res.stdout.strip()
        diff_res = subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True)
        if diff_res.returncode == 0 and diff_res.stdout.strip():
            dirty = True
    except Exception:
        pass
    at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"sha": sha, "at": at, "dirty": dirty}


def get_system_metrics() -> Dict[str, Any]:
    """Measure 1-minute load average and number of active agy processes."""
    load_1min = 0.0
    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as f:
            load_1min = float(f.read().split()[0])
    except Exception:
        pass

    agy_count = 0
    try:
        res = subprocess.run(["pgrep", "-c", "agy"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            agy_count = int(res.stdout.strip())
    except Exception:
        pass

    return {"load_1min": load_1min, "agy_count": agy_count}


def run_alloc_profile(target_dir: Optional[Path] = None) -> Tuple[int, int, List[Dict[str, Any]]]:
    """Run tools/allocprofile and return (allocs_per_request, bytes_per_request, top_sites)."""
    alloc_dir = REPO_ROOT / "tools" / "allocprofile"
    env = os.environ.copy()
    if target_dir:
        env["CARGO_TARGET_DIR"] = str(target_dir)

    cmd = ["cargo", "run", "--manifest-path", str(alloc_dir / "Cargo.toml"), "-q"]
    res = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"allocprofile failed (exit {res.returncode}): {res.stderr}\n{res.stdout}")

    stdout = res.stdout
    m = re.search(r"=====\s*(\d+)\s+allocations,\s*(\d+)\s+bytes", stdout)
    if not m:
        raise ValueError(f"Could not parse allocprofile output: {stdout}")

    tot_allocs = int(m.group(1))
    tot_bytes = int(m.group(2))

    call_sites = []
    site_re = re.compile(r"^\s*(\d+)\s+(\d+)B\s+(.+)$")
    for line in stdout.splitlines():
        sm = site_re.match(line.strip())
        if sm:
            call_sites.append({
                "count": int(sm.group(1)),
                "bytes": int(sm.group(2)),
                "site": sm.group(3).strip(),
            })

    return tot_allocs, tot_bytes, call_sites


def get_target_dir(custom_target: Optional[str] = None) -> Path:
    if custom_target:
        return Path(custom_target)
    if "CARGO_TARGET_DIR" in os.environ:
        return Path(os.environ["CARGO_TARGET_DIR"])
    return REPO_ROOT / "target"


def ensure_ibex_binary(target_dir: Path, profile: str = "release") -> Path:
    """Build ibex binary under given target_dir with specified profile if not present or stale."""
    bin_path = target_dir / profile / "ibex"
    cmd = ["cargo", "build", "--bin", "ibex"]
    if profile == "release":
        cmd.append("--release")
    elif profile == "livepatch":
        cmd.extend(["--profile", "livepatch"])

    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target_dir)
    if profile == "livepatch":
        env["RUSTFLAGS"] = "-C force-frame-pointers=yes -C llvm-args=-align-all-functions=4"

    res = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to build ibex ({profile}): {res.stderr}\n{res.stdout}")

    if not bin_path.exists():
        raise FileNotFoundError(f"ibex binary not found at {bin_path}")
    return bin_path


def measure_binary_size(bin_path: Path) -> Tuple[int, int]:
    """Return (binary_bytes, text_bytes)."""
    binary_bytes = bin_path.stat().st_size
    text_bytes = 0

    # Parse .text section size using `size -A -d <bin>`
    try:
        res = subprocess.run(["size", "-A", "-d", str(bin_path)], capture_output=True, text=True)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ".text":
                    text_bytes = int(parts[1])
                    break
    except Exception:
        pass

    if text_bytes == 0:
        # Fallback to size -B
        try:
            res = subprocess.run(["size", "-B", str(bin_path)], capture_output=True, text=True)
            if res.returncode == 0:
                lines = res.stdout.strip().splitlines()
                if len(lines) >= 2:
                    text_bytes = int(lines[1].split()[0])
        except Exception:
            text_bytes = binary_bytes

    return binary_bytes, text_bytes


def ensure_parity_bench_binary(target_dir: Path) -> Path:
    """Build measure-bench helper binary from tools/measure/bench."""
    bench_dir = REPO_ROOT / "tools" / "measure" / "bench"
    bin_path = target_dir / "release" / "measure-bench"
    if not bin_path.exists():
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(target_dir)
        cmd = ["cargo", "build", "--manifest-path", str(bench_dir / "Cargo.toml"), "--release"]
        res = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to build measure-bench: {res.stderr}\n{res.stdout}")
    return bin_path


def get_process_cpu_ticks(pid: int) -> Tuple[int, int]:
    """Read (utime, stime) ticks for process pid."""
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            fields = f.read().split()
            # utime is field 14 (idx 13), stime is field 15 (idx 14)
            return int(fields[13]), int(fields[14])
    except Exception:
        return 0, 0


def measure_throughput(
    proxy_type: str, # 'ibex' or 'haproxy'
    conns: int,
    target_dir: Path,
    runs: int = 3,
    duration: float = 2.0,
    ibex_bin: Optional[Path] = None,
) -> Tuple[int, Dict[str, Any], float]:
    """
    Measure throughput (RPS) over multiple runs and compute average, spread, and CPU %.
    Returns (avg_rps, spread_dict, cpu_pct).
    """
    fe_port = get_free_port()
    be_port = get_free_port()
    while be_port == fe_port:
        be_port = get_free_port()

    bench_bin = ensure_parity_bench_binary(target_dir)

    # Generate test config
    cfg_content = f"""defaults
    mode http
    timeout client 10s
    timeout server 10s
    timeout connect 5s

frontend fe
    bind 127.0.0.1:{fe_port}
    default_backend be

backend be
    server s1 127.0.0.1:{be_port}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as tf:
        tf.write(cfg_content)
        cfg_path = tf.name

    be_proc = None
    proxy_proc = None
    rps_samples: List[float] = []
    cpu_pct = 0.0

    try:
        # Start mock backend
        be_proc = subprocess.Popen([str(bench_bin), "backend", str(be_port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.15)

        # Start proxy
        if proxy_type == "ibex":
            if not ibex_bin:
                ibex_bin = ensure_ibex_binary(target_dir, profile="release")
            proxy_proc = subprocess.Popen([str(ibex_bin), "-f", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif proxy_type == "haproxy":
            if not HAPROXY_BIN.exists():
                raise FileNotFoundError(f"HAProxy oracle binary not found at {HAPROXY_BIN}")
            proxy_proc = subprocess.Popen([str(HAPROXY_BIN), "-f", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            raise ValueError(f"Unknown proxy type: {proxy_type}")

        time.sleep(0.3)
        if proxy_proc.poll() is not None:
            raise RuntimeError(f"{proxy_type} proxy failed to start (exit code {proxy_proc.returncode})")

        # Measure throughput across runs
        client_addr = f"127.0.0.1:{fe_port}"
        
        # Warmup run (1 second)
        subprocess.run([str(bench_bin), "client", client_addr, str(min(conns, 10)), "1"], capture_output=True, text=True)

        t_start = time.monotonic()
        u_before, s_before = get_process_cpu_ticks(proxy_proc.pid)

        for _ in range(runs):
            res = subprocess.run(
                [str(bench_bin), "client", client_addr, str(conns), str(int(duration))],
                capture_output=True, text=True
            )
            if res.returncode == 0:
                m = re.search(r"rps:\s*([\d\.]+)", res.stdout)
                if m:
                    rps_samples.append(float(m.group(1)))

        t_elapsed = time.monotonic() - t_start
        u_after, s_after = get_process_cpu_ticks(proxy_proc.pid)

        if t_elapsed > 0 and (u_after + s_after > u_before + s_before):
            # clk_tck = 100 on Linux x86_64
            total_ticks = (u_after - u_before) + (s_after - s_before)
            cpu_pct = round((total_ticks / (100.0 * t_elapsed)) * 100.0, 1)

    finally:
        if proxy_proc:
            proxy_proc.terminate()
            try:
                proxy_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
        if be_proc:
            be_proc.terminate()
            try:
                be_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                be_proc.kill()
        if os.path.exists(cfg_path):
            os.remove(cfg_path)

    if not rps_samples:
        raise RuntimeError(f"No successful throughput samples for {proxy_type} ({conns} conns)")

    avg_rps = int(round(sum(rps_samples) / len(rps_samples)))
    min_rps = int(round(min(rps_samples)))
    max_rps = int(round(max(rps_samples)))
    spread_pct = round(((max_rps - min_rps) / avg_rps) * 100.0, 1) if avg_rps > 0 else 0.0

    spread_info = {
        "samples": [int(round(s)) for s in rps_samples],
        "min": min_rps,
        "max": max_rps,
        "spread_pct": spread_pct,
    }

    return avg_rps, spread_info, cpu_pct


def measure_60k_backends_memory(target_dir: Path) -> float:
    """Run request_allocations 60k backends test and return memory in MB."""
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target_dir)
    cmd = [
        "cargo", "test", "-p", "ibex-rt", "--test", "request_allocations",
        "sixty_thousand_backends_memory_bounded", "--", "--nocapture"
    ]
    res = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"60k backend test failed: {res.stderr}\n{res.stdout}")

    m = re.search(r"60,000 backends:.*?bytes\s*\(([\d\.]+)\s*MB\)", res.stdout)
    if not m:
        raise ValueError(f"Could not parse 60k backend memory measurement: {res.stdout}")

    return round(float(m.group(1)), 2)


def measure_vtc_board(target_dir: Path) -> Dict[str, int]:
    """Run HAProxy VTC regression test runner and return scoreboard metrics."""
    if not VTC_RUNNER.exists():
        raise FileNotFoundError(f"VTC runner not found at {VTC_RUNNER}")
    if not VTC_TESTS_DIR.exists():
        raise FileNotFoundError(f"VTC tests directory not found at {VTC_TESTS_DIR}")

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json_tmp = tf.name

    ibex_bin = ensure_ibex_binary(target_dir, profile="release")
    cmd = [sys.executable, str(VTC_RUNNER), str(VTC_TESTS_DIR), "--binary", str(ibex_bin), "--json", json_tmp]

    try:
        subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
        if not os.path.exists(json_tmp):
            raise FileNotFoundError(f"VTC runner JSON not created at {json_tmp}")

        with open(json_tmp, "r", encoding="utf-8") as f:
            data = json.load(f)

        return {
            "pass": data.get("passed", 0),
            "fail": data.get("failed", 0),
            "skip": data.get("skipped", 0),
            "scope": data.get("out_of_scope", 0),
        }
    finally:
        if os.path.exists(json_tmp):
            os.remove(json_tmp)


def generate_flamegraph(target_dir: Path, duration: int = 30) -> Tuple[Path, List[Tuple[str, float]]]:
    """
    Profile Ibex under livepatch/frame-pointer profile with perf and generate flamegraph.
    Returns (svg_path, top_5_frames).
    """
    fe_port = get_free_port()
    be_port = get_free_port()
    while be_port == fe_port:
        be_port = get_free_port()

    bench_bin = ensure_parity_bench_binary(target_dir)
    ibex_bin = ensure_ibex_binary(target_dir, profile="livepatch")
    git_info = get_git_info()
    sha_short = git_info["sha"][:8]

    out_dir = REPO_ROOT / "tools" / "measure"
    out_dir.mkdir(parents=True, exist_ok=True)
    svg_path = out_dir / f"flame-{sha_short}.svg"
    perf_data = Path(tempfile.gettempdir()) / f"perf_{sha_short}_{int(time.time())}.data"

    cfg_content = f"""defaults
    mode http
    timeout client 10s
    timeout server 10s
    timeout connect 5s

frontend fe
    bind 127.0.0.1:{fe_port}
    default_backend be

backend be
    server s1 127.0.0.1:{be_port}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as tf:
        tf.write(cfg_content)
        cfg_path = tf.name

    be_proc = None
    proxy_proc = None
    load_proc = None
    top_frames: List[Tuple[str, float]] = []

    try:
        be_proc = subprocess.Popen([str(bench_bin), "backend", str(be_port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.15)
        proxy_proc = subprocess.Popen([str(ibex_bin), "-f", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.3)

        if proxy_proc.poll() is not None:
            raise RuntimeError(f"ibex proxy failed to start (exit {proxy_proc.returncode})")

        # Start continuous load for duration + 5s
        load_proc = subprocess.Popen(
            [str(bench_bin), "client", f"127.0.0.1:{fe_port}", "50", str(duration + 5)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1.0) # Let load ramp up

        print(f"[*] Recording perf profile for {duration}s on pid {proxy_proc.pid}...")
        perf_cmd = ["perf", "record", "-F", "999", "-g", "-p", str(proxy_proc.pid), "-o", str(perf_data), "--", "sleep", str(duration)]
        perf_res = subprocess.run(perf_cmd, capture_output=True, text=True)
        if perf_res.returncode != 0:
            raise RuntimeError(f"perf record failed: {perf_res.stderr}\n{perf_res.stdout}")

        print(f"[*] Collapsing stacks with inferno...")
        script_proc = subprocess.Popen(["perf", "script", "-i", str(perf_data)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        collapse_proc = subprocess.Popen(["inferno-collapse-perf"], stdin=script_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        script_proc.stdout.close() # Allow script_proc to receive a SIGPIPE if collapse_proc exits

        folded_output, collapse_err = collapse_proc.communicate()
        if collapse_proc.returncode != 0:
            raise RuntimeError(f"inferno-collapse-perf failed: {collapse_err.decode()}")

        print(f"[*] Rendering flamegraph SVG ({svg_path})...")
        flame_proc = subprocess.Popen(["inferno-flamegraph"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        svg_output, flame_err = flame_proc.communicate(input=folded_output)
        if flame_proc.returncode != 0:
            raise RuntimeError(f"inferno-flamegraph failed: {flame_err.decode()}")

        with open(svg_path, "wb") as f:
            f.write(svg_output)

        # Parse SVG title elements to extract top meaningful frames
        import html
        svg_text = svg_output.decode("utf-8", errors="replace")
        matches = re.findall(r"<title>(.*?)\s*\(([\d,]+)\s+samples,\s*([\d\.]+)%\)</title>", svg_text)
        seen = set()
        candidates = []
        skip_prefixes = ("__GI_", "start_thread", "all", "ibex", "[unknown]")
        for frame_raw, samples_str, pct_str in matches:
            frame = html.unescape(frame_raw).strip()
            if (frame in seen or any(frame.startswith(p) for p in skip_prefixes)
                or "Thread>::new" in frame or "call_once" in frame or "ibex::main" in frame
                or "FnOnce<()" in frame or "Layout>::for_value" in frame or "size_of_val" in frame):
                continue
            seen.add(frame)
            samples = int(samples_str.replace(",", ""))
            pct = float(pct_str)
            candidates.append((frame, pct))

        candidates.sort(key=lambda x: x[1], reverse=True)
        top_frames = candidates[:5]

    finally:
        if load_proc:
            load_proc.terminate()
            load_proc.wait(timeout=1)
        if proxy_proc:
            proxy_proc.terminate()
            proxy_proc.wait(timeout=1)
        if be_proc:
            be_proc.terminate()
            be_proc.wait(timeout=1)
        if os.path.exists(cfg_path):
            os.remove(cfg_path)
        if perf_data.exists():
            perf_data.unlink()

    return svg_path, top_frames


def load_previous_measurements(jsonl_path: Path) -> List[Dict[str, Any]]:
    """Load all records from measurements.jsonl."""
    if not jsonl_path.exists():
        return []
    records = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except Exception:
                    pass
    return records


def find_most_recent_metric(records: List[Dict[str, Any]], key: str) -> Optional[Any]:
    """Find the most recent non-null value for a specific key across records."""
    for r in reversed(records):
        val = r.get(key)
        if val is not None:
            return val
    return None


def check_regressions(
    current: Dict[str, Any],
    previous: Optional[Dict[str, Any]],
    records: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[List[MetricDelta], Verdict]:
    """
    Compare current measurements against previous recorded values and evaluate thresholds:
    - allocations per request: any increase is regression
    - bytes per request: > 10% increase is regression
    - vtc pass count: any decrease is regression
    - rps (1-conn & 50-conn): > 15% decrease is regression
    - binary size / text size: > 5% increase is regression
    - 60k backend memory: > 10% increase or > 20 MB is regression
    """
    deltas: List[MetricDelta] = []
    has_regression = False

    def get_prev_val(key: str) -> Optional[Any]:
        if previous and key in previous and previous[key] is not None:
            return previous[key]
        if records:
            return find_most_recent_metric(records, key)
        return None

    # 1. Allocations per request
    if "allocs_per_request" in current and current["allocs_per_request"] is not None:
        c = current["allocs_per_request"]
        p = get_prev_val("allocs_per_request")
        if p is None:
            deltas.append(MetricDelta("allocs_per_request", "Allocations / req", c, "N/A", "baseline", "PASS", False, "allocs"))
        else:
            diff = c - p
            diff_str = f"+{diff}" if diff > 0 else str(diff)
            is_reg = c > p
            if is_reg:
                has_regression = True
            status = "FAIL (regression)" if is_reg else "PASS"
            deltas.append(MetricDelta("allocs_per_request", "Allocations / req", c, p, diff_str, status, is_reg, "allocs"))

    # 2. Bytes per request
    if "bytes_per_request" in current and current["bytes_per_request"] is not None:
        c = current["bytes_per_request"]
        p = get_prev_val("bytes_per_request")
        if p is None:
            deltas.append(MetricDelta("bytes_per_request", "Bytes / req", c, "N/A", "baseline", "PASS", False, "B"))
        else:
            pct_diff = ((c - p) / p) * 100.0 if p > 0 else 0.0
            diff_str = f"{pct_diff:+.1f}%"
            is_reg = pct_diff > 10.0 # > 10% increase
            if is_reg:
                has_regression = True
            status = "FAIL (>10% inc)" if is_reg else "PASS"
            deltas.append(MetricDelta("bytes_per_request", "Bytes / req", c, p, diff_str, status, is_reg, "B"))

    # 3. 1-conn Throughput
    if "rps_1conn" in current and current["rps_1conn"] is not None:
        c = current["rps_1conn"]
        p = get_prev_val("rps_1conn")
        if p is None:
            deltas.append(MetricDelta("rps_1conn", "1-conn Throughput", f"{c:,}", "N/A", "baseline", "PASS", False, "req/s"))
        else:
            pct_diff = ((c - p) / p) * 100.0 if p > 0 else 0.0
            diff_str = f"{pct_diff:+.1f}%"
            is_reg = pct_diff < -15.0 # > 15% drop
            if is_reg:
                has_regression = True
            status = "FAIL (>15% drop)" if is_reg else "PASS"
            deltas.append(MetricDelta("rps_1conn", "1-conn Throughput", f"{c:,}", f"{p:,}", diff_str, status, is_reg, "req/s"))

    # 4. 50-conn Throughput
    if "rps_50conn" in current and current["rps_50conn"] is not None:
        c = current["rps_50conn"]
        p = get_prev_val("rps_50conn")
        if p is None:
            deltas.append(MetricDelta("rps_50conn", "50-conn Throughput", f"{c:,}", "N/A", "baseline", "PASS", False, "req/s"))
        else:
            pct_diff = ((c - p) / p) * 100.0 if p > 0 else 0.0
            diff_str = f"{pct_diff:+.1f}%"
            is_reg = pct_diff < -15.0 # > 15% drop
            if is_reg:
                has_regression = True
            status = "FAIL (>15% drop)" if is_reg else "PASS"
            deltas.append(MetricDelta("rps_50conn", "50-conn Throughput", f"{c:,}", f"{p:,}", diff_str, status, is_reg, "req/s"))

    # 5. 50-conn CPU %
    if "cpu_pct_50conn" in current and current["cpu_pct_50conn"] is not None:
        c = current["cpu_pct_50conn"]
        p = get_prev_val("cpu_pct_50conn")
        diff_str = f"{(c - p):+.1f}%" if p is not None else "baseline"
        deltas.append(MetricDelta("cpu_pct_50conn", "50-conn CPU", f"{c}%", f"{p}%" if p is not None else "N/A", diff_str, "PASS", False, ""))

    # 6. VTC Regression Board
    if "board" in current and current["board"] is not None:
        c_board = current["board"]
        c_pass = c_board.get("pass", 0)
        p_board = get_prev_val("board")
        p_pass = p_board.get("pass") if p_board else None
        if p_pass is None:
            deltas.append(MetricDelta("vtc_pass", "VTC Reg-tests Pass", c_pass, "N/A", "baseline", "PASS", False, "tests",
                                      details=f"Fail: {c_board.get('fail')}, Skip: {c_board.get('skip')}, Scope: {c_board.get('scope')}"))
        else:
            diff = c_pass - p_pass
            diff_str = f"+{diff}" if diff > 0 else str(diff)
            is_reg = c_pass < p_pass # Any decrease is regression
            if is_reg:
                has_regression = True
            status = "FAIL (pass dropped)" if is_reg else "PASS"
            deltas.append(MetricDelta("vtc_pass", "VTC Reg-tests Pass", c_pass, p_pass, diff_str, status, is_reg, "tests",
                                      details=f"Fail: {c_board.get('fail')}, Skip: {c_board.get('skip')}, Scope: {c_board.get('scope')}"))

    # 7. Binary Size
    if "binary_bytes" in current and current["binary_bytes"] is not None:
        c = current["binary_bytes"]
        p = get_prev_val("binary_bytes")
        c_mb = round(c / (1024 * 1024), 2)
        p_mb = round(p / (1024 * 1024), 2) if p else None
        if p is None:
            deltas.append(MetricDelta("binary_bytes", "Binary Size", f"{c_mb} MB", "N/A", "baseline", "PASS", False, ""))
        else:
            pct_diff = ((c - p) / p) * 100.0 if p > 0 else 0.0
            diff_str = f"{pct_diff:+.1f}%"
            is_reg = pct_diff > 5.0 # > 5% increase
            if is_reg:
                has_regression = True
            status = "FAIL (>5% inc)" if is_reg else "PASS"
            deltas.append(MetricDelta("binary_bytes", "Binary Size", f"{c_mb} MB", f"{p_mb} MB", diff_str, status, is_reg, ""))

    # 8. Text Section Size
    if "text_bytes" in current and current["text_bytes"] is not None:
        c = current["text_bytes"]
        p = get_prev_val("text_bytes")
        c_mb = round(c / (1024 * 1024), 2)
        p_mb = round(p / (1024 * 1024), 2) if p else None
        if p is None:
            deltas.append(MetricDelta("text_bytes", "Text Section Size", f"{c_mb} MB", "N/A", "baseline", "PASS", False, ""))
        else:
            pct_diff = ((c - p) / p) * 100.0 if p > 0 else 0.0
            diff_str = f"{pct_diff:+.1f}%"
            is_reg = pct_diff > 5.0 # > 5% increase
            if is_reg:
                has_regression = True
            status = "FAIL (>5% inc)" if is_reg else "PASS"
            deltas.append(MetricDelta("text_bytes", "Text Section Size", f"{c_mb} MB", f"{p_mb} MB", diff_str, status, is_reg, ""))

    # 9. 60k Backend Memory
    if "mem_60k_backends_mb" in current and current["mem_60k_backends_mb"] is not None:
        c = current["mem_60k_backends_mb"]
        p = get_prev_val("mem_60k_backends_mb")
        if p is None:
            deltas.append(MetricDelta("mem_60k_backends_mb", "60k Backend Memory", f"{c} MB", "N/A", "baseline", "PASS", False, ""))
        else:
            pct_diff = ((c - p) / p) * 100.0 if p > 0 else 0.0
            diff_str = f"{pct_diff:+.1f}%"
            is_reg = (pct_diff > 10.0) or (c > 20.0)
            if is_reg:
                has_regression = True
            status = "FAIL (>10% inc / >20MB)" if is_reg else "PASS"
            deltas.append(MetricDelta("mem_60k_backends_mb", "60k Backend Memory", f"{c} MB", f"{p} MB", diff_str, status, is_reg, ""))

    # 10. HAProxy 1-conn & 50-conn (Info)
    if "haproxy_rps_1conn" in current and current["haproxy_rps_1conn"] is not None:
        c = current["haproxy_rps_1conn"]
        p = get_prev_val("haproxy_rps_1conn")
        diff_str = f"{((c - p) / p) * 100.0:+.1f}%" if p else "baseline"
        deltas.append(MetricDelta("haproxy_rps_1conn", "HAProxy 1-conn Throughput", f"{c:,}", f"{p:,}" if p else "N/A", diff_str, "INFO", False, "req/s"))

    if "haproxy_rps_50conn" in current and current["haproxy_rps_50conn"] is not None:
        c = current["haproxy_rps_50conn"]
        p = get_prev_val("haproxy_rps_50conn")
        diff_str = f"{((c - p) / p) * 100.0:+.1f}%" if p else "baseline"
        deltas.append(MetricDelta("haproxy_rps_50conn", "HAProxy 50-conn Throughput", f"{c:,}", f"{p:,}" if p else "N/A", diff_str, "INFO", False, "req/s"))

    if previous is None and (not records or len(records) == 0):
        return deltas, Verdict.BASELINE

    return deltas, Verdict.FAIL if has_regression else Verdict.PASS


def render_diff_table(current: Dict[str, Any], deltas: List[MetricDelta], verdict: Verdict) -> str:
    """Render a clean human-readable diff table against the previous run."""
    lines = []
    lines.append("=" * 80)
    lines.append("                       IBEX CONTINUOUS MEASUREMENT")
    lines.append("=" * 80)
    lines.append(f"Git SHA:     {current.get('sha', 'unknown')[:12]} (dirty: {current.get('dirty', False)})")
    lines.append(f"Timestamp:   {current.get('at', 'unknown')}")
    lines.append(f"System Load: {current.get('load_1min', 0.0):.2f} (1-min avg), Active AGY sessions: {current.get('agy_count', 0)}")
    lines.append("")
    lines.append(f"{'Metric':<28} {'Current':>14} {'Previous':>14} {'Delta':>10}   {'Status':<10}")
    lines.append("-" * 80)

    for d in deltas:
        cur_str = str(d.current)
        prev_str = str(d.previous)
        lines.append(f"{d.label:<28} {cur_str:>14} {prev_str:>14} {d.delta_str:>10}   {d.status:<10}")
        if d.details:
            lines.append(f"  ({d.details})")

    lines.append("-" * 80)
    reg_count = sum(1 for d in deltas if d.is_regression)
    if verdict == Verdict.PASS:
        lines.append(f"Verdict: PASS (0 regressions detected)")
    elif verdict == Verdict.BASELINE:
        lines.append(f"Verdict: BASELINE (recorded as initial baseline)")
    else:
        lines.append(f"Verdict: FAIL ({reg_count} regression{'s' if reg_count != 1 else ''} detected!)")
    lines.append("=" * 80)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Ibex Continuous Measurement Suite")
    parser.add_argument("--fast", action="store_true", help="Run fast suite under 60s (allocs, binary size, 1-conn rps)")
    parser.add_argument("--full", action="store_true", help="Run full suite (adds VTC board, 50-conn rps, 60k mem, HAProxy)")
    parser.add_argument("--flame", action="store_true", help="Produce flamegraph for a 30s load run using perf and inferno")
    parser.add_argument("--flame-duration", type=int, default=30, help="Duration in seconds for flamegraph profiling (default: 30)")
    parser.add_argument("--no-save", action="store_true", help="Do not append results to data/measurements.jsonl")
    parser.add_argument("--target-dir", help="Custom cargo target directory")
    parser.add_argument("--json-out", help="Write snapshot JSON to custom path")

    args = parser.parse_args()

    target_dir = get_target_dir(args.target_dir)

    # If --flame is specified, generate flamegraph and report top 5 frames
    if args.flame:
        print("==> Running Flamegraph Profiling Mode (--flame)...")
        start_t = time.monotonic()
        svg_path, top_frames = generate_flamegraph(target_dir, duration=args.flame_duration)
        elapsed = time.monotonic() - start_t
        print("\n" + "=" * 80)
        print(f"Flamegraph generated successfully in {elapsed:.1f}s:")
        print(f"Path: {svg_path}")
        print("\nTop 5 Frames by Sample %:")
        for idx, (frame, pct) in enumerate(top_frames, 1):
            print(f"  {idx}. {pct:5.2f}%  {frame}")
        print("=" * 80)
        return 0

    mode_full = args.full
    # Default to fast if neither mode specified
    mode_fast = args.fast or (not mode_full)

    mode_label = "FULL" if mode_full else "FAST"
    print(f"==> Starting Ibex Continuous Measurement Suite [{mode_label} mode]...")
    start_total_t = time.monotonic()

    git_info = get_git_info()
    sys_info = get_system_metrics()

    record: Dict[str, Any] = {
        "sha": git_info["sha"],
        "at": git_info["at"],
        "dirty": git_info["dirty"],
    }

    # Step 1: Allocations per request
    print("[1/5] Measuring allocations per request (tools/allocprofile)...")
    allocs, bytes_per_req, _ = run_alloc_profile(target_dir)
    record["allocs_per_request"] = allocs
    record["bytes_per_request"] = bytes_per_req

    # Step 2: Binary & Section size
    print("[2/5] Measuring ibex binary and .text section size...")
    ibex_bin = ensure_ibex_binary(target_dir, profile="release")
    bin_bytes, text_bytes = measure_binary_size(ibex_bin)
    record["binary_bytes"] = bin_bytes
    record["text_bytes"] = text_bytes

    # Step 3: 1-connection throughput
    print("[3/5] Measuring 1-connection keep-alive throughput (ibex rps_1conn)...")
    rps_1, rps_1_spread, _ = measure_throughput("ibex", conns=1, target_dir=target_dir, ibex_bin=ibex_bin)
    record["rps_1conn"] = rps_1
    record["rps_1conn_spread"] = rps_1_spread

    # Record system metrics
    record["load_1min"] = sys_info["load_1min"]
    record["agy_count"] = sys_info["agy_count"]

    # If full mode: add 50-conn, 60k backend memory, HAProxy oracle, and VTC board
    if mode_full:
        print("[4/5] Measuring 50-connection throughput and CPU % (ibex rps_50conn)...")
        rps_50, rps_50_spread, cpu_50 = measure_throughput("ibex", conns=50, target_dir=target_dir, ibex_bin=ibex_bin)
        record["rps_50conn"] = rps_50
        record["rps_50conn_spread"] = rps_50_spread
        record["cpu_pct_50conn"] = cpu_50

        print("      Measuring 60,000 backend memory footprint...")
        mem_60k = measure_60k_backends_memory(target_dir)
        record["mem_60k_backends_mb"] = mem_60k

        print("      Measuring HAProxy side-by-side throughput...")
        ha_rps_1, ha_rps_1_spread, _ = measure_throughput("haproxy", conns=1, target_dir=target_dir)
        ha_rps_50, ha_rps_50_spread, _ = measure_throughput("haproxy", conns=50, target_dir=target_dir)
        record["haproxy_rps_1conn"] = ha_rps_1
        record["haproxy_rps_1conn_spread"] = ha_rps_1_spread
        record["haproxy_rps_50conn"] = ha_rps_50
        record["haproxy_rps_50conn_spread"] = ha_rps_50_spread

        print("[5/5] Running VTC regression test suite (harness/vtc_runner.py)...")
        board = measure_vtc_board(target_dir)
        record["board"] = board
    else:
        print("[4/5] Skipping full-suite metrics (use --full for VTC, 50-conn, 60k backends, HAProxy)")
        print("[5/5] Completing fast measurement...")

    total_wall_time = time.monotonic() - start_total_t

    # Load history and compare
    history = load_previous_measurements(MEASUREMENTS_JSONL)
    prev_record = history[-1] if history else None

    deltas, verdict = check_regressions(record, prev_record, records=history)
    diff_table = render_diff_table(record, deltas, verdict)

    print("\n" + diff_table)
    print(f"Total Wall Time: {total_wall_time:.2f}s\n")

    # Append to measurements.jsonl
    if not args.no_save:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(MEASUREMENTS_JSONL, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        print(f"[+] Appended measurement record to: {MEASUREMENTS_JSONL}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)

    return 0 if verdict in (Verdict.PASS, Verdict.BASELINE) else 1


if __name__ == "__main__":
    sys.exit(main())
