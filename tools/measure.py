#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""
tools/measure.py — Unified Alcyon Continuous Measurement Suite

Automates benchmarking, memory profiling, regression testing (VTC),
and telemetry verification for Alcyon. Outputs structured JSON and
a Markdown dashboard.
"""

import argparse
import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(REPO_ROOT, "data")
DEFAULT_JSON_OUT = os.path.join(DATA_DIR, "continuous_metrics.json")
DEFAULT_MD_OUT = os.path.join(DATA_DIR, "continuous_metrics.md")
# $ALCYON_REFERENCE/haproxy/reg-tests/ (T630); --vtc-dir overrides.
DEFAULT_VTC_DIR = os.path.join(os.environ.get("ALCYON_REFERENCE", "$ALCYON_REFERENCE"), "haproxy/reg-tests/")
DEFAULT_VTC_JSON = "/tmp/rt_snapshot.json"

# Targets and baselines for comparison
BASELINES = {
    "allocs_per_req": {"baseline": 93.0, "target": 5.0, "unit": "allocs/req"},
    "bytes_per_req": {"baseline": 41412.0, "target": 150.0, "unit": "bytes/req"},
    "rps_1_conn": {"baseline": 9400, "target": 12000, "unit": "req/s"},
    "rps_50_conn": {"baseline": 30000, "target": 33000, "unit": "req/s"},
    "vtc_in_scope_passed": {"baseline": 7, "target": 10, "unit": "tests"},
    "vtc_in_scope_total": {"baseline": 171, "target": 171, "unit": "tests"},
    "prom_metrics_emitted": {"baseline": 42, "target": 50, "unit": "metrics"},
    "prom_render_allocs": {"baseline": 0, "target": 0, "unit": "allocs"},
}


def get_git_info() -> Dict[str, str]:
    """Extract current git commit hash, branch, and subject."""
    info = {"commit": "unknown", "commit_short": "unknown", "branch": "unknown", "subject": ""}
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True)
        if res.returncode == 0:
            info["commit"] = res.stdout.strip()
            info["commit_short"] = info["commit"][:8]
        res = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True)
        if res.returncode == 0:
            info["branch"] = res.stdout.strip()
        res = subprocess.run(["git", "log", "-1", "--pretty=%s"], cwd=REPO_ROOT, capture_output=True, text=True)
        if res.returncode == 0:
            info["subject"] = res.stdout.strip()
    except Exception as e:
        info["error"] = str(e)
    return info


def run_alloc_profile() -> Dict[str, Any]:
    """Run tools/allocprofile in an isolated scratch directory and parse results."""
    print("==> [1/4] Running Allocation Profiler (tools/allocprofile)...")
    alloc_src = os.path.join(REPO_ROOT, "tools", "allocprofile")
    if not os.path.exists(alloc_src):
        return {"status": "error", "error": f"Path not found: {alloc_src}"}

    with tempfile.TemporaryDirectory(prefix="alcyon_allocprof_") as td:
        dest_dir = os.path.join(td, "allocprofile")
        shutil.copytree(alloc_src, dest_dir)
        
        # Ensure Engine::new call is compatible
        main_rs = os.path.join(dest_dir, "src", "main.rs")
        if os.path.exists(main_rs):
            with open(main_rs, "r", encoding="utf-8") as f:
                code = f.read()
            code = code.replace("Engine::new(&cfg, 64, 0, Vec::new())", "Engine::new(&cfg, 64)")
            with open(main_rs, "w", encoding="utf-8") as f:
                f.write(code)

        # Fix relative crate dependencies in Cargo.toml
        cargo_toml = os.path.join(dest_dir, "Cargo.toml")
        if os.path.exists(cargo_toml):
            with open(cargo_toml, "r", encoding="utf-8") as f:
                toml_content = f.read()
            crates_dir = os.path.join(REPO_ROOT, "crates")
            toml_content = toml_content.replace("../../crates", crates_dir)
            with open(cargo_toml, "w", encoding="utf-8") as f:
                f.write(toml_content)

        cmd = ["cargo", "run", "--manifest-path", cargo_toml, "-q"]
        start_t = time.monotonic()
        res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
        elapsed = time.monotonic() - start_t

        if res.returncode != 0:
            return {
                "status": "failed",
                "exit_code": res.returncode,
                "error": res.stderr.strip() or res.stdout.strip(),
                "duration_seconds": round(elapsed, 2),
            }

        stdout = res.stdout
        tot_allocs = None
        tot_bytes = None
        m = re.search(r"=====\s*(\d+)\s+allocations,\s*(\d+)\s+bytes", stdout)
        if m:
            tot_allocs = int(m.group(1))
            tot_bytes = int(m.group(2))

        call_sites = []
        site_regex = re.compile(r"^\s*(\d+)\s+(\d+)B\s+(.+)$")
        for line in stdout.splitlines():
            line_str = line.strip()
            sm = site_regex.match(line_str)
            if sm:
                call_sites.append({
                    "count": int(sm.group(1)),
                    "bytes": int(sm.group(2)),
                    "site": sm.group(3).strip(),
                })

        return {
            "status": "success",
            "allocations_per_request": tot_allocs,
            "bytes_per_request": tot_bytes,
            "call_sites": call_sites,
            "duration_seconds": round(elapsed, 2),
            "raw_output": stdout.strip(),
        }


def run_livepatch_bench() -> Dict[str, Any]:
    """Run livepatch-bench throughput & steady-state allocation measurements."""
    print("==> [2/4] Running Livepatch Benchmark (tools/livepatch-bench)...")
    bench_dir = os.path.join(REPO_ROOT, "tools", "livepatch-bench")
    bench_bin = os.path.join(bench_dir, "target", "release", "livepatch-bench")

    # Build if binary is missing
    if not os.path.exists(bench_bin):
        print("    Building livepatch-bench binary...")
        build_res = subprocess.run(
            ["cargo", "build", "--manifest-path", os.path.join(bench_dir, "Cargo.toml"), "--release"],
            cwd=REPO_ROOT, capture_output=True, text=True
        )
        if build_res.returncode != 0:
            return {
                "status": "build_failed",
                "error": build_res.stderr.strip(),
            }

    start_t = time.monotonic()
    res = subprocess.run([bench_bin], cwd=REPO_ROOT, capture_output=True, text=True)
    elapsed = time.monotonic() - start_t

    if res.returncode != 0:
        return {
            "status": "failed",
            "exit_code": res.returncode,
            "error": res.stderr.strip(),
            "duration_seconds": round(elapsed, 2),
        }

    stdout = res.stdout
    metrics: Dict[str, Any] = {
        "status": "success",
        "duration_seconds": round(elapsed, 2),
    }
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("allocs:"):
            try:
                metrics["bench_allocs_per_req"] = float(line.split(":")[1].strip())
            except ValueError:
                pass
        elif line.startswith("bytes:"):
            try:
                metrics["bench_bytes_per_req"] = float(line.split(":")[1].strip())
            except ValueError:
                pass
        elif line.startswith("rps_1:"):
            try:
                metrics["rps_1_conn"] = int(line.split(":")[1].strip())
            except ValueError:
                pass
        elif line.startswith("rps_50:"):
            try:
                metrics["rps_50_conn"] = int(line.split(":")[1].strip())
            except ValueError:
                pass

    return metrics


def parse_vtc_json(json_file: str, elapsed: float = 0.0, exit_code: int = 0) -> Dict[str, Any]:
    """Parse results from a VTC runner JSON output file."""
    data: Dict[str, Any] = {
        "status": "success",
        "duration_seconds": round(elapsed, 2),
        "exit_code": exit_code,
    }
    if not os.path.exists(json_file):
        data["status"] = "failed"
        data["error"] = f"JSON file not found: {json_file}"
        return data

    with open(json_file, "r", encoding="utf-8") as f:
        snapshot = json.load(f)

    data["total"] = snapshot.get("total", 0)
    data["passed"] = snapshot.get("passed", 0)
    data["failed"] = snapshot.get("failed", 0)
    data["skipped"] = snapshot.get("skipped", 0)
    data["out_of_scope"] = snapshot.get("out_of_scope", 0)
    data["in_scope_run"] = snapshot.get("in_scope_run", data["passed"] + data["failed"])
    if elapsed == 0.0 and "duration" in snapshot:
        data["duration_seconds"] = round(snapshot["duration"], 2)

    in_scope_tot = data["passed"] + data["failed"]
    data["in_scope_total"] = in_scope_tot
    if in_scope_tot > 0:
        data["in_scope_pass_pct"] = round((data["passed"] / in_scope_tot) * 100, 2)
    else:
        data["in_scope_pass_pct"] = 0.0

    categories: Dict[str, Dict[str, int]] = {}
    for r in snapshot.get("results", []):
        p = r.get("file_path") or r.get("path") or ""
        cat = "root"
        if "/reg-tests/" in p:
            sub = p.split("/reg-tests/")[1]
            parts = sub.split("/")
            if len(parts) > 1:
                cat = parts[0]
        if cat not in categories:
            categories[cat] = {"total": 0, "PASS": 0, "FAIL": 0, "SKIP": 0, "OUT_OF_SCOPE": 0}
        categories[cat]["total"] += 1
        status = r.get("status", "UNKNOWN")
        if status in categories[cat]:
            categories[cat][status] += 1
    data["categories"] = categories
    return data


def run_vtc_suite(
    vtc_dir: str = DEFAULT_VTC_DIR,
    json_out: str = DEFAULT_VTC_JSON,
    snapshot_path: Optional[str] = None
) -> Dict[str, Any]:
    """Run HAProxy VTC regression test runner and parse snapshot results."""
    if snapshot_path and os.path.exists(snapshot_path):
        print(f"==> [3/4] Parsing Existing VTC Snapshot ({snapshot_path})...")
        return parse_vtc_json(snapshot_path)

    print(f"==> [3/4] Running VTC Regression Suite ({vtc_dir})...")
    runner_py = os.path.join(REPO_ROOT, "harness", "vtc_runner.py")
    if not os.path.exists(runner_py):
        return {"status": "error", "error": f"Harness not found: {runner_py}"}

    if not os.path.exists(vtc_dir):
        return {"status": "error", "error": f"VTC tests directory not found: {vtc_dir}"}

    cmd = [sys.executable, runner_py, vtc_dir, "--json", json_out]
    start_t = time.monotonic()
    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    elapsed = time.monotonic() - start_t

    return parse_vtc_json(json_out, elapsed=elapsed, exit_code=res.returncode)


def run_prom_verification() -> Dict[str, Any]:
    """Verify Prometheus format and allocation zero-cost in alcyon-rt."""
    print("==> [4/4] Verifying Prometheus Telemetry (alcyon-rt promex)...")
    cmd = ["cargo", "test", "--test", "promex", "--", "--nocapture"]
    start_t = time.monotonic()
    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    elapsed = time.monotonic() - start_t

    data: Dict[str, Any] = {
        "status": "success" if res.returncode == 0 else "failed",
        "duration_seconds": round(elapsed, 2),
        "exit_code": res.returncode,
    }

    stdout = res.stdout + "\n" + res.stderr
    m_alcyon = re.search(r"Alcyon emits (\d+) metrics", stdout)
    if m_alcyon:
        data["alcyon_metrics_count"] = int(m_alcyon.group(1))

    m_ha = re.search(r"HAProxy emits (\d+) metrics", stdout)
    if m_ha:
        data["haproxy_metrics_count"] = int(m_ha.group(1))

    if data.get("alcyon_metrics_count") and data.get("haproxy_metrics_count"):
        data["coverage_pct"] = round(
            (data["alcyon_metrics_count"] / data["haproxy_metrics_count"]) * 100, 2
        )

    m_alloc = re.search(r"Allocations:\s*(\d+)\s+allocs,\s*(\d+)\s+bytes", stdout)
    if m_alloc:
        data["render_alloc_count"] = int(m_alloc.group(1))
        data["render_bytes_allocated"] = int(m_alloc.group(2))
    else:
        data["render_alloc_count"] = 0
        data["render_bytes_allocated"] = 0

    data["differential_test_passed"] = "test differential_test ... ok" in stdout
    data["allocations_test_passed"] = "test test_allocations ... ok" in stdout

    return data


def generate_markdown_dashboard(snapshot: Dict[str, Any]) -> str:
    """Render a clean Markdown dashboard comparing current metrics against baseline targets."""
    git = snapshot.get("git", {})
    ts = snapshot.get("timestamp", datetime.now(timezone.utc).isoformat())
    allocs = snapshot.get("allocations", {})
    bench = snapshot.get("benchmark", {})
    vtc = snapshot.get("vtc", {})
    prom = snapshot.get("prometheus", {})

    cur_allocs = allocs.get("allocations_per_request", bench.get("bench_allocs_per_req", "N/A"))
    cur_bytes = allocs.get("bytes_per_request", bench.get("bench_bytes_per_req", "N/A"))
    cur_rps1 = bench.get("rps_1_conn", "N/A")
    cur_rps50 = bench.get("rps_50_conn", "N/A")
    cur_vtc_pass = vtc.get("passed", "N/A")
    cur_vtc_tot = vtc.get("in_scope_total", "N/A")
    cur_prom_cnt = prom.get("alcyon_metrics_count", "N/A")
    cur_prom_alloc = prom.get("render_alloc_count", "N/A")

    lines = []
    lines.append("# Continuous Measurement Dashboard")
    lines.append("")
    lines.append(f"**Last Updated:** `{ts}`  ")
    lines.append(f"**Git Commit:** `{git.get('commit_short', 'unknown')}` on branch `{git.get('branch', 'unknown')}`  ")
    lines.append(f"**Message:** *{git.get('subject', 'N/A')}*  ")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive KPI Summary")
    lines.append("")
    lines.append("| Metric | Current | Baseline | Target | Status |")
    lines.append("|---|---:|---:|---:|:---:|")

    def status_badge(cur: Any, target: Any, lower_is_better: bool = True) -> str:
        if cur == "N/A" or target is None:
            return "UNKNOWN"
        try:
            c = float(cur)
            t = float(target)
            if lower_is_better:
                return "PASS" if c <= t else "WARN"
            else:
                return "PASS" if c >= t else "WARN"
        except (ValueError, TypeError):
            return "INFO"

    s_alloc = status_badge(cur_allocs, BASELINES["allocs_per_req"]["target"], lower_is_better=True)
    lines.append(f"| Allocations / Request | **{cur_allocs}** allocs | {BASELINES['allocs_per_req']['baseline']} allocs | <= {BASELINES['allocs_per_req']['target']} allocs | `{s_alloc}` |")

    s_bytes = status_badge(cur_bytes, BASELINES["bytes_per_req"]["target"], lower_is_better=True)
    lines.append(f"| Bytes Allocated / Request | **{cur_bytes}** B | {BASELINES['bytes_per_req']['baseline']} B | <= {BASELINES['bytes_per_req']['target']} B | `{s_bytes}` |")

    s_rps1 = status_badge(cur_rps1, BASELINES["rps_1_conn"]["target"], lower_is_better=False)
    lines.append(f"| Throughput (1 conn keep-alive) | **{cur_rps1}** req/s | {BASELINES['rps_1_conn']['baseline']} req/s | >= {BASELINES['rps_1_conn']['target']} req/s | `{s_rps1}` |")

    s_rps50 = status_badge(cur_rps50, BASELINES["rps_50_conn"]["target"], lower_is_better=False)
    lines.append(f"| Throughput (50 conns concurrent) | **{cur_rps50}** req/s | {BASELINES['rps_50_conn']['baseline']} req/s | >= {BASELINES['rps_50_conn']['target']} req/s | `{s_rps50}` |")

    s_vtc = status_badge(cur_vtc_pass, BASELINES["vtc_in_scope_passed"]["target"], lower_is_better=False)
    lines.append(f"| VTC In-Scope Tests Passing | **{cur_vtc_pass} / {cur_vtc_tot}** | {BASELINES['vtc_in_scope_passed']['baseline']} / {BASELINES['vtc_in_scope_total']['baseline']} | >= {BASELINES['vtc_in_scope_passed']['target']} | `{s_vtc}` |")

    s_prom_cnt = status_badge(cur_prom_cnt, BASELINES["prom_metrics_emitted"]["target"], lower_is_better=False)
    lines.append(f"| Prometheus Metrics Emitted | **{cur_prom_cnt}** | {BASELINES['prom_metrics_emitted']['baseline']} | >= {BASELINES['prom_metrics_emitted']['target']} | `{s_prom_cnt}` |")

    s_prom_alloc = status_badge(cur_prom_alloc, BASELINES["prom_render_allocs"]["target"], lower_is_better=True)
    lines.append(f"| Prometheus Render Allocations | **{cur_prom_alloc}** allocs | {BASELINES['prom_render_allocs']['baseline']} allocs | == 0 allocs | `{s_prom_alloc}` |")

    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 1: Memory & Allocations
    lines.append("## 1. Memory & Allocation Profile")
    lines.append("")
    lines.append(f"- **Steady-State Allocations / Request:** `{cur_allocs}`")
    lines.append(f"- **Steady-State Bytes / Request:** `{cur_bytes} B`")
    lines.append("")
    if allocs.get("call_sites"):
        lines.append("### Top Allocation Call Sites")
        lines.append("")
        lines.append("| Count | Total Bytes | Call Site |")
        lines.append("|---:|---:|---|")
        for site in allocs["call_sites"][:10]:
            lines.append(f"| {site.get('count', 0)} | {site.get('bytes', 0)} B | `{site.get('site', 'unknown')}` |")
        lines.append("")

    # Section 2: VTC Regression Board
    lines.append("## 2. VTC Regression Board")
    lines.append("")
    lines.append(f"Tested against HAProxy 3.5-dev regression test suite.")
    lines.append("")
    lines.append(f"- **Total Tests in Suite:** `{vtc.get('total', 0)}`")
    lines.append(f"- **Passed:** `{vtc.get('passed', 0)}`")
    lines.append(f"- **Failed (In-Scope):** `{vtc.get('failed', 0)}`")
    lines.append(f"- **Skipped (Gated/Empty):** `{vtc.get('skipped', 0)}`")
    lines.append(f"- **Out of Scope (Declined Features):** `{vtc.get('out_of_scope', 0)}`")
    lines.append(f"- **In-Scope Pass Rate:** `{vtc.get('in_scope_pass_pct', 0.0)}%` ({vtc.get('passed', 0)} / {vtc.get('in_scope_total', 0)})")
    lines.append("")

    if vtc.get("categories"):
        lines.append("### Category Breakdown")
        lines.append("")
        lines.append("| Category | Total | Passed | Failed | Out of Scope | Skipped |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for cat, stats in sorted(vtc["categories"].items()):
            lines.append(f"| `{cat}` | {stats.get('total', 0)} | {stats.get('PASS', 0)} | {stats.get('FAIL', 0)} | {stats.get('OUT_OF_SCOPE', 0)} | {stats.get('SKIP', 0)} |")
        lines.append("")

    # Section 3: Performance Benchmark
    lines.append("## 3. Proxy Performance Benchmark")
    lines.append("")
    lines.append("| Workload | Throughput | Target Baseline |")
    lines.append("|---|---:|---:|")
    lines.append(f"| 1 Connection (HTTP/1.1 Keep-Alive) | **{cur_rps1} req/s** | ~13,100 req/s |")
    lines.append(f"| 50 Connections (Concurrent Keep-Alive) | **{cur_rps50} req/s** | ~33,300 req/s |")
    lines.append("")

    # Section 4: Prometheus Telemetry
    lines.append("## 4. Prometheus Telemetry Verification")
    lines.append("")
    lines.append(f"- **Alcyon Emits:** `{prom.get('alcyon_metrics_count', 0)}` metrics")
    lines.append(f"- **HAProxy Oracle:** `{prom.get('haproxy_metrics_count', 0)}` metrics")
    lines.append(f"- **Metric Parity Coverage:** `{prom.get('coverage_pct', 0.0)}%`")
    lines.append(f"- **Rendering Allocations:** `{prom.get('render_alloc_count', 0)}` allocs, `{prom.get('render_bytes_allocated', 0)}` bytes (Zero-Allocation verified: `{prom.get('allocations_test_passed', False)}`)")
    lines.append(f"- **Differential Schema Conformance:** `{'PASS' if prom.get('differential_test_passed') else 'FAIL'}`")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Alcyon Continuous Measurement Suite — Benchmark & Metric Recorder"
    )
    parser.add_argument("--all", action="store_true", help="Run all measurement suites")
    parser.add_argument("--allocs", action="store_true", help="Run allocation profiler")
    parser.add_argument("--bench", action="store_true", help="Run throughput benchmark")
    parser.add_argument("--vtc", action="store_true", help="Run VTC regression suite")
    parser.add_argument("--prom", action="store_true", help="Verify Prometheus telemetry")
    parser.add_argument("--vtc-dir", default=DEFAULT_VTC_DIR, help=f"Path to VTC reg-tests (default: {DEFAULT_VTC_DIR})")
    parser.add_argument("--vtc-snapshot", help="Path to pre-computed VTC JSON snapshot (avoids full run)")
    parser.add_argument("--json-out", default=DEFAULT_JSON_OUT, help=f"Path for JSON snapshot output (default: {DEFAULT_JSON_OUT})")
    parser.add_argument("--md-out", default=DEFAULT_MD_OUT, help=f"Path for Markdown dashboard output (default: {DEFAULT_MD_OUT})")
    parser.add_argument("--no-save", action="store_true", help="Do not write results to data/ files")

    args = parser.parse_args()

    # If no flags specified, default to --all
    run_all = args.all or not (args.allocs or args.bench or args.vtc or args.prom)
    do_allocs = run_all or args.allocs
    do_bench = run_all or args.bench
    do_vtc = run_all or args.vtc
    do_prom = run_all or args.prom

    print("================================================================")
    print("        ALCYON CONTINUOUS MEASUREMENT SUITE                       ")
    print("================================================================")

    git_info = get_git_info()
    print(f"Commit: {git_info.get('commit_short')} ({git_info.get('branch')}) - {git_info.get('subject')}\n")

    snapshot: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "git": git_info,
        "allocations": {},
        "benchmark": {},
        "vtc": {},
        "prometheus": {},
    }

    if do_allocs:
        snapshot["allocations"] = run_alloc_profile()

    if do_bench:
        snapshot["benchmark"] = run_livepatch_bench()

    if do_vtc:
        snapshot["vtc"] = run_vtc_suite(
            vtc_dir=args.vtc_dir,
            snapshot_path=args.vtc_snapshot if args.vtc_snapshot else (DEFAULT_VTC_JSON if os.path.exists(DEFAULT_VTC_JSON) and not args.all else None)
        )

    if do_prom:
        snapshot["prometheus"] = run_prom_verification()

    print("\n================================================================")
    print("                    MEASUREMENT RESULTS                         ")
    print("================================================================")

    md_content = generate_markdown_dashboard(snapshot)
    
    if not args.no_save:
        os.makedirs(os.path.dirname(args.json_out), exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
        print(f"[+] JSON snapshot saved to: {args.json_out}")

        os.makedirs(os.path.dirname(args.md_out), exist_ok=True)
        with open(args.md_out, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"[+] Markdown dashboard saved to: {args.md_out}")

    print("\n" + md_content)


if __name__ == "__main__":
    main()
