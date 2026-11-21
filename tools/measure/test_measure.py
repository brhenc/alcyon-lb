#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""
Unit tests for Alcyon Continuous Measurement regression detector.
"""

import os
import signal
import subprocess
import sys
import tempfile
import unittest

# The gate runs `cd tools/measure && python3 -m unittest test_measure`; the file also runs
# directly as `python3 -I tools/measure/test_measure.py`, and -I (--safe-path) keeps this
# directory off sys.path, so find measure.py by the file's own location.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from measure import (check_regressions, MetricDelta, Verdict, reference_sha, split_modes,
                     parse_insreq, min_ins_per_req, host_problems, load_previous_measurements)
from h3board import board, render


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                          text=True).stdout.strip()


class TestReferenceSha(unittest.TestCase):
    """On a main with uncommitted changes, the reference is HEAD: the change being measured
    is the uncommitted one. Only a change to what builds the binary counts. A note under
    tasks/ once made T98's merge commit its own reference, and a +0.0% size A/B looked like
    a pass (2026-10-03)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        _git(self.repo, "init", "-q", "-b", "main")
        _git(self.repo, "config", "user.email", "t@example.invalid")
        _git(self.repo, "config", "user.name", "t")
        _git(self.repo, "config", "commit.gpgsign", "false")
        for rel, text in (("crates/x/src/lib.rs", "fn a() {}\n"), ("tasks/T1.md", "one\n"),
                          ("Cargo.toml", "[workspace]\n")):
            self.write(rel, text)
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-q", "-m", "root")
        self.parent = _git(self.repo, "rev-parse", "HEAD")
        self.write("crates/x/src/lib.rs", "fn a() {}\nfn b() {}\n")
        _git(self.repo, "commit", "-q", "-am", "change")
        self.head = _git(self.repo, "rev-parse", "HEAD")
        self.env = {k: v for k, v in os.environ.items() if k != "ALCYON_MEASURE_REF"}

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, text):
        path = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    def ref(self):
        return reference_sha(self.repo, self.env)

    def test_clean_main_is_judged_against_the_parent(self):
        self.assertEqual(self.ref(), self.parent)

    def test_a_task_note_does_not_make_the_commit_its_own_reference(self):
        self.write("tasks/T1.md", "one\ntwo\n")
        self.assertEqual(self.ref(), self.parent)

    def test_uncommitted_source_is_judged_against_head(self):
        self.write("crates/x/src/lib.rs", "fn a() {}\nfn b() {}\nfn c() {}\n")
        self.assertEqual(self.ref(), self.head)

    def test_an_uncommitted_manifest_change_is_judged_against_head(self):
        self.write("Cargo.toml", "[workspace]\nmembers = []\n")
        self.assertEqual(self.ref(), self.head)



class TestRegressionDetector(unittest.TestCase):
    def test_allocations_increase_is_regression(self):
        current = {"allocs_per_request": 6}
        previous = {"allocs_per_request": 5}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertTrue(any(d.name == "allocs_per_request" and d.is_regression for d in deltas))

    def test_allocations_equal_is_pass(self):
        current = {"allocs_per_request": 5}
        previous = {"allocs_per_request": 5}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.PASS)

    def test_bytes_per_request_threshold(self):
        # <= 10% increase is PASS
        current = {"bytes_per_request": 136} # 124 * 1.096
        previous = {"bytes_per_request": 124}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.PASS)

        # > 10% increase is FAIL
        current = {"bytes_per_request": 150} # > 124 * 1.10
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertTrue(any(d.name == "bytes_per_request" and d.is_regression for d in deltas))

    def test_vtc_pass_decrease_is_regression(self):
        # 7 -> 6 is regression
        current = {"board": {"pass": 6, "fail": 165, "skip": 89, "scope": 52}}
        previous = {"board": {"pass": 7, "fail": 164, "skip": 89, "scope": 52}}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertTrue(any(d.name == "vtc_pass" and d.is_regression for d in deltas))

        # 7 -> 8 is PASS
        current = {"board": {"pass": 8, "fail": 163, "skip": 89, "scope": 52}}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.PASS)

    def test_throughput_decrease_threshold(self):
        # <= 15% decrease is PASS (spread / noise)
        current = {"rps_1conn": 8500} # 10000 * 0.85
        previous = {"rps_1conn": 10000}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.PASS)

        # > 15% decrease is FAIL
        current = {"rps_1conn": 8400} # < 10000 * 0.85
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertTrue(any(d.name == "rps_1conn" and d.is_regression for d in deltas))

    def test_throughput_is_judged_against_the_reference_build_of_the_same_run(self):
        # An alternating A/B against the base commit's build measured in the same run.
        # The last record does not matter: it may come from a noisier machine or moment.
        previous = {"rps_1conn": 20000, "cpu_ns_per_req_50conn": 10000}
        current = {"rps_1conn": 9200, "rps_1conn_ref": 10000,
                   "cpu_ns_per_req_50conn": 41200, "cpu_ns_per_req_50conn_ref": 40000}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.PASS)

        # Requests/s samples move 10% between identical builds; only a large drop fails.
        current = {"rps_1conn": 8400, "rps_1conn_ref": 10000}
        deltas, verdict = check_regressions(current, {"rps_1conn": 5000})
        self.assertEqual(verdict, Verdict.FAIL)
        d = next(d for d in deltas if d.name == "rps_1conn")
        self.assertTrue(d.is_regression)
        self.assertEqual(d.previous, "10,000 (ref)")

    def test_cpu_per_request_is_the_tight_ab_check(self):
        # alcyon CPU per request at 50 connections varies about 2% between identical builds.
        current = {"cpu_ns_per_req_50conn": 41800, "cpu_ns_per_req_50conn_ref": 40000}
        deltas, verdict = check_regressions(current, {"cpu_ns_per_req_50conn": 99999})
        self.assertEqual(verdict, Verdict.FAIL)
        d = next(d for d in deltas if d.name == "cpu_ns_per_req_50conn")
        self.assertTrue(d.is_regression)

        current = {"cpu_ns_per_req_50conn": 41000, "cpu_ns_per_req_50conn_ref": 40000}
        deltas, verdict = check_regressions(current, {"cpu_ns_per_req_50conn": 1})
        self.assertEqual(verdict, Verdict.PASS)

    def test_instructions_per_request_fail_at_one_percent_over_the_ref(self):
        # instructions:u are deterministic to ~0.3% per build (design/memory 7c): +1% is a
        # regression for both scenarios, +0.8% is not.
        for sc in ("keepalive", "rules"):
            current = {f"ins_per_req_{sc}": 101200, f"ins_per_req_{sc}_ref": 100000}
            deltas, verdict = check_regressions(current, {})
            self.assertEqual(verdict, Verdict.FAIL, sc)
            d = next(d for d in deltas if d.name == f"ins_per_req_{sc}")
            self.assertTrue(d.is_regression)
            current = {f"ins_per_req_{sc}": 100800, f"ins_per_req_{sc}_ref": 100000}
            deltas, verdict = check_regressions(current, {})
            self.assertEqual(verdict, Verdict.PASS, sc)
            d = next(d for d in deltas if d.name == f"ins_per_req_{sc}")
            self.assertFalse(d.is_regression)

    def test_insreq_output_is_parsed_and_the_min_of_the_rounds_is_taken(self):
        out = ("x round 1: 2200000000 instructions, 36666 ins/req\n"
               "x round 2: 2100000000 instructions, 35000 ins/req\n"
               "x round 3: 2150000000 instructions, 35833 ins/req\n"
               "x done (proxy pid 1 and backend pid 2 stopped)\n")
        self.assertEqual(parse_insreq(out), [2200000000, 2100000000, 2150000000])
        self.assertEqual(min_ins_per_req(parse_insreq(out), 60000), 35000)
        self.assertRaises(RuntimeError, parse_insreq, "perf: not permitted\n")

    def test_binary_size_threshold(self):
        # <= 5% increase is PASS
        current = {"binary_bytes": 105000000}
        previous = {"binary_bytes": 100000000}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.PASS)

        # > 5% increase is FAIL
        current = {"binary_bytes": 106000000}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertTrue(any(d.name == "binary_bytes" and d.is_regression for d in deltas))

    def test_insreq_h3_rows_are_not_the_previous_gate_record(self):
        # T555: insreq.sh's h3 rows (`"kind": "insreq-h3"`) share data/measurements.jsonl;
        # the gate's history is its own rows only.
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "m.jsonl"
            p.write_text('{"rps_1conn": 1}\n{"kind": "insreq-h3", "h3_fit": 2}\n')
            self.assertEqual(load_previous_measurements(p), [{"rps_1conn": 1}])

    def test_no_previous_run_is_baseline_pass(self):
        current = {"allocs_per_request": 5, "rps_1conn": 10000}
        previous = None
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.BASELINE)



class TestSplitModes(unittest.TestCase):
    """The 1-conn samples fall in two clusters ~25% apart (T452). Both sides of an A/B are
    split at one threshold, so the report can say how many samples each build had in each
    mode: a median taken over a 3:1 mix and one over a 1:3 mix differ by the gap between
    the modes, not by what the change did."""

    def test_rc2_run_2_splits_at_one_threshold(self):
        cand = [13335, 18664, 13151, 13404]
        ref = [14558, 19050, 19032, 15342]
        m = split_modes(cand, ref)
        self.assertEqual(m["cand"], {"slow": 3, "fast": 1})
        self.assertEqual(m["ref"], {"slow": 2, "fast": 2})
        self.assertTrue(15342 < m["threshold"] < 18664)
        # Within a mode the builds are compared like with like.
        self.assertEqual(m["cand_slow_median"], 13335)
        self.assertEqual(m["ref_slow_median"], (14558 + 15342) // 2)

    def test_one_mode_has_no_threshold(self):
        m = split_modes([15000, 15300, 14800, 15100], [15200, 14900, 15050, 15400])
        self.assertIsNone(m["threshold"])
        self.assertEqual(m["cand"], {"slow": 4, "fast": 0})
        self.assertEqual(m["ref"], {"slow": 4, "fast": 0})

    def test_a_lone_outlier_is_not_a_mode_of_its_own(self):
        # rc3 gate: 11017 is one low sample, not a cluster; the gap rule alone would split it.
        m = split_modes([12438, 14966, 15454, 13519], [15034, 11017, 18832, 13445])
        self.assertEqual(m["cand"]["slow"] + m["cand"]["fast"], 4)
        self.assertGreaterEqual(m["threshold"] or 0, 15454)


class TestInsreqShBackend(unittest.TestCase):
    """T639 (11-17): when the measure-bench backend binary is missing, the backend dies
    without a word, the proxy has no server, and the warm-up ab waits forever on a
    connection the proxy will never answer. The script must fail fast with the path,
    not hold the load slot until the overnight queue is stopped by hand."""

    # A stand-in proxy: accepts every connection and answers nothing, as the real proxy
    # does for a request its missing backend cannot serve, so the warm-up ab waits.
    FAKE_PROXY = """\
#!/usr/bin/env python3
import re, socket, sys
cfg = sys.argv[sys.argv.index("-f") + 1]
port = int(re.search(r"bind 127\\.0\\.0\\.1:(\\d+)", open(cfg).read()).group(1))
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(128)
held = []
while True:
    held.append(s.accept()[0])
"""

    def setUp(self):
        self.fakes = []

    def tearDown(self):
        # On its error paths the script does not stop the proxy, and a timed-out run is
        # killed mid warm-up; a fake left behind holds its port, and the ab that waits on
        # it. Kill them by the fake's unique path.
        for path in self.fakes:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as f:
                        cmd = f.read().decode(errors="replace")
                except OSError:
                    continue
                if path in cmd:
                    try:
                        os.kill(int(pid), signal.SIGTERM)
                    except OSError:
                        pass

    def run_insreq(self, out, bench):
        """insreq.sh with small N and rounds, bounded at 30 s; the fake stand-in proxy is
        its proxy binary. A hang is a failure: that is the T639 defect."""
        here = os.path.dirname(os.path.abspath(__file__))
        fake = os.path.join(out, "fake-proxy")
        with open(fake, "w") as f:
            f.write(self.FAKE_PROXY)
        os.chmod(fake, 0o755)
        self.fakes.append(fake)
        env = {k: v for k, v in os.environ.items() if k not in ("MEASURE_BENCH", "ALCYON_MEASURE_CPUS")}
        env["MEASURE_BENCH"] = bench
        # Three CPUs (proxy, client, backend) even on a host with fewer: a short list leaves
        # `taskset -c ""` to fail, and the test would pass on that failure, not on the fix.
        n = os.cpu_count() or 1
        env["ALCYON_MEASURE_CPUS"] = ",".join(str(i % n) for i in range(3))
        p = subprocess.Popen([os.path.join(here, "insreq.sh"), "t", fake,
                              os.path.join(here, "scenarios", "keepalive.body"), "ab1", "1", "1", out],
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             start_new_session=True)
        try:
            stdout, stderr = p.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            p.stdout.close(); p.stderr.close()
            self.fail(f"insreq.sh hung with MEASURE_BENCH={bench} (T639: expected a fail-fast error)")
        return p.returncode, stdout + stderr

    def test_missing_measure_bench_fails_fast_with_the_path(self):
        # The caller named the binary (MEASURE_BENCH), so the script must not build it; it
        # reports the missing path and exits non-zero within the bound, not in 35 minutes.
        with tempfile.TemporaryDirectory() as out:
            rc, output = self.run_insreq(out, "/nonexistent/measure-bench")
        self.assertNotEqual(rc, 0)
        self.assertIn("measure-bench not found", output)
        self.assertIn("/nonexistent/measure-bench", output)

    def test_backend_that_never_listens_fails_fast(self):
        # The named binary exists but is not a backend: it never listens, so the script
        # stops with "backend did not start" instead of letting ab poll a proxy with no
        # server forever.
        with tempfile.TemporaryDirectory() as out:
            bench = os.path.join(out, "not-a-backend")
            with open(bench, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(bench, 0o755)
            rc, output = self.run_insreq(out, bench)
        self.assertNotEqual(rc, 0)
        self.assertIn("backend did not start", output)
        self.assertIn(bench, output)


if __name__ == "__main__":
    unittest.main()


class TestHostProblems(unittest.TestCase):
    """The host must be quiet where the gate pins: governor performance on the CPUs used, and
    the CPUs, the proxy's SMT sibling and its CCX idle over a second (T452)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        for c in (4, 5, 6, 7, 36):
            self.sys(c, "cpufreq/scaling_governor", "performance\n")
            self.sys(c, "topology/thread_siblings_list", f"{c % 32},{c % 32 + 32}\n" if c < 32 else "4,36\n")
            self.sys(c, "cache/index3/shared_cpu_list", "4-7,36-39\n")

    def tearDown(self):
        self.tmp.cleanup()

    def sys(self, cpu, rel, text):
        path = os.path.join(self.root, f"cpu{cpu}", rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    @staticmethod
    def stat(busy):
        """/proc/stat text with 100 jiffies on each CPU; `busy` maps cpu -> jiffies of them in
        user mode, the rest idle. Time since an all-zero first reading."""
        return "cpu  0 0 0 0 0 0 0\n" + "".join(
            f"cpu{c} {busy.get(c, 0)} 0 0 {100 - busy.get(c, 0)} 0 0 0 0 0 0\n"
            for c in (4, 5, 6, 7, 36, 37, 38, 39))

    def check(self, after):
        zero = "".join(f"cpu{c} 0 0 0 0 0 0 0 0 0 0\n" for c in (4, 5, 6, 7, 36, 37, 38, 39))
        return host_problems(zero, self.stat(after), [4, 5, 6], self.root)

    def test_quiet_host(self):
        self.assertEqual(self.check({}), [])

    def test_busy_sibling_is_refused(self):
        why = self.check({36: 100})
        self.assertEqual(len(why), 1)
        self.assertIn("36", why[0])

    def test_wrong_governor_is_refused(self):
        self.sys(5, "cpufreq/scaling_governor", "schedutil\n")
        why = self.check({})
        self.assertEqual(len(why), 1)
        self.assertIn("schedutil", why[0])


class TestH3Board(unittest.TestCase):
    """M1: the h3 board has a non-PGO column, a PGO ("shipped") column and HAProxy's."""

    def row(self, label, fit, build=None, binary="/t/release-perf/alcyon", sha="aaa", method="get"):
        r = {"kind": "insreq-h3", "sha": sha, "label": label, "binary": binary, "scenario": "h3.body",
             "method": method, "h3_fit": fit, "fit_rate": 1.97, "at": "2026-11-01T00:00:00Z"}
        if build:
            r["build"] = build
        return r

    def test_pgo_is_its_own_column_and_haproxy_the_ratio_base(self):
        rows = [self.row("i", 109000), self.row("p", 95000, "pgo"),
                self.row("h", 64000, binary="/ref/haproxy-quic/haproxy"), {"kind": "other"}]
        (b,) = board(rows)
        self.assertEqual((b["release-perf"], b["pgo"], b["haproxy"]), (109000, 95000, 64000))
        self.assertAlmostEqual(b["ratio"], 109000 / 64000)
        self.assertAlmostEqual(b["pgo_ratio"], 95000 / 64000)
        out = render([b])
        self.assertIn("pgo", out.splitlines()[0])
        self.assertIn("1.48x", out)

    def test_the_last_row_of_a_column_wins_and_shas_are_separate_lines(self):
        rows = [self.row("a", 100, sha="s1"), self.row("b", 90, sha="s1"), self.row("c", 80, sha="s2")]
        got = board(rows)
        self.assertEqual([(g["sha"], g["release-perf"]) for g in got], [("s1", 90), ("s2", 80)])
        self.assertIsNone(got[0]["pgo"])
        self.assertIn("-", render(got))


class TestInsreqGateRef(unittest.TestCase):
    """insreq_gate.pick_ref: the quick gate's baseline is the last clean, passing measurement."""

    @staticmethod
    def row(sha, ka, ka_ref, rules=50000, rules_ref=50000, **kw):
        return dict(sha=sha, ins_per_req_keepalive=ka, ins_per_req_keepalive_ref=ka_ref,
                    ins_per_req_rules=rules, ins_per_req_rules_ref=rules_ref, **kw)

    def test_a_failed_measurement_is_not_the_baseline(self):
        from insreq_gate import pick_ref
        # 11-21: 2eea785f measured keepalive +1.8% over c246669a and failed.
        rows = [self.row("c246669a", 35078, 35062), self.row("2eea785f", 35769, 35135)]
        self.assertEqual(pick_ref(rows, lambda s: True), "c246669a")
        rows.append(self.row("next", 35000, 35000, rules=51923, rules_ref=50644))
        self.assertEqual(pick_ref(rows, lambda s: True), "c246669a")

    def test_dirty_other_kinds_missing_counts_and_non_ancestors_are_skipped(self):
        from insreq_gate import pick_ref
        rows = [self.row("old", 35000, 35000),
                self.row("dirty", 35000, 35000, dirty=True),
                self.row("h3", 35000, 35000, kind="insreq-h3"),
                {"sha": "nocount", "rps_1conn": 1},
                self.row("branch", 35000, 35000)]
        self.assertEqual(pick_ref(rows, lambda s: s != "branch"), "old")
        self.assertIsNone(pick_ref(rows, lambda s: False))

    def test_judge_is_the_rise_in_percent(self):
        from insreq_gate import judge
        r = judge({"keepalive": 35769, "rules": 50644}, {"keepalive": 35135, "rules": 50644})
        self.assertAlmostEqual(r["keepalive"], 1.804, places=2)
        self.assertEqual(r["rules"], 0.0)
