# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""harness/reference.py: the oracles are found through ALCYON_REFERENCE, never a home path (T630)."""
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reference  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference.py")


def tree(*rels: str) -> str:
    d = tempfile.mkdtemp(prefix="alcyon-ref-")
    for rel in rels:
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").close()
    return d


class Resolve(unittest.TestCase):
    def test_unset_or_empty_finds_nothing(self):
        for env in ({}, {"ALCYON_REFERENCE": ""}):
            self.assertIsNone(reference.root(env))
            self.assertIsNone(reference.path(reference.HAPROXY, env=env))

    def test_set_names_a_file_under_it(self):
        env = {"ALCYON_REFERENCE": "/r"}
        self.assertEqual(reference.root(env), "/r")
        self.assertEqual(reference.path(reference.HAPROXY, env=env), "/r/haproxy/haproxy")
        self.assertEqual(reference.path(reference.HAPROXY_QUIC, env=env), "/r/haproxy-quic/haproxy")
        self.assertEqual(reference.path(reference.HAPROXY_102, env=env), "/r/haproxy-1.0.2/haproxy102")

    def test_a_per_binary_override_wins_and_works_without_the_root(self):
        for env in ({"HAPROXY": "/x/hap"}, {"HAPROXY": "/x/hap", "ALCYON_REFERENCE": "/r"}):
            self.assertEqual(reference.path(reference.HAPROXY, "HAPROXY", env), "/x/hap")
        # An empty override is no override.
        self.assertEqual(reference.path(reference.HAPROXY, "HAPROXY", {"HAPROXY": "", "ALCYON_REFERENCE": "/r"}),
                         "/r/haproxy/haproxy")


class Require(unittest.TestCase):
    def test_unset_fails_naming_the_variable(self):
        with self.assertRaises(SystemExit) as e:
            reference.require(reference.HAPROXY, who="smoke", env={})
        self.assertIn("ALCYON_REFERENCE", str(e.exception.code))
        self.assertIn("smoke", str(e.exception.code))

    def test_set_but_missing_fails_naming_the_path(self):
        d = tree()
        with self.assertRaises(SystemExit) as e:
            reference.require(reference.HAPROXY, env={"ALCYON_REFERENCE": d})
        self.assertIn(os.path.join(d, "haproxy/haproxy"), str(e.exception.code))
        self.assertIn("ALCYON_REFERENCE", str(e.exception.code))

    def test_present_is_returned(self):
        d = tree("haproxy/haproxy")
        self.assertEqual(reference.require(reference.HAPROXY, env={"ALCYON_REFERENCE": d}),
                         os.path.join(d, "haproxy/haproxy"))

    def test_the_command_line_check_is_what_the_gate_runs(self):
        full = tree(*reference.GATE_NEEDS)
        base = {k: v for k, v in os.environ.items() if k != "ALCYON_REFERENCE"}
        ok = subprocess.run([sys.executable, SCRIPT, "--require"], env=dict(base, ALCYON_REFERENCE=full),
                            capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        unset = subprocess.run([sys.executable, SCRIPT, "--require", "--who", "suite"], env=base,
                               capture_output=True, text=True)
        self.assertNotEqual(unset.returncode, 0)
        self.assertIn("ALCYON_REFERENCE", unset.stdout + unset.stderr)
        self.assertIn("suite", unset.stdout + unset.stderr)
        partial = tree(reference.HAPROXY)
        miss = subprocess.run([sys.executable, SCRIPT, "--require"], env=dict(base, ALCYON_REFERENCE=partial),
                              capture_output=True, text=True)
        self.assertNotEqual(miss.returncode, 0)
        self.assertIn("haproxy-quic/haproxy", miss.stdout + miss.stderr)


if __name__ == "__main__":
    unittest.main()
