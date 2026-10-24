# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""harness/pool_layout.py: no hand-written per-thread cache outside the allowlist (S0)."""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pool_layout  # noqa: E402


def tree(files: dict[str, str]) -> str:
    d = tempfile.mkdtemp(prefix="pool-layout-")
    for rel, text in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(text)
    return d


STRAY = "use std::cell::RefCell;\nthread_local! {\n    static X: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };\n}\n"


class PoolLayout(unittest.TestCase):
    def test_a_stray_cache_is_named_with_file_line_and_rule(self):
        d = tree({"crates/foo/src/lib.rs": STRAY})
        self.assertEqual([(h[0], h[1], h[2]) for h in pool_layout.violations(d, {})],
                         [("crates/foo/src/lib.rs", 3, "X")])
        r = subprocess.run([sys.executable, os.path.join(HERE, "pool_layout.py"), d],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("crates/foo/src/lib.rs:3", r.stdout)
        self.assertIn("AGENTS.md section 8", r.stdout)

    def test_every_listed_shape_is_caught(self):
        for ty in ("RefCell<Vec<u8>>", "RefCell<VecDeque<u8>>", "Cell<Option<Vec<u8>>>",
                   "Cell<Option<String>>", "Vec<Box<u8>>"):
            d = tree({"crates/foo/src/a.rs": f"thread_local! {{ static X: {ty} = x(); }}\n"})
            self.assertEqual(len(pool_layout.violations(d, {})), 1, ty)

    def test_allowlisted_sites_alone_are_green(self):
        d = tree({"crates/foo/src/lib.rs": STRAY})
        self.assertEqual(pool_layout.violations(d, {("crates/foo/src/lib.rs", "X"): "S1"}), [])

    def test_a_second_static_in_an_allowlisted_file_is_not_allowed(self):
        d = tree({"crates/foo/src/lib.rs": STRAY.replace("}\n", "    static Y: RefCell<Vec<u8>> = x();\n}\n")})
        self.assertEqual([h[2] for h in pool_layout.violations(d, {("crates/foo/src/lib.rs", "X"): "S1"})], ["Y"])

    def test_ibex_alloc_tests_and_non_cache_statics_are_skipped(self):
        d = tree({"crates/ibex-alloc/src/lib.rs": STRAY, "crates/foo/src/tests/t.rs": STRAY,
                  "crates/foo/src/ok.rs": "thread_local! { static N: Cell<u32> = x(); }\n"
                                          "fn f() { let v: RefCell<Vec<u8>>; }\n"})
        self.assertEqual(pool_layout.violations(d, {}), [])

    def test_the_real_tree_is_green_and_the_allowlist_has_no_stale_entry(self):
        root = os.path.dirname(HERE)
        self.assertEqual(pool_layout.violations(root), [])
        seen = {(h[0], h[2]) for h in pool_layout.scan(root)}
        self.assertEqual(sorted(set(pool_layout.ALLOWLIST) - seen), [])


if __name__ == "__main__":
    unittest.main()
