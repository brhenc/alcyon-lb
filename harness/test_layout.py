# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""harness/layout.py: no test file under crates/*/tests is left uncompiled (T260)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layout  # noqa: E402


def crate(files: dict[str, str]) -> str:
    d = tempfile.mkdtemp(prefix="layout-")
    for rel, text in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(text)
    return d


ONE_BINARY = '[package]\nname = "x"\nautotests = false\n\n[[test]]\nname = "it"\npath = "tests/it/main.rs"\n'


class Unreached(unittest.TestCase):
    def names(self, d):
        return [os.path.relpath(f, d) for f in layout.unreached(d)]

    def test_a_new_top_level_file_in_a_one_binary_crate_is_named(self):
        d = crate({"Cargo.toml": ONE_BINARY, "tests/it/main.rs": "mod a;\n", "tests/it/a.rs": "",
                   "tests/new_one.rs": "#[test] fn t() {}\n"})
        self.assertEqual(self.names(d), ["tests/new_one.rs"])

    def test_a_module_file_main_rs_does_not_declare_is_named(self):
        d = crate({"Cargo.toml": ONE_BINARY, "tests/it/main.rs": "mod a;\n// mod b;\n",
                   "tests/it/a.rs": "", "tests/it/b.rs": ""})
        self.assertEqual(self.names(d), ["tests/it/b.rs"])

    def test_path_attributes_nested_modules_and_own_binaries_are_reached(self):
        toml = ONE_BINARY + '\n[[test]]\nname = "own"\npath = "tests/own.rs"\n'
        d = crate({"Cargo.toml": toml,
                   "tests/it/main.rs": '#[path = "../common/mod.rs"]\nmod common;\nmod lm;\n',
                   "tests/it/lm.rs": "mod h1;\n", "tests/it/lm/h1.rs": "",
                   "tests/common/mod.rs": "", "tests/own.rs": '#[path = "common/mod.rs"] mod common;'})
        self.assertEqual(self.names(d), [])

    def test_autotests_crates_reach_every_top_level_file(self):
        d = crate({"Cargo.toml": '[package]\nname = "x"\n', "tests/a.rs": "mod common;\n",
                   "tests/common/mod.rs": "", "tests/orphan/x.rs": ""})
        self.assertEqual(self.names(d), ["tests/orphan/x.rs"])

    def test_the_workspace_compiles_every_test_file(self):
        bad = [os.path.relpath(f, layout.REPO) for c in layout.crates() for f in layout.unreached(c)]
        self.assertEqual(bad, [], "test files no test target compiles (declare them in tests/it/main.rs)")


if __name__ == "__main__":
    unittest.main()
