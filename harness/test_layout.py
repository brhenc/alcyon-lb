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

    def test_a_crate_with_tests_and_autotests_is_named(self):
        # With autotests on, a new tests/x.rs is a new binary: not lost, but the layout is.
        self.assertTrue(layout.autotests(crate({"Cargo.toml": '[package]\nname = "x"\n', "tests/a.rs": ""})))
        self.assertFalse(layout.autotests(crate({"Cargo.toml": ONE_BINARY, "tests/it/main.rs": ""})))
        self.assertFalse(layout.autotests(crate({"Cargo.toml": '[package]\nname = "x"\n'})))

    def test_every_crate_with_tests_has_autotests_off(self):
        self.assertEqual([os.path.basename(c) for c in layout.crates() if layout.autotests(c)], [])

    def test_the_workspace_compiles_every_test_file(self):
        bad = [os.path.relpath(f, layout.REPO) for c in layout.crates() for f in layout.unreached(c)]
        self.assertEqual(bad, [], "test files no test target compiles (declare them in tests/it/main.rs)")


# data/suite_baseline.json on main before T260 (07b7634), and what each entry is now. The
# table is the migration: every old entry is here, and every entry here is in the baseline.
OLD_TO_NEW = {
    "alcyon-dns/resolver_behavior::test_retry_and_failover":
        "alcyon-dns/it::resolver_behavior::test_retry_and_failover",
    "alcyon-rt/request_allocations::sixty_thousand_backends_with_checks_memory_bounded":
        "alcyon-rt/request_allocations::sixty_thousand_backends_with_checks_memory_bounded",
    "alcyon-rt/h3_end_to_end::curl_http3_is_proxied_to_a_backend":
        "alcyon-rt/it::h3_end_to_end::curl_http3_is_proxied_to_a_backend",
    "alcyon-rt/lib::proxy::tests::an_h2_body_left_when_the_passes_run_out_runs_the_session_again":
        "alcyon-rt/lib::proxy::tests::an_h2_body_left_when_the_passes_run_out_runs_the_session_again",
}


class BaselineNames(unittest.TestCase):
    """data/suite_baseline.json names tests `crate/target::test`; a name that no longer
    names a test excuses nothing and hides that the test it meant is unexcused."""

    def baseline(self):
        import json
        doc = json.load(open(os.path.join(layout.REPO, "data", "suite_baseline.json")))
        return {**doc["known_failures"], **doc["known_flaky"]}

    def test_the_migration_maps_every_old_name_by_the_rule(self):
        for old, new in OLD_TO_NEW.items():
            self.assertEqual(layout.migrate_key(old), new, old)

    def test_every_migrated_name_names_an_existing_test(self):
        for old, new in OLD_TO_NEW.items():
            self.assertIsNotNone(layout.resolve_key(new), f"{old} -> {new} names no test in the sources")

    def test_every_baseline_entry_names_an_existing_test(self):
        for key in self.baseline():
            self.assertIsNotNone(layout.resolve_key(key), f"{key} names no test in the sources")

    def test_resolve_refuses_a_name_in_the_old_layout(self):
        self.assertIsNone(layout.resolve_key("alcyon-rt/h3_end_to_end::curl_http3_is_proxied_to_a_backend"))
        self.assertIsNone(layout.resolve_key("alcyon-rt/it::h3_end_to_end::no_such_test"))

    def test_every_serial_entry_names_a_target_or_module(self):
        import suite
        for s in suite.SERIAL_TARGETS:
            self.assertIsNotNone(layout.resolve_key(s + "::"), s)


if __name__ == "__main__":
    unittest.main()
