# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""tools/review/check.py against the real repository objects (T643 rule 1): each check has a
red case on the commit that had the defect (it must fire) and a green case (it must not).
A commit the clone lacks skips the test with the SHA named.

Run:  python3 -I tools/review/test_check.py      (or: python3 -m unittest tools/review/test_check.py)
"""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check  # noqa: E402

REPO = os.environ.get("T643_REPO") or os.path.dirname(os.path.dirname(HERE))
_cache: dict = {}


def have(*shas: str) -> None:
    for s in shas:
        r = subprocess.run(["git", "-C", REPO, "cat-file", "-e", s + "^{commit}"], capture_output=True)
        if r.returncode != 0:
            raise unittest.SkipTest(f"commit {s} is not in this clone")


def findings(base: str, cand: str, name: str) -> list:
    have(base, cand)
    k = (base, cand, name)
    if k not in _cache:
        _cache[k] = [f for f in check.run(REPO, base, cand, {name}) if f.check == name]
    return _cache[k]


class Case(unittest.TestCase):
    def fires(self, base, cand, name, path=None, text=None, blocking=None):
        fs = findings(base, cand, name)
        sel = [f for f in fs if (path is None or path in f.path) and (text is None or text in f.msg)
               and (blocking is None or f.blocking == blocking)]
        self.assertTrue(sel, f"{name} did not fire on {base}..{cand} (path={path!r} text={text!r}); got {[f.text() for f in fs][:5]}")

    def silent(self, base, cand, name, text=None):
        fs = [f for f in findings(base, cand, name) if text is None or text in f.msg]
        self.assertEqual(fs, [], f"{name} fired on {base}..{cand}: {[f.text() for f in fs][:5]}")


class RemovedTest(Case):
    def test_red_s4delsrv_test_attribute_removed_from_kept_fn(self):
        self.fires("f62dd59b", "4ca6323d", "removed-test", "cli_del_server.rs", "del_server_in_flight_and_keepalive", True)

    def test_green_s4delsrv_after_the_attribute_was_restored(self):
        self.silent("f62dd59b", "3a34e140", "removed-test")

    def test_red_queuefetch_refusal_test_fn_removed(self):
        self.fires("ab3b87d4", "fbbdb626", "removed-test", "server_state_refusals.rs", "alcyon_c_refuses", True)

    def test_red_hchkmulti_refusal_rows_deleted_are_flagged_not_blocking(self):
        self.fires("f4988a3e", "1da861dc", "removed-test", "check_rules_parse.rs", "refusal table", False)
        self.fires("f4988a3e", "1da861dc", "removed-test", "check_rules.rs", "refusal table", False)

    def test_green_a_pure_addition(self):
        self.silent("abce60bb", "ed5c928e", "removed-test")

    def test_sizemap_ignore_is_flagged_blocking(self):
        # A manual report test: `#[ignore = "prints a report; run by hand"]`. The rule is
        # "#[ignore] added = block"; whether this one is acceptable is the reviewer's call.
        self.fires("b5fef2d2", "c67ca88b", "removed-test", "size_map.rs", "#[ignore] added", True)


class MergeHiddenEdit(Case):
    def test_red_netscaler_831cac1b(self):
        self.fires("e55e3eaf", "831cac1b", "merge-hidden-edit", None, "merge 831cac1b", True)

    def test_red_queuefetch_2fe7c94b(self):
        self.fires("fbbdb626", "2fe7c94b", "merge-hidden-edit", None, "merge 2fe7c94b", True)

    def test_red_logprofile_bb170a4b_resolution_is_flagged_with_its_size(self):
        # The audit note "5+/25- beyond merge-tree" is a resolution inside git's conflict markers
        # (the fc ConnView plumbing); the check cannot call it hidden, it reports it, F, with the size.
        self.fires("d9ea1b5e", "bb170a4b", "merge-hidden-edit", "engine.rs", "merge bb170a4b: conflict resolution, 17 hunks +5/-25", False)

    def test_green_md5sig_88387aa3_conflict_resolution_only(self):
        have("88387aa3")
        fs = [f for f in findings("f9be4c93", "88387aa3", "merge-hidden-edit") if "merge 88387aa3" in f.msg]
        self.assertEqual([f for f in fs if f.blocking], [], [f.text() for f in fs])

    def test_green_savedsyn_aeefc3bf_conflict_resolution_only(self):
        have("aeefc3bf")
        fs = [f for f in findings("88387aa3", "aeefc3bf", "merge-hidden-edit") if "merge aeefc3bf" in f.msg]
        self.assertEqual([f for f in fs if f.blocking], [], [f.text() for f in fs])


class ModelCommit(Case):
    def test_red_as_written_by_without_trailer(self):
        self.fires("eda5e450^", "eda5e450", "model-commit", "commit:eda5e450", "no Model-Authored-By", True)

    def test_green_connaddr_model_commit(self):
        self.silent("f44a22b9", "1299484d", "model-commit")

    def test_red_hchkmulti_rebased_with_an_edit_inside_the_model_commit(self):
        have("1da861dc", "53e751b2")
        fs = check.compare_commits(check.Repo(REPO), "53e751b2", "1da861dc")
        self.assertTrue(fs, "53e751b2 differs from 1da861dc (T644 #12) and was not reported")

    def test_green_identical_commit_compared_to_itself(self):
        have("1da861dc")
        self.assertEqual(check.compare_commits(check.Repo(REPO), "1da861dc", "1da861dc"), [])


class CheckinFile(Case):
    def test_red_commit_touching_a_listed_file(self):
        self.fires("7310f2f1^", "7310f2f1", "checkin-file", "sample_semantics.rs", None, True)

    def test_green_commit_touching_none(self):
        self.silent("b5fef2d2", "c67ca88b", "checkin-file")


class NewSharedState(Case):
    def test_green_webstats_adds_none(self):
        self.silent("abce60bb", "ed5c928e", "new-shared-state")

    def test_red_connaddr(self):
        self.fires("f44a22b9", "1299484d", "new-shared-state", None, "Atomic", False)

    def test_red_observe(self):
        self.fires("5c22d85f", "47a3733d", "new-shared-state", None, "Atomic", False)

    def test_red_queuefetch(self):
        self.fires("ab3b87d4", "fbbdb626", "new-shared-state", None, "Atomic", False)


class ConstantFetch(Case):
    def test_red_timerfetch_handshake(self):
        self.fires("187a20a2", "eed2acde", "constant-fetch", "registry.rs", "fc.timer.handshake", True)

    def test_red_connaddr_queue_fetches(self):
        self.fires("f44a22b9", "1299484d", "constant-fetch", "registry.rs", "bc_be_queue", True)
        self.fires("f44a22b9", "1299484d", "constant-fetch", "registry.rs", "bc_srv_queue", True)

    def test_green_timerfetch_fix_refuses_the_fetch(self):
        self.silent("187a20a2", "65ab9336", "constant-fetch", "fc.timer.handshake")
        self.silent("eed2acde", "65ab9336", "constant-fetch")


class Synthetic(unittest.TestCase):
    """The corpus holds no real commit with a write-only field, a todo!/panic! in non-test code
    or an unreached test file, so these checks run on a throw-away repository in a temp dir
    (real git objects, not the project's). `--repo` points the check at it."""

    def repo(self, base_files: dict, cand_files: dict):
        d = tempfile.mkdtemp(prefix="t643-synth-")
        g = lambda *a: subprocess.run(["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@t", *a],
                                      check=True, capture_output=True, text=True).stdout.strip()
        g("init", "-q", "-b", "main")
        for files, msg in ((base_files, "base"), (cand_files, "cand")):
            for rel, text in files.items():
                path = os.path.join(d, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                open(path, "w").write(text)
            g("add", "-A")
            g("commit", "-q", "-m", msg)
            if msg == "base":
                base = g("rev-parse", "HEAD")
        return d, base, g("rev-parse", "HEAD")

    def run_check(self, d, base, cand, name):
        return [f for f in check.run(d, base, cand, {name}) if f.check == name]

    def test_red_write_only_field_read_but_only_initialised_with_a_literal(self):
        lib = "pub struct T {\n    pub t_handshake: i64,\n}\nimpl T {\n    pub fn new() -> T { T { t_handshake: 0 } }\n    pub fn get(&self) -> i64 { self.t_handshake }\n}\n"
        d, b, c = self.repo({"crates/x/src/old.rs": "pub fn f() {}\n"}, {"crates/x/src/lib.rs": lib})
        fs = self.run_check(d, b, c, "write-only-field")
        self.assertEqual([(f.path, f.line, f.blocking) for f in fs], [("crates/x/src/lib.rs", 2, False)], [f.text() for f in fs])

    def test_green_write_only_field_when_it_is_assigned_later(self):
        lib = "pub struct T {\n    pub t_handshake: i64,\n}\nimpl T {\n    pub fn new() -> T { T { t_handshake: 0 } }\n    pub fn set(&mut self, v: i64) { self.t_handshake = v; }\n    pub fn get(&self) -> i64 { self.t_handshake }\n}\n"
        d, b, c = self.repo({"crates/x/src/old.rs": "pub fn f() {}\n"}, {"crates/x/src/lib.rs": lib})
        self.assertEqual(self.run_check(d, b, c, "write-only-field"), [])

    def test_red_new_panic_in_non_test_code_but_not_in_tests_or_comments(self):
        lib = ("pub fn f(x: u8) {\n    if x == 0 { panic!(\"zero\"); }\n    // TODO later\n    let _ = \"panic!\";\n}\n"
               "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() { panic!(\"in a test\"); }\n}\n")
        d, b, c = self.repo({"crates/x/src/old.rs": "pub fn f() {}\n"}, {"crates/x/src/lib.rs": lib})
        fs = self.run_check(d, b, c, "new-panic")
        self.assertEqual([(f.line, f.blocking) for f in fs], [(2, True), (3, True)], [f.text() for f in fs])

    def test_green_new_panic_with_none_added(self):
        d, b, c = self.repo({"crates/x/src/old.rs": "pub fn f() {}\n"}, {"crates/x/src/lib.rs": "pub fn g() -> u8 { 1 }\n"})
        self.assertEqual(self.run_check(d, b, c, "new-panic"), [])

    def test_red_test_layout_a_test_file_main_rs_does_not_declare(self):
        toml = '[package]\nname = "x"\nautotests = false\n\n[[test]]\nname = "it"\npath = "tests/it/main.rs"\n'
        base = {"crates/x/Cargo.toml": toml, "crates/x/tests/it/main.rs": "mod a;\n", "crates/x/tests/it/a.rs": ""}
        cand = {"crates/x/tests/it/orphan.rs": "#[test] fn t() {}\n"}
        d, b, c = self.repo(base, cand)
        fs = self.run_check(d, b, c, "test-layout")
        self.assertEqual([(f.path, f.blocking) for f in fs], [("crates/x/tests/it/orphan.rs", True)], [f.text() for f in fs])

    def test_green_test_layout_when_the_file_is_declared(self):
        toml = '[package]\nname = "x"\nautotests = false\n\n[[test]]\nname = "it"\npath = "tests/it/main.rs"\n'
        base = {"crates/x/Cargo.toml": toml, "crates/x/tests/it/main.rs": "mod a;\n", "crates/x/tests/it/a.rs": ""}
        cand = {"crates/x/tests/it/main.rs": "mod a;\nmod b;\n", "crates/x/tests/it/b.rs": "#[test] fn t() {}\n"}
        d, b, c = self.repo(base, cand)
        self.assertEqual(self.run_check(d, b, c, "test-layout"), [])


class RequestPathAlloc(Case):
    def test_red_agentchk_vec_new_in_engine(self):
        self.fires("23bf5305", "5541529c", "request-path-alloc", "engine.rs", "Vec::new", False)

    def test_green_webstats_adds_none(self):
        self.silent("abce60bb", "ed5c928e", "request-path-alloc")


class TestRegionLimit(unittest.TestCase):
    def test_mod_tests_without_its_cfg_attribute_is_still_test_code(self):
        # crates/alcyon-rt/src/check.rs at 53e751b2 has `mod tests {` after a misplaced #[cfg(test)]
        have("53e751b2")
        s = check.Repo(REPO).src("53e751b2", "crates/alcyon-rt/src/check.rs")
        self.assertIn(4227, s.test_lines())


if __name__ == "__main__":
    unittest.main(verbosity=2)
