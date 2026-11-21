#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Mechanical review checks for a local-model candidate branch (T643 step 1).

Usage:  python3 -I tools/review/check.py [--json] [--repo DIR] [--only NAME,...]
                                         [--orig CAND=ORIG ...] BASE CANDIDATE

Compares BASE...CANDIDATE (the changes CANDIDATE makes since it left BASE) and prints one line
per finding, `CHECK-NAME file:line [B|F] message`, then a summary line. Exit 1 when a BLOCKING
check fired, 0 otherwise. Git is only read: `git diff`, `git log`, `git show`, `git archive`
and `git merge-tree --write-tree` (which writes loose objects, no refs, no working tree).
Checks report findings, never grades.

Checks (B = blocking, F = flag only):
  removed-test (B/F)       a #[test]/#[tokio::test] removed, #[ignore] added; refusal rows removed
  merge-hidden-edit (B/F)  edits in a merge commit that `git merge-tree` does not make itself
  model-commit (B)         Model-Authored-By trailer vs "as written by ... (unmodified)"; with
                           --orig CAND=ORIG, CAND's patch must equal ORIG's (rebased with an edit)
  checkin-file (B)         a file listed in tools/checkin.sha256 changed
  new-shared-state (F)     Atomic*, Arc, Mutex, RwLock, thread_local! added in crates/*/src
  constant-fetch (B)       a sample fetch added whose body returns a literal constant
  write-only-field (F)     a struct field added that is read but only initialised with literals
  new-panic (B)            todo!/unimplemented!/panic!/TODO/FIXME added in non-test code
  request-path-alloc (F)   allocation added in engine/proxy/mux/h1/h2 files
  test-layout (B)          a tests/ file no test target compiles (harness/layout.py)

The limits of each heuristic are in its docstring (`mask`, `Src.test_lines`, `check_*`).
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from typing import Iterator, NamedTuple, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(os.path.dirname(HERE))


class Finding(NamedTuple):
    check: str
    path: str
    line: int
    msg: str
    blocking: bool

    def text(self) -> str:
        return f"{self.check} {self.path}:{self.line} [{'B' if self.blocking else 'F'}] {self.msg}"


# ---------------------------------------------------------------------------------- git

class Repo:
    def __init__(self, root: str):
        self.root = root
        self._show: dict = {}
        self._src: dict = {}

    def git(self, *args: str, ok: tuple = (0,)) -> str:
        p = subprocess.run(["git", "-C", self.root, "-c", "core.quotepath=off", *args],
                           capture_output=True, text=True, errors="replace")
        if p.returncode not in ok:
            raise RuntimeError(f"git {' '.join(args)}: {p.stderr.strip()}")
        return p.stdout

    def show(self, rev: str, path: str) -> Optional[str]:
        k = (rev, path)
        if k not in self._show:
            p = subprocess.run(["git", "-C", self.root, "show", f"{rev}:{path}"],
                               capture_output=True, text=True, errors="replace")
            self._show[k] = p.stdout if p.returncode == 0 else None
        return self._show[k]

    def src(self, rev: str, path: str) -> Optional["Src"]:
        k = (rev, path)
        if k not in self._src:
            t = self.show(rev, path)
            self._src[k] = Src(path, t) if t is not None else None
        return self._src[k]

    def resolve(self, rev: str) -> str:
        return self.git("rev-parse", "--verify", rev + "^{commit}").strip()


class Hunk(NamedTuple):
    old_start: int
    new_start: int
    removed: list  # [(old line number, text)]
    added: list    # [(new line number, text)]


def parse_diff(text: str) -> dict:
    """`git diff -U0 --no-renames` -> {path: [Hunk]}. A deleted file is keyed by its path."""
    files: dict = {}
    path = None
    cur: Optional[Hunk] = None
    old = new = 0
    for ln in text.split("\n"):
        if ln.startswith("diff --git "):
            m = re.match(r"diff --git a/(.*) b/(.*)$", ln)
            path = m.group(2) if m else None
            cur = None
            if path:
                files.setdefault(path, [])
        elif ln.startswith("@@") and path:
            m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", ln)
            if not m:
                continue
            old, new = int(m.group(1)), int(m.group(3))
            if m.group(2) == "0":
                old += 1  # -U0 pure insertion: the start names the line before
            if m.group(4) == "0":
                new += 1
            cur = Hunk(old, new, [], [])
            files[path].append(cur)
        elif cur is not None and ln.startswith("-") and not ln.startswith("---"):
            cur.removed.append((old, ln[1:]))
            old += 1
        elif cur is not None and ln.startswith("+") and not ln.startswith("+++"):
            cur.added.append((new, ln[1:]))
            new += 1
    return files


# -------------------------------------------------------------------------- Rust lexing

def mask(text: str, keep_strings: bool = False) -> str:
    """The text with comments (and, unless `keep_strings`, string and char literal contents)
    replaced by spaces; newlines and offsets are preserved so line numbers still hold.
    A lite lexer: handles // and nested /* */, "..." with escapes, r#"..."# and char literals
    against lifetimes. It does not understand macros that build tokens from strings."""
    out = list(text)
    n = len(text)
    i = 0

    def blank(a: int, b: int) -> None:
        for j in range(a, min(b, n)):
            if out[j] != "\n":
                out[j] = " "

    while i < n:
        c = text[i]
        if c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c == "r" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")) and re.match(r'r#*"', text[i:i + 12]):
            m = re.match(r'r(#*)"', text[i:i + 12])
            hashes = m.group(1)
            start = i + len(m.group(0))
            end = text.find('"' + hashes, start)
            end = n if end < 0 else end
            if not keep_strings:
                blank(start, end)
            i = end + 1 + len(hashes)
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if not keep_strings:
                blank(i + 1, j)
            i = j + 1
        elif c == "'":
            if i + 1 < n and text[i + 1] == "\\":
                j = text.find("'", i + 2)
                j = n if j < 0 else j
                if not keep_strings:
                    blank(i + 1, j)
                i = j + 1
            elif i + 2 < n and text[i + 2] == "'" and text[i + 1] != "'":
                if not keep_strings:
                    blank(i + 1, i + 2)
                i += 3
            else:
                i += 1  # a lifetime
        else:
            i += 1
    return "".join(out)


def match_brace(masked: str, open_pos: int) -> int:
    """Offset of the `}` closing the `{` at `open_pos` (len(masked) if there is none)."""
    depth = 0
    for j in range(open_pos, len(masked)):
        ch = masked[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j
    return len(masked)


CFG_TEST = re.compile(r"#\[cfg\((?:all\()?test\b")


def is_test_path(path: str) -> bool:
    """Files that are test code as a whole: a `tests` directory component, `tests.rs`,
    `*_tests.rs`, `test_*.rs`."""
    parts = path.split("/")
    base = parts[-1]
    return "tests" in parts[:-1] or base == "tests.rs" or base.endswith("_tests.rs") or base.startswith("test_")


class Src:
    def __init__(self, path: str, text: str):
        self.path = path
        self.text = text
        self.lines = text.split("\n")
        self.code = mask(text)
        self.code_lines = self.code.split("\n")
        self._test: Optional[set] = None

    def lineno(self, off: int) -> int:
        return self.code.count("\n", 0, off) + 1

    def test_lines(self) -> set:
        """1-based lines inside `#[cfg(test)]` items (a mod, fn or impl): from the attribute to
        the brace closing the item's first `{`, found by brace depth over masked text. Limits:
        `#[cfg(test)]` on an item ending in `;` covers that line only; a cfg(test) inside a
        macro body or `cfg_attr` is not seen. A file under tests/ is test code as a whole, and
        so is any `mod tests {`/`mod <x>_tests {` block, attribute or not."""
        if self._test is None:
            s: set = set()
            if is_test_path(self.path):
                s = set(range(1, len(self.lines) + 2))
            else:
                for m in CFG_TEST.finditer(self.code):
                    a = self.lineno(m.start())
                    k = re.search(r"[{;]", self.code[m.end():])
                    if not k:
                        continue
                    pos = m.end() + k.start()
                    end = pos if self.code[pos] == ";" else match_brace(self.code, pos)
                    s.update(range(a, self.lineno(end) + 1))
                # `mod tests {` counts as test code even when its #[cfg(test)] sits elsewhere
                for m in re.finditer(r"\bmod\s+(?:tests?|\w+_tests?)\s*\{", self.code):
                    s.update(range(self.lineno(m.start()), self.lineno(match_brace(self.code, m.end() - 1)) + 1))
            self._test = s
        return self._test


# ------------------------------------------------------------------------------ context

class Ctx:
    def __init__(self, repo: Repo, base: str, cand: str, orig: Optional[dict] = None):
        self.repo = repo
        self.base = base
        self.cand = cand
        self.orig = orig or {}
        self.old_rev = repo.git("merge-base", base, cand).strip() or base
        self.diff = parse_diff(repo.git("diff", "-U0", "--no-renames", "--no-color", f"{self.old_rev}..{cand}"))

    def rs_files(self) -> Iterator:
        for p in sorted(self.diff):
            if p.endswith(".rs"):
                yield p

    def added(self, path: str) -> list:
        return [a for h in self.diff[path] for a in h.added]

    def removed(self, path: str) -> list:
        return [r for h in self.diff[path] for r in h.removed]


# ------------------------------------------------------------------------ 1 removed-test

TEST_ATTR = re.compile(r"#\[\s*(?:tokio::|async_std::)?test\b")
FN_DECL = re.compile(r"\bfn\s+(\w+)")
REFUSAL = re.compile(r"(?i)refus|reject|not_?implemented|unimplemented|unsupported|invalid|_errors?\b|fail")


def test_fns(src: Optional[Src]) -> tuple:
    """({test fn name: line}, {every fn name: line}); a fn is a test when an attribute line
    above it (over other attributes, comments and blank lines) is #[test]-like."""
    tests: dict = {}
    allfns: dict = {}
    if src is None:
        return tests, allfns
    for i, ln in enumerate(src.code_lines):
        m = FN_DECL.search(ln)
        if not m:
            continue
        allfns.setdefault(m.group(1), i + 1)
        j = i - 1
        while j >= 0:
            cl = src.code_lines[j].strip()
            if cl.startswith("#"):
                if TEST_ATTR.search(cl):
                    tests.setdefault(m.group(1), i + 1)
                    break
            elif cl and not cl.endswith(("]", ")")):
                break  # code that is not an attribute (or its multi-line continuation)
            j -= 1
    return tests, allfns


def enclosing(src: Src, line: int) -> str:
    """The table opener (`for x in [`, `let t = [`, `const T`) and fn name above `line`."""
    names = []
    for i in range(line - 2, max(-1, line - 150), -1):
        c = src.code_lines[i]
        if not names and re.search(r"\bfor\s+\w+\s+in\s*&?\[|\b(?:let|const|static)\s+\w+[^=]*=\s*&?\[|\b(?:const|static)\s+\w+", c):
            names.append(c.strip())
        m = FN_DECL.search(c)
        if m:
            names.append(m.group(1))
            break
    return " ".join(names)


def check_removed_test(ctx: Ctx) -> list:
    """Test fns lost between the merge base and CANDIDATE, per changed file, by name: the
    `#[test]` attribute gone with the fn kept (B), the fn gone (B), the fn gone but a test of
    the same name added in another changed file (F, probably moved). `#[ignore]` added (B).
    Rows removed from a table inside a fn or const whose name says refusal (F). Limits:
    names are compared, not bodies, so a test emptied in place is not seen; two fns of one
    name in one file collapse; a table row is a removed test-region line that starts like an
    array element and ends in a comma."""
    out: list = []
    added_tests: dict = {}
    per_file = {}
    for p in ctx.diff:
        if not p.endswith(".rs"):
            continue
        old = ctx.repo.src(ctx.old_rev, p)
        new = ctx.repo.src(ctx.cand, p)
        ot, _ = test_fns(old)
        nt, na = test_fns(new)
        per_file[p] = (old, new, ot, nt, na)
        for n in nt:
            added_tests.setdefault(n, p)
    for p, (old, new, ot, nt, na) in per_file.items():
        for name, line in ot.items():
            if name in nt:
                continue
            if name in na:
                out.append(Finding("removed-test", p, na[name],
                                   f"`#[test]` removed from fn {name} (the fn is kept and no longer runs)", True))
            elif name in added_tests and added_tests[name] != p:
                out.append(Finding("removed-test", p, line,
                                   f"test fn {name} removed here; a test of that name is added in {added_tests[name]} (moved?)", False))
            else:
                out.append(Finding("removed-test", p, line, f"test fn {name} removed", True))
        if new is not None:
            for no, text in ctx.added(p):
                if re.match(r"\s*#\[\s*ignore\b", text):
                    out.append(Finding("removed-test", p, no, "#[ignore] added", True))
        if old is not None:
            tl = old.test_lines()
            for no, text in ctx.removed(p):
                s = text.strip()
                if no in tl and re.match(r'^(?:\(|"|r#*"|&\[|&?\w+\()', s) and s.endswith(",") and not TEST_ATTR.search(s):
                    where = enclosing(old, no)
                    if REFUSAL.search(where):
                        out.append(Finding("removed-test", p, no,
                                           f"row removed from a refusal table ({where.split()[-1]}): {s[:60]}", False))
    return out


# ------------------------------------------------------------------- 2 merge-hidden-edit

def marker_regions(text: str) -> list:
    """(first, last) 1-based line ranges of the `<<<<<<<` .. `>>>>>>>` blocks in a file git
    merged with conflicts (diff3 style markers included)."""
    regions, start = [], None
    for i, ln in enumerate(text.split("\n"), 1):
        if ln.startswith("<<<<<<<") and start is None:
            start = i
        elif ln.startswith(">>>>>>>") and start is not None:
            regions.append((start, i))
            start = None
    return regions


def in_regions(h: Hunk, regions: list) -> bool:
    """Whether the hunk's lines of the conflicted tree lie inside one conflict block. Limit: a
    resolution that also edits a line next to a block, outside the markers, shows as a hidden
    edit."""
    a = h.old_start
    b = a + max(len(h.removed), 1) - 1
    return any(r0 <= a and b <= r1 for r0, r1 in regions)


def check_merge_hidden_edit(ctx: Ctx) -> list:
    """For every merge in BASE..CANDIDATE: `git merge-tree --write-tree p1 p2` is what git merges
    by itself. Files that merge cleanly but differ from the merge commit's tree hold hand edits
    hidden in the merge (B). In files git reports as conflicted, hunks inside its conflict markers
    are the resolution (F, with hunk and +/- line counts); hunks outside the markers are hidden
    edits again (B). Merges with other than two parents are skipped with a note."""
    out: list = []
    merges = ctx.repo.git("rev-list", "--merges", f"{ctx.base}..{ctx.cand}").split()
    for m in merges:
        parents = ctx.repo.git("rev-list", "--parents", "-n", "1", m).split()[1:]
        short = m[:8]
        if len(parents) != 2:
            print(f"NOTE merge-hidden-edit: {short} has {len(parents)} parents, skipped", file=sys.stderr)
            continue
        p = subprocess.run(["git", "-C", ctx.repo.root, "merge-tree", "--write-tree", "--name-only",
                            "--no-messages", parents[0], parents[1]], capture_output=True, text=True, errors="replace")
        if p.returncode not in (0, 1):
            print(f"NOTE merge-hidden-edit: merge-tree failed for {short}: {p.stderr.strip()}", file=sys.stderr)
            continue
        lines = p.stdout.split("\n")
        tree = lines[0].strip()
        conflicted = {ln for ln in lines[1:] if ln.strip()}
        d = parse_diff(ctx.repo.git("diff", "-U0", "--no-renames", "--no-color", tree, m))
        for path, hunks in sorted(d.items()):
            if not hunks:
                continue
            if path in conflicted:
                regions = marker_regions(ctx.repo.show(tree, path) or "")
                inside = [h for h in hunks if in_regions(h, regions)]
                outside = [h for h in hunks if not in_regions(h, regions)]
            else:
                inside, outside = [], hunks
            if inside:
                plus = sum(len(h.added) for h in inside)
                minus = sum(len(h.removed) for h in inside)
                out.append(Finding("merge-hidden-edit", path, inside[0].new_start,
                                   f"merge {short}: conflict resolution, {len(inside)} hunks +{plus}/-{minus} inside git's conflict markers", False))
            if outside:
                plus = sum(len(h.added) for h in outside)
                minus = sum(len(h.removed) for h in outside)
                what = "outside git's conflict markers in a conflicted file" if path in conflicted else "in a file git merged cleanly"
                out.append(Finding("merge-hidden-edit", path, outside[0].new_start,
                                   f"merge {short}: edit {what} (hidden fix), {len(outside)} hunks +{plus}/-{minus}", True))
    return out


# --------------------------------------------------------------------------- 3 model-commit

def final_diff_for(case: str) -> Optional[str]:
    base = "/var/tmp/qwen-next-eval"
    try:
        for d in sorted(os.listdir(base)):
            if d.startswith(f"scratch-{case}-"):
                f = os.path.join(base, d, "final.diff")
                if os.path.isfile(f):
                    return f
    except OSError:
        pass
    return None


def diff_lines(text: str) -> dict:
    """{path: sorted +/- lines} of a unified diff, ignoring hunk headers and index lines."""
    d: dict = {}
    path = None
    for ln in text.split("\n"):
        m = re.match(r"diff --git a/(.*) b/(.*)$", ln)
        if m:
            path = m.group(2)
            d.setdefault(path, [])
        elif path and ln[:1] in ("+", "-") and not ln.startswith(("+++", "---")):
            d[path].append(ln)
    return {k: sorted(v) for k, v in d.items()}


def commit_patch(repo: Repo, c: str) -> str:
    return repo.git("diff", "--no-renames", "--no-color", c + "^", c)


def compare_commits(repo: Repo, cand: str, orig: str) -> list:
    """Findings when the patch of commit `cand` is not the patch of `orig` (a model commit
    rebased with an edit inside it, T644 #12): per file, the sorted +/- lines differ."""
    a, b = diff_lines(commit_patch(repo, cand)), diff_lines(commit_patch(repo, orig))
    out = []
    for path in sorted(set(a) | set(b)):
        if a.get(path) != b.get(path):
            na, nb = len(a.get(path) or []), len(b.get(path) or [])
            out.append(Finding("model-commit", path, 0,
                               f"commit {cand[:8]} differs from {orig[:8]} here ({na} vs {nb} +/- lines): edited after the model wrote it", True))
    return out


TRAILER = re.compile(r"^Model-Authored-By:\s*(.+)$", re.M)


def check_model_commit(ctx: Ctx) -> list:
    """Rule 9 over every non-merge commit in BASE..CANDIDATE: a subject saying "as written
    by" needs the Model-Authored-By trailer and "(... unmodified)"; every trailer must read
    `<model> (<CASE>, <run id>)`. When the run's final.diff is in /var/tmp/qwen-next-eval
    (scratch-CASE-*/), an "unmodified" commit's +/- lines per file in that diff must equal it
    (files the diff lacks are untracked-new in the run and not compared). `--orig CAND=ORIG`
    compares two commits the same way. Limit: a trailer is not required on a commit that does
    not claim 'as written by' (fixers add theirs; a human fix has none)."""
    out: list = []
    for c in ctx.repo.git("rev-list", "--no-merges", f"{ctx.base}..{ctx.cand}").split():
        body = ctx.repo.git("log", "-1", "--format=%B", c)
        subj = body.split("\n", 1)[0]
        tr = TRAILER.findall(body)
        written = re.search(r"\bas written by\b", subj, re.I)
        loc = f"commit:{c[:8]}"
        if written and not tr:
            out.append(Finding("model-commit", loc, 0, f"subject says 'as written by' but no Model-Authored-By trailer: {subj[:70]}", True))
        if written and not re.search(r"\(.*unmodified\)", subj, re.I):
            out.append(Finding("model-commit", loc, 0, f"'as written by' subject without '(... unmodified)': {subj[:70]}", True))
        for t in tr:
            m = re.search(r"\(([^,()]+),\s*([^()]+)\)\s*$", t)
            if not m:
                out.append(Finding("model-commit", loc, 0, f"Model-Authored-By trailer is not '<model> (<CASE>, <run id>)': {t[:70]}", True))
            elif written:
                fd = final_diff_for(m.group(1).strip())
                if fd:
                    want = diff_lines(open(fd, errors="replace").read())
                    got = diff_lines(commit_patch(ctx.repo, c))
                    for path, lines in want.items():
                        if path not in got:
                            out.append(Finding("model-commit", path, 0, f"commit {c[:8]} lacks {path}, which {fd} has", True))
                        elif got[path] != lines:
                            out.append(Finding("model-commit", path, 0,
                                               f"commit {c[:8]} differs from {fd} ({len(got[path])} vs {len(lines)} +/- lines): edited after the run", True))
    for cand, orig in ctx.orig.items():
        out.extend(compare_commits(ctx.repo, cand, orig))
    return out


# -------------------------------------------------------------------------- 4 checkin-file

def check_checkin_file(ctx: Ctx) -> list:
    """Any file listed in tools/checkin.sha256 (at CANDIDATE or at the merge base) changed, or
    the list itself changed (B)."""
    listed = set()
    for rev in (ctx.cand, ctx.old_rev):
        t = ctx.repo.show(rev, "tools/checkin.sha256")
        for ln in (t or "").split("\n"):
            parts = ln.split()
            if len(parts) >= 2:
                listed.add(parts[-1])
    out: list = []
    for p, hunks in sorted(ctx.diff.items()):
        if p in listed:
            first = hunks[0].new_start if hunks else 0
            out.append(Finding("checkin-file", p, first, "file listed in tools/checkin.sha256 changed (rule 2)", True))
        elif p == "tools/checkin.sha256":
            out.append(Finding("checkin-file", p, 1, "tools/checkin.sha256 itself changed (rule 2)", True))
    return out


# -------------------------------------------------------------------- 5 new-shared-state

SHARED = re.compile(r"\bAtomic[A-Z]\w*|\bArc::new\b|\bArc<|\bMutex\b|\bRwLock\b|\bthread_local!")


def in_src(path: str) -> bool:
    return bool(re.match(r"crates/[^/]+/src/.*\.rs$", path)) and not is_test_path(path)


def added_nontest(ctx: Ctx, path: str):
    """(line number, raw text, masked text) of the added lines outside test code."""
    new = ctx.repo.src(ctx.cand, path)
    if new is None:
        return
    tl = new.test_lines()
    for no, raw in ctx.added(path):
        if no in tl or no > len(new.code_lines):
            continue
        yield no, raw, new.code_lines[no - 1]


def check_new_shared_state(ctx: Ctx) -> list:
    """Added Atomic*/Arc::new/Arc</Mutex/RwLock/thread_local! in non-test crates/*/src code
    (comments and strings masked; `use` lines skipped). Flag only: whether a shared cell is
    allowed (rule 8) is judgement."""
    out: list = []
    for p in ctx.rs_files():
        if not in_src(p):
            continue
        for no, raw, code in added_nontest(ctx, p):
            if code.lstrip().startswith(("use ", "pub use ")):
                continue
            kinds = sorted(set(SHARED.findall(code)))
            if kinds:
                out.append(Finding("new-shared-state", p, no, f"added {', '.join(kinds)}: {raw.strip()[:70]}", False))
    return out


# ------------------------------------------------------------------------ 6 constant-fetch

LIT = r'(?:-?\d[\d_]*(?:i64|u64|u32|i32|usize)?|true|false|"[^"]*"(?:\s*\.\s*(?:to_string|into|to_owned)\(\))?|String::new\(\)|Vec::new\(\)|vec!\[\s*\])'
CONST_SAMPLE = re.compile(r"Sample::(?:Sint|Bool|Str|Bin)\(\s*" + LIT + r"\s*\)")


def read_expr(text: str, pos: int) -> str:
    """The expression starting at `pos`: up to a `,` at depth 0 or the bracket that closes the
    enclosing struct literal."""
    depth = 0
    for j in range(pos, len(text)):
        c = text[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                return text[pos:j].strip()
        elif c == "," and depth == 0:
            return text[pos:j].strip()
    return text[pos:].strip()


def strip_outer_braces(b: str) -> str:
    b = b.strip()
    while b.startswith("{") and match_brace(b, 0) == len(b) - 1:
        b = b[1:-1].strip()
    return b


def const_body(body: str) -> bool:
    """The body builds only literal Samples (no match/if/loops, no Sample from a value)."""
    body = strip_outer_braces(body)
    if not CONST_SAMPLE.search(body):
        return False
    rest = CONST_SAMPLE.sub("K", body)
    return "Sample::" not in rest and not re.search(r"\b(match|if|else|while|for|loop)\b", rest)


def const_fetches(src: Optional[Src]) -> dict:
    """{fetch name: line} of `FetchDesc { name: "x", func: <body> }` registrations whose body
    only ever returns one literal Sample (`Some(Sample::Sint(0))`, `cond.then_some(Sample::Bool(false))`,
    `x.map(|_| Sample::Sint(1))`). `func: ident` follows to `fn ident` in the same file.
    Limits: a constant that is correct (HAProxy's `always_true`) fires too; helpers in other
    files and `register_multi_fetch` are not followed."""
    res: dict = {}
    if src is None:
        return res
    text = mask(src.text, keep_strings=True)
    for m in re.finditer(r"\bFetchDesc\s*\{", text):
        end = match_brace(text, m.end() - 1)
        block = text[m.end():end]
        nm = re.search(r'\bname:\s*"([^"]+)"', block)
        fm = re.search(r"\bfunc:\s*", block)
        if not nm or not fm:
            continue
        pos = fm.end()
        body = None
        if block.startswith("|", pos):
            k = block.find("|", pos + 1)  # the closure's parameters may hold a comma
            if k > 0:
                body = read_expr(block, k + 1)
            expr = ""
        else:
            expr = read_expr(block, pos)
        if body is None and re.fullmatch(r"\w+", expr):
            f = re.search(r"\bfn\s+" + expr + r"\b[^{;]*\{", text)
            if f:
                body = text[f.end() - 1:match_brace(text, f.end() - 1) + 1]
        if body is not None and const_body(body):
            res[nm.group(1)] = text.count("\n", 0, m.end() + nm.start()) + 1
    return res


def check_constant_fetch(ctx: Ctx) -> list:
    """A sample fetch that is constant at CANDIDATE and was not at the merge base (rule 5: it
    parses and answers, but not from the connection)."""
    out: list = []
    for p in ctx.rs_files():
        if is_test_path(p) or "FetchDesc" not in (ctx.repo.show(ctx.cand, p) or ""):
            continue
        before = const_fetches(ctx.repo.src(ctx.old_rev, p))
        for name, line in const_fetches(ctx.repo.src(ctx.cand, p)).items():
            if name not in before:
                out.append(Finding("constant-fetch", p, line, f"fetch {name} returns a literal constant whatever the input", True))
    return out


# -------------------------------------------------------------------- 7 write-only-field

FIELD = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?([a-z_]\w*)\s*:\s*[^:]")
LITERAL_INIT = re.compile(r"^(?:-?\d[\d_]*\w*|true|false|None|String::new\(\)|Vec::new\(\)|Default::default\(\)|\[\]|\"[^\"]*\"|0\.0)$")


def struct_field_lines(src: Src) -> dict:
    """{line: struct name} for the lines directly inside a named-field `struct X { ... }`."""
    if getattr(src, "_fields", None) is not None:
        return src._fields
    res: dict = {}
    src._fields = res
    for m in re.finditer(r"\bstruct\s+(\w+)[^;{]*\{", src.code):
        a = src.lineno(m.end() - 1)
        b = src.lineno(match_brace(src.code, m.end() - 1))
        depth = 0
        for ln in range(a, b + 1):
            c = src.code_lines[ln - 1]
            if ln > a and depth == 1:
                res[ln] = m.group(1)
            depth += c.count("{") - c.count("}")
    return res


def check_write_only_field(ctx: Ctx) -> list:
    """A struct field added by the diff that the tree at CANDIDATE reads but never writes after
    construction: at least one `name: <literal>` initialiser exists, none takes a value (a
    shorthand `Struct { name }` counts as one), and no `.name =`,
    `.name op=`, `&mut ..name` or mutating method call exists. Scans crates/*/src of CANDIDATE
    with `git grep -w`; cfg(test) hits are ignored. Limits: a write through a macro, a `ref mut`
    pattern or a raw pointer is not seen, so a field that is written can be flagged; a field set
    by any non-literal initialiser counts as written."""
    out: list = []
    for p in ctx.rs_files():
        if not in_src(p):
            continue
        new = ctx.repo.src(ctx.cand, p)
        if new is None:
            continue
        fl = struct_field_lines(new)
        tl = new.test_lines()
        for no, raw in ctx.added(p):
            if no not in fl or no in tl:
                continue
            m = FIELD.match(new.code_lines[no - 1])
            if not m:
                continue
            name = m.group(1)
            reads = writes = inits = nonlit = 0
            g = ctx.repo.git("grep", "-n", "-I", "-w", "-e", name, ctx.cand, "--", "crates/*/src/*.rs", "crates/*/src/**/*.rs", ok=(0, 1))
            seen = set()
            for hit in g.split("\n"):
                hm = re.match(r"^[0-9a-f]+:(.+?):(\d+):", hit)
                if not hm:
                    continue
                hp, hn = hm.group(1), int(hm.group(2))
                if (hp, hn) in seen or (hp == p and hn == no):
                    continue
                seen.add((hp, hn))
                s = ctx.repo.src(ctx.cand, hp)
                if s is None or hn in s.test_lines():
                    continue
                code = s.code_lines[hn - 1]
                if re.search(r"\.\s*" + name + r"\s*(?:[-+*/|&^%]|<<|>>)?=(?!=)", code) \
                        or re.search(r"&mut\s+[\w.\[\]()]*\." + name + r"\b", code) \
                        or re.search(r"\.\s*" + name + r"\s*\.\s*(?:store|swap|fetch_\w+|set|insert|push\w*|extend|replace|take|clear|get_or_insert\w*|as_mut|get_mut|entry|remove|retain|truncate|resize)\s*\(", code):
                    writes += 1
                    continue
                im = re.search(r"(?<![.\w])" + name + r"\s*:\s*(?!:)([^,}]*)", code)
                if im and hn not in struct_field_lines(s):
                    inits += 1
                    if not LITERAL_INIT.match(im.group(1).strip()):
                        nonlit += 1
                    continue
                if re.search(r"(?<![.\w])" + name + r"\s*[,}]", code) and hn not in struct_field_lines(s):
                    inits += 1  # `Struct { name, .. }`: initialised from a variable
                    nonlit += 1
                    continue
                if re.search(r"\.\s*" + name + r"\b", code):
                    reads += 1
            if reads and not writes and inits and not nonlit:
                out.append(Finding("write-only-field", p, no,
                                   f"field {fl[no]}.{name} is read at {reads} sites but never written after construction ({inits} literal initialisers)", False))
    return out


# --------------------------------------------------------------------------- 8 new-panic

PANIC = re.compile(r"\b(?:todo|unimplemented|panic)\s*!")
MARKER = re.compile(r"\b(?:TODO|FIXME)\b")


def check_new_panic(ctx: Ctx) -> list:
    """todo!/unimplemented!/panic! (in code, not comments or strings) and TODO/FIXME markers
    (anywhere, comments included) added to non-test .rs code (B)."""
    out: list = []
    for p in ctx.rs_files():
        if is_test_path(p):
            continue
        for no, raw, code in added_nontest(ctx, p):
            hit = PANIC.search(code)
            if hit:
                out.append(Finding("new-panic", p, no, f"added {hit.group(0)}: {raw.strip()[:70]}", True))
            elif MARKER.search(raw):
                out.append(Finding("new-panic", p, no, f"added {MARKER.search(raw).group(0)} marker: {raw.strip()[:70]}", True))
    return out


# -------------------------------------------------------------------- 9 request-path-alloc

ALLOC = re.compile(r"\bBox::new\b|\bVec::new\b|\bvec!|\bString::new\b|\bformat!|\.to_string\(\)|\.to_vec\(\)|\.clone\(\)")


def request_path_file(p: str) -> bool:
    if p in ("crates/alcyon-rt/src/engine.rs", "crates/alcyon-rt/src/proxy.rs"):
        return True
    m = re.match(r"crates/[^/]+/src/(?:.*/)?([^/]+)\.rs$", p)
    return bool(m and re.search(r"(?:^|_)(?:mux|h1|h2)(?:_|$)", m.group(1)))


def check_request_path_alloc(ctx: Ctx) -> list:
    """Allocations added in the request-path files (alcyon-rt engine.rs and proxy.rs, any
    *mux*, *h1*, *h2* file under crates/*/src) outside test code (F). Rule 8 wants the
    instructions-per-request figure, not a verdict: this lists lines and cannot tell a startup
    path from a per-request one."""
    out: list = []
    for p in ctx.rs_files():
        if is_test_path(p) or not request_path_file(p):
            continue
        for no, raw, code in added_nontest(ctx, p):
            kinds = sorted(set(ALLOC.findall(code)))
            if kinds:
                out.append(Finding("request-path-alloc", p, no, f"added {', '.join(kinds)}: {raw.strip()[:70]}", False))
    return out


# ------------------------------------------------------------------------- 10 test-layout

def unreached_at(repo: Repo, rev: str, layout) -> tuple:
    """(unreached test files, autotests crates) of the tree at `rev`, via harness/layout.py on a
    temporary extract of every crate's Cargo.toml and tests/."""
    names = repo.git("ls-tree", "-r", "--name-only", rev, "--", "crates").split("\n")
    keep = [n for n in names if n and (re.fullmatch(r"crates/[^/]+/Cargo\.toml", n) or re.match(r"crates/[^/]+/tests/", n))]
    with tempfile.TemporaryDirectory(prefix="t643-layout-") as d:
        p = subprocess.run(["git", "-C", repo.root, "archive", rev, "--", *keep], capture_output=True)
        if p.returncode != 0:
            raise RuntimeError(p.stderr.decode(errors="replace"))
        with tarfile.open(fileobj=io.BytesIO(p.stdout)) as t:
            t.extractall(d, filter="data")
        un = {os.path.relpath(f, d) for c in layout.crates(d) for f in layout.unreached(c)}
        auto = {os.path.relpath(c, d) for c in layout.crates(d) if layout.autotests(c)}
    return un, auto


def check_test_layout(ctx: Ctx) -> list:
    """Test files that no test target compiles at CANDIDATE and did not at the merge base, via
    this tree's harness/layout.py on an extract of crates/*/{Cargo.toml,tests}. Skipped with a
    note on stderr when layout.py cannot be imported or the extract fails."""
    sys.path.insert(0, os.path.join(TREE, "harness"))
    try:
        import layout  # type: ignore
    except Exception as e:  # noqa: BLE001
        print(f"NOTE test-layout skipped: cannot import harness/layout.py ({e})", file=sys.stderr)
        return []
    try:
        un_c, auto_c = unreached_at(ctx.repo, ctx.cand, layout)
        un_b, auto_b = unreached_at(ctx.repo, ctx.old_rev, layout)
    except Exception as e:  # noqa: BLE001
        print(f"NOTE test-layout skipped: {e}", file=sys.stderr)
        return []
    out: list = []
    for f in sorted(un_c - un_b):
        out.append(Finding("test-layout", f, 1, "test file no test target compiles (declare it in tests/it/main.rs)", True))
    for c in sorted(auto_c - auto_b):
        out.append(Finding("test-layout", c + "/Cargo.toml", 1, "crate with tests/ lets cargo build one binary per file (autotests)", True))
    return out


# ------------------------------------------------------------------------------- driver

CHECKS = [
    ("removed-test", check_removed_test),
    ("merge-hidden-edit", check_merge_hidden_edit),
    ("model-commit", check_model_commit),
    ("checkin-file", check_checkin_file),
    ("new-shared-state", check_new_shared_state),
    ("constant-fetch", check_constant_fetch),
    ("write-only-field", check_write_only_field),
    ("new-panic", check_new_panic),
    ("request-path-alloc", check_request_path_alloc),
    ("test-layout", check_test_layout),
]


def run(repo_root: str, base: str, cand: str, only: Optional[set] = None, orig: Optional[dict] = None) -> list:
    repo = Repo(repo_root)
    base, cand = repo.resolve(base), repo.resolve(cand)
    ctx = Ctx(repo, base, cand, orig)
    out: list = []
    for name, fn in CHECKS:
        if only and name not in only:
            continue
        out.extend(fn(ctx))
    return out


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("base")
    ap.add_argument("candidate")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--repo", default=TREE)
    ap.add_argument("--only", help="comma-separated check names")
    ap.add_argument("--orig", action="append", default=[], metavar="CAND=ORIG",
                    help="compare commit CAND's patch to ORIG's (a rebased model commit)")
    a = ap.parse_args(argv)
    only = set(a.only.split(",")) if a.only else None
    orig = dict(o.split("=", 1) for o in a.orig)
    findings = run(a.repo, a.base, a.candidate, only, orig)
    blocking = sum(1 for f in findings if f.blocking)
    if a.json:
        print(json.dumps({"base": a.base, "candidate": a.candidate, "blocking": blocking,
                          "findings": [f._asdict() for f in findings]}, indent=1))
    else:
        for f in findings:
            print(f.text())
        print(f"SUMMARY {a.base[:8]}..{a.candidate[:8]}: {len(findings)} findings, {blocking} blocking")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
