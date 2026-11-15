#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Ledger of the code written by models other than the Claude models that maintain this tree.

Finds every commit that carries a model's output in this repository's history, then counts how
many of the lines it added are still on HEAD, line by line (`git blame`). The output is
`docs/provenance/LOCAL-MODELS.md`. It is derived from git only, so it can be regenerated and
checked in any clone (commit IDs differ between the full and the published history; the
subjects do not).

A model commit is recognised by any of:
  * a `Model-Authored-By: <model>` trailer (the rule since 2026-11-15, AGENTS.md rule 9);
  * a subject "<case>: <x> patch from the <model> queue (unreviewed)" (2026-10 queues);
  * a subject "..., as written by <model> (<CASE> case, unmodified)";
  * a body line "Written by <model> (local, ..." (TRACKSC, 2026-11-14).

Usage: tools/model_provenance.py [--check]   (--check: exit 1 if the file is out of date)
"""
import argparse
import collections
import os
import re
import subprocess
import sys

OUT = "docs/provenance/LOCAL-MODELS.md"
SEP = "\x1e"

PATTERNS = [
    ("trailer", re.compile(r"^Model-Authored-By:\s*(?P<model>[^\n(]+?)\s*(\(|$)", re.M)),
    ("queue", re.compile(r"^(?P<case>[\w.-]+): (?:\w+ )?patch from the (?P<model>[\w. -]+?) queue \(unreviewed\)")),
    ("as-written", re.compile(r"as written by (?P<model>[\w.-]+) \((?P<case>\w+) case, unmodified\)")),
    ("body", re.compile(r"^Written by (?P<model>[\w.-]+) \(local, \S+ (?P<case>\w+) run", re.M)),
]

# The 2026-10-15 Qwen queue commits did not record the model's version. The queue that day ran
# Qwen3.6-35B-A3B (the harness's model until Muse Glimmer took over on 10-16).
MODEL_ALIASES = {"Qwen": "Qwen (version not recorded; the 10-15 queue ran Qwen3.6-35B-A3B)"}

# Commits that mix a model's code with the maintainers' changes in one commit, from before the
# rule that a model's output is committed unmodified on its own. Keyed by subject prefix:
# (model, case, what else is in the commit, which files to count).
MIXED = {
    "Refuse a track-sc in a defaults section that names a missing table": (
        "Qwen3.8-Flash-Next", "TRACKSC",
        "also has the supervisor's changes: an unreachable branch removed in `refs.rs`, and "
        "`fetch_be_conn.rs` (the test) written by the supervisor; that file is not counted",
        {"exclude": {"crates/alcyon-rt/tests/it/fetch_be_conn.rs"}}),
    "vtc_runner: hex strings as VTest reads them": (
        "Muse Glimmer 30B", "t363l",
        "Muse's `vtc_runner.py` hex fix, corrected by the maintainer in the same commit, together "
        "with unrelated docs; only `harness/vtc_runner.py` is counted",
        {"only": {"harness/vtc_runner.py"}}),
}


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def model_commits():
    log = git("log", f"--format=%H{SEP}%ad{SEP}%s{SEP}%B{SEP}\x1d", "--date=short", "HEAD")
    found = []
    for rec in log.split("\x1d"):
        rec = rec.strip("\n")
        if not rec:
            continue
        h, date, subj, body, _ = rec.split(SEP)
        if subj.startswith("Merge "):
            continue
        mixed = next((v for k, v in MIXED.items() if subj.startswith(k)), None)
        if mixed:
            found.append(dict(hash=h, date=date, subject=subj, model=mixed[0], case=mixed[1], note=mixed[2], paths=mixed[3]))
            continue
        for kind, pat in PATTERNS:
            m = pat.search(subj if kind in ("queue", "as-written") else body)
            if m:
                model = m.group("model").strip()
                model = {"Qwen": MODEL_ALIASES["Qwen"]}.get(model, model)
                model = model.replace("Muse-Glimmer-30B", "Muse Glimmer 30B")
                case = m.groupdict().get("case") or subj.split(":")[0]
                found.append(dict(hash=h, date=date, subject=subj, model=model, case=case, note="", paths={}))
                break
    return found


def current_path(path):
    if os.path.exists(path):
        return path
    renamed = path.replace("ibex-", "alcyon-").replace("ibex_", "alcyon_")
    return renamed if os.path.exists(renamed) else None


def added_lines(h):
    out = {}
    for line in git("show", "--numstat", "--format=", h).splitlines():
        a, _d, path = line.split("\t", 2)
        if a != "-":
            out[path] = int(a)
    return out


_blame = {}


def blame_counts(path):
    if path not in _blame:
        counts = collections.Counter()
        out = git("blame", "--line-porcelain", "HEAD", "--", path)
        for line in out.splitlines():
            m = re.match(r"^([0-9a-f]{40}) \d+ \d+", line)
            if m:
                counts[m.group(1)] += 1
        _blame[path] = counts
    return _blame[path]


def render(commits):
    by_model = collections.OrderedDict()
    rows = []
    for c in sorted(commits, key=lambda c: (c["date"], c["case"])):
        added = added_lines(c["hash"])
        if "only" in c["paths"]:
            added = {p: n for p, n in added.items() if p in c["paths"]["only"]}
        added = {p: n for p, n in added.items() if p not in c["paths"].get("exclude", set())}
        total_add = sum(added.values())
        alive = 0
        files = []
        for path, n in sorted(added.items()):
            cur = current_path(path)
            left = blame_counts(cur).get(c["hash"], 0) if cur else 0
            alive += left
            files.append(f"`{cur or path}`{'' if cur else ' (gone)'} +{n}/{left}")
        rows.append((c, total_add, alive, files))
        s = by_model.setdefault(c["model"], [0, 0, 0])
        s[0] += 1
        s[1] += total_add
        s[2] += alive
    lines = [
        "<!-- Generated by tools/model_provenance.py from git history. Do not edit by hand. -->",
        "# Code written by local models",
        "",
        "Alcyon is written by Claude models under one maintainer. Some code was written by other",
        "models, run locally and graded as part of evaluations. This file lists every such commit so",
        "that the code can be audited. It is regenerated from `git log` and `git blame` by",
        "`tools/model_provenance.py`; run it in any clone to check it.",
        "",
        "How the code came in:",
        "",
        "- Since 2026-10, the model's output is committed **unmodified**, as its own commit, before anyone changes",
        "  it. The subject or a `Model-Authored-By:` trailer names the model. The fixes and tests",
        "  that make it mergeable are separate commits on top, so `git show <commit>` is exactly",
        "  what the model wrote.",
        "- Every change passed review by a Claude model and the project's full gate (tests, oracle",
        "  comparison against HAProxy, fuzzing, lints) before it was merged.",
        "- Two early commits mix a model's code with the maintainers' changes; the Note column says",
        "  which, and only the files that trace to the model are counted.",
        "- **Lines on HEAD** counts the model's lines that are still unchanged in the current tree",
        "  (`git blame`). A line edited later is attributed to the later commit.",
        "",
        "## Summary",
        "",
        "| Model | Commits | Lines added | Lines on HEAD |",
        "|---|---:|---:|---:|",
    ]
    for model, (n, add, alive) in by_model.items():
        lines.append(f"| {model} | {n} | {add} | {alive} |")
    lines += ["", "## Commits", "",
              "Each file is shown as `path +added/still-on-HEAD`.", "",
              "| Date | Case | Model | Commit | Lines added | On HEAD | Files | Note |",
              "|---|---|---|---|---:|---:|---|---|"]
    for c, add, alive, files in rows:
        lines.append(f"| {c['date']} | {c['case']} | {c['model']} | `{c['hash'][:10]}` | {add} | {alive} | {'<br>'.join(files)} | {c['note'] or 'unmodified model output'} |")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    os.chdir(git("rev-parse", "--show-toplevel").strip())
    text = render(model_commits())
    if args.check:
        cur = open(OUT).read() if os.path.exists(OUT) else ""
        if cur != text:
            print(f"{OUT} is out of date: run tools/model_provenance.py", file=sys.stderr)
            return 1
        return 0
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        f.write(text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
