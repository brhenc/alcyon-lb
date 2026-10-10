#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""The integration-test layout (T260): one test binary per crate, `tests/it/main.rs`.

A crate with `autotests = false` compiles only the test targets its Cargo.toml declares,
and a module file nothing declares is not compiled either. A `tests/<name>.rs` added the
way it always was -- or a `tests/it/<name>.rs` left out of `main.rs` -- then builds
nothing, runs nothing and fails nothing, silently: the T48 failure mode (a test that exists
and never runs). `unreached()` names every `.rs` file under a crate's `tests/` that no test
target reaches through `mod` declarations; harness/test_layout.py fails the gate's
harness-tests stage on any.

Usage:  python3 harness/layout.py          # list unreached test files, exit 1 if any
"""
from __future__ import annotations

import os
import re
import sys
import tomllib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# `mod name;`, optionally preceded by `#[path = "..."]` (and other attributes) on the lines
# before it. Inline modules (`mod name { ... }`) declare no file.
MOD_RE = re.compile(r'((?:#\[[^\]]*\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;')
PATH_RE = re.compile(r'#\[path\s*=\s*"([^"]+)"\s*\]')
COMMENT_RE = re.compile(r'//[^\n]*')


def test_roots(crate: str) -> list[str]:
    """The source files of the crate's test targets, as cargo would build them."""
    with open(os.path.join(crate, "Cargo.toml"), "rb") as f:
        manifest = tomllib.load(f)
    pkg = manifest.get("package", {})
    roots = []
    for t in manifest.get("test", []):
        roots.append(os.path.join(crate, t.get("path", f"tests/{t['name']}.rs")))
    if pkg.get("autotests", True):
        tests = os.path.join(crate, "tests")
        for e in sorted(os.listdir(tests)) if os.path.isdir(tests) else []:
            p = os.path.join(tests, e)
            if e.endswith(".rs") and os.path.isfile(p):
                roots.append(p)
            elif os.path.isfile(os.path.join(p, "main.rs")):
                roots.append(os.path.join(p, "main.rs"))
    return [os.path.normpath(r) for r in roots]


def declared_modules(path: str, root: bool = False) -> list[str]:
    """The files `path` declares as modules (those that exist; a missing one is rustc's
    error, not this check's). A crate root (`root`) looks beside itself, as mod.rs does."""
    src = COMMENT_RE.sub("", open(path, encoding="utf-8").read())
    here = os.path.dirname(path)
    base = os.path.basename(path)
    # A `mod x;` in a crate root or mod.rs looks beside it; in foo.rs, in foo/.
    sub = here if root or base == "mod.rs" else os.path.join(here, base[:-3])
    out = []
    for m in MOD_RE.finditer(src):
        p = PATH_RE.search(m.group(1))
        if p:
            cands = [os.path.join(here, p.group(1))]
        else:
            cands = [os.path.join(sub, m.group(2) + ".rs"), os.path.join(sub, m.group(2), "mod.rs")]
        out += [os.path.normpath(c) for c in cands if os.path.isfile(c)]
    return out


def unreached(crate: str) -> list[str]:
    """Every `.rs` file under `crate/tests` that no test target compiles, sorted."""
    tests = os.path.join(crate, "tests")
    if not os.path.isdir(tests):
        return []
    roots = test_roots(crate)
    seen, todo = set(), list(roots)
    while todo:
        p = todo.pop()
        if p in seen or not os.path.isfile(p):
            continue
        seen.add(p)
        todo += declared_modules(p, p in roots)
    files = [os.path.normpath(os.path.join(d, f)) for d, _, fs in os.walk(tests)
             for f in fs if f.endswith(".rs")]
    return sorted(f for f in files if f not in seen)


def crates(repo: str = REPO) -> list[str]:
    root = os.path.join(repo, "crates")
    return sorted(os.path.join(root, c) for c in os.listdir(root)
                  if os.path.isfile(os.path.join(root, c, "Cargo.toml")))


def package_dirs(repo: str = REPO) -> dict[str, str]:
    """Package name -> crate directory."""
    out = {}
    for c in crates(repo):
        with open(os.path.join(c, "Cargo.toml"), "rb") as f:
            out[tomllib.load(f)["package"]["name"]] = c
    return out


def own_targets(crate: str) -> dict[str, str]:
    """The crate's test targets other than `it`, name -> source file."""
    with open(os.path.join(crate, "Cargo.toml"), "rb") as f:
        manifest = tomllib.load(f)
    return {t["name"]: os.path.join(crate, t.get("path", f"tests/{t['name']}.rs"))
            for t in manifest.get("test", []) if t["name"] != "it"}


def migrate_key(old: str) -> str:
    """A suite key (`crate/target::test`) from before T260 in today's layout: a test file
    that became a module of `it` is `crate/it::file::test`; a unit test (`lib`), the doc
    tests and a file that kept its own binary keep their name."""
    pkg, rest = old.split("/", 1)
    target, _, test = rest.partition("::")
    crate = package_dirs().get(pkg)
    if crate is None or target in ("lib", "doc", "it") or ":" in target or target in own_targets(crate):
        return old
    return f"{pkg}/it::{target}::{test}"


def _defines(paths: list[str], fn: str) -> bool:
    pat = re.compile(r"\bfn\s+" + re.escape(fn) + r"\b")
    return any(pat.search(open(p, encoding="utf-8").read()) for p in paths if os.path.isfile(p))


def resolve_key(key: str) -> str | None:
    """The source file that defines the test a suite key names, or None when it names none.
    A key ending in `::` names a target or a module of `it` (SERIAL_TARGETS' prefixes)."""
    pkg, _, rest = key.partition("/")
    target, _, test = rest.partition("::")
    crate = package_dirs().get(pkg)
    if crate is None:
        return None
    parts = test.split("::")
    if target == "lib":
        files = [os.path.join(d, f) for d, _, fs in os.walk(os.path.join(crate, "src")) for f in fs
                 if f.endswith(".rs")]
    elif target == "it":
        base = os.path.join(crate, "tests", "it", parts[0])
        files = [base + ".rs"] + [os.path.join(d, f) for d, _, fs in os.walk(base) for f in fs]
        parts = parts[1:] or [""]
    elif target in own_targets(crate):
        files = [own_targets(crate)[target]]
    else:
        return None
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        return None
    if parts[-1] == "":
        return files[0]
    return next((f for f in files if _defines([f], parts[-1])), None)


def main() -> int:
    bad = [f for c in crates() for f in unreached(c)]
    for f in bad:
        print(f"layout: {os.path.relpath(f, REPO)} is compiled by no test target: declare it "
              f"`mod` in its crate's tests/it/main.rs (or give it its own [[test]])")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
