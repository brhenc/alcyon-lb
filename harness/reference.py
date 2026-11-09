#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Where the oracles are: the directory `$ALCYON_REFERENCE` (T630; README, "Running the oracle tests").

Its layout:

    haproxy/haproxy              HAProxy 3.5-dev8, the oracle (built in its source tree:
    haproxy/src, haproxy/include   alcyon-h1-sys compiles src/h1.c and src/http.c)
    haproxy/reg-tests            its reg-tests (the smoke board)
    haproxy-quic/haproxy         HAProxy 3.5-dev10 built with USE_QUIC
    haproxy-1.0.2/haproxy102     HAProxy 1.0.2

There is no default: a test that needs an oracle skips when the variable is unset, and a gate
stage fails naming it (`require`), so a gate cannot pass by skipping its oracles. A per-binary
variable that already existed (`HAPROXY`, `HQ`, ...) still wins over the directory.

    python3 harness/reference.py --require [--who NAME] [REL ...]

exits 1 naming the variable or the missing file, unless every REL (default: `GATE_NEEDS`) is
under `$ALCYON_REFERENCE`. tools/checkin.sh runs it before the stages that build or run oracles.
"""
from __future__ import annotations

import os
import sys

VAR = "ALCYON_REFERENCE"
HAPROXY = "haproxy/haproxy"
HAPROXY_QUIC = "haproxy-quic/haproxy"
HAPROXY_102 = "haproxy-1.0.2/haproxy102"
HAPROXY_SRC = "haproxy"
REGTESTS = "haproxy/reg-tests"
# What the gate's stages use: the suite's oracle tests and alcyon-h1-sys's build (src/h1.c).
GATE_NEEDS = [HAPROXY, HAPROXY_QUIC, HAPROXY_102, REGTESTS, "haproxy/src/h1.c"]
HINT = 'the directory of the reference HAProxy builds (README, "Running the oracle tests")'


def root(env: dict | None = None) -> str | None:
    """`$ALCYON_REFERENCE`, or None when it is unset or empty."""
    env = os.environ if env is None else env
    return env.get(VAR) or None


def path(rel: str, override: str | None = None, env: dict | None = None) -> str | None:
    """The oracle file `rel` (one of the names above): `$override` when that variable is set,
    else `$ALCYON_REFERENCE/rel`, else None."""
    env = os.environ if env is None else env
    if override and env.get(override):
        return env[override]
    r = root(env)
    return os.path.join(r, rel) if r else None


def require(rel: str, override: str | None = None, who: str = "", env: dict | None = None) -> str:
    """`path(...)`, which must exist; otherwise SystemExit with a message naming the variable."""
    p = path(rel, override, env)
    prefix = f"{who}: " if who else ""
    alt = f" (or {override})" if override else ""
    if p is None:
        raise SystemExit(f"{prefix}{VAR} is not set{alt}: it names {HINT}; needed: $"
                         f"{VAR}/{rel}")
    if not os.path.exists(p):
        raise SystemExit(f"{prefix}{p} does not exist ({VAR}={root(env) or ''}{alt})")
    return p


def main(argv: list[str]) -> int:
    if not argv or argv[0] != "--require":
        print(__doc__.strip().splitlines()[0])
        print("usage: reference.py --require [--who NAME] [REL ...]", file=sys.stderr)
        return 2
    argv = argv[1:]
    who = ""
    if argv[:1] == ["--who"] and len(argv) >= 2:
        who, argv = argv[1], argv[2:]
    for rel in argv or GATE_NEEDS:
        try:
            require(rel, who=who)
        except SystemExit as e:
            print(e.code)
            return 1
    print(f"{who + ': ' if who else ''}{VAR}={root()}: {' '.join(argv or GATE_NEEDS)} present")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
