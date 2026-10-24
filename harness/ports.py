# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Loopback ports for the harness, handed out the way the Rust tests' `common::reserve_addr`
(`crates/ibex-rt/tests/common/mod.rs`) does.

A port taken by binding `:0` and closing the socket is in the kernel's ephemeral range
(32768-60999 by default): until the proxy binds it, the kernel can hand it to any outgoing
connection, so the proxy fails to start, or a "dead" server address answers. A port here:

* comes from 20000..32767, below the ephemeral range, so the kernel never assigns it;
* is `flock`ed in the same directory as the Rust helper uses, so no test of either kind,
  in this process or another, is given it while the lock is held (until the process exits);
* was bindable when it was handed out.
"""

import fcntl
import os
import socket
import tempfile
import threading

FIRST = 20000
COUNT = 12768

_held: list = []
_lock = threading.Lock()
_next = [0]


def _bindable(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def reserve_port() -> int:
    """A loopback port no other test is given, held until this process exits."""
    d = os.path.join(tempfile.gettempdir(), "ibex-test-ports")
    os.makedirs(d, exist_ok=True)
    start = (os.getpid() * 97) % COUNT
    with _lock:
        for _ in range(COUNT):
            i = _next[0] % COUNT
            _next[0] += 1
            port = FIRST + (start + i) % COUNT
            try:
                f = open(os.path.join(d, str(port)), "w")
            except OSError:
                continue
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                f.close()
                continue
            if not _bindable(port):
                f.close()
                continue
            _held.append(f)
            return port
    raise RuntimeError(f"no free test port in {FIRST}..{FIRST + COUNT}")
