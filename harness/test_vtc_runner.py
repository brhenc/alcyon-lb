#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Tests for the vtest environment the runner provides to a test.

Run:  python3 -m unittest harness/test_vtc_runner.py

vtest defines macros of its own (`${bad_backend}`, `${bad_ip}`, ...) and exports
$HAPROXY_PROGRAM to `shell` blocks and `feature cmd`. The runner did neither, so four
reg-tests failed before the proxy under test saw a meaningful configuration.
"""
from __future__ import annotations

import asyncio
import os
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vtc_runner  # noqa: E402


def executor(vtc_text: str, binary: str = "/bin/true") -> "vtc_runner.VtcExecutor":
    f = tempfile.NamedTemporaryFile("w", suffix=".vtc", delete=False)
    f.write(vtc_text)
    f.close()
    parser = vtc_runner.VtcParser(vtc_text, f.name)
    parser.parse()
    return vtc_runner.VtcExecutor(parser, binary, timeout=5.0)


class BuiltinMacros(unittest.TestCase):
    def test_bad_backend_is_an_address_that_refuses(self):
        ex = executor('varnishtest "x"\n')
        addr = ex.macro_engine.expand("${bad_backend}")
        self.assertNotEqual(addr, "${bad_backend}")
        host, port = addr.rsplit(":", 1)
        with self.assertRaises(ConnectionRefusedError):
            socket.create_connection((host, int(port)), timeout=2).close()

    def test_bad_ip_and_localhost_are_defined(self):
        ex = executor('varnishtest "x"\n')
        for m in ("bad_ip", "localhost"):
            self.assertNotEqual(ex.macro_engine.expand("${%s}" % m), "${%s}" % m, m)

    def test_shell_block_sees_haproxy_program(self):
        ex = executor('varnishtest "x"\nshell {\n  test "$HAPROXY_PROGRAM" = /bin/echo\n}\n',
                      "/bin/echo")
        res = asyncio.run(ex.execute())
        self.assertEqual(res.status, "PASS", res.error_message)

    def test_failing_shell_block_fails(self):
        ex = executor('varnishtest "x"\nshell {\n  false\n}\n')
        self.assertEqual(asyncio.run(ex.execute()).status, "FAIL")

    def test_feature_cmd_sees_haproxy_program(self):
        ex = executor('varnishtest "x"\nfeature cmd "test $HAPROXY_PROGRAM = /bin/echo"\n',
                      "/bin/echo")
        res = asyncio.run(ex.execute())
        self.assertNotIn("Feature condition unsatisfied", res.error_message or "")


class ChunkedBodies(unittest.TestCase):
    """The header read is a `read(4096)` and takes what follows the blank line with it. For a
    chunked message that is the start of the chunk stream, size line included, and it was
    kept as body bytes: the next line was then read as a chunk size
    ("invalid literal for int() with base 16", converter/when_debug.vtc against /stats)."""

    wire = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")

    def parse(self, fn, wire):
        async def go():
            r = asyncio.StreamReader()
            r.feed_data(wire)
            r.feed_eof()
            return await fn(r)
        return asyncio.run(go())

    def test_response(self):
        resp = self.parse(vtc_runner.parse_http_response, self.wire)
        self.assertEqual(resp.body, b"hello world")

    def test_request(self):
        wire = self.wire.replace(b"HTTP/1.1 200 OK", b"POST / HTTP/1.1")
        req = self.parse(vtc_runner.parse_http_request, wire)
        self.assertEqual(req.body, b"hello world")


class BlockBraces(unittest.TestCase):
    def test_lone_double_quote_in_a_block_does_not_open_a_string(self):
        # startup/check_condition.vtc: a shell block holding `-cc 'streq(a,"a)'`. vtest
        # counts only braces inside { }; the quote swallowed the closing brace here.
        text = 'shell {\n  ! x -cc \'streq(a,"a)\'\n} -run\n'
        first, last = vtc_runner.find_block_braces(text)
        self.assertEqual(text[last:], "} -run\n")


if __name__ == "__main__":
    unittest.main()
