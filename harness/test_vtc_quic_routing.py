#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""T528: which binary runs which `haproxy` block of a QUIC reg-test.

Run:  python3 -m unittest harness/test_vtc_quic_routing.py

vtest does not speak h3, so a QUIC reg-test chains a second `haproxy` block as the QUIC client
(`server ... quic4@...`, `ssl alpn h3`, `proto qmux`). Ibex refuses QUIC towards servers (out of
M2 scope), so that block runs on the QUIC-enabled reference binary
(`VTC_QUIC_CLIENT_BINARY`, default ~/reference/haproxy-quic/haproxy); the others on Ibex.
"""
import asyncio
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vtc_runner  # noqa: E402
from test_vtc_runner import FakeProxy  # noqa: E402

SERVER_BLOCK = "frontend fe\n  bind quic+fd@${fe_quic} ssl crt x.pem\n  default_backend be\n"
CLIENT_BLOCK = "backend be\n  server s 127.0.0.1:1 quic4@127.0.0.1:2 ssl verify none\n"


def vtc(*confs):
    text = 'varnishtest "x"\n'
    for i, c in enumerate(confs, 1):
        text += "haproxy h%d -conf-OK {\n%s}\n" % (i, c)
    return text


def run(text, ibex, quic_client):
    f = tempfile.NamedTemporaryFile("w", suffix=".vtc", delete=False)
    f.write(text)
    f.close()
    p = vtc_runner.VtcParser(text, f.name)
    p.parse()
    ex = vtc_runner.VtcExecutor(p, ibex, timeout=5.0, quic_client_binary=quic_client)
    return asyncio.run(ex.execute())


class Routing(unittest.TestCase):
    def setUp(self):
        self.ibex = FakeProxy("ibex")
        self.oracle = FakeProxy("haproxy")
        self.addCleanup(self.ibex.tmp.cleanup)
        self.addCleanup(self.oracle.tmp.cleanup)

    def ran(self, fp):
        return os.path.exists(fp.log + ".args")

    def test_client_block_runs_on_the_oracle_the_other_on_ibex(self):
        res = run(vtc(SERVER_BLOCK, CLIENT_BLOCK), self.ibex.path, self.oracle.path)
        self.assertEqual(res.status, "PASS", res.error_message)
        self.assertTrue(self.ran(self.ibex))
        self.assertTrue(self.ran(self.oracle))
        self.assertIn("bind quic4@127.0.0.1:", open(self.ibex.log + ".cfg").read())
        self.assertIn("quic4@", open(self.oracle.log + ".cfg").read())

    def test_ssl_alpn_h3_and_proto_qmux_on_a_server_line_need_the_client(self):
        for line in ("server s 1.2.3.4:80 ssl alpn h3", "server s 1.2.3.4:80 proto qmux"):
            self.assertTrue(vtc_runner.quic_roles("backend b\n  %s\n" % line)[0], line)

    def test_a_bind_line_is_the_server_side(self):
        needs, serves = vtc_runner.quic_roles("frontend f\n  bind fd@1 ssl crt x alpn h3\n  bind fd@2 proto qmux\n")
        self.assertEqual((needs, serves), (False, True))

    def test_quic_fd_bind_stays_a_quic_bind_and_a_tcp_fd_bind_stays_tcp(self):
        eng = vtc_runner.MacroEngine({})
        cfg, _ = vtc_runner.preprocess_haproxy_config(
            'frontend a\n  bind "quic+fd@${fq}" ssl crt x\nfrontend b\n  bind fd@${ft} ssl crt x\n', eng, "h1")
        self.assertRegex(cfg, r"bind quic4@127\.0\.0\.1:\d+ ssl crt x")
        self.assertRegex(cfg, r"bind 127\.0\.0\.1:\d+ ssl crt x")
        self.assertEqual(eng.get("h1_fq_addr"), "127.0.0.1")

    def test_a_comment_does_not_count(self):
        self.assertEqual(vtc_runner.quic_roles("# server s quic4@1.2.3.4:5\nbackend b\n"), (False, False))

    def test_without_a_client_block_the_oracle_is_not_needed(self):
        res = run(vtc(SERVER_BLOCK), self.ibex.path, None)
        self.assertEqual(res.status, "PASS", res.error_message)
        self.assertFalse(self.ran(self.oracle))

    def test_a_missing_client_binary_is_refused_by_name(self):
        for missing in (None, "/nonexistent/haproxy"):
            res = run(vtc(SERVER_BLOCK, CLIENT_BLOCK), self.ibex.path, missing)
            self.assertEqual(res.status, "FAIL")
            self.assertIn("VTC_QUIC_CLIENT_BINARY", res.error_message or "")
        self.assertFalse(self.ran(self.ibex))

    def test_one_block_that_serves_quic_and_needs_the_client_is_out_of_scope(self):
        res = run(vtc(SERVER_BLOCK + CLIENT_BLOCK), self.ibex.path, self.oracle.path)
        self.assertEqual(res.status, "OUT_OF_SCOPE")
        self.assertIn("QUIC client", res.error_message or "")
        self.assertFalse(self.ran(self.ibex))
        self.assertFalse(self.ran(self.oracle))

    def test_force_features_runs_a_test_whose_feature_cmd_fails(self):
        text = 'varnishtest "x"\nfeature cmd "false"\n' + vtc("frontend f\n  bind fd@1\n").split("\n", 1)[1]
        f = tempfile.NamedTemporaryFile("w", suffix=".vtc", delete=False)
        f.write(text)
        f.close()
        for force, want in ((False, "SKIP"), (True, "PASS")):
            p = vtc_runner.VtcParser(text, f.name)
            p.parse()
            ex = vtc_runner.VtcExecutor(p, self.ibex.path, timeout=5.0, force_features=force)
            self.assertEqual(asyncio.run(ex.execute()).status, want)

    def test_a_plain_test_never_looks_at_the_client_binary(self):
        res = run(vtc("frontend f\n  bind fd@1\n"), self.ibex.path, None)
        self.assertEqual(res.status, "PASS", res.error_message)


if __name__ == "__main__":
    unittest.main()
