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

    def test_bad_backend_port_stays_reserved(self):
        # The board runs tests in parallel. A port that was only probed and released can be
        # bound by another test's server, and then `${bad_backend}` answers (when_debug.vtc
        # got a 504 instead of a 503). vtest keeps the socket bound, without listen().
        ex = executor('varnishtest "x"\n')
        host, port = ex.macro_engine.expand("${bad_backend}").rsplit(":", 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with self.assertRaises(OSError):
                s.bind((host, int(port)))
        finally:
            s.close()

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


class FakeProxy:
    """A stand-in binary: `-c -f cfg` exits 1 when the config holds the word BAD; any other
    run copies argv and the config to files and exits, so the test sees what it was given."""

    def __init__(self, name="fakeproxy"):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, name)
        self.log = os.path.join(self.tmp.name, "log")
        with open(self.path, "w") as f:
            f.write("#!/bin/sh\n"
                    f"echo \"$@\" >{self.log}.args\ncfg=\n"
                    "while [ $# -gt 0 ]; do [ \"$1\" = -f ] && cfg=$2; shift; done\n"
                    f"cp \"$cfg\" {self.log}.cfg\n"
                    "if grep -q BAD \"$cfg\"; then exit 1; fi\n"
                    "exit 0\n")
        os.chmod(self.path, 0o755)


class ConfBad(unittest.TestCase):
    """`haproxy h1 -conf-BAD {expected stderr} {config}`: two blocks. The parser took the
    first (empty) one for the config, so the check ran on nothing and "unexpectedly
    succeeded" for startup/default_rules and converter/has_ctl, on every binary."""

    def run_vtc(self, text):
        fp = FakeProxy()
        self.addCleanup(fp.tmp.cleanup)
        ex = executor(text, fp.path)
        return asyncio.run(ex.execute()), fp

    def test_the_second_block_is_the_config(self):
        res, fp = self.run_vtc('varnishtest "x"\nhaproxy h1 -conf-BAD {} {\n  BAD line\n}\n')
        self.assertEqual(res.status, "PASS", res.error_message)
        self.assertIn("BAD line", open(fp.log + ".cfg").read())

    def test_a_good_config_is_still_reported_as_unexpectedly_good(self):
        res, _ = self.run_vtc('varnishtest "x"\nhaproxy h1 -conf-BAD {} {\n  fine\n}\n')
        self.assertEqual(res.status, "FAIL")
        self.assertIn("unexpectedly succeeded", res.error_message or "")

    def test_a_diagnostic_that_does_not_match_the_regex_fails(self):
        res, _ = self.run_vtc('varnishtest "x"\nhaproxy h1 -conf-BAD {nothing like this} {\n  BAD\n}\n')
        self.assertEqual(res.status, "FAIL")
        self.assertIn("does not match", res.error_message or "")

    def test_the_first_block_is_a_regex_for_the_diagnostic(self):
        ex = executor('varnishtest "x"\nhaproxy h1 -conf-BAD {not in stderr} {\n  BAD\n}\n')
        d = [d for d in ex.parser.directives if d.cmd == "haproxy"][0]
        self.assertEqual(d.block_content.strip(), "BAD")


class MasterCliVersusStatsSocket(unittest.TestCase):
    """vtest puts `stats socket` ahead of the config; `-S` is HAProxy's *master* CLI, which
    answers `Unknown command: 'show'` to worker commands, so ~18 reg-tests failed on HAProxy
    itself (T138)."""

    def test_alcyon_gets_the_same_prelude_and_no_master_socket(self):
        # T146: several `global` sections merge, so the prelude is the same for both.
        fp = FakeProxy()
        self.addCleanup(fp.tmp.cleanup)
        ex = executor('varnishtest "x"\nhaproxy h1 -conf {\n  defaults\n} -start\n', fp.path)
        asyncio.run(ex.execute())
        self.assertNotIn("-S", open(fp.log + ".args").read().split())
        cfg = open(fp.log + ".cfg").read().splitlines()
        self.assertEqual(cfg[0], "global")
        self.assertRegex(cfg[1], r"^\s*stats socket \S+/h1\.sock level admin$")

    def test_config_has_a_stats_socket_admin_ahead_of_the_test_block(self):
        fp = FakeProxy("haproxy")
        self.addCleanup(fp.tmp.cleanup)
        ex = executor('varnishtest "x"\nhaproxy h1 -conf {\n  defaults\n} -start\n', fp.path)
        asyncio.run(ex.execute())
        self.assertNotIn("-S", open(fp.log + ".args").read().split())
        cfg = open(fp.log + ".cfg").read().splitlines()
        self.assertEqual(cfg[0], "global")
        self.assertRegex(cfg[1], r"^\s*stats socket \S+/h1\.sock level admin$")

        self.assertEqual(cfg[2].lstrip()[:1], "#")
        self.assertIn("defaults", cfg[3].strip() + "".join(cfg[4:]))


class SockMacroIsAddrColonPort(unittest.TestCase):
    """VTest expands `${s1_sock}` to `addr:port`, so `server s1 ${s1_sock}` is a valid HAProxy
    line (T401). The runner used `addr port`, which HAProxy itself rejects."""

    def test_server_sock_macro(self):
        eng = vtc_runner.MacroEngine()
        sd = vtc_runner.ServerBlock(server_id="s1", opts_before=[], actions=[], modifiers_after=[])
        r = vtc_runner.MockServerRunner(sd, eng, {})

        async def go():
            await r.initialize_socket()
            r.srv.close()
        asyncio.run(go())
        self.assertEqual(eng.get("s1_sock"), f"127.0.0.1:{r.port}")
        self.assertEqual(eng.get("s1_addr"), "127.0.0.1")

    def test_syslog_sock_macro(self):
        eng = vtc_runner.MacroEngine()
        r = vtc_runner.SyslogRunner("S1", eng, [])
        r.initialize_socket()
        r.sock.close()
        self.assertEqual(eng.get("S1_sock"), f"127.0.0.1:{r.port}")


class VtcQuotingTest(unittest.TestCase):
    """`expect ... == {Basic realm="protected area"}` lost its quotes to shlex, so
    http-rules/http_auth.vtc failed on the runner, not on the proxy (T151 item 4)."""

    def test_braces_are_one_verbatim_word(self):
        acts = vtc_runner.parse_inner_actions(
            'expect resp.http.www-authenticate == {Basic realm="protected area"}\n'
            'txreq -hdr "X-A: b c" -hdr \'X-B: d\'\n'
        )
        self.assertEqual(acts[0].args, ["resp.http.www-authenticate", "==", 'Basic realm="protected area"'])
        self.assertEqual(acts[1].args, ["-hdr", "X-A: b c", "-hdr", "X-B: d"])


class ClientSendCoalescing(unittest.TestCase):
    """Consecutive send/sendhex lines go out in one write, as in vtest."""

    def _received(self, actions):
        async def go():
            chunks = []
            done = asyncio.Event()

            async def handle(reader, writer):
                # The first read returns as soon as any byte arrives, so a split
                # write shows up as a short first chunk.
                chunks.append(await reader.read(4096))
                await asyncio.sleep(0.3)
                rest = await reader.read(4096)
                if rest:
                    chunks.append(rest)
                writer.close()
                done.set()

            srv = await asyncio.start_server(handle, "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]
            blk = vtc_runner.ClientBlock("c1", [], actions, [], connect_target=f"127.0.0.1 {port}")
            macros = vtc_runner.MacroEngine({}) if hasattr(vtc_runner, "MacroEngine") else None
            runner = vtc_runner.MockClientRunner(blk, macros, {})
            # Each StreamWriter.write is one send(2) on the socket, i.e. a possible
            # segment boundary; count them (in-process timing cannot show a split).
            real_write = asyncio.StreamWriter.write
            self.writes = []

            def counting_write(w, data):
                self.writes.append(bytes(data))
                return real_write(w, data)

            asyncio.StreamWriter.write = counting_write
            try:
                runner.start()
                await asyncio.wait_for(done.wait(), 5)
            finally:
                asyncio.StreamWriter.write = real_write
            await asyncio.wait_for(runner.done_event.wait(), 5)
            srv.close()
            self.assertIsNone(runner.error)
            return chunks

        return asyncio.run(go())

    def test_two_sendhex_arrive_in_one_recv(self):
        A = vtc_runner.ActionItem
        got = self._received([A("sendhex", ['"0D 0A"']), A("sendhex", ['"0A 51"']), A("send", ['"hi"'])])
        self.assertEqual(self.writes, [b"\r\n\nQhi"])
        self.assertEqual(got, [b"\r\n\nQhi"])

    def test_txreq_body_escapes_are_bytes(self):
        # `-body "0\\r\\n\\r\\n"` is CR LF on the wire, not a backslash and an `r`
        # (T363f, http_transfer_encoding.vtc: the literal text made a valid chunked request a 400).
        A = vtc_runner.ActionItem
        got = self._received([A("txreq", ["-method", "POST", "-nolen", "-hdr", "Transfer-Encoding: chunked",
                                          "-body", "0\\r\\n\\r\\nx\\x41"])])
        self.assertTrue(b"".join(got).endswith(b"\r\n\r\n0\r\n\r\nxA"), got)

    def test_client_chunkedlen_and_chunked_send_chunks(self):
        # T528: only the server side knew them; the client sent the head and nothing else.
        A = vtc_runner.ActionItem
        got = b"".join(self._received([A("chunkedlen", ["20"]), A("chunked", ['"hi"']), A("chunkedlen", ["0"])]))
        self.assertEqual(got, b"14\r\n0123456789abcdef0123\r\n2\r\nhi\r\n0\r\n\r\n")

    def test_txreq_with_transfer_encoding_gets_no_content_length(self):
        # T528, quic/h3_unknown_length_req.vtc: `txreq -method POST -hdr "Transfer-Encoding: chunked"`
        # followed by chunkedlen lines. The runner added `Content-Length: 0` to the POST, and HAProxy
        # (the oracle too) answered 400 to a request with both.
        A = vtc_runner.ActionItem
        got = b"".join(self._received([A("txreq", ["-method", "POST", "-hdr", "Transfer-Encoding: chunked"])]))
        self.assertIn(b"Transfer-Encoding: chunked", got)
        self.assertNotIn(b"Content-Length", got)


class HeadersOnly(unittest.TestCase):
    """`rxreqhdrs` / `rxresphdrs` stop after the head: the body is for a later `recv` (T363f,
    http_transfer_encoding.vtc c12 reads 47 bytes of a chunked body and its trailers)."""

    @staticmethod
    def _reader(data: bytes) -> asyncio.StreamReader:
        r = asyncio.StreamReader()
        r.feed_data(data)
        r.feed_eof()
        return r

    def test_request_head_leaves_the_chunked_body_unread(self):
        async def go():
            r = self._reader(b"POST /t HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nx: y\r\n\r\n")
            req = await vtc_runner.parse_http_request(r, headers_only=True)
            self.assertEqual(req.url, "/t")
            self.assertEqual(await r.readexactly(21), b"5\r\nhello\r\n0\r\nx: y\r\n\r\n")

        asyncio.run(go())

    def test_response_head_leaves_the_body_unread(self):
        async def go():
            r = self._reader(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            resp = await vtc_runner.parse_http_response(r, headers_only=True)
            self.assertEqual(resp.status, 200)
            self.assertEqual(await r.readexactly(5), b"hello")

        asyncio.run(go())


class VtestHex(unittest.TestCase):
    """`sendhex` / hex `expect` strings parse as VTest's vtc_hex_to_bin (T363l, converter/mqtt.vtc)."""

    def test_whitespace_and_newlines_between_digits_are_skipped(self):
        self.assertEqual(vtc_runner.vtest_hex("30 0C\n\t02 01"), b"\x30\x0c\x02\x01")

    def test_an_odd_last_digit_is_the_high_nibble_of_a_last_byte(self):
        self.assertEqual(vtc_runner.vtest_hex("a5f"), b"\xa5\xf0")

    def test_a_non_hex_character_is_an_error(self):
        with self.assertRaises(ValueError):
            vtc_runner.vtest_hex("3x")


if __name__ == "__main__":
    unittest.main()


class NothingSurvivesTheRunner(unittest.TestCase):
    """The runner must not leave the proxy (or its children) or a /tmp/vtc_alcyon_* dir behind.

    A board run left an `alcyon -f /tmp/vtc_alcyon_*/h1/cfg -d` alive for 9 h: a test that
    raised, a timeout, or a SIGTERM of the runner skipped the cleanup. The "proxy" here is
    a script that forks a child (as `-W` does), so only a process-group kill gets both.
    """

    FAKE = (
        "#!/usr/bin/env python3\n"
        "import os, time\n"
        "if os.fork() == 0:\n"
        "    time.sleep(300)\n"
        "    os._exit(0)\n"
        "time.sleep(300)\n"
    )
    VTC_START = 'varnishtest "leak"\nhaproxy h1 -conf {\n    global\n        daemon\n} -start\n'

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="leaktest_")
        self.addCleanup(self._reap)
        self.fake = os.path.join(self.root, "fakealcyon")
        with open(self.fake, "w") as f:
            f.write(self.FAKE)
        os.chmod(self.fake, 0o755)
        self.runner_pid = -1
        self.tmp = os.path.join(self.root, "tmp")
        os.mkdir(self.tmp)

    def _procs(self):
        pids = []
        for p in os.listdir("/proc"):
            if not p.isdigit():
                continue
            try:
                with open(f"/proc/{p}/cmdline", "rb") as f:
                    cmd = f.read()
                with open(f"/proc/{p}/stat") as f:
                    state = f.read().rsplit(")", 1)[1].split()[0]
            except OSError:
                continue
            if self.root.encode() in cmd and state != "Z" and int(p) != self.runner_pid:
                pids.append(int(p))
        return pids

    def _reap(self):
        import shutil
        import signal
        for pid in self._procs():
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        shutil.rmtree(self.root, ignore_errors=True)

    def _start(self, vtc_text, timeout="5"):
        vtc = os.path.join(self.root, "t.vtc")
        with open(vtc, "w") as f:
            f.write(vtc_text)
        import subprocess
        env = dict(os.environ, TMPDIR=self.tmp)
        r = subprocess.Popen(
            [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vtc_runner.py"),
             "--binary", self.fake, "--timeout", timeout, vtc],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.runner_pid = r.pid
        return r

    def _wait_for_proxy(self):
        import time
        for _ in range(100):
            if self._procs():
                return
            time.sleep(0.1)
        self.fail("the fake proxy never started")

    def _assert_clean(self):
        import time
        for _ in range(30):
            if not self._procs():
                break
            time.sleep(0.1)
        self.assertEqual(self._procs(), [], "a process of the test survived")
        self.assertEqual(os.listdir(self.tmp), [], "the test's temp dir survived")

    def test_a_test_that_raises_leaves_nothing(self):
        r = self._start(self.VTC_START + "shell {\n    exit 1\n}\n")
        r.wait(timeout=30)
        self._assert_clean()

    def test_a_timeout_with_a_proxy_that_never_exits_leaves_nothing(self):
        r = self._start(self.VTC_START + "haproxy h1 -wait\n", timeout="2")
        try:
            r.wait(timeout=20)
        except Exception:
            r.kill()
            self.fail("the runner hung: `haproxy -wait` blocks the event loop, so the timeout never fires")
        self._assert_clean()

    def test_sigterm_of_the_runner_leaves_nothing(self):
        import signal
        r = self._start(self.VTC_START + "delay 60\n", timeout="120")
        self._wait_for_proxy()
        r.send_signal(signal.SIGTERM)
        r.wait(timeout=30)
        self._assert_clean()

    def test_sigint_of_the_runner_leaves_nothing(self):
        import signal
        r = self._start(self.VTC_START + "delay 60\n", timeout="120")
        self._wait_for_proxy()
        r.send_signal(signal.SIGINT)
        r.wait(timeout=30)
        self._assert_clean()
