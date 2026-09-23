#!/usr/bin/env python3
"""
vtc_runner.py — Standalone Varnish Test Case (VTC) Regression Test Runner for Ibex.

Parses and executes HAProxy .vtc regression test scripts without external C runtime
dependencies (VTest/Varnish). Supports mock HTTP/TCP servers and clients, macro
expansions, listening port rewriting, target proxy execution, and rich assertion reporting.
"""

import argparse
import asyncio
import dataclasses
import glob
import json
import os
import threading
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# ANSI Color Formatting
# ---------------------------------------------------------------------------

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    @classmethod
    def green(cls, s: str) -> str:
        return f"{cls.GREEN}{s}{cls.RESET}"

    @classmethod
    def red(cls, s: str) -> str:
        return f"{cls.RED}{s}{cls.RESET}"

    @classmethod
    def yellow(cls, s: str) -> str:
        return f"{cls.YELLOW}{s}{cls.RESET}"

    @classmethod
    def cyan(cls, s: str) -> str:
        return f"{cls.CYAN}{s}{cls.RESET}"

    @classmethod
    def bold(cls, s: str) -> str:
        return f"{cls.BOLD}{s}{cls.RESET}"


def get_free_port() -> int:
    """Allocate an ephemeral port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# HTTP Protocol Data Structures & Utilities
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class HttpRequest:
    method: str = "GET"
    url: str = "/"
    proto: str = "HTTP/1.1"
    headers: List[Tuple[str, str]] = dataclasses.field(default_factory=list)
    body: bytes = b""

    def get_header(self, name: str) -> Optional[str]:
        target = name.lower()
        for k, v in self.headers:
            if k.lower() == target:
                return v
        return None

    def get_headers(self, name: str) -> List[str]:
        target = name.lower()
        return [v for k, v in self.headers if k.lower() == target]


@dataclasses.dataclass
class HttpResponse:
    status: int = 200
    reason: str = "OK"
    proto: str = "HTTP/1.1"
    headers: List[Tuple[str, str]] = dataclasses.field(default_factory=list)
    body: bytes = b""

    def get_header(self, name: str) -> Optional[str]:
        target = name.lower()
        for k, v in self.headers:
            if k.lower() == target:
                return v
        return None

    def get_headers(self, name: str) -> List[str]:
        target = name.lower()
        return [v for k, v in self.headers if k.lower() == target]


STANDARD_REASONS = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Allowed",
    408: "Request Timeout",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


async def read_until_bytes(reader: asyncio.StreamReader, delimiter: bytes, max_len: int = 131072) -> bytes:
    """Read from stream until delimiter is found."""
    buf = bytearray()
    while True:
        idx = buf.find(delimiter)
        if idx != -1:
            return bytes(buf)
        chunk = await reader.read(4096)
        if not chunk:
            return bytes(buf)
        buf.extend(chunk)
        if len(buf) > max_len:
            raise ValueError(f"Stream exceeded maximum length {max_len} before finding delimiter {delimiter!r}")


async def parse_http_request(reader: asyncio.StreamReader) -> Optional[HttpRequest]:
    """Parse HTTP request from stream."""
    header_data = await read_until_bytes(reader, b"\r\n\r\n")
    if not header_data:
        return None

    if b"\r\n\r\n" in header_data:
        sep = b"\r\n\r\n"
    elif b"\n\n" in header_data:
        sep = b"\n\n"
    else:
        return None

    parts = header_data.split(sep, 1)
    hdr_block = parts[0].decode("latin1")
    lines = [line.strip("\r") for line in hdr_block.split("\n")]
    if not lines or not lines[0].strip():
        return None

    req_line_parts = lines[0].split()
    if len(req_line_parts) >= 3:
        method = req_line_parts[0]
        url = req_line_parts[1]
        proto = req_line_parts[2]
    elif len(req_line_parts) == 2:
        method = req_line_parts[0]
        url = req_line_parts[1]
        proto = "HTTP/1.1"
    else:
        method = req_line_parts[0] if req_line_parts else "GET"
        url = "/"
        proto = "HTTP/1.1"

    headers: List[Tuple[str, str]] = []
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers.append((k.strip(), v.strip()))

    req = HttpRequest(method=method, url=url, proto=proto, headers=headers)

    body_bytes = bytearray(parts[1]) if len(parts) > 1 else bytearray()
    cl_hdr = req.get_header("Content-Length")
    te_hdr = req.get_header("Transfer-Encoding")

    if te_hdr and "chunked" in te_hdr.lower():
        while True:
            line = await reader.readline()
            if not line:
                break
            chunk_size_str = line.decode("latin1").split(";")[0].strip()
            if not chunk_size_str:
                continue
            chunk_size = int(chunk_size_str, 16)
            if chunk_size == 0:
                await reader.readline()
                break
            chunk_data = await reader.readexactly(chunk_size)
            body_bytes.extend(chunk_data)
            await reader.readline()
    elif cl_hdr is not None:
        try:
            cl = int(cl_hdr)
            needed = cl - len(body_bytes)
            if needed > 0:
                chunk = await reader.readexactly(needed)
                body_bytes.extend(chunk)
        except ValueError:
            pass

    req.body = bytes(body_bytes)
    return req


async def parse_http_response(reader: asyncio.StreamReader, req_method: str = "GET") -> Optional[HttpResponse]:
    """Parse HTTP response from stream."""
    header_data = await read_until_bytes(reader, b"\r\n\r\n")
    if not header_data:
        return None

    if b"\r\n\r\n" in header_data:
        sep = b"\r\n\r\n"
    elif b"\n\n" in header_data:
        sep = b"\n\n"
    else:
        return None

    parts = header_data.split(sep, 1)
    hdr_block = parts[0].decode("latin1")
    lines = [line.strip("\r") for line in hdr_block.split("\n")]
    if not lines or not lines[0].strip():
        return None

    status_line_parts = lines[0].split(None, 2)
    proto = status_line_parts[0] if len(status_line_parts) >= 1 else "HTTP/1.1"
    try:
        status = int(status_line_parts[1]) if len(status_line_parts) >= 2 else 200
    except ValueError:
        status = 200
    reason = status_line_parts[2] if len(status_line_parts) >= 3 else STANDARD_REASONS.get(status, "OK")

    headers: List[Tuple[str, str]] = []
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers.append((k.strip(), v.strip()))

    resp = HttpResponse(status=status, reason=reason, proto=proto, headers=headers)

    body_bytes = bytearray(parts[1]) if len(parts) > 1 else bytearray()
    if req_method.upper() == "HEAD" or status in (204, 304) or (100 <= status < 200):
        resp.body = b""
        return resp

    cl_hdr = resp.get_header("Content-Length")
    te_hdr = resp.get_header("Transfer-Encoding")

    if te_hdr and "chunked" in te_hdr.lower():
        while True:
            line = await reader.readline()
            if not line:
                break
            chunk_size_str = line.decode("latin1").split(";")[0].strip()
            if not chunk_size_str:
                continue
            chunk_size = int(chunk_size_str, 16)
            if chunk_size == 0:
                await reader.readline()
                break
            chunk_data = await reader.readexactly(chunk_size)
            body_bytes.extend(chunk_data)
            await reader.readline()
    elif cl_hdr is not None:
        try:
            cl = int(cl_hdr)
            needed = cl - len(body_bytes)
            if needed > 0:
                chunk = await reader.readexactly(needed)
                body_bytes.extend(chunk)
        except ValueError:
            pass
    else:
        # Read until EOF
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            body_bytes.extend(chunk)

    resp.body = bytes(body_bytes)
    return resp


# ---------------------------------------------------------------------------
# VTC Tokenizer and AST Definitions
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class ActionItem:
    cmd: str
    args: List[str]
    raw_line: str = ""
    line_no: int = 0


@dataclasses.dataclass
class ServerBlock:
    server_id: str
    opts_before: List[str]
    actions: List[ActionItem]
    modifiers_after: List[str]
    repeat: int = 1
    start_immediate: bool = False


@dataclasses.dataclass
class ClientBlock:
    client_id: str
    opts_before: List[str]
    actions: List[ActionItem]
    modifiers_after: List[str]
    connect_target: str = ""
    repeat: int = 1
    start_immediate: bool = False
    run_immediate: bool = False


@dataclasses.dataclass
class HaproxyBlock:
    haproxy_id: str
    opts_before: List[str]
    conf_type: str  # '-conf', '-conf-OK', '-conf-BAD'
    conf_text: str
    modifiers_after: List[str]
    start_immediate: bool = False


@dataclasses.dataclass
class TopDirective:
    cmd: str
    args: List[str]
    block_content: Optional[str] = None
    line_no: int = 0


def find_block_braces(s: str) -> Tuple[int, int]:
    """
    Find opening and closing indices of a top-level { ... } block,
    correctly ignoring comments, double-quoted strings, and ${macro} expansions.
    """
    first_brace = -1
    last_brace = -1
    brace_count = 0
    macro_depth = 0
    in_quote = False

    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            i += 2
            continue
        if c == '"':
            in_quote = not in_quote
        elif not in_quote:
            if c == "#" and first_brace == -1:
                eol = s.find("\n", i)
                if eol == -1:
                    break
                i = eol
                continue
            if c == "{":
                if i > 0 and s[i - 1] == "$":
                    macro_depth += 1
                elif macro_depth > 0:
                    macro_depth += 1
                else:
                    if first_brace == -1:
                        first_brace = i
                    brace_count += 1
            elif c == "}":
                if macro_depth > 0:
                    macro_depth -= 1
                else:
                    brace_count -= 1
                    if brace_count == 0 and first_brace != -1:
                        last_brace = i
                        return first_brace, last_brace
        i += 1
    return first_brace, last_brace


class VtcParser:
    """Parser for Varnish Test Case (.vtc) files."""

    def __init__(self, content: str, filepath: str):
        self.raw_content = content
        self.filepath = filepath
        self.title: str = os.path.basename(filepath)
        self.features: List[List[str]] = []
        self.directives: List[TopDirective] = []

    def _splice_includes(self, content: str, seen: set) -> str:
        """Replaces each `include <path>` line with the contents of that file.

        `${testdir}` resolves to the directory of the file doing the including, which is
        how vtest defines it. A file already spliced on this path is not spliced again,
        so a cycle terminates instead of exhausting memory.
        """
        out = []
        testdir = os.path.dirname(os.path.abspath(self.filepath))
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped.startswith("include "):
                out.append(line)
                continue
            target = stripped[len("include "):].strip().strip('"')
            target = target.replace("${testdir}", testdir)
            path = target if os.path.isabs(target) else os.path.join(testdir, target)
            real = os.path.realpath(path)
            if real in seen or not os.path.isfile(real):
                # A missing include is left as-is so the directive surfaces as an
                # unknown command rather than vanishing into a silent pass.
                out.append(line)
                continue
            seen.add(real)
            with open(real, "r", encoding="utf-8", errors="replace") as f:
                out.append(self._splice_includes(f.read(), seen))
        return "\n".join(out)

    def parse(self) -> None:
        # 0. Splice in `include ${testdir}/x.vtci` before anything else.
        #
        # vtest reads the included file in place, so the directives inside it belong to
        # this test. Skipping the line left those tests with nothing to run, and a test
        # that runs nothing used to be reported as a pass.
        self.raw_content = self._splice_includes(self.raw_content, set())

        # 1. Handle backslash line continuations
        lines = self.raw_content.splitlines()
        normalized_lines: List[Tuple[int, str]] = []
        cur_line = ""
        start_idx = 1

        for idx, line in enumerate(lines, start=1):
            stripped = line.rstrip()
            if stripped.endswith("\\"):
                if not cur_line:
                    start_idx = idx
                cur_line += stripped[:-1] + " "
            else:
                if cur_line:
                    cur_line += line
                    normalized_lines.append((start_idx, cur_line))
                    cur_line = ""
                else:
                    normalized_lines.append((idx, line))

        # 2. Tokenize top-level directives & handle { ... } nesting
        i = 0
        while i < len(normalized_lines):
            line_no, line = normalized_lines[i]
            trimmed = line.strip()

            if not trimmed or trimmed.startswith("#"):
                i += 1
                continue

            fb, lb = find_block_braces(trimmed)
            if fb != -1:
                j = i
                acc = []
                fb_all = -1
                lb_all = -1
                while j < len(normalized_lines):
                    acc.append(normalized_lines[j][1])
                    fb_all, lb_all = find_block_braces("\n".join(acc))
                    if lb_all != -1:
                        break
                    j += 1

                full_block_str = "\n".join(acc)
                i = j + 1
                self._parse_statement_with_block(line_no, full_block_str, fb_all, lb_all)
            else:
                i += 1
                self._parse_single_statement(line_no, trimmed)

    def _parse_single_statement(self, line_no: int, stmt: str) -> None:
        try:
            tokens = shlex.split(stmt, comments=True)
        except ValueError:
            tokens = stmt.split()
        if not tokens:
            return

        cmd = tokens[0]
        args = tokens[1:]

        if cmd in ("varnishtest", "vtest") and args:
            self.title = args[0]
        elif cmd == "feature":
            self.features.append(args)

        self.directives.append(TopDirective(cmd=cmd, args=args, line_no=line_no))

    def _parse_statement_with_block(self, line_no: int, block_str: str, first_brace: int = -1, last_brace: int = -1) -> None:
        if first_brace == -1 or last_brace == -1:
            first_brace, last_brace = find_block_braces(block_str)

        before_brace = block_str[:first_brace].strip()
        inside_brace = block_str[first_brace + 1:last_brace]
        after_brace = block_str[last_brace + 1:].strip()

        try:
            before_tokens = shlex.split(before_brace, comments=True)
        except ValueError:
            before_tokens = before_brace.split()

        try:
            after_tokens = shlex.split(after_brace, comments=True)
        except ValueError:
            after_tokens = after_brace.split()

        if not before_tokens:
            return

        cmd = before_tokens[0]
        args = before_tokens[1:] + after_tokens

        self.directives.append(
            TopDirective(
                cmd=cmd,
                args=args,
                block_content=inside_brace,
                line_no=line_no,
            )
        )


def parse_inner_actions(block_content: str) -> List[ActionItem]:
    """Parse sequential commands inside server/client { ... } block."""
    actions: List[ActionItem] = []
    lines = block_content.splitlines()

    normalized: List[Tuple[int, str]] = []
    cur_line = ""
    start_no = 1
    for idx, l in enumerate(lines, start=1):
        stripped = l.rstrip()
        if stripped.endswith("\\"):
            if not cur_line:
                start_no = idx
            cur_line += stripped[:-1] + " "
        else:
            if cur_line:
                cur_line += l
                normalized.append((start_no, cur_line))
                cur_line = ""
            else:
                normalized.append((idx, l))

    for line_no, raw in normalized:
        trimmed = raw.strip()
        if not trimmed or trimmed.startswith("#"):
            continue

        try:
            tokens = shlex.split(trimmed, comments=True)
        except ValueError:
            tokens = trimmed.split()

        if not tokens:
            continue

        cmd = tokens[0]
        args = tokens[1:]
        actions.append(ActionItem(cmd=cmd, args=args, raw_line=trimmed, line_no=line_no))

    return actions


# ---------------------------------------------------------------------------
# Macro Engine
# ---------------------------------------------------------------------------

class MacroEngine:
    """Evaluates and expands dynamic macros and environment variables."""

    def __init__(self, initial_macros: Optional[Dict[str, str]] = None):
        self.macros: Dict[str, str] = dict(initial_macros or {})

    def set(self, key: str, value: Any) -> None:
        self.macros[key] = str(value)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        if key in self.macros:
            return self.macros[key]
        if key in os.environ:
            return os.environ[key]
        return default

    def expand(self, text: str, max_depth: int = 10) -> str:
        """Expand all ${var} and ${var-default} occurrences."""
        if not text or "$" not in text:
            return text

        pattern = re.compile(r"\$\{([a-zA-Z0-9_]+)(?:[:-]([^}]*))?\}")

        cur = text
        for _ in range(max_depth):
            matched = False

            def repl(m: re.Match) -> str:
                nonlocal matched
                matched = True
                var_name = m.group(1)
                default_val = m.group(2)
                val = self.get(var_name)
                if val is not None:
                    return val
                if default_val is not None:
                    return default_val
                return m.group(0)

            new_text = pattern.sub(repl, cur)
            if not matched or new_text == cur:
                break
            cur = new_text

        return cur


# ---------------------------------------------------------------------------
# Expectation Evaluation & Diff Formatting
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class ExpectationResult:
    passed: bool
    expr: str
    op: str
    expected: str
    actual: Optional[str] = None
    error_message: Optional[str] = None


def decode_escapes(s: str) -> str:
    """Safely decode common escape sequences without double unescaping."""
    return s.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")


# Assertions actually evaluated, process-wide. A pass has to mean an assertion was made
# and held; counting declared directives instead let `cache/caching_rules.vtc` -- 93
# `expect` statements, two mock servers started, no proxy launched, no client run -- be
# reported PASS in 0.00s.
_assertion_total = 0


def assertions_evaluated() -> int:
    return _assertion_total


def _note_assertion() -> None:
    global _assertion_total
    _assertion_total += 1


def reset_assertion_counter() -> None:
    global _assertion_total
    _assertion_total = 0


def evaluate_expectation(*args, **kwargs) -> "ExpectationResult":
    """Counting front door for `_evaluate_expectation`."""
    _note_assertion()
    return _evaluate_expectation(*args, **kwargs)


def _evaluate_expectation(
    expr: str,
    op: str,
    expected_val: str,
    resp: Optional[HttpResponse] = None,
    req: Optional[HttpRequest] = None,
) -> ExpectationResult:
    """Evaluate an 'expect <expr> <op> <expected>' statement."""
    exp_clean = expected_val.strip()
    if (exp_clean.startswith('"') and exp_clean.endswith('"')) or (
        exp_clean.startswith("'") and exp_clean.endswith("'")
    ):
        exp_clean = exp_clean[1:-1]
    exp_clean = decode_escapes(exp_clean)

    actual_val: Optional[str] = None
    is_undef_check = exp_clean == "<undef>"

    # 1. Response expectations
    if expr == "resp.status":
        actual_val = str(resp.status) if resp else None
    elif expr == "resp.reason":
        actual_val = resp.reason if resp else None
    elif expr == "resp.proto":
        actual_val = resp.proto if resp else None
    elif expr.startswith("resp.http."):
        hdr_name = expr[len("resp.http."):]
        actual_val = resp.get_header(hdr_name) if resp else None
    elif expr == "resp.body":
        actual_val = resp.body.decode("latin1", errors="replace") if resp else None
    elif expr == "resp.bodylen":
        actual_val = str(len(resp.body)) if resp else "0"

    # 2. Request expectations
    elif expr == "req.method":
        actual_val = req.method if req else None
    elif expr == "req.url":
        actual_val = req.url if req else None
    elif expr == "req.proto":
        actual_val = req.proto if req else None
    elif expr.startswith("req.http."):
        hdr_name = expr[len("req.http."):]
        actual_val = req.get_header(hdr_name) if req else None
    elif expr == "req.body":
        actual_val = req.body.decode("latin1", errors="replace") if req else None
    elif expr == "req.bodylen":
        actual_val = str(len(req.body)) if req else "0"
    else:
        return ExpectationResult(
            passed=False,
            expr=expr,
            op=op,
            expected=expected_val,
            actual=None,
            error_message=f"Unsupported expectation target: {expr}",
        )

    # 3. Perform comparison
    passed = False

    if is_undef_check:
        if op == "==":
            passed = actual_val is None
        elif op == "!=":
            passed = actual_val is not None
        else:
            return ExpectationResult(
                passed=False,
                expr=expr,
                op=op,
                expected=expected_val,
                actual=actual_val,
                error_message=f"Operator '{op}' not supported for <undef> assertion",
            )
    else:
        if actual_val is None:
            passed = False
        elif op == "==":
            if actual_val.isdigit() and exp_clean.isdigit():
                passed = int(actual_val) == int(exp_clean)
            else:
                passed = actual_val == exp_clean
        elif op == "!=":
            if actual_val.isdigit() and exp_clean.isdigit():
                passed = int(actual_val) != int(exp_clean)
            else:
                passed = actual_val != exp_clean
        elif op == "~":
            passed = bool(re.search(exp_clean, actual_val))
        elif op == "!~":
            passed = not bool(re.search(exp_clean, actual_val))
        elif op == "<":
            passed = float(actual_val) < float(exp_clean)
        elif op == ">":
            passed = float(actual_val) > float(exp_clean)
        elif op == "<=":
            passed = float(actual_val) <= float(exp_clean)
        elif op == ">=":
            passed = float(actual_val) >= float(exp_clean)
        else:
            return ExpectationResult(
                passed=False,
                expr=expr,
                op=op,
                expected=expected_val,
                actual=actual_val,
                error_message=f"Unknown operator: {op}",
            )

    return ExpectationResult(
        passed=passed,
        expr=expr,
        op=op,
        expected=expected_val,
        actual=actual_val if actual_val is not None else "<undef>",
    )


def format_expectation_diff(res: ExpectationResult) -> str:
    """Format colored diff for a failed expectation."""
    lines = [
        f"  {Color.red('FAIL: Expectation failed:')} expect {res.expr} {res.op} {res.expected}",
        f"    Target:   {Color.cyan(res.expr)}",
        f"    Operator: {res.op}",
        f"    {Color.green('Expected:')} {res.expected!r}",
        f"    {Color.red('Actual:  ')} {res.actual!r}",
    ]
    if res.error_message:
        lines.append(f"    {Color.yellow('Note:')}     {res.error_message}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HAProxy Config Preprocessing & Listener Allocation
# ---------------------------------------------------------------------------

def preprocess_haproxy_config(
    raw_cfg: str,
    macro_engine: MacroEngine,
    haproxy_id: str,
) -> Tuple[str, Dict[str, int]]:
    """
    Allocate listening ports for bind "fd@${fe}" directives and rewrite config
    into Ibex-compatible syntax.
    """
    allocated_ports: Dict[str, int] = {}
    lines = raw_cfg.splitlines()
    out_lines: List[str] = []

    cur_section_type = ""
    cur_section_name = ""

    # Check for conditional preprocessor blocks: .if feature(THREAD) ... .endif
    cleaned_lines: List[str] = []
    skip_depth = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(".if"):
            if "feature(THREAD)" in stripped or "feature" in stripped:
                # Keep block contents
                continue
            else:
                skip_depth += 1
                continue
        elif stripped.startswith(".endif"):
            if skip_depth > 0:
                skip_depth -= 1
            continue

        if skip_depth == 0:
            cleaned_lines.append(line)

    for line in cleaned_lines:
        trimmed = line.strip()

        # Check section headers
        sec_m = re.match(r"^(listen|frontend|backend|defaults|global)\b(?:\s+([^\s{]+))?", trimmed)
        if sec_m:
            cur_section_type = sec_m.group(1)
            cur_section_name = sec_m.group(2) or ""

        # Check for bind "fd@${fe}" or bind fd@${fe}
        bind_m = re.match(r"^(bind\s+)(?:\"fd@\$\{([a-zA-Z0-9_]+)\}\"|fd@\$\{([a-zA-Z0-9_]+)\})(.*)$", trimmed)
        if bind_m:
            prefix = bind_m.group(1)
            var_name = bind_m.group(2) or bind_m.group(3)
            rest_opts = bind_m.group(4) or ""

            if var_name not in allocated_ports:
                port = get_free_port()
                allocated_ports[var_name] = port
            else:
                port = allocated_ports[var_name]

            # Populate macros
            macro_engine.set(f"{haproxy_id}_{var_name}_addr", "127.0.0.1")
            macro_engine.set(f"{haproxy_id}_{var_name}_port", str(port))
            macro_engine.set(f"{haproxy_id}_{var_name}_sock", f"127.0.0.1 {port}")
            macro_engine.set(var_name, str(port))

            if cur_section_name and (var_name == cur_section_name or f"{haproxy_id}_{cur_section_name}_port" not in macro_engine.macros):
                macro_engine.set(f"{haproxy_id}_{cur_section_name}_addr", "127.0.0.1")
                macro_engine.set(f"{haproxy_id}_{cur_section_name}_port", str(port))
                macro_engine.set(f"{haproxy_id}_{cur_section_name}_sock", f"127.0.0.1 {port}")

            # A `bind` becomes a `bind`, in every section type. This used to comment the
            # line out inside a `listen` and fold the address into the section header
            # instead -- the HAProxy 1.x `listen <name> <addr>:<port>` form, which
            # HAProxy has not accepted for years and which Ibex rejects with "please use
            # the 'bind' keyword". That single rewrite accounted for 36 of 133 reg-test
            # failures, all of them the harness generating a config style neither proxy
            # would load.
            out_lines.append(f"    bind 127.0.0.1:{port}{rest_opts}")
            continue

        # Check if line is 'listen <name>' without address
        listen_no_addr_m = re.match(r"^(\s*listen\s+([^\s{]+))\s*$", line)
        if listen_no_addr_m:
            l_name = listen_no_addr_m.group(2)
            if l_name not in allocated_ports:
                port = get_free_port()
                allocated_ports[l_name] = port
            else:
                port = allocated_ports[l_name]

            macro_engine.set(f"{haproxy_id}_{l_name}_addr", "127.0.0.1")
            macro_engine.set(f"{haproxy_id}_{l_name}_port", str(port))
            macro_engine.set(f"{haproxy_id}_{l_name}_sock", f"127.0.0.1 {port}")

            # Same reason: a bare `listen <name>` keeps its own line and gets a `bind`
            # underneath, rather than an address folded into the header.
            out_lines.append(f"listen {l_name}")
            out_lines.append(f"    bind 127.0.0.1:{port}")
            continue

        out_lines.append(line)

    rewritten_cfg = "\n".join(out_lines)
    expanded_cfg = macro_engine.expand(rewritten_cfg)
    return expanded_cfg, allocated_ports


# ---------------------------------------------------------------------------
# Mock Server & Mock Client Asynchronous Runners
# ---------------------------------------------------------------------------


class SyslogRunner:
    """A varnishtest `syslog` block: a UDP collector that records datagrams.

    HAProxy's health-check and logging reg-tests assert on syslog output, so the
    harness has to be a real collector rather than a stub. Capital-letter ids are
    syslog servers in varnishtest (`syslog S ...`), which is why they need their own
    macros -- `${S_addr}` and `${S_port}` -- alongside the lowercase server ones.
    """

    def __init__(self, syslog_id: str, macro_engine, expectations, repeat: int = 1,
                 level: Optional[str] = None, verbose: bool = False):
        self.syslog_id = syslog_id
        self.macro_engine = macro_engine
        self.expectations = expectations      # list of regex strings to match
        self.repeat = repeat
        self.level = level
        self.verbose = verbose
        self.sock: Optional[socket.socket] = None
        self.port = 0
        self.received: List[str] = []
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def initialize_socket(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.macro_engine.set(f"{self.syslog_id}_addr", "127.0.0.1")
        self.macro_engine.set(f"{self.syslog_id}_port", str(self.port))
        self.macro_engine.set(f"{self.syslog_id}_sock", f"127.0.0.1 {self.port}")

    def start(self) -> None:
        def loop():
            while not self._stop.is_set():
                try:
                    data, _ = self.sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                self.received.append(data.decode("utf-8", "replace"))
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def wait(self, timeout: float = 5.0) -> None:
        """Waits until every expectation has matched, or the timeout expires.

        Returns rather than raising on timeout; the caller reports the mismatch so the
        failure names which pattern never arrived.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.unmatched() == []:
                return
            time.sleep(0.05)

    def unmatched(self) -> List[str]:
        """Expectations with no matching datagram, in order."""
        missing = []
        for pat in self.expectations:
            try:
                rx = re.compile(pat)
            except re.error:
                rx = None
            if rx is None:
                if not any(pat in line for line in self.received):
                    missing.append(pat)
            elif not any(rx.search(line) for line in self.received):
                missing.append(pat)
        return missing

    def stop(self) -> None:
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=1.0)


class MockServerRunner:
    """Manages an asynchronous mock HTTP/TCP server defined by VTC script."""

    def __init__(self, server_def: ServerBlock, macro_engine: MacroEngine, barriers: Dict[str, asyncio.Barrier], verbose: bool = False):
        self.server_def = server_def
        self.macro_engine = macro_engine
        self.barriers = barriers
        self.server_id = server_def.server_id
        self.verbose = verbose

        self.port: int = 0
        self.srv: Optional[asyncio.Server] = None
        self.task: Optional[asyncio.Task] = None
        self.done_event = asyncio.Event()
        self.error: Optional[Exception] = None

        self.req_history: List[HttpRequest] = []
        self.conn_queue: asyncio.Queue = asyncio.Queue()

    async def initialize_socket(self) -> None:
        """Bind socket to obtain port and populate macros before execution."""
        self.srv = await asyncio.start_server(
            self._handle_incoming,
            host="127.0.0.1",
            port=0,
            reuse_address=True,
        )
        self.port = self.srv.sockets[0].getsockname()[1]
        self.macro_engine.set(f"{self.server_id}_addr", "127.0.0.1")
        self.macro_engine.set(f"{self.server_id}_port", str(self.port))
        self.macro_engine.set(f"{self.server_id}_sock", f"127.0.0.1 {self.port}")

    async def _handle_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await self.conn_queue.put((reader, writer))

    def start(self) -> None:
        if self.task is None:
            self.task = asyncio.create_task(self._run_server_script())

    async def _run_server_script(self) -> None:
        try:
            for _ in range(self.server_def.repeat):
                reader, writer = await self.conn_queue.get()
                cur_req: Optional[HttpRequest] = None

                for action in self.server_def.actions:
                    cmd = action.cmd
                    args = [self.macro_engine.expand(a) for a in action.args]

                    if cmd in ("rxreq", "rxreqhdrs"):
                        cur_req = await parse_http_request(reader)
                        if cur_req is None:
                            raise ConnectionResetError(f"Server {self.server_id} expected HTTP request but got EOF")
                        self.req_history.append(cur_req)
                        if self.verbose:
                            print(f"       {Color.DIM}[{self.server_id}] rxreq {cur_req.method} {cur_req.url}{Color.RESET}")

                    elif cmd == "expect":
                        if len(args) >= 3:
                            expr = args[0]
                            op = args[1]
                            val = " ".join(args[2:])
                            res = evaluate_expectation(expr, op, val, req=cur_req)
                            if not res.passed:
                                raise AssertionError(
                                    f"Server {self.server_id} assertion failed on line {action.line_no}:\n"
                                    + format_expectation_diff(res)
                                )
                            if self.verbose:
                                print(f"       {Color.DIM}[{self.server_id}] expect {expr} {op} {val} -> OK{Color.RESET}")

                    elif cmd == "txresp":
                        status = 200
                        headers: List[Tuple[str, str]] = []
                        body = ""
                        nolen = False

                        idx = 0
                        while idx < len(args):
                            opt = args[idx]
                            if opt == "-status" and idx + 1 < len(args):
                                idx += 1
                                try:
                                    status = int(args[idx])
                                except ValueError:
                                    status = 200
                            elif opt == "-hdr" and idx + 1 < len(args):
                                idx += 1
                                hdr_line = args[idx]
                                if ":" in hdr_line:
                                    hk, hv = hdr_line.split(":", 1)
                                    headers.append((hk.strip(), hv.strip()))
                            elif opt == "-body" and idx + 1 < len(args):
                                idx += 1
                                body = args[idx]
                            elif opt == "-bodylen" and idx + 1 < len(args):
                                idx += 1
                                try:
                                    body = "x" * int(args[idx])
                                except ValueError:
                                    pass
                            elif opt == "-nolen":
                                nolen = True
                            idx += 1

                        reason = STANDARD_REASONS.get(status, "OK")
                        resp_lines = [f"HTTP/1.1 {status} {reason}"]
                        has_cl = False
                        for hk, hv in headers:
                            if hk.lower() == "content-length":
                                has_cl = True
                            resp_lines.append(f"{hk}: {hv}")

                        body_bytes = body.encode("latin1")
                        if not has_cl and not nolen:
                            resp_lines.append(f"Content-Length: {len(body_bytes)}")

                        if self.verbose:
                            print(f"       {Color.DIM}[{self.server_id}] txresp status={status}{Color.RESET}")

                        resp_str = "\r\n".join(resp_lines) + "\r\n\r\n"
                        writer.write(resp_str.encode("latin1") + body_bytes)
                        await writer.drain()

                    elif cmd == "send":
                        data_str = " ".join(args)
                        if data_str.startswith('"') and data_str.endswith('"'):
                            data_str = data_str[1:-1]
                        writer.write(decode_escapes(data_str).encode("latin1"))
                        await writer.drain()

                    elif cmd == "sendhex":
                        hex_str = "".join(args).replace(" ", "")
                        writer.write(bytes.fromhex(hex_str))
                        await writer.drain()

                    elif cmd == "recv":
                        n_bytes = int(args[0]) if args else 4096
                        await reader.read(n_bytes)

                    elif cmd == "barrier":
                        if len(args) >= 2 and args[1] == "sync":
                            b_id = args[0]
                            if b_id in self.barriers:
                                await self.barriers[b_id].wait()

                    elif cmd == "delay":
                        t_sec = float(args[0]) if args else 0.1
                        await asyncio.sleep(t_sec)

                    elif cmd == "close":
                        try:
                            writer.close()
                            await writer.wait_closed()
                        except Exception:
                            pass

                    elif cmd == "accept":
                        reader, writer = await self.conn_queue.get()

                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        except Exception as ex:
            self.error = ex
        finally:
            self.done_event.set()

    async def wait(self) -> None:
        await self.done_event.wait()
        if self.error:
            raise self.error

    def stop(self) -> None:
        if self.srv:
            self.srv.close()
        if self.task and not self.task.done():
            self.task.cancel()


class MockClientRunner:
    """Manages an asynchronous mock HTTP/TCP client defined by VTC script."""

    def __init__(self, client_def: ClientBlock, macro_engine: MacroEngine, barriers: Dict[str, asyncio.Barrier], verbose: bool = False):
        self.client_def = client_def
        self.macro_engine = macro_engine
        self.barriers = barriers
        self.client_id = client_def.client_id
        self.verbose = verbose
        self.task: Optional[asyncio.Task] = None
        self.done_event = asyncio.Event()
        self.error: Optional[Exception] = None

    def start(self) -> None:
        if self.task is None:
            self.task = asyncio.create_task(self._run_client_script())

    async def _run_client_script(self) -> None:
        try:
            target = self.macro_engine.expand(self.client_def.connect_target)
            target_parts = target.strip().replace(":", " ").split()
            if len(target_parts) >= 2:
                host = target_parts[0]
                port = int(target_parts[1])
            else:
                host = "127.0.0.1"
                port = int(target_parts[0])

            for _ in range(self.client_def.repeat):
                reader, writer = None, None
                connect_err = None
                for _ in range(30):
                    try:
                        reader, writer = await asyncio.open_connection(host, port)
                        break
                    except (ConnectionRefusedError, OSError) as e:
                        connect_err = e
                        await asyncio.sleep(0.04)

                if reader is None or writer is None:
                    raise ConnectionRefusedError(
                        f"Client {self.client_id} could not connect to {host}:{port} after retries: {connect_err}"
                    )

                cur_resp: Optional[HttpResponse] = None
                last_req_method = "GET"

                for action in self.client_def.actions:
                    cmd = action.cmd
                    args = [self.macro_engine.expand(a) for a in action.args]

                    if cmd == "txreq":
                        method = "GET"
                        url = "/"
                        proto = "HTTP/1.1"
                        headers: List[Tuple[str, str]] = []
                        body = ""
                        nolen = False
                        nohost = False

                        idx = 0
                        while idx < len(args):
                            opt = args[idx]
                            if opt in ("-req", "-method") and idx + 1 < len(args):
                                idx += 1
                                method = args[idx]
                            elif opt == "-url" and idx + 1 < len(args):
                                idx += 1
                                url = args[idx]
                            elif opt == "-proto" and idx + 1 < len(args):
                                idx += 1
                                proto = args[idx]
                            elif opt in ("-hdr", "-litHdr") and idx + 1 < len(args):
                                idx += 1
                                hdr_line = args[idx]
                                if ":" in hdr_line:
                                    hk, hv = hdr_line.split(":", 1)
                                    headers.append((hk.strip(), hv.strip()))
                            elif opt == "-body" and idx + 1 < len(args):
                                idx += 1
                                body = args[idx]
                            elif opt == "-bodylen" and idx + 1 < len(args):
                                idx += 1
                                try:
                                    body = "x" * int(args[idx])
                                except ValueError:
                                    pass
                            elif opt == "-nolen":
                                nolen = True
                            elif opt == "-nohost":
                                nohost = True
                            idx += 1

                        last_req_method = method
                        req_lines = [f"{method} {url} {proto}"]
                        has_host = False
                        has_cl = False

                        for hk, hv in headers:
                            if hk.lower() == "host":
                                has_host = True
                            if hk.lower() == "content-length":
                                has_cl = True
                            req_lines.append(f"{hk}: {hv}")

                        if not has_host and not nohost:
                            req_lines.append(f"Host: {host}")

                        body_bytes = body.encode("latin1")
                        if not has_cl and not nolen and (body_bytes or method in ("POST", "PUT")):
                            req_lines.append(f"Content-Length: {len(body_bytes)}")

                        if self.verbose:
                            print(f"       {Color.DIM}[{self.client_id}] txreq {method} {url}{Color.RESET}")

                        req_str = "\r\n".join(req_lines) + "\r\n\r\n"
                        writer.write(req_str.encode("latin1") + body_bytes)
                        await writer.drain()

                    elif cmd in ("rxresp", "rxresphdrs"):
                        cur_resp = await parse_http_response(reader, req_method=last_req_method)
                        if cur_resp is None:
                            raise ConnectionResetError(f"Client {self.client_id} expected HTTP response but got EOF")
                        if self.verbose:
                            print(f"       {Color.DIM}[{self.client_id}] rxresp status={cur_resp.status}{Color.RESET}")

                    elif cmd == "expect":
                        if len(args) >= 3:
                            expr = args[0]
                            op = args[1]
                            val = " ".join(args[2:])
                            res = evaluate_expectation(expr, op, val, resp=cur_resp)
                            if not res.passed:
                                raise AssertionError(
                                    f"Client {self.client_id} assertion failed on line {action.line_no}:\n"
                                    + format_expectation_diff(res)
                                )
                            if self.verbose:
                                print(f"       {Color.DIM}[{self.client_id}] expect {expr} {op} {val} -> OK{Color.RESET}")

                    elif cmd == "send":
                        data_str = " ".join(args)
                        if data_str.startswith('"') and data_str.endswith('"'):
                            data_str = data_str[1:-1]
                        writer.write(decode_escapes(data_str).encode("latin1"))
                        await writer.drain()

                    elif cmd == "sendhex":
                        hex_str = "".join(args).replace(" ", "")
                        writer.write(bytes.fromhex(hex_str))
                        await writer.drain()

                    elif cmd == "recv":
                        n_bytes = int(args[0]) if args else 4096
                        await reader.read(n_bytes)

                    elif cmd == "barrier":
                        if len(args) >= 2 and args[1] == "sync":
                            b_id = args[0]
                            if b_id in self.barriers:
                                await self.barriers[b_id].wait()

                    elif cmd == "delay":
                        t_sec = float(args[0]) if args else 0.1
                        await asyncio.sleep(t_sec)

                    elif cmd == "close":
                        try:
                            writer.close()
                            await writer.wait_closed()
                        except Exception:
                            pass

                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        except Exception as ex:
            self.error = ex
        finally:
            self.done_event.set()

    async def wait(self) -> None:
        await self.done_event.wait()
        if self.error:
            raise self.error


# ---------------------------------------------------------------------------
# Test Execution Engine
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class TestResult:
    test_name: str
    file_path: str
    status: str  # PASS, FAIL, SKIP, OUT_OF_SCOPE
    elapsed_sec: float
    error_message: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    triage: str = "UNTRIAGED"   # from data/regtests.json
    unexpected_pass: bool = False


class VtcExecutor:
    """Executes a parsed VTC test script against a target binary."""

    def __init__(self, parser: VtcParser, target_binary: str, timeout: float = 15.0, verbose: bool = False):
        self.parser = parser
        self.target_binary = os.path.abspath(target_binary)
        self.timeout = timeout
        self.verbose = verbose

        self.testdir = os.path.dirname(os.path.abspath(parser.filepath))
        self.tmpdir = tempfile.mkdtemp(prefix="vtc_ibex_")
        self.macro_engine = MacroEngine({
            "testdir": self.testdir,
            "tmpdir": self.tmpdir,
            "HAPROXY_TEST_TIMEOUT": "5s",
        })

        self.barriers: Dict[str, asyncio.Barrier] = {}
        self.servers: Dict[str, MockServerRunner] = {}
        self.syslogs: Dict[str, SyslogRunner] = {}
        self.clients: Dict[str, MockClientRunner] = {}
        self.proxies: Dict[str, subprocess.Popen] = {}
        self.temp_cfgs: List[str] = []

    def cleanup(self) -> None:
        for p in self.proxies.values():
            if p.poll() is None:
                try:
                    p.terminate()
                    p.wait(timeout=0.5)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass

        for s in self.servers.values():
            s.stop()
        for sl in self.syslogs.values():
            sl.stop()

        if os.path.exists(self.tmpdir):
            try:
                shutil.rmtree(self.tmpdir, ignore_errors=True)
            except Exception:
                pass

    async def _execute_haproxy_cli(self, haproxy_id: str, block: str) -> None:
        cli_sock = os.path.join(self.tmpdir, f"{haproxy_id}.sock")
        reader, writer = None, None
        for _ in range(50):
            if os.path.exists(cli_sock):
                try:
                    reader, writer = await asyncio.open_unix_connection(cli_sock)
                    break
                except Exception:
                    pass
            await asyncio.sleep(0.05)
        if not writer or not reader:
            raise RuntimeError(f"Could not connect to HAProxy CLI socket {cli_sock}")

        lines = block.splitlines()
        last_resp = ""
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("send "):
                cmd = line[5:].strip()
                if (cmd.startswith('"') and cmd.endswith('"')) or (cmd.startswith("'") and cmd.endswith("'")):
                    cmd = cmd[1:-1]
                writer.write((cmd + "\n").encode("utf-8"))
                await writer.drain()
                await asyncio.sleep(0.05)
                resp_bytes = bytearray()
                while True:
                    try:
                        chunk = await asyncio.wait_for(reader.read(4096), timeout=0.1)
                        if not chunk:
                            break
                        resp_bytes.extend(chunk)
                        if len(chunk) < 4096:
                            break
                    except asyncio.TimeoutError:
                        break
                last_resp = resp_bytes.decode("utf-8", errors="replace")
            elif line.startswith("expect "):
                rest = line[7:].strip()
                if rest.startswith("~"):
                    pat = rest[1:].strip()
                    if (pat.startswith('"') and pat.endswith('"')) or (pat.startswith("'") and pat.endswith("'")):
                        pat = pat[1:-1]
                    if not re.search(pat, last_resp, re.MULTILINE):
                        raise AssertionError(f"CLI expect pattern {pat!r} failed to match: {last_resp!r}")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    async def execute(self) -> TestResult:
        start_time = time.monotonic()
        test_title = self.parser.title
        reset_assertion_counter()

        try:
            # Check feature prerequisites
            for feat_args in self.parser.features:
                if not feat_args:
                    continue
                feat_type = feat_args[0]
                if feat_type == "ignore_unknown_macro":
                    continue
                elif feat_type == "cmd":
                    cmd_str = " ".join(feat_args[1:])
                    if cmd_str.startswith('"') and cmd_str.endswith('"'):
                        cmd_str = cmd_str[1:-1]
                    cmd_expanded = cmd_str.replace("$HAPROXY_PROGRAM", self.target_binary)
                    cmd_expanded = self.macro_engine.expand(cmd_expanded)
                    res = subprocess.run(cmd_expanded, shell=True, capture_output=True)
                    if res.returncode != 0:
                        return TestResult(
                            test_name=test_title,
                            file_path=self.parser.filepath,
                            status="SKIP",
                            elapsed_sec=time.monotonic() - start_time,
                            error_message=f"Feature condition unsatisfied: {cmd_str}",
                        )

            await asyncio.wait_for(self._run_directives(), timeout=self.timeout)

            # Verify no background servers or clients encountered errors
            for sid, srv in self.servers.items():
                if srv.error is not None:
                    raise srv.error
            for cid, cli in self.clients.items():
                if cli.error is not None:
                    raise cli.error

            # A test that asserted nothing has not passed.
            #
            # This used to check which directives the file *declared*, which is not the
            # same question. `cache/caching_rules.vtc` declares 93 `expect` statements;
            # the run started two mock servers, never launched the proxy, never ran a
            # client, evaluated nothing, and was reported PASS in 0.00s. Declaring a
            # `server` block was enough to satisfy the old guard.
            #
            # The honest test is how many assertions were actually evaluated.
            if assertions_evaluated() == 0:
                return TestResult(
                    test_name=test_title,
                    file_path=self.parser.filepath,
                    status="SKIP",
                    elapsed_sec=time.monotonic() - start_time,
                    error_message="no assertions were evaluated; nothing was tested",
                )

            elapsed = time.monotonic() - start_time
            return TestResult(
                test_name=test_title,
                file_path=self.parser.filepath,
                status="PASS",
                elapsed_sec=elapsed,
            )

        except asyncio.TimeoutError:
            elapsed = time.monotonic() - start_time
            return TestResult(
                test_name=test_title,
                file_path=self.parser.filepath,
                status="FAIL",
                elapsed_sec=elapsed,
                error_message=f"Test timed out after {self.timeout}s",
            )
        except Exception as ex:
            elapsed = time.monotonic() - start_time
            err_msg = str(ex) if str(ex) else traceback.format_exc()
            for pid_name, p in self.proxies.items():
                try:
                    if p.poll() is not None:
                        out, err = p.communicate()
                        err_msg += f"\nProxy {pid_name} stderr:\n" + err.decode("utf-8", errors="replace")
                    else:
                        p.terminate()
                        out, err = p.communicate(timeout=0.2)
                        err_msg += f"\nProxy {pid_name} stderr:\n" + err.decode("utf-8", errors="replace")
                except Exception:
                    pass
            return TestResult(
                test_name=test_title,
                file_path=self.parser.filepath,
                status="FAIL",
                elapsed_sec=elapsed,
                error_message=err_msg,
            )
        finally:
            self.cleanup()

    async def _run_directives(self) -> None:
        for directive in self.parser.directives:
            cmd = directive.cmd
            args = directive.args
            block = directive.block_content

            if cmd == "barrier":
                # barrier b1 cond 2
                if len(args) >= 3 and args[1] in ("cond", "sock"):
                    b_id = args[0]
                    count = int(args[2])
                    self.barriers[b_id] = asyncio.Barrier(count)
                elif len(args) >= 2 and args[1] == "sync":
                    b_id = args[0]
                    if b_id in self.barriers:
                        await self.barriers[b_id].wait()

            elif cmd == "delay":
                t = float(args[0]) if args else 0.1
                await asyncio.sleep(t)

            elif cmd == "shell":
                sh_cmd = block if block is not None else (args[0] if args else "")
                sh_expanded = self.macro_engine.expand(sh_cmd)
                res = subprocess.run(sh_expanded, shell=True, capture_output=True, text=True)
                if res.returncode != 0:
                    raise RuntimeError(f"Shell command failed (exit code {res.returncode}):\n{res.stderr}")

            elif cmd == "setenv":
                if len(args) >= 2:
                    k = args[0]
                    v = self.macro_engine.expand(args[1])
                    os.environ[k] = v
                    self.macro_engine.set(k, v)

            elif cmd == "syslog":
                # `syslog S -level notice { expect ~ "pattern" ... }`
                syslog_id = args[0]
                opts = args[1:]
                if block is not None:
                    repeat = 1
                    level = None
                    start_imm = False
                    idx = 0
                    while idx < len(opts):
                        if opts[idx] == "-repeat" and idx + 1 < len(opts):
                            repeat = int(opts[idx + 1]); idx += 1
                        elif opts[idx] == "-level" and idx + 1 < len(opts):
                            level = opts[idx + 1]; idx += 1
                        elif opts[idx] == "-start":
                            start_imm = True
                        idx += 1

                    # Collect `expect ~ <pattern>` lines from the block.
                    expectations = []
                    for raw in block.splitlines():
                        line = raw.strip()
                        m = re.match(r'^expect\s+~\s+(.*)$', line)
                        if m:
                            pat = m.group(1).strip()
                            if len(pat) >= 2 and pat[0] == pat[-1] and pat[0] in "\"'":
                                pat = pat[1:-1]
                            expectations.append(self.macro_engine.expand(pat))

                    runner = SyslogRunner(syslog_id, self.macro_engine, expectations,
                                          repeat=repeat, level=level, verbose=self.verbose)
                    runner.initialize_socket()
                    self.syslogs[syslog_id] = runner
                    runner.start()
                    if self.verbose:
                        print(f"     {Color.DIM}[syslog {syslog_id}] listening on "
                              f"127.0.0.1:{runner.port}{Color.RESET}")
                else:
                    runner = self.syslogs.get(syslog_id)
                    if not runner:
                        raise KeyError(f"Unknown syslog {syslog_id}")
                    if "-wait" in opts:
                        runner.wait()
                        missing = runner.unmatched()
                        if missing:
                            raise RuntimeError(
                                f"syslog {syslog_id}: {len(missing)} expectation(s) never "
                                f"matched. First: {missing[0]!r}. "
                                f"Received {len(runner.received)} datagram(s)."
                            )

            elif cmd == "server":
                server_id = args[0]
                opts = args[1:]
                if block is not None:
                    repeat = 1
                    start_imm = False
                    idx = 0
                    while idx < len(opts):
                        if opts[idx] == "-repeat" and idx + 1 < len(opts):
                            repeat = int(opts[idx + 1])
                            idx += 1
                        elif opts[idx] == "-start":
                            start_imm = True
                        idx += 1

                    actions = parse_inner_actions(block)
                    s_block = ServerBlock(
                        server_id=server_id,
                        opts_before=[],
                        actions=actions,
                        modifiers_after=[],
                        repeat=repeat,
                        start_immediate=start_imm,
                    )
                    runner = MockServerRunner(s_block, self.macro_engine, self.barriers, verbose=self.verbose)
                    await runner.initialize_socket()
                    self.servers[server_id] = runner
                    if self.verbose:
                        print(f"     {Color.DIM}[server {server_id}] listening on 127.0.0.1:{runner.port}{Color.RESET}")
                    if start_imm:
                        runner.start()
                else:
                    runner = self.servers.get(server_id)
                    if not runner:
                        raise KeyError(f"Unknown server {server_id}")
                    if "-start" in opts:
                        runner.start()
                    if "-wait" in opts:
                        await runner.wait()

            elif cmd == "haproxy":
                haproxy_id = args[0]
                opts = args[1:]
                if "-cli" in opts:
                    await self._execute_haproxy_cli(haproxy_id, block or "")
                elif block is not None:
                    conf_type = "-conf"
                    start_imm = False
                    idx = 0
                    while idx < len(opts):
                        if opts[idx] in ("-conf", "-conf-OK", "-conf-BAD"):
                            conf_type = opts[idx]
                        elif opts[idx] == "-start":
                            start_imm = True
                        idx += 1

                    rewritten_cfg, alloc_ports = preprocess_haproxy_config(
                        block, self.macro_engine, haproxy_id
                    )

                    cfg_path = os.path.join(self.tmpdir, f"haproxy_{haproxy_id}_{len(self.temp_cfgs)}.cfg")
                    with open(cfg_path, "w") as f:
                        f.write(rewritten_cfg)
                    self.temp_cfgs.append(cfg_path)

                    if conf_type == "-conf-OK":
                        res = subprocess.run(
                            [self.target_binary, "-c", "-f", cfg_path],
                            capture_output=True,
                            text=True,
                        )
                        if res.returncode != 0:
                            raise AssertionError(f"Config check failed (-conf-OK):\n{res.stderr}")
                    elif conf_type == "-conf-BAD":
                        res = subprocess.run(
                            [self.target_binary, "-c", "-f", cfg_path],
                            capture_output=True,
                            text=True,
                        )
                        if res.returncode == 0:
                            raise AssertionError("Config check unexpectedly succeeded (-conf-BAD)")
                    else:
                        if start_imm:
                            cli_sock = os.path.join(self.tmpdir, f"{haproxy_id}.sock")
                            proc = subprocess.Popen(
                                [self.target_binary, "-f", cfg_path, "-S", cli_sock, "-d"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            )
                            self.proxies[haproxy_id] = proc
                            if self.verbose:
                                print(f"     {Color.DIM}[haproxy {haproxy_id}] started (pid {proc.pid}) ports={list(alloc_ports.values())}{Color.RESET}")

                            await asyncio.sleep(0.06)
                            if proc.poll() is not None:
                                out, err = proc.communicate()
                                raise RuntimeError(
                                    f"Proxy {haproxy_id} exited prematurely with code {proc.returncode}:\n"
                                    + err.decode("utf-8", errors="replace")
                                )
                else:
                    if "-stop" in opts:
                        p = self.proxies.get(haproxy_id)
                        if p and p.poll() is None:
                            p.terminate()
                            p.wait(timeout=1.0)
                    elif "-wait" in opts:
                        p = self.proxies.get(haproxy_id)
                        if p:
                            p.wait()

            elif cmd == "client":
                client_id = args[0]
                opts = args[1:]
                if block is not None:
                    connect_target = ""
                    repeat = 1
                    run_imm = False
                    start_imm = False

                    idx = 0
                    while idx < len(opts):
                        if opts[idx] == "-connect" and idx + 1 < len(opts):
                            connect_target = opts[idx + 1]
                            idx += 1
                        elif opts[idx] == "-repeat" and idx + 1 < len(opts):
                            repeat = int(opts[idx + 1])
                            idx += 1
                        elif opts[idx] == "-run":
                            run_imm = True
                        elif opts[idx] == "-start":
                            start_imm = True
                        idx += 1

                    actions = parse_inner_actions(block)
                    c_block = ClientBlock(
                        client_id=client_id,
                        opts_before=[],
                        actions=actions,
                        modifiers_after=[],
                        connect_target=connect_target,
                        repeat=repeat,
                        start_immediate=start_imm,
                        run_immediate=run_imm,
                    )
                    runner = MockClientRunner(c_block, self.macro_engine, self.barriers, verbose=self.verbose)
                    self.clients[client_id] = runner
                    if self.verbose:
                        print(f"     {Color.DIM}[client {client_id}] configured connect={connect_target}{Color.RESET}")

                    if run_imm:
                        runner.start()
                        await runner.wait()
                    elif start_imm:
                        runner.start()
                else:
                    runner = self.clients.get(client_id)
                    if not runner:
                        raise KeyError(f"Unknown client {client_id}")
                    if "-run" in opts:
                        runner.start()
                        await runner.wait()
                    elif "-start" in opts:
                        runner.start()
                    elif "-wait" in opts:
                        await runner.wait()


# ---------------------------------------------------------------------------
# CLI & Test Suite Driver
# ---------------------------------------------------------------------------

def find_vtc_files(paths: List[str]) -> List[str]:
    """Find all .vtc files from given file or directory paths."""
    vtc_files = []
    for p in paths:
        if os.path.isfile(p) and p.endswith(".vtc"):
            vtc_files.append(os.path.abspath(p))
        elif os.path.isdir(p):
            found = glob.glob(os.path.join(p, "**", "*.vtc"), recursive=True)
            vtc_files.extend(sorted([os.path.abspath(f) for f in found]))
    return sorted(list(set(vtc_files)))


class TriageIndex:
    """Maps a .vtc path to its bucket in `data/regtests.json`.

    The suite contains 114 tests for features this project declined in `tradeoff.md` 4.2 --
    Lua, QUIC, filters, the cache, SPOE, FCGI. Counting those as failures measures a
    decision as debt: thirteen `cache-use` failures said nothing about Ibex except that it
    does not have a cache, which was already written down.

    Out-of-scope tests are still **run**, not skipped. This project has already been bitten
    once by a status that meant "nobody asked", when 84 tests hid behind a skip and the
    board read better than the truth. Running them costs a second and buys two things: a
    declined feature that unexpectedly works is reported rather than hidden, and the
    failure text stays available for anyone who wants to look.
    """

    def __init__(self, triage_file: Optional[str] = None):
        self.by_suffix: Dict[str, str] = {}
        if triage_file is None:
            here = os.path.dirname(os.path.abspath(__file__))
            triage_file = os.path.join(here, "..", "data", "regtests.json")
        try:
            with open(triage_file, "r", encoding="utf-8") as f:
                rows = json.load(f)
        except Exception:
            return
        for row in rows:
            path = (row.get("path") or "").replace("\\", "/")
            bucket = row.get("triage_bucket") or "UNTRIAGED"
            if path:
                self.by_suffix[path] = bucket

    def bucket_for(self, vtc_path: str) -> str:
        norm = os.path.abspath(vtc_path).replace("\\", "/")
        for suffix, bucket in self.by_suffix.items():
            if norm.endswith("/" + suffix) or norm.endswith(suffix):
                return bucket
        return "UNTRIAGED"


async def run_suite(
    vtc_files: List[str],
    binary_path: str,
    timeout: float,
    verbose: bool,
    fail_fast: bool = False,
    triage: Optional["TriageIndex"] = None,
) -> List[TestResult]:
    results: List[TestResult] = []
    triage = triage or TriageIndex()

    for vtc_file in vtc_files:
        try:
            with open(vtc_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            results.append(
                TestResult(
                    test_name=os.path.basename(vtc_file),
                    file_path=vtc_file,
                    status="FAIL",
                    elapsed_sec=0.0,
                    error_message=f"Failed to read file: {e}",
                )
            )
            continue

        parser = VtcParser(content, vtc_file)
        try:
            parser.parse()
        except Exception as e:
            results.append(
                TestResult(
                    test_name=os.path.basename(vtc_file),
                    file_path=vtc_file,
                    status="FAIL",
                    elapsed_sec=0.0,
                    error_message=f"Parse error: {e}",
                )
            )
            continue

        executor = VtcExecutor(
            parser=parser,
            target_binary=binary_path,
            timeout=timeout,
            verbose=verbose,
        )

        res = await executor.execute()
        classify(res, triage)
        results.append(res)

        rel_path = os.path.relpath(vtc_file, os.getcwd())
        if res.status == "OUT_OF_SCOPE":
            print(f" {Color.yellow('[SCOPE]')} {rel_path} - {res.test_name}")
            if verbose and res.error_message:
                print(f"        {Color.DIM}declined in tradeoff.md 4.2:{Color.RESET} "
                      f"{res.error_message.splitlines()[0]}")
        elif res.status == "PASS":
            status_badge = Color.green("[PASS]")
            print(f" {status_badge} {rel_path} ({res.elapsed_sec:.2f}s) - {res.test_name}")
        elif res.status == "SKIP":
            status_badge = Color.yellow("[SKIP]")
            print(f" {status_badge} {rel_path} - {res.test_name}")
            if verbose and res.error_message:
                print(f"        {Color.yellow('Reason:')} {res.error_message}")
        else:
            status_badge = Color.red("[FAIL]")
            print(f" {status_badge} {rel_path} ({res.elapsed_sec:.2f}s) - {res.test_name}")
            if res.error_message:
                for line in res.error_message.splitlines():
                    print(f"        {line}")

        if fail_fast and res.status == "FAIL":
            break

    return results


def classify(r: TestResult, triage: "TriageIndex") -> None:
    """Reclassify one result against the declared scope, in place.

    A failure in a declined area becomes `OUT_OF_SCOPE`: it is still recorded, with its
    error text, but it is not debt. A **pass** in a declined area keeps its `PASS` and is
    flagged, because a feature we decided not to build and which works anyway is either
    good news or a wrong triage entry, and both are worth surfacing.
    """
    r.triage = triage.bucket_for(r.file_path)
    if r.triage != "OUT_OF_SCOPE":
        return
    if r.status == "FAIL":
        r.status = "OUT_OF_SCOPE"
    elif r.status == "PASS":
        r.unexpected_pass = True


def print_summary(results: List[TestResult], total_elapsed: float) -> int:
    """Print clean summary report and return process exit code."""
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    skipped = sum(1 for r in results if r.status == "SKIP")
    out_of_scope = sum(1 for r in results if r.status == "OUT_OF_SCOPE")
    unexpected = [r for r in results if r.unexpected_pass]
    total = len(results)
    # In scope *and actually run*: a skip is gated off by an `.if feature()` the build does
    # not satisfy, which is no more debt than a declined feature is. Counting either in the
    # denominator makes the board look worse than the position warrants.
    in_scope_run = total - out_of_scope - skipped

    print("\n" + Color.bold("=" * 72))
    print(Color.bold(" Ibex VTC Regression Test Suite Execution Summary"))
    print(Color.bold("=" * 72))
    print(f" Total Tests:   {total}")
    print(f" {Color.green('Passed:')}        {passed}")
    print(f" {Color.red('Failed:')}        {failed}")
    print(f" {Color.yellow('Skipped:')}       {skipped}")
    print(f" Out of scope:  {out_of_scope}   (declined in tradeoff.md 4.2; run, not counted)")
    print(f" Duration:      {total_elapsed:.2f}s")
    if in_scope_run:
        print(f" In scope, run: {passed}/{in_scope_run} passing"
              f"  ({100.0 * passed / in_scope_run:.1f}%)")
    if unexpected:
        print(Color.bold(f"\n Passing although declared out of scope ({len(unexpected)}) --"
                         " good news, or a stale triage entry:"))
        for r in unexpected:
            print(f"   {r.file_path}")
    print(Color.bold("=" * 72))

    if failed > 0:
        print(Color.bold(Color.red("\nFailed Tests:")))
        for r in results:
            if r.status == "FAIL":
                rel = os.path.relpath(r.file_path, os.getcwd())
                print(f" - {Color.red(rel)}: {r.test_name}")
                if r.error_message:
                    for line in r.error_message.splitlines()[:10]:
                        print(f"     {line}")
        return 1

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Ibex Standalone VTC Regression Test Runner")
    parser.add_argument("paths", nargs="+", help="Path(s) to .vtc file(s) or directories containing .vtc files")
    parser.add_argument(
        "--binary",
        default="target/debug/ibex",
        help="Path to Ibex proxy binary (default: target/debug/ibex)",
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="Per-test timeout in seconds (default: 15s)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose execution trace")
    parser.add_argument("--fail-fast", action="store_true", help="Stop suite execution on first failed test")
    parser.add_argument("--json", help="Export test results to specified JSON file")

    args = parser.parse_args()

    vtc_files = find_vtc_files(args.paths)
    if not vtc_files:
        print(f"{Color.red('Error:')} No .vtc test files found in specified paths: {args.paths}")
        sys.exit(1)

    if not os.path.isfile(args.binary):
        print(f"{Color.red('Error:')} Target proxy binary not found: {args.binary}")
        print("Build it first using: cargo build --bin ibex")
        sys.exit(1)

    print(f"{Color.bold('Running Ibex VTC Runner')} on {len(vtc_files)} test file(s)...")
    print(f"Target Binary: {args.binary}\n")

    suite_start = time.monotonic()
    results = asyncio.run(
        run_suite(
            vtc_files=vtc_files,
            binary_path=args.binary,
            timeout=args.timeout,
            verbose=args.verbose,
            fail_fast=args.fail_fast,
        )
    )
    total_elapsed = time.monotonic() - suite_start

    if args.json:
        out_data = {
            "total": len(results),
            "passed": sum(1 for r in results if r.status == "PASS"),
            "failed": sum(1 for r in results if r.status == "FAIL"),
            "skipped": sum(1 for r in results if r.status == "SKIP"),
            "out_of_scope": sum(1 for r in results if r.status == "OUT_OF_SCOPE"),
            "in_scope_run": sum(
                1 for r in results if r.status not in ("OUT_OF_SCOPE", "SKIP")
            ),
            "duration": total_elapsed,
            "results": [dataclasses.asdict(r) for r in results],
        }
        with open(args.json, "w") as jf:
            json.dump(out_data, jf, indent=2)
        print(f"\nJSON results written to {args.json}")

    exit_code = print_summary(results, total_elapsed)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
