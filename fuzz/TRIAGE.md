# Triage of the differential findings (2026-10-11, Alcyon f974340 vs HAProxy 3.5-dev8)

`FINDINGS.md` compares parsers; the lines below were confirmed with `fuzz/e2e.py` (real
`alcyon` binary and real HAProxy, same config, raw socket, status line + bytes the backend
received). Of the 17 findings in the dev7 report, 10 no longer differ end to end
(CL+TE, doubled CRLF, oversized header count/name, comma/duplicate Content-Length,
pipelining); the harness's Category 3 reports for them were parser-level artefacts
(`consumed < len` on a request Alcyon then closes the connection after). 7 still differ, all
with Alcyon the more permissive side. A 2545-case `--soak` run found 97 e2e differences, all
in the classes below except as noted.

1. Request-line tokens are not validated. HAProxy answers 400, Alcyon forwards the line to the
   backend: NUL in method, URI or version; method `P:ST`; space inside the URI
   (`GET /a b HTTP/1.1`); malformed version (`TTP/1.1`, `HTTP:1.1`, `HTTP/`, `HTTP\0001.1`);
   no version at all (`PUT /index.html`, Alcyon adds `HTTP/1.1`). Includes a NUL-prefixed
   pipelined second request (old 007). Findings 004-008, 010, 011.
2. Request line is forwarded verbatim where HAProxy normalises: `HTTP/1.2` stays `HTTP/1.2`
   (HAProxy sends `HTTP/1.1`), a double space `GET /p  HTTP/1.1` stays double.
3. A header line ended by a bare LF, then the blank line (`Host: a.com\n\r\n`), followed by
   a pipelined request: Alcyon answers only the first, HAProxy answers both (soak 1025;
   reproduced without the trailing space and with another header).
4. Trailing space + bare LF at the end of the request line (`HTTP/1.1 \n\r\nHost: x`): Alcyon
   ends the head at the blank line and forwards a header-less request (finding 006).
5. Chunk extension with a non-token byte (`5;ext\xff"quoted;with;semis"`): HAProxy strips
   the extension, Alcyon forwards it verbatim (soak 1732).
Opposite direction (Alcyon stricter, harmless): `Transfer-Encoding: chunked \n` plus
Content-Length: HAProxy 200 (drops CL), Alcyon 400. Differing 400-vs-wait: a NUL inside a
pipelined second head, HAProxy 400 at once, Alcyon waits for more and sends 408. Duplicate
different Content-Length: both reject, HAProxy closes silently, Alcyon sends a 400.
A client half-close (FIN) right after a complete request made both proxies answer 400.
