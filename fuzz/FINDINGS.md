# Differential Fuzzing Findings: Ibex vs HAProxy

## Executive Summary

This report documents differential testing between the **Ibex HTTP/1 parser** (`crates/ibex-proto`) and the reference **HAProxy version 3.5-dev8-885761-29 2026/10/02 - https://haproxy.org/** oracle (`/home/bhenc/reference/haproxy/haproxy`); Ibex at commit `f974340`.

- **Total Inputs Evaluated:** 295
- **Accepted by Both Parsers:** 189
- **Rejected by Both Parsers:** 100
- **Total Disagreements Found:** 13
- **Category 1 (Acceptance Disagreements):** 4
- **Category 2 (Framing Disagreements):** 0
- **Category 3 (Smuggling / Boundary Findings):** 9
- **Self-Differential (Streaming Consistency):** 0

## Discrepancy Classification Framework

1. **Category 1 (Acceptance):** One parser accepted the input as valid HTTP/1 while the other rejected it (HTTP 400 Bad Request or parse syntax error).
2. **Category 2 (Framing):** Both parsers accepted the input, but disagreed on parsed method, URI, header count, or body length.
3. **Category 3 (Smuggling Boundary):** Disagreements on message boundaries (where this request ends and the next begins), keep-alive connection reuse enforcement on ambiguous framing, or request smuggling desynchronization.
4. **Self-Differential:** Discrepancies within Ibex itself across single-pass buffer evaluation versus incremental byte-by-byte streaming.

---

## Detailed Findings

### Finding 001: cl_te_both_present_cl_first

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** CL-TE / TE-CL Conflict
- **Description:** Both Content-Length and Transfer-Encoding: chunked present (CL first). Body contains chunked 0 and smuggled prefix.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 73 6d  75 67 67 6c 65 20 48 54  |POST /smuggle HT|
00000010: 54 50 2f 31 2e 31 0d 0a  48 6f 73 74 3a 20 65 78  |TP/1.1..Host: ex|
00000020: 61 6d 70 6c 65 2e 63 6f  6d 0d 0a 43 6f 6e 74 65  |ample.com..Conte|
00000030: 6e 74 2d 4c 65 6e 67 74  68 3a 20 36 0d 0a 54 72  |nt-Length: 6..Tr|
00000040: 61 6e 73 66 65 72 2d 45  6e 63 6f 64 69 6e 67 3a  |ansfer-Encoding:|
00000050: 20 63 68 75 6e 6b 65 64  0d 0a 0d 0a 30 0d 0a 0d  | chunked....0...|
00000060: 0a 58                                             |.X|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `97 / 98`
- **Parsed Method:** `POST`
- **Parsed URI:** `/smuggle`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `true`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/smuggle`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 002: cl_te_both_present_te_first

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** CL-TE / TE-CL Conflict
- **Description:** Both Transfer-Encoding: chunked and Content-Length present (TE first).

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 73 6d  75 67 67 6c 65 20 48 54  |POST /smuggle HT|
00000010: 54 50 2f 31 2e 31 0d 0a  48 6f 73 74 3a 20 65 78  |TP/1.1..Host: ex|
00000020: 61 6d 70 6c 65 2e 63 6f  6d 0d 0a 54 72 61 6e 73  |ample.com..Trans|
00000030: 66 65 72 2d 45 6e 63 6f  64 69 6e 67 3a 20 63 68  |fer-Encoding: ch|
00000040: 75 6e 6b 65 64 0d 0a 43  6f 6e 74 65 6e 74 2d 4c  |unked..Content-L|
00000050: 65 6e 67 74 68 3a 20 36  0d 0a 0d 0a 30 0d 0a 0d  |ength: 6....0...|
00000060: 0a 58                                             |.X|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `97 / 98`
- **Parsed Method:** `POST`
- **Parsed URI:** `/smuggle`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `true`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/smuggle`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 003: line_term_doubled_crlf_before_headers

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Line Terminator Variations (CR/LF)
- **Description:** Doubled CRLF immediately following request line.

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 64 6f 75  62 6c 65 64 20 48 54 54  |GET /doubled HTT|
00000010: 50 2f 31 2e 31 0d 0a 0d  0a 48 6f 73 74 3a 20 65  |P/1.1....Host: e|
00000020: 78 61 6d 70 6c 65 2e 63  6f 6d 0d 0a 0d 0a        |xample.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `25 / 46`
- **Parsed Method:** `GET`
- **Parsed URI:** `/doubled`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/doubled`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 004: mutated_base_35_pipelined_body_underflow_smuggle

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in pipelined_body_underflow_smuggle

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 70 31  20 48 54 54 50 2f 31 2e  |POST /p1 HTTP/1.|
00000010: 31 0d 0a 48 6f 73 74 3a  20 61 2e 63 6f 6d 0d 0a  |1..Host: a.com..|
00000020: 43 6f 6e 74 65 6e 74 2d  4c 65 6e 67 74 68 3a 20  |Content-Length: |
00000030: 34 0d 0a 0d 0a 31 32 33  34 45 58 54 00 41 5f 42  |4....1234EXT.A_B|
00000040: 59 54 45 53 47 45 54 20  2f 70 32 20 48 54 54 50  |YTESGET /p2 HTTP|
00000050: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 62 2e 63 6f  |/1.1..Host: b.co|
00000060: 6d 0d 0a 0d 0a                                    |m....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `57 / 101`
- **Parsed Method:** `POST`
- **Parsed URI:** `/p1`
- **Body Length:** `4 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/p1`
- **Forwarded Body Length:** `4 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 005: mutated_base_76_oversized_uri_4k

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in oversized_uri_4k

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 61 61 61  61 61 61 61 61 61 61 61  |GET /aaaaaaaaaaa|
00000010: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000020: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000030: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000040: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000050: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000060: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000070: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000080: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000090: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000000a0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000000b0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000000c0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000000d0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000000e0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000000f0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000100: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000110: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000120: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000130: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000140: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000150: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000160: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000170: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000180: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000190: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000001a0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000001b0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000001c0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000001d0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000001e0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000001f0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000200: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000210: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000220: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000230: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000240: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000250: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000260: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000270: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000280: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000290: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000002a0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000002b0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000002c0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000002d0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000002e0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000002f0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000300: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000310: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000320: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000330: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000340: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000350: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000360: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000370: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000380: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000390: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000003a0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000003b0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000003c0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000003d0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000003e0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000003f0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000400: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000410: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000420: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000430: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000440: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000450: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000460: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000470: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000480: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 00 61  |aaaaaaaaaaaaaa.a|
00000490: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000004a0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000004b0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000004c0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000004d0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000004e0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000004f0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000500: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000510: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000520: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000530: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000540: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000550: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000560: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000570: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000580: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000590: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000005a0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000005b0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000005c0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000005d0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000005e0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000005f0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000600: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000610: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000620: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000630: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000640: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000650: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000660: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000670: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000680: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000690: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000006a0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000006b0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000006c0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000006d0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000006e0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000006f0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000700: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000710: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000720: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000730: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000740: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000750: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000760: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000770: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000780: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000790: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000007a0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000007b0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000007c0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000007d0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000007e0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000007f0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000800: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000810: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000820: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000830: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000840: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000850: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000860: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000870: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000880: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000890: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000008a0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000008b0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000008c0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000008d0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000008e0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000008f0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000900: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000910: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000920: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000930: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000940: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000950: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000960: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000970: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000980: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000990: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000009a0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000009b0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000009c0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000009d0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000009e0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
000009f0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000a00: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000a10: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000a20: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000a30: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000a40: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000a50: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000a60: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000a70: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000a80: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000a90: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000aa0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ab0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ac0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ad0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ae0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000af0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000b00: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000b10: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000b20: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000b30: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000b40: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000b50: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000b60: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000b70: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000b80: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000b90: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ba0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000bb0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000bc0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000bd0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000be0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000bf0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000c00: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000c10: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000c20: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000c30: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000c40: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000c50: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000c60: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000c70: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000c80: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000c90: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ca0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000cb0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000cc0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000cd0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ce0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000cf0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000d00: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000d10: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000d20: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000d30: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000d40: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000d50: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000d60: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000d70: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000d80: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000d90: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000da0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000db0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000dc0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000dd0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000de0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000df0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000e00: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000e10: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000e20: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000e30: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000e40: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000e50: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000e60: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000e70: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000e80: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000e90: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ea0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000eb0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ec0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ed0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ee0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ef0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000f00: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000f10: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000f20: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000f30: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000f40: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000f50: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000f60: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000f70: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000f80: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000f90: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000fa0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000fb0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000fc0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000fd0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000fe0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000ff0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00001000: 61 61 61 61 61 20 48 54  54 50 2f 31 2e 31 0d 0a  |aaaaa HTTP/1.1..|
00001010: 48 6f 73 74 3a 20 65 78  61 6d 70 6c 65 2e 63 6f  |Host: example.co|
00001020: 6d 0d 0a 0d 0a                                    |m....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `4133 / 4133`
- **Parsed Method:** `GET`
- **Parsed URI:** `/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Ibex: accepted=true, phase="Done", err=None. HAProxy: accepted=false, status=Some(400), err=None

---

### Finding 006: mutated_base_107_line_term_doubled_crlf_before_headers

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in line_term_doubled_crlf_before_headers

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 64 6f 75  62 6c 65 64 20 48 54 54  |GET /doubled HTT|
00000010: 50 2f 31 2e 31 20 0a 0d  0a 48 6f 73 74 3a 20 65  |P/1.1 ...Host: e|
00000020: 78 61 6d 70 6c 65 2e 63  6f 6d 0d 0a 0d 0a        |xample.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `25 / 46`
- **Parsed Method:** `GET`
- **Parsed URI:** `/doubled`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 007: mutated_startline_110

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line PUT / bad HTTP/1.2

#### Raw Input Hex Dump

```text
00000000: 50 55 54 20 2f 00 62 61  64 20 48 54 54 50 2f 31  |PUT /.bad HTTP/1|
00000010: 2e 32 0d 0a 48 6f 73 74  3a 20 65 78 61 6d 70 6c  |.2..Host: exampl|
00000020: 65 2e 63 6f 6d 0d 0a 0d  0a                       |e.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `41 / 41`
- **Parsed Method:** `PUT`
- **Parsed URI:** `/ bad`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Ibex: accepted=true, phase="Done", err=None. HAProxy: accepted=false, status=Some(400), err=None

---

### Finding 008: mutated_base_115_baseline_simple_get

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in baseline_simple_get

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 69 6e 64  65 78 2e 68 74 6d 6c 20  |GET /index.html |
00000010: 48 54 54 50 2f 20 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/ .1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 0d 0a     |example.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `47 / 47`
- **Parsed Method:** `GET`
- **Parsed URI:** `/index.html`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Ibex: accepted=true, phase="Done", err=None. HAProxy: accepted=false, status=Some(400), err=None

---

### Finding 009: mutated_cl_te_rand_138

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (19) vs TE with payload len (0)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 39  |ntent-Length: 19|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 30 0d 0a 0d 0a 30 0d 0a  0d 0a                    |0....0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `101 / 106`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `true`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 010: mutated_base_160_pipelined_chunked_premature_end

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in pipelined_chunked_premature_end

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 70 2d  63 68 75 6e 6b 20 48 54  |POST /p-chunk HT|
00000010: 54 50 00 31 2e 31 0d 0a  48 6f 73 74 3a 20 61 2e  |TP.1.1..Host: a.|
00000020: 63 6f 6d 0d 0a 54 72 61  6e 73 66 65 72 2d 45 6e  |com..Transfer-En|
00000030: 63 6f 64 69 6e 67 3a 20  63 68 75 6e 6b 65 64 0d  |coding: chunked.|
00000040: 0a 0d 0a 34 0d 0a 74 65  73 74 0d 0a 30 0d 0a 0d  |...4..test..0...|
00000050: 0a 47 45 54 20 2f 70 2d  61 66 74 65 72 20 48 54  |.GET /p-after HT|
00000060: 54 50 2f 31 2e 31 0d 0a  48 6f 73 74 3a 20 62 2e  |TP/1.1..Host: b.|
00000070: 63 6f 6d 0d 0a 0d 0a                              |com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `81 / 119`
- **Parsed Method:** `POST`
- **Parsed URI:** `/p-chunk`
- **Body Length:** `4 bytes`
- **Connection Close Set:** `true`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 011: mutated_base_211_duplicate_cl_identical

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in duplicate_cl_identical

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 64 75  70 2d 63 6c 20 20 54 54  |POST /dup-cl  TT|
00000010: 50 2f 31 2e 31 0d 0a 48  6f 73 74 3a 20 65 78 61  |P/1.1..Host: exa|
00000020: 6d 70 6c 65 2e 63 6f 6d  0d 0a 43 6f 6e 74 65 6e  |mple.com..Conten|
00000030: 74 2d 4c 65 6e 67 74 68  3a 20 35 0d 0a 43 6f 6e  |t-Length: 5..Con|
00000040: 74 65 6e 74 2d 4c 65 6e  67 74 68 3a 20 35 0d 0a  |tent-Length: 5..|
00000050: 0d 0a 68 65 6c 6c 6f                              |..hello|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `87 / 87`
- **Parsed Method:** `POST`
- **Parsed URI:** `/dup-cl`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `None`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Ibex: accepted=true, phase="Done", err=None. HAProxy: accepted=false, status=None, err=None

---

### Finding 012: mutated_base_247_pipelined_standard_two_requests

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in pipelined_standard_two_requests

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 66 69 72  73 74 20 48 54 54 50 2f  |GET /first HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 73 65 63 6f 6e 64 20  |....GET /second |
00000030: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000040: 62 2e 63 6f 6d 0d 0a 0d  0a                       |b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 73`
- **Parsed Method:** `GET`
- **Parsed URI:** `/first`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/first`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 013: mutated_base_248_cl_comma_separated_conflicting

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in cl_comma_separated_conflicting

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6f  6d 6d 61 2d 63 6f 6e 66  |POST /comma-conf|
00000010: 6c 69 63 74 20 48 54 54  50 2f 31 2e 31 0d 0a 48  |lict HTTP/1.1..H|
00000020: 6f 73 74 3a 20 65 78 61  6d 70 6c 65 2e 63 6f 6d  |ost: example.com|
00000030: 0d 0a 43 6f 6e 74 65 6e  74 2d 4c 65 6e 3a 74 68  |..Content-Len:th|
00000040: 3a 20 35 2c 20 31 30 0d  0a 0d 0a 68 65 6c 6c 6f  |: 5, 10....hello|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `75 / 80`
- **Parsed Method:** `POST`
- **Parsed URI:** `/comma-conflict`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/comma-conflict`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

