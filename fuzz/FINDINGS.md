# Differential Fuzzing Findings: Ibex vs HAProxy 3.5

## Executive Summary

This report documents differential testing between the **Ibex HTTP/1 parser** (`crates/ibex-proto`) and the reference **HAProxy 3.5-dev7** oracle (`/home/bhenc/reference/haproxy/haproxy`).

- **Total Inputs Evaluated:** 295
- **Accepted by Both Parsers:** 188
- **Rejected by Both Parsers:** 13
- **Total Disagreements Found:** 245
- **Category 1 (Acceptance Disagreements):** 69
- **Category 2 (Framing Disagreements):** 107
- **Category 3 (Smuggling / Boundary Findings):** 44
- **Self-Differential (Streaming Consistency):** 25

## Discrepancy Classification Framework

1. **Category 1 (Acceptance):** One parser accepted the input as valid HTTP/1 while the other rejected it (HTTP 400 Bad Request or parse syntax error).
2. **Category 2 (Framing):** Both parsers accepted the input, but disagreed on parsed method, URI, header count, or body length.
3. **Category 3 (Smuggling Boundary):** Disagreements on message boundaries (where this request ends and the next begins), keep-alive connection reuse enforcement on ambiguous framing, or request smuggling desynchronization.
4. **Self-Differential:** Discrepancies within Ibex itself across single-pass buffer evaluation versus incremental byte-by-byte streaming.

---

## Detailed Findings

### Finding 001: baseline_simple_get

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Baseline Valid HTTP/1
- **Description:** Standard HTTP/1.1 GET request with Host header

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 69 6e 64  65 78 2e 68 74 6d 6c 20  |GET /index.html |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
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
- **HTTP Status Code:** `None`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Ibex: accepted=true, phase="Done", err=None. HAProxy: accepted=false, status=None, err=None

---

### Finding 002: baseline_chunked_body

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Baseline Valid HTTP/1
- **Description:** Standard HTTP/1.1 POST request with Chunked body

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 61 70  69 2f 63 68 75 6e 6b 65  |POST /api/chunke|
00000010: 64 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  |d HTTP/1.1..Host|
00000020: 3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 54  |: example.com..T|
00000030: 72 61 6e 73 66 65 72 2d  45 6e 63 6f 64 69 6e 67  |ransfer-Encoding|
00000040: 3a 20 63 68 75 6e 6b 65  64 0d 0a 0d 0a 35 0d 0a  |: chunked....5..|
00000050: 68 65 6c 6c 6f 0d 0a 36  0d 0a 20 77 6f 72 6c 64  |hello..6.. world|
00000060: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `103 / 103`
- **Parsed Method:** `POST`
- **Parsed URI:** `/api/chunked`
- **Body Length:** `11 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/api/chunked`
- **Forwarded Body Length:** `16 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 11 bytes, HAProxy: 16 bytes)

---

### Finding 003: cl_te_both_present_cl_first

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
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/smuggle`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Ibex accepted ambiguous CL+TE without setting Connection: close, risking downstream pipelined request smuggling.

---

### Finding 004: cl_te_both_present_te_first

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
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/smuggle`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Ibex accepted ambiguous CL+TE without setting Connection: close, risking downstream pipelined request smuggling.

---

### Finding 005: cl_te_conflicting_lengths_te_cl_smuggle

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** CL-TE / TE-CL Conflict
- **Description:** TE-CL smuggling payload: CL specifies 4 bytes, but TE chunked specifies 11 bytes + end chunk.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 74 72  61 6e 73 66 65 72 20 48  |POST /transfer H|
00000010: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 65  |TTP/1.1..Host: e|
00000020: 78 61 6d 70 6c 65 2e 63  6f 6d 0d 0a 43 6f 6e 74  |xample.com..Cont|
00000030: 65 6e 74 2d 4c 65 6e 67  74 68 3a 20 34 0d 0a 54  |ent-Length: 4..T|
00000040: 72 61 6e 73 66 65 72 2d  45 6e 63 6f 64 69 6e 67  |ransfer-Encoding|
00000050: 3a 20 63 68 75 6e 6b 65  64 0d 0a 0d 0a 35 0d 0a  |: chunked....5..|
00000060: 68 65 6c 6c 6f 0d 0a 36  0d 0a 20 77 6f 72 6c 64  |hello..6.. world|
00000070: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `119 / 119`
- **Parsed Method:** `POST`
- **Parsed URI:** `/transfer`
- **Body Length:** `11 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/transfer`
- **Forwarded Body Length:** `16 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Ibex accepted ambiguous CL+TE without setting Connection: close, risking downstream pipelined request smuggling.

---

### Finding 006: cl_te_multiple_te_headers

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** CL-TE / TE-CL Conflict
- **Description:** Multiple Transfer-Encoding headers: first 'identity', second 'chunked' alongside Content-Length.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 64 61  74 61 20 48 54 54 50 2f  |POST /data HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 65 78 61 6d 70  |1.1..Host: examp|
00000020: 6c 65 2e 63 6f 6d 0d 0a  43 6f 6e 74 65 6e 74 2d  |le.com..Content-|
00000030: 4c 65 6e 67 74 68 3a 20  31 30 0d 0a 54 72 61 6e  |Length: 10..Tran|
00000040: 73 66 65 72 2d 45 6e 63  6f 64 69 6e 67 3a 20 69  |sfer-Encoding: i|
00000050: 64 65 6e 74 69 74 79 0d  0a 54 72 61 6e 73 66 65  |dentity..Transfe|
00000060: 72 2d 45 6e 63 6f 64 69  6e 67 3a 20 63 68 75 6e  |r-Encoding: chun|
00000070: 6b 65 64 0d 0a 0d 0a 35  0d 0a 68 65 6c 6c 6f 0d  |ked....5..hello.|
00000080: 0a 30 0d 0a 0d 0a                                 |.0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `129 / 134`
- **Parsed Method:** `POST`
- **Parsed URI:** `/data`
- **Body Length:** `10 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(422)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Ibex: accepted=true, phase="Done", err=None. HAProxy: accepted=false, status=Some(422), err=None

---

### Finding 007: duplicate_cl_conflicting_values

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Duplicate / Conflicting Content-Length
- **Description:** Conflicting Content-Length headers (5 and 10).

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6f  6e 66 6c 69 63 74 2d 63  |POST /conflict-c|
00000010: 6c 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  |l HTTP/1.1..Host|
00000020: 3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 43  |: example.com..C|
00000030: 6f 6e 74 65 6e 74 2d 4c  65 6e 67 74 68 3a 20 35  |ontent-Length: 5|
00000040: 0d 0a 43 6f 6e 74 65 6e  74 2d 4c 65 6e 67 74 68  |..Content-Length|
00000050: 3a 20 31 30 0d 0a 0d 0a  68 65 6c 6c 6f 77 6f 72  |: 10....hellowor|
00000060: 6c 64                                             |ld|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `93 / 98`
- **Parsed Method:** `POST`
- **Parsed URI:** `/conflict-cl`
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

### Finding 008: cl_comma_separated_values

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Duplicate / Conflicting Content-Length
- **Description:** Content-Length with comma-separated values '5, 5'.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6f  6d 6d 61 2d 63 6c 20 48  |POST /comma-cl H|
00000010: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 65  |TTP/1.1..Host: e|
00000020: 78 61 6d 70 6c 65 2e 63  6f 6d 0d 0a 43 6f 6e 74  |xample.com..Cont|
00000030: 65 6e 74 2d 4c 65 6e 67  74 68 3a 20 35 2c 20 35  |ent-Length: 5, 5|
00000040: 0d 0a 0d 0a 68 65 6c 6c  6f                       |....hello|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `68 / 73`
- **Parsed Method:** `POST`
- **Parsed URI:** `/comma-cl`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/comma-cl`
- **Forwarded Body Length:** `5 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 0 bytes, HAProxy: 5 bytes)

---

### Finding 009: cl_comma_separated_conflicting

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Duplicate / Conflicting Content-Length
- **Description:** Content-Length with comma-separated conflicting values '5, 10'.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6f  6d 6d 61 2d 63 6f 6e 66  |POST /comma-conf|
00000010: 6c 69 63 74 20 48 54 54  50 2f 31 2e 31 0d 0a 48  |lict HTTP/1.1..H|
00000020: 6f 73 74 3a 20 65 78 61  6d 70 6c 65 2e 63 6f 6d  |ost: example.com|
00000030: 0d 0a 43 6f 6e 74 65 6e  74 2d 4c 65 6e 67 74 68  |..Content-Length|
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

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Ibex: accepted=true, phase="Done", err=None. HAProxy: accepted=false, status=Some(400), err=None

---

### Finding 010: cl_signed_positive

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Duplicate / Conflicting Content-Length
- **Description:** Content-Length with leading '+' sign (+5).

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 73 69  67 6e 65 64 2d 63 6c 20  |POST /signed-cl |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 43 6f 6e  |example.com..Con|
00000030: 74 65 6e 74 2d 4c 65 6e  67 74 68 3a 20 2b 35 0d  |tent-Length: +5.|
00000040: 0a 0d 0a 68 65 6c 6c 6f                           |...hello|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `72 / 72`
- **Parsed Method:** `POST`
- **Parsed URI:** `/signed-cl`
- **Body Length:** `5 bytes`
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

### Finding 011: cl_signed_negative

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Duplicate / Conflicting Content-Length
- **Description:** Content-Length with negative sign (-5).

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 73 69  67 6e 65 64 2d 6e 65 67  |POST /signed-neg|
00000010: 2d 63 6c 20 48 54 54 50  2f 31 2e 31 0d 0a 48 6f  |-cl HTTP/1.1..Ho|
00000020: 73 74 3a 20 65 78 61 6d  70 6c 65 2e 63 6f 6d 0d  |st: example.com.|
00000030: 0a 43 6f 6e 74 65 6e 74  2d 4c 65 6e 67 74 68 3a  |.Content-Length:|
00000040: 20 2d 35 0d 0a 0d 0a 68  65 6c 6c 6f              | -5....hello|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `71 / 76`
- **Parsed Method:** `POST`
- **Parsed URI:** `/signed-neg-cl`
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

### Finding 012: cl_overflow_u64

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Duplicate / Conflicting Content-Length
- **Description:** Content-Length with massive integer overflowing 64-bit integer.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6f 76  65 72 66 6c 6f 77 2d 63  |POST /overflow-c|
00000010: 6c 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  |l HTTP/1.1..Host|
00000020: 3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 43  |: example.com..C|
00000030: 6f 6e 74 65 6e 74 2d 4c  65 6e 67 74 68 3a 20 39  |ontent-Length: 9|
00000040: 39 39 39 39 39 39 39 39  39 39 39 39 39 39 39 39  |9999999999999999|
00000050: 39 39 39 39 39 39 39 39  39 39 39 39 39 39 39 0d  |999999999999999.|
00000060: 0a 0d 0a 68 65 6c 6c 6f                           |...hello|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `99 / 104`
- **Parsed Method:** `POST`
- **Parsed URI:** `/overflow-cl`
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

### Finding 013: te_mixed_case

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Transfer-Encoding Formatting & Casing
- **Description:** Transfer-Encoding with mixed casing: 'cHuNkEd'.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 61  73 69 6e 67 20 48 54 54  |POST /casing HTT|
00000010: 50 2f 31 2e 31 0d 0a 48  6f 73 74 3a 20 65 78 61  |P/1.1..Host: exa|
00000020: 6d 70 6c 65 2e 63 6f 6d  0d 0a 54 72 61 6e 73 66  |mple.com..Transf|
00000030: 65 72 2d 45 6e 63 6f 64  69 6e 67 3a 20 63 48 75  |er-Encoding: cHu|
00000040: 4e 6b 45 64 0d 0a 0d 0a  35 0d 0a 68 65 6c 6c 6f  |NkEd....5..hello|
00000050: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `87 / 87`
- **Parsed Method:** `POST`
- **Parsed URI:** `/casing`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/casing`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 014: te_trailing_identity

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Transfer-Encoding Formatting & Casing
- **Description:** Transfer-Encoding: chunked, identity (RFC 9112 §6.1 invalid final encoding).

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 74 72  61 69 6c 69 6e 67 2d 69  |POST /trailing-i|
00000010: 64 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  |d HTTP/1.1..Host|
00000020: 3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 54  |: example.com..T|
00000030: 72 61 6e 73 66 65 72 2d  45 6e 63 6f 64 69 6e 67  |ransfer-Encoding|
00000040: 3a 20 63 68 75 6e 6b 65  64 2c 20 69 64 65 6e 74  |: chunked, ident|
00000050: 69 74 79 0d 0a 0d 0a 35  0d 0a 68 65 6c 6c 6f 0d  |ity....5..hello.|
00000060: 0a 30 0d 0a 0d 0a                                 |.0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `102 / 102`
- **Parsed Method:** `POST`
- **Parsed URI:** `/trailing-id`
- **Body Length:** `5 bytes`
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

### Finding 015: te_leading_identity

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Transfer-Encoding Formatting & Casing
- **Description:** Transfer-Encoding: identity, chunked.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6c 65  61 64 69 6e 67 2d 69 64  |POST /leading-id|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 54 72  | example.com..Tr|
00000030: 61 6e 73 66 65 72 2d 45  6e 63 6f 64 69 6e 67 3a  |ansfer-Encoding:|
00000040: 20 69 64 65 6e 74 69 74  79 2c 20 63 68 75 6e 6b  | identity, chunk|
00000050: 65 64 0d 0a 0d 0a 35 0d  0a 68 65 6c 6c 6f 0d 0a  |ed....5..hello..|
00000060: 30 0d 0a 0d 0a                                    |0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `101 / 101`
- **Parsed Method:** `POST`
- **Parsed URI:** `/leading-id`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(422)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Ibex: accepted=true, phase="Done", err=None. HAProxy: accepted=false, status=Some(422), err=None

---

### Finding 016: te_tab_whitespace

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Transfer-Encoding Formatting & Casing
- **Description:** Transfer-Encoding with tab separator: 'Transfer-Encoding:	chunked'.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 74 65  2d 74 61 62 20 48 54 54  |POST /te-tab HTT|
00000010: 50 2f 31 2e 31 0d 0a 48  6f 73 74 3a 20 65 78 61  |P/1.1..Host: exa|
00000020: 6d 70 6c 65 2e 63 6f 6d  0d 0a 54 72 61 6e 73 66  |mple.com..Transf|
00000030: 65 72 2d 45 6e 63 6f 64  69 6e 67 3a 09 63 68 75  |er-Encoding:.chu|
00000040: 6e 6b 65 64 0d 0a 0d 0a  35 0d 0a 68 65 6c 6c 6f  |nked....5..hello|
00000050: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `87 / 87`
- **Parsed Method:** `POST`
- **Parsed URI:** `/te-tab`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/te-tab`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 017: te_prefix_unknown_encoding

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Transfer-Encoding Formatting & Casing
- **Description:** Transfer-Encoding containing chunked substring in unrecognized token: 'not-chunked'.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 74 65  2d 75 6e 6b 6e 6f 77 6e  |POST /te-unknown|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 54 72  | example.com..Tr|
00000030: 61 6e 73 66 65 72 2d 45  6e 63 6f 64 69 6e 67 3a  |ansfer-Encoding:|
00000040: 20 6e 6f 74 2d 63 68 75  6e 6b 65 64 0d 0a 0d 0a  | not-chunked....|
00000050: 35 0d 0a 68 65 6c 6c 6f  0d 0a 30 0d 0a 0d 0a     |5..hello..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `95 / 95`
- **Parsed Method:** `POST`
- **Parsed URI:** `/te-unknown`
- **Body Length:** `5 bytes`
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

### Finding 018: obs_fold_transfer_encoding

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Obs-Fold Continuation Lines
- **Description:** Obs-fold on Transfer-Encoding header line itself.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6f 62  73 2d 74 65 20 48 54 54  |POST /obs-te HTT|
00000010: 50 2f 31 2e 31 0d 0a 48  6f 73 74 3a 20 65 78 61  |P/1.1..Host: exa|
00000020: 6d 70 6c 65 2e 63 6f 6d  0d 0a 54 72 61 6e 73 66  |mple.com..Transf|
00000030: 65 72 2d 45 6e 63 6f 64  69 6e 67 3a 0d 0a 20 63  |er-Encoding:.. c|
00000040: 68 75 6e 6b 65 64 0d 0a  0d 0a 35 0d 0a 68 65 6c  |hunked....5..hel|
00000050: 6c 6f 0d 0a 30 0d 0a 0d  0a                       |lo..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `89 / 89`
- **Parsed Method:** `POST`
- **Parsed URI:** `/obs-te`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/obs-te`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 019: obs_fold_first_line

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Obs-Fold Continuation Lines
- **Description:** Obs-fold immediately after request line (no preceding header).

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6f 62 73  2d 66 69 72 73 74 20 48  |GET /obs-first H|
00000010: 54 54 50 2f 31 2e 31 0d  0a 20 66 6f 6c 64 65 64  |TTP/1.1.. folded|
00000020: 2d 77 69 74 68 6f 75 74  2d 68 65 61 64 65 72 3a  |-without-header:|
00000030: 20 76 61 6c 75 65 0d 0a  48 6f 73 74 3a 20 65 78  | value..Host: ex|
00000040: 61 6d 70 6c 65 2e 63 6f  6d 0d 0a 0d 0a           |ample.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `77 / 77`
- **Parsed Method:** `GET`
- **Parsed URI:** `/obs-first`
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

### Finding 020: line_term_cr_only

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Line Terminator Variations (CR/LF)
- **Description:** HTTP request using CR-only (\r) line endings throughout.

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 63 72 2d  6f 6e 6c 79 20 48 54 54  |GET /cr-only HTT|
00000010: 50 2f 31 2e 31 0d 48 6f  73 74 3a 20 65 78 61 6d  |P/1.1.Host: exam|
00000020: 70 6c 65 2e 63 6f 6d 0d  58 2d 48 65 61 64 65 72  |ple.com.X-Header|
00000030: 3a 20 76 61 6c 75 65 0d  0d                       |: value..|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `57 / 57`
- **Parsed Method:** `GET`
- **Parsed URI:** `/cr-only`
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

### Finding 021: chunk_leading_zeros

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Chunk Size & Extensions
- **Description:** Chunk size formatted with leading zeros (00005).

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 68  75 6e 6b 2d 7a 65 72 6f  |POST /chunk-zero|
00000010: 73 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  |s HTTP/1.1..Host|
00000020: 3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 54  |: example.com..T|
00000030: 72 61 6e 73 66 65 72 2d  45 6e 63 6f 64 69 6e 67  |ransfer-Encoding|
00000040: 3a 20 63 68 75 6e 6b 65  64 0d 0a 0d 0a 30 30 30  |: chunked....000|
00000050: 30 35 0d 0a 68 65 6c 6c  6f 0d 0a 30 0d 0a 0d 0a  |05..hello..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `96 / 96`
- **Parsed Method:** `POST`
- **Parsed URI:** `/chunk-zeros`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/chunk-zeros`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 022: chunk_signed_plus

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Chunk Size & Extensions
- **Description:** Chunk size formatted with leading '+' sign (+5).

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 68  75 6e 6b 2d 70 6c 75 73  |POST /chunk-plus|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 54 72  | example.com..Tr|
00000030: 61 6e 73 66 65 72 2d 45  6e 63 6f 64 69 6e 67 3a  |ansfer-Encoding:|
00000040: 20 63 68 75 6e 6b 65 64  0d 0a 0d 0a 2b 35 0d 0a  | chunked....+5..|
00000050: 68 65 6c 6c 6f 0d 0a 30  0d 0a 0d 0a              |hello..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `92 / 92`
- **Parsed Method:** `POST`
- **Parsed URI:** `/chunk-plus`
- **Body Length:** `5 bytes`
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

### Finding 023: chunk_extension_standard

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Chunk Size & Extensions
- **Description:** Chunk extension with key-value parameters: '5;ext=foo;bar=123'.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 68  75 6e 6b 2d 65 78 74 20  |POST /chunk-ext |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 35 3b 65 78 74  |chunked....5;ext|
00000050: 3d 66 6f 6f 3b 62 61 72  3d 31 32 33 0d 0a 68 65  |=foo;bar=123..he|
00000060: 6c 6c 6f 0d 0a 30 3b 66  69 6e 61 6c 3d 74 72 75  |llo..0;final=tru|
00000070: 65 0d 0a 0d 0a                                    |e....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `117 / 117`
- **Parsed Method:** `POST`
- **Parsed URI:** `/chunk-ext`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/chunk-ext`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 024: chunk_extension_quoted_semicolon

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Chunk Size & Extensions
- **Description:** Chunk extension with quoted string containing semicolons.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 68  75 6e 6b 2d 71 75 6f 74  |POST /chunk-quot|
00000010: 65 64 20 48 54 54 50 2f  31 2e 31 0d 0a 48 6f 73  |ed HTTP/1.1..Hos|
00000020: 74 3a 20 65 78 61 6d 70  6c 65 2e 63 6f 6d 0d 0a  |t: example.com..|
00000030: 54 72 61 6e 73 66 65 72  2d 45 6e 63 6f 64 69 6e  |Transfer-Encodin|
00000040: 67 3a 20 63 68 75 6e 6b  65 64 0d 0a 0d 0a 35 3b  |g: chunked....5;|
00000050: 65 78 74 3d 22 71 75 6f  74 65 64 3b 77 69 74 68  |ext="quoted;with|
00000060: 3b 73 65 6d 69 73 22 0d  0a 68 65 6c 6c 6f 0d 0a  |;semis"..hello..|
00000070: 30 0d 0a 0d 0a                                    |0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `117 / 117`
- **Parsed Method:** `POST`
- **Parsed URI:** `/chunk-quoted`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/chunk-quoted`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 025: chunk_whitespace_around_size

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Chunk Size & Extensions
- **Description:** Chunk size line with leading and trailing whitespace around size hex: ' 5 '.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 68  75 6e 6b 2d 77 73 20 48  |POST /chunk-ws H|
00000010: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 65  |TTP/1.1..Host: e|
00000020: 78 61 6d 70 6c 65 2e 63  6f 6d 0d 0a 54 72 61 6e  |xample.com..Tran|
00000030: 73 66 65 72 2d 45 6e 63  6f 64 69 6e 67 3a 20 63  |sfer-Encoding: c|
00000040: 68 75 6e 6b 65 64 0d 0a  0d 0a 20 35 20 0d 0a 68  |hunked.... 5 ..h|
00000050: 65 6c 6c 6f 0d 0a 30 0d  0a 0d 0a                 |ello..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `91 / 91`
- **Parsed Method:** `POST`
- **Parsed URI:** `/chunk-ws`
- **Body Length:** `5 bytes`
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

### Finding 026: header_space_before_colon

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Header Name Malformations
- **Description:** Header with whitespace before colon: 'X-Header : value' (RFC 7230 §3.2.4 violation).

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 73 70 61  63 65 2d 62 65 66 6f 72  |GET /space-befor|
00000010: 65 2d 63 6f 6c 6f 6e 20  48 54 54 50 2f 31 2e 31  |e-colon HTTP/1.1|
00000020: 0d 0a 48 6f 73 74 3a 20  65 78 61 6d 70 6c 65 2e  |..Host: example.|
00000030: 63 6f 6d 0d 0a 58 2d 48  65 61 64 65 72 20 3a 20  |com..X-Header : |
00000040: 76 61 6c 75 65 0d 0a 0d  0a                       |value....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `73 / 73`
- **Parsed Method:** `GET`
- **Parsed URI:** `/space-before-colon`
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

### Finding 027: header_tab_before_colon

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Header Name Malformations
- **Description:** Header with TAB character before colon: 'X-Header	: value'.

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 74 61 62  2d 62 65 66 6f 72 65 2d  |GET /tab-before-|
00000010: 63 6f 6c 6f 6e 20 48 54  54 50 2f 31 2e 31 0d 0a  |colon HTTP/1.1..|
00000020: 48 6f 73 74 3a 20 65 78  61 6d 70 6c 65 2e 63 6f  |Host: example.co|
00000030: 6d 0d 0a 58 2d 48 65 61  64 65 72 09 3a 20 76 61  |m..X-Header.: va|
00000040: 6c 75 65 0d 0a 0d 0a                              |lue....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `71 / 71`
- **Parsed Method:** `GET`
- **Parsed URI:** `/tab-before-colon`
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

### Finding 028: header_nul_in_name

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Header Name Malformations
- **Description:** Header name containing embedded NUL (\x00) byte: 'X-Foo\x00Bar: val'.

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6e 75 6c  2d 69 6e 2d 6e 61 6d 65  |GET /nul-in-name|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 46 6f 6f 00 42 61 72 3a  20 76 61 6c 75 65 0d 0a  |Foo.Bar: value..|
00000040: 0d 0a                                             |..|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `66 / 66`
- **Parsed Method:** `GET`
- **Parsed URI:** `/nul-in-name`
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

### Finding 029: header_nul_in_value

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Header Name Malformations
- **Description:** Header value containing embedded NUL (\x00) byte: 'X-Header: val\x00ue'.

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6e 75 6c  2d 69 6e 2d 76 61 6c 75  |GET /nul-in-valu|
00000010: 65 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  |e HTTP/1.1..Host|
00000020: 3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 58  |: example.com..X|
00000030: 2d 48 65 61 64 65 72 3a  20 76 61 6c 00 75 65 0d  |-Header: val.ue.|
00000040: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `67 / 67`
- **Parsed Method:** `GET`
- **Parsed URI:** `/nul-in-value`
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

### Finding 030: header_empty_name

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Header Name Malformations
- **Description:** Header line with empty name before colon: ': empty-name-value'.

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 65 6d 70  74 79 2d 6e 61 6d 65 20  |GET /empty-name |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 3a 20 65  |example.com..: e|
00000030: 6d 70 74 79 2d 6e 61 6d  65 2d 76 61 6c 75 65 0d  |mpty-name-value.|
00000040: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `67 / 67`
- **Parsed Method:** `GET`
- **Parsed URI:** `/empty-name`
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

### Finding 031: pipelined_standard_two_requests

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Two back-to-back pipelined GET requests on the same connection.

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
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 032: pipelined_body_underflow_smuggle

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Request 1 specifies CL: 4, but body is 8 bytes before Request 2 start line.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 70 31  20 48 54 54 50 2f 31 2e  |POST /p1 HTTP/1.|
00000010: 31 0d 0a 48 6f 73 74 3a  20 61 2e 63 6f 6d 0d 0a  |1..Host: a.com..|
00000020: 43 6f 6e 74 65 6e 74 2d  4c 65 6e 67 74 68 3a 20  |Content-Length: |
00000030: 34 0d 0a 0d 0a 31 32 33  34 45 58 54 52 41 5f 42  |4....1234EXTRA_B|
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
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 033: pipelined_chunked_premature_end

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Request 1 terminates chunked stream early with 0\r\n\r\n, followed by second request.

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 70 2d  63 68 75 6e 6b 20 48 54  |POST /p-chunk HT|
00000010: 54 50 2f 31 2e 31 0d 0a  48 6f 73 74 3a 20 61 2e  |TP/1.1..Host: a.|
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
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/p-chunk`
- **Forwarded Body Length:** `9 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 034: oversized_header_count_120

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Oversized Headers & Limits
- **Description:** Request containing 120 unique custom headers.

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 61 6e  79 2d 68 65 61 64 65 72  |GET /many-header|
00000010: 73 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  |s HTTP/1.1..Host|
00000020: 3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 58  |: example.com..X|
00000030: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
00000040: 30 30 3a 20 76 61 6c 75  65 5f 30 0d 0a 58 2d 43  |00: value_0..X-C|
00000050: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 30 31  |ustom-Header-001|
00000060: 3a 20 76 61 6c 75 65 5f  31 0d 0a 58 2d 43 75 73  |: value_1..X-Cus|
00000070: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 30 32 3a 20  |tom-Header-002: |
00000080: 76 61 6c 75 65 5f 32 0d  0a 58 2d 43 75 73 74 6f  |value_2..X-Custo|
00000090: 6d 2d 48 65 61 64 65 72  2d 30 30 33 3a 20 76 61  |m-Header-003: va|
000000a0: 6c 75 65 5f 33 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |lue_3..X-Custom-|
000000b0: 48 65 61 64 65 72 2d 30  30 34 3a 20 76 61 6c 75  |Header-004: valu|
000000c0: 65 5f 34 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |e_4..X-Custom-He|
000000d0: 61 64 65 72 2d 30 30 35  3a 20 76 61 6c 75 65 5f  |ader-005: value_|
000000e0: 35 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |5..X-Custom-Head|
000000f0: 65 72 2d 30 30 36 3a 20  76 61 6c 75 65 5f 36 0d  |er-006: value_6.|
00000100: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000110: 2d 30 30 37 3a 20 76 61  6c 75 65 5f 37 0d 0a 58  |-007: value_7..X|
00000120: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
00000130: 30 38 3a 20 76 61 6c 75  65 5f 38 0d 0a 58 2d 43  |08: value_8..X-C|
00000140: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 30 39  |ustom-Header-009|
00000150: 3a 20 76 61 6c 75 65 5f  39 0d 0a 58 2d 43 75 73  |: value_9..X-Cus|
00000160: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 31 30 3a 20  |tom-Header-010: |
00000170: 76 61 6c 75 65 5f 31 30  0d 0a 58 2d 43 75 73 74  |value_10..X-Cust|
00000180: 6f 6d 2d 48 65 61 64 65  72 2d 30 31 31 3a 20 76  |om-Header-011: v|
00000190: 61 6c 75 65 5f 31 31 0d  0a 58 2d 43 75 73 74 6f  |alue_11..X-Custo|
000001a0: 6d 2d 48 65 61 64 65 72  2d 30 31 32 3a 20 76 61  |m-Header-012: va|
000001b0: 6c 75 65 5f 31 32 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_12..X-Custom|
000001c0: 2d 48 65 61 64 65 72 2d  30 31 33 3a 20 76 61 6c  |-Header-013: val|
000001d0: 75 65 5f 31 33 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_13..X-Custom-|
000001e0: 48 65 61 64 65 72 2d 30  31 34 3a 20 76 61 6c 75  |Header-014: valu|
000001f0: 65 5f 31 34 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_14..X-Custom-H|
00000200: 65 61 64 65 72 2d 30 31  35 3a 20 76 61 6c 75 65  |eader-015: value|
00000210: 5f 31 35 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_15..X-Custom-He|
00000220: 61 64 65 72 2d 30 31 36  3a 20 76 61 6c 75 65 5f  |ader-016: value_|
00000230: 31 36 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |16..X-Custom-Hea|
00000240: 64 65 72 2d 30 31 37 3a  20 76 61 6c 75 65 5f 31  |der-017: value_1|
00000250: 37 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |7..X-Custom-Head|
00000260: 65 72 2d 30 31 38 3a 20  76 61 6c 75 65 5f 31 38  |er-018: value_18|
00000270: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000280: 72 2d 30 31 39 3a 20 76  61 6c 75 65 5f 31 39 0d  |r-019: value_19.|
00000290: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
000002a0: 2d 30 32 30 3a 20 76 61  6c 75 65 5f 32 30 0d 0a  |-020: value_20..|
000002b0: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
000002c0: 30 32 31 3a 20 76 61 6c  75 65 5f 32 31 0d 0a 58  |021: value_21..X|
000002d0: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
000002e0: 32 32 3a 20 76 61 6c 75  65 5f 32 32 0d 0a 58 2d  |22: value_22..X-|
000002f0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 32  |Custom-Header-02|
00000300: 33 3a 20 76 61 6c 75 65  5f 32 33 0d 0a 58 2d 43  |3: value_23..X-C|
00000310: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 32 34  |ustom-Header-024|
00000320: 3a 20 76 61 6c 75 65 5f  32 34 0d 0a 58 2d 43 75  |: value_24..X-Cu|
00000330: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 32 35 3a  |stom-Header-025:|
00000340: 20 76 61 6c 75 65 5f 32  35 0d 0a 58 2d 43 75 73  | value_25..X-Cus|
00000350: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 32 36 3a 20  |tom-Header-026: |
00000360: 76 61 6c 75 65 5f 32 36  0d 0a 58 2d 43 75 73 74  |value_26..X-Cust|
00000370: 6f 6d 2d 48 65 61 64 65  72 2d 30 32 37 3a 20 76  |om-Header-027: v|
00000380: 61 6c 75 65 5f 32 37 0d  0a 58 2d 43 75 73 74 6f  |alue_27..X-Custo|
00000390: 6d 2d 48 65 61 64 65 72  2d 30 32 38 3a 20 76 61  |m-Header-028: va|
000003a0: 6c 75 65 5f 32 38 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_28..X-Custom|
000003b0: 2d 48 65 61 64 65 72 2d  30 32 39 3a 20 76 61 6c  |-Header-029: val|
000003c0: 75 65 5f 32 39 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_29..X-Custom-|
000003d0: 48 65 61 64 65 72 2d 30  33 30 3a 20 76 61 6c 75  |Header-030: valu|
000003e0: 65 5f 33 30 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_30..X-Custom-H|
000003f0: 65 61 64 65 72 2d 30 33  31 3a 20 76 61 6c 75 65  |eader-031: value|
00000400: 5f 33 31 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_31..X-Custom-He|
00000410: 61 64 65 72 2d 30 33 32  3a 20 76 61 6c 75 65 5f  |ader-032: value_|
00000420: 33 32 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |32..X-Custom-Hea|
00000430: 64 65 72 2d 30 33 33 3a  20 76 61 6c 75 65 5f 33  |der-033: value_3|
00000440: 33 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |3..X-Custom-Head|
00000450: 65 72 2d 30 33 34 3a 20  76 61 6c 75 65 5f 33 34  |er-034: value_34|
00000460: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000470: 72 2d 30 33 35 3a 20 76  61 6c 75 65 5f 33 35 0d  |r-035: value_35.|
00000480: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000490: 2d 30 33 36 3a 20 76 61  6c 75 65 5f 33 36 0d 0a  |-036: value_36..|
000004a0: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
000004b0: 30 33 37 3a 20 76 61 6c  75 65 5f 33 37 0d 0a 58  |037: value_37..X|
000004c0: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
000004d0: 33 38 3a 20 76 61 6c 75  65 5f 33 38 0d 0a 58 2d  |38: value_38..X-|
000004e0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 33  |Custom-Header-03|
000004f0: 39 3a 20 76 61 6c 75 65  5f 33 39 0d 0a 58 2d 43  |9: value_39..X-C|
00000500: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 34 30  |ustom-Header-040|
00000510: 3a 20 76 61 6c 75 65 5f  34 30 0d 0a 58 2d 43 75  |: value_40..X-Cu|
00000520: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 34 31 3a  |stom-Header-041:|
00000530: 20 76 61 6c 75 65 5f 34  31 0d 0a 58 2d 43 75 73  | value_41..X-Cus|
00000540: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 34 32 3a 20  |tom-Header-042: |
00000550: 76 61 6c 75 65 5f 34 32  0d 0a 58 2d 43 75 73 74  |value_42..X-Cust|
00000560: 6f 6d 2d 48 65 61 64 65  72 2d 30 34 33 3a 20 76  |om-Header-043: v|
00000570: 61 6c 75 65 5f 34 33 0d  0a 58 2d 43 75 73 74 6f  |alue_43..X-Custo|
00000580: 6d 2d 48 65 61 64 65 72  2d 30 34 34 3a 20 76 61  |m-Header-044: va|
00000590: 6c 75 65 5f 34 34 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_44..X-Custom|
000005a0: 2d 48 65 61 64 65 72 2d  30 34 35 3a 20 76 61 6c  |-Header-045: val|
000005b0: 75 65 5f 34 35 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_45..X-Custom-|
000005c0: 48 65 61 64 65 72 2d 30  34 36 3a 20 76 61 6c 75  |Header-046: valu|
000005d0: 65 5f 34 36 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_46..X-Custom-H|
000005e0: 65 61 64 65 72 2d 30 34  37 3a 20 76 61 6c 75 65  |eader-047: value|
000005f0: 5f 34 37 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_47..X-Custom-He|
00000600: 61 64 65 72 2d 30 34 38  3a 20 76 61 6c 75 65 5f  |ader-048: value_|
00000610: 34 38 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |48..X-Custom-Hea|
00000620: 64 65 72 2d 30 34 39 3a  20 76 61 6c 75 65 5f 34  |der-049: value_4|
00000630: 39 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |9..X-Custom-Head|
00000640: 65 72 2d 30 35 30 3a 20  76 61 6c 75 65 5f 35 30  |er-050: value_50|
00000650: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000660: 72 2d 30 35 31 3a 20 76  61 6c 75 65 5f 35 31 0d  |r-051: value_51.|
00000670: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000680: 2d 30 35 32 3a 20 76 61  6c 75 65 5f 35 32 0d 0a  |-052: value_52..|
00000690: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
000006a0: 30 35 33 3a 20 76 61 6c  75 65 5f 35 33 0d 0a 58  |053: value_53..X|
000006b0: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
000006c0: 35 34 3a 20 76 61 6c 75  65 5f 35 34 0d 0a 58 2d  |54: value_54..X-|
000006d0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 35  |Custom-Header-05|
000006e0: 35 3a 20 76 61 6c 75 65  5f 35 35 0d 0a 58 2d 43  |5: value_55..X-C|
000006f0: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 35 36  |ustom-Header-056|
00000700: 3a 20 76 61 6c 75 65 5f  35 36 0d 0a 58 2d 43 75  |: value_56..X-Cu|
00000710: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 35 37 3a  |stom-Header-057:|
00000720: 20 76 61 6c 75 65 5f 35  37 0d 0a 58 2d 43 75 73  | value_57..X-Cus|
00000730: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 35 38 3a 20  |tom-Header-058: |
00000740: 76 61 6c 75 65 5f 35 38  0d 0a 58 2d 43 75 73 74  |value_58..X-Cust|
00000750: 6f 6d 2d 48 65 61 64 65  72 2d 30 35 39 3a 20 76  |om-Header-059: v|
00000760: 61 6c 75 65 5f 35 39 0d  0a 58 2d 43 75 73 74 6f  |alue_59..X-Custo|
00000770: 6d 2d 48 65 61 64 65 72  2d 30 36 30 3a 20 76 61  |m-Header-060: va|
00000780: 6c 75 65 5f 36 30 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_60..X-Custom|
00000790: 2d 48 65 61 64 65 72 2d  30 36 31 3a 20 76 61 6c  |-Header-061: val|
000007a0: 75 65 5f 36 31 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_61..X-Custom-|
000007b0: 48 65 61 64 65 72 2d 30  36 32 3a 20 76 61 6c 75  |Header-062: valu|
000007c0: 65 5f 36 32 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_62..X-Custom-H|
000007d0: 65 61 64 65 72 2d 30 36  33 3a 20 76 61 6c 75 65  |eader-063: value|
000007e0: 5f 36 33 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_63..X-Custom-He|
000007f0: 61 64 65 72 2d 30 36 34  3a 20 76 61 6c 75 65 5f  |ader-064: value_|
00000800: 36 34 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |64..X-Custom-Hea|
00000810: 64 65 72 2d 30 36 35 3a  20 76 61 6c 75 65 5f 36  |der-065: value_6|
00000820: 35 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |5..X-Custom-Head|
00000830: 65 72 2d 30 36 36 3a 20  76 61 6c 75 65 5f 36 36  |er-066: value_66|
00000840: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000850: 72 2d 30 36 37 3a 20 76  61 6c 75 65 5f 36 37 0d  |r-067: value_67.|
00000860: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000870: 2d 30 36 38 3a 20 76 61  6c 75 65 5f 36 38 0d 0a  |-068: value_68..|
00000880: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
00000890: 30 36 39 3a 20 76 61 6c  75 65 5f 36 39 0d 0a 58  |069: value_69..X|
000008a0: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
000008b0: 37 30 3a 20 76 61 6c 75  65 5f 37 30 0d 0a 58 2d  |70: value_70..X-|
000008c0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 37  |Custom-Header-07|
000008d0: 31 3a 20 76 61 6c 75 65  5f 37 31 0d 0a 58 2d 43  |1: value_71..X-C|
000008e0: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 37 32  |ustom-Header-072|
000008f0: 3a 20 76 61 6c 75 65 5f  37 32 0d 0a 58 2d 43 75  |: value_72..X-Cu|
00000900: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 37 33 3a  |stom-Header-073:|
00000910: 20 76 61 6c 75 65 5f 37  33 0d 0a 58 2d 43 75 73  | value_73..X-Cus|
00000920: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 37 34 3a 20  |tom-Header-074: |
00000930: 76 61 6c 75 65 5f 37 34  0d 0a 58 2d 43 75 73 74  |value_74..X-Cust|
00000940: 6f 6d 2d 48 65 61 64 65  72 2d 30 37 35 3a 20 76  |om-Header-075: v|
00000950: 61 6c 75 65 5f 37 35 0d  0a 58 2d 43 75 73 74 6f  |alue_75..X-Custo|
00000960: 6d 2d 48 65 61 64 65 72  2d 30 37 36 3a 20 76 61  |m-Header-076: va|
00000970: 6c 75 65 5f 37 36 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_76..X-Custom|
00000980: 2d 48 65 61 64 65 72 2d  30 37 37 3a 20 76 61 6c  |-Header-077: val|
00000990: 75 65 5f 37 37 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_77..X-Custom-|
000009a0: 48 65 61 64 65 72 2d 30  37 38 3a 20 76 61 6c 75  |Header-078: valu|
000009b0: 65 5f 37 38 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_78..X-Custom-H|
000009c0: 65 61 64 65 72 2d 30 37  39 3a 20 76 61 6c 75 65  |eader-079: value|
000009d0: 5f 37 39 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_79..X-Custom-He|
000009e0: 61 64 65 72 2d 30 38 30  3a 20 76 61 6c 75 65 5f  |ader-080: value_|
000009f0: 38 30 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |80..X-Custom-Hea|
00000a00: 64 65 72 2d 30 38 31 3a  20 76 61 6c 75 65 5f 38  |der-081: value_8|
00000a10: 31 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |1..X-Custom-Head|
00000a20: 65 72 2d 30 38 32 3a 20  76 61 6c 75 65 5f 38 32  |er-082: value_82|
00000a30: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000a40: 72 2d 30 38 33 3a 20 76  61 6c 75 65 5f 38 33 0d  |r-083: value_83.|
00000a50: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000a60: 2d 30 38 34 3a 20 76 61  6c 75 65 5f 38 34 0d 0a  |-084: value_84..|
00000a70: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
00000a80: 30 38 35 3a 20 76 61 6c  75 65 5f 38 35 0d 0a 58  |085: value_85..X|
00000a90: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
00000aa0: 38 36 3a 20 76 61 6c 75  65 5f 38 36 0d 0a 58 2d  |86: value_86..X-|
00000ab0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 38  |Custom-Header-08|
00000ac0: 37 3a 20 76 61 6c 75 65  5f 38 37 0d 0a 58 2d 43  |7: value_87..X-C|
00000ad0: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 38 38  |ustom-Header-088|
00000ae0: 3a 20 76 61 6c 75 65 5f  38 38 0d 0a 58 2d 43 75  |: value_88..X-Cu|
00000af0: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 38 39 3a  |stom-Header-089:|
00000b00: 20 76 61 6c 75 65 5f 38  39 0d 0a 58 2d 43 75 73  | value_89..X-Cus|
00000b10: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 39 30 3a 20  |tom-Header-090: |
00000b20: 76 61 6c 75 65 5f 39 30  0d 0a 58 2d 43 75 73 74  |value_90..X-Cust|
00000b30: 6f 6d 2d 48 65 61 64 65  72 2d 30 39 31 3a 20 76  |om-Header-091: v|
00000b40: 61 6c 75 65 5f 39 31 0d  0a 58 2d 43 75 73 74 6f  |alue_91..X-Custo|
00000b50: 6d 2d 48 65 61 64 65 72  2d 30 39 32 3a 20 76 61  |m-Header-092: va|
00000b60: 6c 75 65 5f 39 32 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_92..X-Custom|
00000b70: 2d 48 65 61 64 65 72 2d  30 39 33 3a 20 76 61 6c  |-Header-093: val|
00000b80: 75 65 5f 39 33 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_93..X-Custom-|
00000b90: 48 65 61 64 65 72 2d 30  39 34 3a 20 76 61 6c 75  |Header-094: valu|
00000ba0: 65 5f 39 34 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_94..X-Custom-H|
00000bb0: 65 61 64 65 72 2d 30 39  35 3a 20 76 61 6c 75 65  |eader-095: value|
00000bc0: 5f 39 35 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_95..X-Custom-He|
00000bd0: 61 64 65 72 2d 30 39 36  3a 20 76 61 6c 75 65 5f  |ader-096: value_|
00000be0: 39 36 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |96..X-Custom-Hea|
00000bf0: 64 65 72 2d 30 39 37 3a  20 76 61 6c 75 65 5f 39  |der-097: value_9|
00000c00: 37 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |7..X-Custom-Head|
00000c10: 65 72 2d 30 39 38 3a 20  76 61 6c 75 65 5f 39 38  |er-098: value_98|
00000c20: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000c30: 72 2d 30 39 39 3a 20 76  61 6c 75 65 5f 39 39 0d  |r-099: value_99.|
00000c40: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000c50: 2d 31 30 30 3a 20 76 61  6c 75 65 5f 31 30 30 0d  |-100: value_100.|
00000c60: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000c70: 2d 31 30 31 3a 20 76 61  6c 75 65 5f 31 30 31 0d  |-101: value_101.|
00000c80: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000c90: 2d 31 30 32 3a 20 76 61  6c 75 65 5f 31 30 32 0d  |-102: value_102.|
00000ca0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000cb0: 2d 31 30 33 3a 20 76 61  6c 75 65 5f 31 30 33 0d  |-103: value_103.|
00000cc0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000cd0: 2d 31 30 34 3a 20 76 61  6c 75 65 5f 31 30 34 0d  |-104: value_104.|
00000ce0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000cf0: 2d 31 30 35 3a 20 76 61  6c 75 65 5f 31 30 35 0d  |-105: value_105.|
00000d00: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d10: 2d 31 30 36 3a 20 76 61  6c 75 65 5f 31 30 36 0d  |-106: value_106.|
00000d20: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d30: 2d 31 30 37 3a 20 76 61  6c 75 65 5f 31 30 37 0d  |-107: value_107.|
00000d40: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d50: 2d 31 30 38 3a 20 76 61  6c 75 65 5f 31 30 38 0d  |-108: value_108.|
00000d60: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d70: 2d 31 30 39 3a 20 76 61  6c 75 65 5f 31 30 39 0d  |-109: value_109.|
00000d80: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d90: 2d 31 31 30 3a 20 76 61  6c 75 65 5f 31 31 30 0d  |-110: value_110.|
00000da0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000db0: 2d 31 31 31 3a 20 76 61  6c 75 65 5f 31 31 31 0d  |-111: value_111.|
00000dc0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000dd0: 2d 31 31 32 3a 20 76 61  6c 75 65 5f 31 31 32 0d  |-112: value_112.|
00000de0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000df0: 2d 31 31 33 3a 20 76 61  6c 75 65 5f 31 31 33 0d  |-113: value_113.|
00000e00: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e10: 2d 31 31 34 3a 20 76 61  6c 75 65 5f 31 31 34 0d  |-114: value_114.|
00000e20: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e30: 2d 31 31 35 3a 20 76 61  6c 75 65 5f 31 31 35 0d  |-115: value_115.|
00000e40: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e50: 2d 31 31 36 3a 20 76 61  6c 75 65 5f 31 31 36 0d  |-116: value_116.|
00000e60: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e70: 2d 31 31 37 3a 20 76 61  6c 75 65 5f 31 31 37 0d  |-117: value_117.|
00000e80: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e90: 2d 31 31 38 3a 20 76 61  6c 75 65 5f 31 31 38 0d  |-118: value_118.|
00000ea0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000eb0: 2d 31 31 39 3a 20 76 61  6c 75 65 5f 31 31 39 0d  |-119: value_119.|
00000ec0: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `3779 / 3779`
- **Parsed Method:** `GET`
- **Parsed URI:** `/many-headers`
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

### Finding 035: oversized_header_name_300b

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Oversized Headers & Limits
- **Description:** Header name exceeding HTX limit of 255 bytes (302 bytes name).

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6c 6f 6e  67 2d 68 64 72 20 48 54  |GET /long-hdr HT|
00000010: 54 50 2f 31 2e 31 0d 0a  48 6f 73 74 3a 20 65 78  |TP/1.1..Host: ex|
00000020: 61 6d 70 6c 65 2e 63 6f  6d 0d 0a 58 2d 61 61 61  |ample.com..X-aaa|
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
00000150: 61 61 61 61 61 61 61 61  61 3a 20 74 65 73 74 0d  |aaaaaaaaa: test.|
00000160: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `355 / 355`
- **Parsed Method:** `GET`
- **Parsed URI:** `/long-hdr`
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

### Finding 036: mutated_cl_te_rand_0

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (11) vs TE with payload len (14)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 31  |ntent-Length: 11|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 65 0d 0a 30 31 32 33 34  35 36 37 38 39 30 31 32  |e..0123456789012|
00000070: 33 0d 0a 30 0d 0a 0d 0a                           |3..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `120 / 120`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `14 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `19 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 14 bytes, HAProxy: 19 bytes)

---

### Finding 037: mutated_cl_te_rand_1

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (2) vs TE with payload len (7)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 32 0d  |ntent-Length: 2.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 37  |ng: chunked....7|
00000060: 0d 0a 30 31 32 33 34 35  36 0d 0a 30 0d 0a 0d 0a  |..0123456..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `112 / 112`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `7 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `12 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 7 bytes, HAProxy: 12 bytes)

---

### Finding 038: mutated_startline_2

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line DELETE / 

#### Raw Input Hex Dump

```text
00000000: 44 45 4c 45 54 45 20 2f  0d 0d 0a 48 6f 73 74 3a  |DELETE /...Host:|
00000010: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 0d 0a  | example.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `11 / 32`
- **Parsed Method:** `DELETE`
- **Parsed URI:** `/`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 039: mutated_base_3_oversized_header_count_120

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in oversized_header_count_120

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 61 6e  79 2d 68 65 61 64 65 72  |GET /many-header|
00000010: 73 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  |s HTTP/1.1..Host|
00000020: 3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 58  |: example.com..X|
00000030: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
00000040: 30 30 3a 20 76 61 6c 75  65 5f 30 0d 0a 58 2d 43  |00: value_0..X-C|
00000050: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 30 31  |ustom-Header-001|
00000060: 3a 20 76 61 6c 75 65 5f  31 0d 0a 58 2d 43 75 73  |: value_1..X-Cus|
00000070: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 30 32 3a 20  |tom-Header-002: |
00000080: 76 61 6c 75 65 5f 32 0d  0a 58 2d 43 75 73 74 6f  |value_2..X-Custo|
00000090: 6d 2d 48 65 61 64 65 72  2d 30 30 33 3a 20 76 61  |m-Header-003: va|
000000a0: 6c 75 65 5f 33 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |lue_3..X-Custom-|
000000b0: 48 65 61 64 65 72 2d 30  30 34 3a 20 76 61 6c 75  |Header-004: valu|
000000c0: 20 5f 34 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  | _4..X-Custom-He|
000000d0: 61 64 65 72 2d 30 30 35  3a 20 76 61 6c 75 65 5f  |ader-005: value_|
000000e0: 35 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |5..X-Custom-Head|
000000f0: 65 72 2d 30 30 36 3a 20  76 61 6c 75 65 5f 36 0d  |er-006: value_6.|
00000100: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000110: 2d 30 30 37 3a 20 76 61  6c 75 65 5f 37 0d 0a 58  |-007: value_7..X|
00000120: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
00000130: 30 38 3a 20 76 61 6c 75  65 5f 38 0d 0a 58 2d 43  |08: value_8..X-C|
00000140: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 30 39  |ustom-Header-009|
00000150: 3a 20 76 61 6c 75 65 5f  39 0d 0a 58 2d 43 75 73  |: value_9..X-Cus|
00000160: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 31 30 3a 20  |tom-Header-010: |
00000170: 76 61 6c 75 65 5f 31 30  0d 0a 58 2d 43 75 73 74  |value_10..X-Cust|
00000180: 6f 6d 2d 48 65 61 64 65  72 2d 30 31 31 3a 20 76  |om-Header-011: v|
00000190: 61 6c 75 65 5f 31 31 0d  0a 58 2d 43 75 73 74 6f  |alue_11..X-Custo|
000001a0: 6d 2d 48 65 61 64 65 72  2d 30 31 32 3a 20 76 61  |m-Header-012: va|
000001b0: 6c 75 65 5f 31 32 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_12..X-Custom|
000001c0: 2d 48 65 61 64 65 72 2d  30 31 33 3a 20 76 61 6c  |-Header-013: val|
000001d0: 75 65 5f 31 33 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_13..X-Custom-|
000001e0: 48 65 61 64 65 72 2d 30  31 34 3a 20 76 61 6c 75  |Header-014: valu|
000001f0: 65 5f 31 34 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_14..X-Custom-H|
00000200: 65 61 64 65 72 2d 30 31  35 3a 20 76 61 6c 75 65  |eader-015: value|
00000210: 5f 31 35 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_15..X-Custom-He|
00000220: 61 64 65 72 2d 30 31 36  3a 20 76 61 6c 75 65 5f  |ader-016: value_|
00000230: 31 36 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |16..X-Custom-Hea|
00000240: 64 65 72 2d 30 31 37 3a  20 76 61 6c 75 65 5f 31  |der-017: value_1|
00000250: 37 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |7..X-Custom-Head|
00000260: 65 72 2d 30 31 38 3a 20  76 61 6c 75 65 5f 31 38  |er-018: value_18|
00000270: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000280: 72 2d 30 31 39 3a 20 76  61 6c 75 65 5f 31 39 0d  |r-019: value_19.|
00000290: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
000002a0: 2d 30 32 30 3a 20 76 61  6c 75 65 5f 32 30 0d 0a  |-020: value_20..|
000002b0: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
000002c0: 30 32 31 3a 20 76 61 6c  75 65 5f 32 31 0d 0a 58  |021: value_21..X|
000002d0: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
000002e0: 32 32 3a 20 76 61 6c 75  65 5f 32 32 0d 0a 58 2d  |22: value_22..X-|
000002f0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 32  |Custom-Header-02|
00000300: 33 3a 20 76 61 6c 75 65  5f 32 33 0d 0a 58 2d 43  |3: value_23..X-C|
00000310: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 32 34  |ustom-Header-024|
00000320: 3a 20 76 61 6c 75 65 5f  32 34 0d 0a 58 2d 43 75  |: value_24..X-Cu|
00000330: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 32 35 3a  |stom-Header-025:|
00000340: 20 76 61 6c 75 65 5f 32  35 0d 0a 58 2d 43 75 73  | value_25..X-Cus|
00000350: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 32 36 3a 20  |tom-Header-026: |
00000360: 76 61 6c 75 65 5f 32 36  0d 0a 58 2d 43 75 73 74  |value_26..X-Cust|
00000370: 6f 6d 2d 48 65 61 64 65  72 2d 30 32 37 3a 20 76  |om-Header-027: v|
00000380: 61 6c 75 65 5f 32 37 0d  0a 58 2d 43 75 73 74 6f  |alue_27..X-Custo|
00000390: 6d 2d 48 65 61 64 65 72  2d 30 32 38 3a 20 76 61  |m-Header-028: va|
000003a0: 6c 75 65 5f 32 38 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_28..X-Custom|
000003b0: 2d 48 65 61 64 65 72 2d  30 32 39 3a 20 76 61 6c  |-Header-029: val|
000003c0: 75 65 5f 32 39 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_29..X-Custom-|
000003d0: 48 65 61 64 65 72 2d 30  33 30 3a 20 76 61 6c 75  |Header-030: valu|
000003e0: 65 5f 33 30 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_30..X-Custom-H|
000003f0: 65 61 64 65 72 2d 30 33  31 3a 20 76 61 6c 75 65  |eader-031: value|
00000400: 5f 33 31 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_31..X-Custom-He|
00000410: 61 64 65 72 2d 30 33 32  3a 20 76 61 6c 75 65 5f  |ader-032: value_|
00000420: 33 32 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |32..X-Custom-Hea|
00000430: 64 65 72 2d 30 33 33 3a  20 76 61 6c 75 65 5f 33  |der-033: value_3|
00000440: 33 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |3..X-Custom-Head|
00000450: 65 72 2d 30 33 34 3a 20  76 61 6c 75 65 5f 33 34  |er-034: value_34|
00000460: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000470: 72 2d 30 33 35 3a 20 76  61 6c 75 65 5f 33 35 0d  |r-035: value_35.|
00000480: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000490: 2d 30 33 36 3a 20 76 61  6c 75 65 5f 33 36 0d 0a  |-036: value_36..|
000004a0: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
000004b0: 30 33 37 3a 20 76 61 6c  75 65 5f 33 37 0d 0a 58  |037: value_37..X|
000004c0: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
000004d0: 33 38 3a 20 76 61 6c 75  65 5f 33 38 0d 0a 58 2d  |38: value_38..X-|
000004e0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 33  |Custom-Header-03|
000004f0: 39 3a 20 76 61 6c 75 65  5f 33 39 0d 0a 58 2d 43  |9: value_39..X-C|
00000500: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 34 30  |ustom-Header-040|
00000510: 3a 20 76 61 6c 75 65 5f  34 30 0d 0a 58 2d 43 75  |: value_40..X-Cu|
00000520: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 34 31 3a  |stom-Header-041:|
00000530: 20 76 61 6c 75 65 5f 34  31 0d 0a 58 2d 43 75 73  | value_41..X-Cus|
00000540: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 34 32 3a 20  |tom-Header-042: |
00000550: 76 61 6c 75 65 5f 34 32  0d 0a 58 2d 43 75 73 74  |value_42..X-Cust|
00000560: 6f 6d 2d 48 65 61 64 65  72 2d 30 34 33 3a 20 76  |om-Header-043: v|
00000570: 61 6c 75 65 5f 34 33 0d  0a 58 2d 43 75 73 74 6f  |alue_43..X-Custo|
00000580: 6d 2d 48 65 61 64 65 72  2d 30 34 34 3a 20 76 61  |m-Header-044: va|
00000590: 6c 75 65 5f 34 34 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_44..X-Custom|
000005a0: 2d 48 65 61 64 65 72 2d  30 34 35 3a 20 76 61 6c  |-Header-045: val|
000005b0: 75 65 5f 34 35 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_45..X-Custom-|
000005c0: 48 65 61 64 65 72 2d 30  34 36 3a 20 76 61 6c 75  |Header-046: valu|
000005d0: 65 5f 34 36 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_46..X-Custom-H|
000005e0: 65 61 64 65 72 2d 30 34  37 3a 20 76 61 6c 75 65  |eader-047: value|
000005f0: 5f 34 37 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_47..X-Custom-He|
00000600: 61 64 65 72 2d 30 34 38  3a 20 76 61 6c 75 65 5f  |ader-048: value_|
00000610: 34 38 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |48..X-Custom-Hea|
00000620: 64 65 72 2d 30 34 39 3a  20 76 61 6c 75 65 5f 34  |der-049: value_4|
00000630: 39 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |9..X-Custom-Head|
00000640: 65 72 2d 30 35 30 3a 20  76 61 6c 75 65 5f 35 30  |er-050: value_50|
00000650: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000660: 72 2d 30 35 31 3a 20 76  61 6c 75 65 5f 35 31 0d  |r-051: value_51.|
00000670: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000680: 2d 30 35 32 3a 20 76 61  6c 75 65 5f 35 32 0d 0a  |-052: value_52..|
00000690: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
000006a0: 30 35 33 3a 20 76 61 6c  75 65 5f 35 33 0d 0a 58  |053: value_53..X|
000006b0: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
000006c0: 35 34 3a 20 76 61 6c 75  65 5f 35 34 0d 0a 58 2d  |54: value_54..X-|
000006d0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 35  |Custom-Header-05|
000006e0: 35 3a 20 76 61 6c 75 65  5f 35 35 0d 0a 58 2d 43  |5: value_55..X-C|
000006f0: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 35 36  |ustom-Header-056|
00000700: 3a 20 76 61 6c 75 65 5f  35 36 0d 0a 58 2d 43 75  |: value_56..X-Cu|
00000710: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 35 37 3a  |stom-Header-057:|
00000720: 20 76 61 6c 75 65 5f 35  37 0d 0a 58 2d 43 75 73  | value_57..X-Cus|
00000730: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 35 38 3a 20  |tom-Header-058: |
00000740: 76 61 6c 75 65 5f 35 38  0d 0a 58 2d 43 75 73 74  |value_58..X-Cust|
00000750: 6f 6d 2d 48 65 61 64 65  72 2d 30 35 39 3a 20 76  |om-Header-059: v|
00000760: 61 6c 75 65 5f 35 39 0d  0a 58 2d 43 75 73 74 6f  |alue_59..X-Custo|
00000770: 6d 2d 48 65 61 64 65 72  2d 30 36 30 3a 20 76 61  |m-Header-060: va|
00000780: 6c 75 65 5f 36 30 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_60..X-Custom|
00000790: 2d 48 65 61 64 65 72 2d  30 36 31 3a 20 76 61 6c  |-Header-061: val|
000007a0: 75 65 5f 36 31 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_61..X-Custom-|
000007b0: 48 65 61 64 65 72 2d 30  36 32 3a 20 76 61 6c 75  |Header-062: valu|
000007c0: 65 5f 36 32 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_62..X-Custom-H|
000007d0: 65 61 64 65 72 2d 30 36  33 3a 20 76 61 6c 75 65  |eader-063: value|
000007e0: 5f 36 33 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_63..X-Custom-He|
000007f0: 61 64 65 72 2d 30 36 34  3a 20 76 61 6c 75 65 5f  |ader-064: value_|
00000800: 36 34 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |64..X-Custom-Hea|
00000810: 64 65 72 2d 30 36 35 3a  20 76 61 6c 75 65 5f 36  |der-065: value_6|
00000820: 35 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |5..X-Custom-Head|
00000830: 65 72 2d 30 36 36 3a 20  76 61 6c 75 65 5f 36 36  |er-066: value_66|
00000840: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000850: 72 2d 30 36 37 3a 20 76  61 6c 75 65 5f 36 37 0d  |r-067: value_67.|
00000860: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000870: 2d 30 36 38 3a 20 76 61  6c 75 65 5f 36 38 0d 0a  |-068: value_68..|
00000880: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
00000890: 30 36 39 3a 20 76 61 6c  75 65 5f 36 39 0d 0a 58  |069: value_69..X|
000008a0: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
000008b0: 37 30 3a 20 76 61 6c 75  65 5f 37 30 0d 0a 58 2d  |70: value_70..X-|
000008c0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 37  |Custom-Header-07|
000008d0: 31 3a 20 76 61 6c 75 65  5f 37 31 0d 0a 58 2d 43  |1: value_71..X-C|
000008e0: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 37 32  |ustom-Header-072|
000008f0: 3a 20 76 61 6c 75 65 5f  37 32 0d 0a 58 2d 43 75  |: value_72..X-Cu|
00000900: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 37 33 3a  |stom-Header-073:|
00000910: 20 76 61 6c 75 65 5f 37  33 0d 0a 58 2d 43 75 73  | value_73..X-Cus|
00000920: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 37 34 3a 20  |tom-Header-074: |
00000930: 76 61 6c 75 65 5f 37 34  0d 0a 58 2d 43 75 73 74  |value_74..X-Cust|
00000940: 6f 6d 2d 48 65 61 64 65  72 2d 30 37 35 3a 20 76  |om-Header-075: v|
00000950: 61 6c 75 65 5f 37 35 0d  0a 58 2d 43 75 73 74 6f  |alue_75..X-Custo|
00000960: 6d 2d 48 65 61 64 65 72  2d 30 37 36 3a 20 76 61  |m-Header-076: va|
00000970: 6c 75 65 5f 37 36 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_76..X-Custom|
00000980: 2d 48 65 61 64 65 72 2d  30 37 37 3a 20 76 61 6c  |-Header-077: val|
00000990: 75 65 5f 37 37 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_77..X-Custom-|
000009a0: 48 65 61 64 65 72 2d 30  37 38 3a 20 76 61 6c 75  |Header-078: valu|
000009b0: 65 5f 37 38 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_78..X-Custom-H|
000009c0: 65 61 64 65 72 2d 30 37  39 3a 20 76 61 6c 75 65  |eader-079: value|
000009d0: 5f 37 39 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_79..X-Custom-He|
000009e0: 61 64 65 72 2d 30 38 30  3a 20 76 61 6c 75 65 5f  |ader-080: value_|
000009f0: 38 30 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |80..X-Custom-Hea|
00000a00: 64 65 72 2d 30 38 31 3a  20 76 61 6c 75 65 5f 38  |der-081: value_8|
00000a10: 31 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |1..X-Custom-Head|
00000a20: 65 72 2d 30 38 32 3a 20  76 61 6c 75 65 5f 38 32  |er-082: value_82|
00000a30: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000a40: 72 2d 30 38 33 3a 20 76  61 6c 75 65 5f 38 33 0d  |r-083: value_83.|
00000a50: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000a60: 2d 30 38 34 3a 20 76 61  6c 75 65 5f 38 34 0d 0a  |-084: value_84..|
00000a70: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
00000a80: 30 38 35 3a 20 76 61 6c  75 65 5f 38 35 0d 0a 58  |085: value_85..X|
00000a90: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
00000aa0: 38 36 3a 20 76 61 6c 75  65 5f 38 36 0d 0a 58 2d  |86: value_86..X-|
00000ab0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 38  |Custom-Header-08|
00000ac0: 37 3a 20 76 61 6c 75 65  5f 38 37 0d 0a 58 2d 43  |7: value_87..X-C|
00000ad0: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 38 38  |ustom-Header-088|
00000ae0: 3a 20 76 61 6c 75 65 5f  38 38 0d 0a 58 2d 43 75  |: value_88..X-Cu|
00000af0: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 38 39 3a  |stom-Header-089:|
00000b00: 20 76 61 6c 75 65 5f 38  39 0d 0a 58 2d 43 75 73  | value_89..X-Cus|
00000b10: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 39 30 3a 20  |tom-Header-090: |
00000b20: 76 61 6c 75 65 5f 39 30  0d 0a 58 2d 43 75 73 74  |value_90..X-Cust|
00000b30: 6f 6d 2d 48 65 61 64 65  72 2d 30 39 31 3a 20 76  |om-Header-091: v|
00000b40: 61 6c 75 65 5f 39 31 0d  0a 58 2d 43 75 73 74 6f  |alue_91..X-Custo|
00000b50: 6d 2d 48 65 61 64 65 72  2d 30 39 32 3a 20 76 61  |m-Header-092: va|
00000b60: 6c 75 65 5f 39 32 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_92..X-Custom|
00000b70: 2d 48 65 61 64 65 72 2d  30 39 33 3a 20 76 61 6c  |-Header-093: val|
00000b80: 75 65 5f 39 33 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_93..X-Custom-|
00000b90: 48 65 61 64 65 72 2d 30  39 34 3a 20 76 61 6c 75  |Header-094: valu|
00000ba0: 65 5f 39 34 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_94..X-Custom-H|
00000bb0: 65 61 64 65 72 2d 30 39  35 3a 20 76 61 6c 75 65  |eader-095: value|
00000bc0: 5f 39 35 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_95..X-Custom-He|
00000bd0: 61 64 65 72 2d 30 39 36  3a 20 76 61 6c 75 65 5f  |ader-096: value_|
00000be0: 39 36 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |96..X-Custom-Hea|
00000bf0: 64 65 72 2d 30 39 37 3a  20 76 61 6c 75 65 5f 39  |der-097: value_9|
00000c00: 37 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |7..X-Custom-Head|
00000c10: 65 72 2d 30 39 38 3a 20  76 61 6c 75 65 5f 39 38  |er-098: value_98|
00000c20: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000c30: 72 2d 30 39 39 3a 20 76  61 6c 75 65 5f 39 39 0d  |r-099: value_99.|
00000c40: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000c50: 2d 31 30 30 3a 20 76 61  6c 75 65 5f 31 30 30 0d  |-100: value_100.|
00000c60: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000c70: 2d 31 30 31 3a 20 76 61  6c 75 65 5f 31 30 31 0d  |-101: value_101.|
00000c80: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000c90: 2d 31 30 32 3a 20 76 61  6c 75 65 5f 31 30 32 0d  |-102: value_102.|
00000ca0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000cb0: 2d 31 30 33 3a 20 76 61  6c 75 65 5f 31 30 33 0d  |-103: value_103.|
00000cc0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000cd0: 2d 31 30 34 3a 20 76 61  6c 75 65 5f 31 30 34 0d  |-104: value_104.|
00000ce0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000cf0: 2d 31 30 35 3a 20 76 61  6c 75 65 5f 31 30 35 0d  |-105: value_105.|
00000d00: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d10: 2d 31 30 36 3a 20 76 61  6c 75 65 5f 31 30 36 0d  |-106: value_106.|
00000d20: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d30: 2d 31 30 37 3a 20 76 61  6c 75 65 5f 31 30 37 0d  |-107: value_107.|
00000d40: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d50: 2d 31 30 38 3a 20 76 61  6c 75 65 5f 31 30 38 0d  |-108: value_108.|
00000d60: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d70: 2d 31 30 39 3a 20 76 61  6c 75 65 5f 31 30 39 0d  |-109: value_109.|
00000d80: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d90: 2d 31 31 30 3a 20 76 61  6c 75 65 5f 31 31 30 0d  |-110: value_110.|
00000da0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000db0: 2d 31 31 31 3a 20 76 61  6c 75 65 5f 31 31 31 0d  |-111: value_111.|
00000dc0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000dd0: 2d 31 31 32 3a 20 76 61  6c 75 65 5f 31 31 32 0d  |-112: value_112.|
00000de0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000df0: 2d 31 31 33 3a 20 76 61  6c 75 65 5f 31 31 33 0d  |-113: value_113.|
00000e00: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e10: 2d 31 31 34 3a 20 76 61  6c 75 65 5f 31 31 34 0d  |-114: value_114.|
00000e20: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e30: 2d 31 31 35 3a 20 76 61  6c 75 65 5f 31 31 35 0d  |-115: value_115.|
00000e40: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e50: 2d 31 31 36 3a 20 76 61  6c 75 65 5f 31 31 36 0d  |-116: value_116.|
00000e60: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e70: 2d 31 31 37 3a 20 76 61  6c 75 65 5f 31 31 37 0d  |-117: value_117.|
00000e80: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e90: 2d 31 31 38 3a 20 76 61  6c 75 65 5f 31 31 38 0d  |-118: value_118.|
00000ea0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000eb0: 2d 31 31 39 3a 20 76 61  6c 75 65 5f 31 31 39 0d  |-119: value_119.|
00000ec0: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `3779 / 3779`
- **Parsed Method:** `GET`
- **Parsed URI:** `/many-headers`
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

### Finding 040: mutated_pipelined_pair_4

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  34 20 48 54 54 50 2f 31  |GET /p1_4 HTTP/1|
00000010: 2e 31 0d 0a 48 6f 73 74  3a 20 61 2e 63 6f 6d 0d  |.1..Host: a.com.|
00000020: 0a 0d 0a 47 45 54 20 2f  70 32 5f 34 20 48 54 54  |...GET /p2_4 HTT|
00000030: 50 2f 31 2e 31 0d 0a 48  6f 73 74 3a 20 62 2e 63  |P/1.1..Host: b.c|
00000040: 6f 6d 0d 0a 0d 0a                                 |om....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `35 / 70`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_4`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_4`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 041: mutated_base_5_cl_signed_negative

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in cl_signed_negative

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 73 69  67 6e 65 64 2d 6e 65 67  |POST /signed-neg|
00000010: 2d 63 6c 20 48 54 54 50  2f 31 2e 31 0d 0a 48 6f  |-cl HTTP/1.1..Ho|
00000020: 73 74 3a 20 65 78 61 6d  70 6c 65 2e 63 6f 6d 0d  |st: example.com.|
00000030: 0a 43 6f 6e 74 65 6e 74  2d 4c 65 6e 67 74 68 3a  |.Content-Length:|
00000040: 20 2d 35 0d 0a 0d 0a 00  65 6c 6c 6f              | -5.....ello|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `71 / 76`
- **Parsed Method:** `POST`
- **Parsed URI:** `/signed-neg-cl`
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

### Finding 042: mutated_startline_6

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line PROPFIND /api/v1/resource HTTP/9.9

#### Raw Input Hex Dump

```text
00000000: 50 52 4f 50 46 49 4e 44  20 2f 61 70 69 2f 76 31  |PROPFIND /api/v1|
00000010: 2f 72 65 73 6f 75 72 63  65 20 48 54 54 50 2f 39  |/resource HTTP/9|
00000020: 2e 39 0d 0d 0a 48 6f 73  74 3a 20 65 78 61 6d 70  |.9...Host: examp|
00000030: 6c 65 2e 63 6f 6d 0d 0a  0d 0a                    |le.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 58`
- **Parsed Method:** `PROPFIND`
- **Parsed URI:** `/api/v1/resource`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 043: mutated_cl_te_rand_8

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (7) vs TE with payload len (17)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 37 0d  |ntent-Length: 7.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 31  |ng: chunked....1|
00000060: 31 0d 0a 30 31 32 33 34  35 36 37 38 39 30 31 32  |1..0123456789012|
00000070: 33 34 35 36 0d 0a 30 0d  0a 0d 0a                 |3456..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `123 / 123`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `17 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `23 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 17 bytes, HAProxy: 23 bytes)

---

### Finding 044: mutated_headers_ws_9

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 76 61 6c 75 65 5f  |Header-0: value_|
00000040: 30 0d 0a 58 2d 48 65 61  64 65 72 2d 31 20 3a 20  |0..X-Header-1 : |
00000050: 76 61 6c 75 65 5f 31 0d  0a 58 2d 48 65 61 64 65  |value_1..X-Heade|
00000060: 72 2d 32 3a 20 20 76 61  6c 75 65 5f 32 0d 0a 58  |r-2:  value_2..X|
00000070: 2d 48 65 61 64 65 72 2d  33 3a 20 20 76 61 6c 75  |-Header-3:  valu|
00000080: 65 5f 33 0d 0a 58 2d 48  65 61 64 65 72 2d 34 3a  |e_3..X-Header-4:|
00000090: 20 20 76 61 6c 75 65 5f  34 0d 0a 58 2d 48 65 61  |  value_4..X-Hea|
000000a0: 64 65 72 2d 35 3a 20 20  76 61 6c 75 65 5f 35 0d  |der-5:  value_5.|
000000b0: 0a 58 2d 48 65 61 64 65  72 2d 36 3a 20 76 61 6c  |.X-Header-6: val|
000000c0: 75 65 5f 36 0d 0a 0d 0a                           |ue_6....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `200 / 200`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 045: mutated_base_10_cl_te_conflicting_lengths_te_cl_smuggle

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in cl_te_conflicting_lengths_te_cl_smuggle

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 74 72  61 6e 73 66 65 72 20 48  |POST /transfer H|
00000010: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 65  |TTP/1.1..Host: e|
00000020: 78 61 6d 70 6c 65 2e 63  6f 6d 0d 0a 00 6f 6e 74  |xample.com...ont|
00000030: 65 6e 74 2d 4c 65 6e 67  74 68 3a 20 34 0d 0a 54  |ent-Length: 4..T|
00000040: 72 61 6e 73 66 65 72 2d  45 6e 63 6f 64 69 6e 67  |ransfer-Encoding|
00000050: 3a 20 63 68 75 6e 6b 65  64 0d 0a 0d 0a 35 0d 0a  |: chunked....5..|
00000060: 68 65 6c 6c 6f 0d 0a 36  0d 0a 20 77 6f 72 6c 64  |hello..6.. world|
00000070: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `119 / 119`
- **Parsed Method:** `POST`
- **Parsed URI:** `/transfer`
- **Body Length:** `11 bytes`
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

### Finding 046: mutated_startline_11

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line PUT /%20encoded%20 HTTP/1.2

#### Raw Input Hex Dump

```text
00000000: 50 55 54 20 2f 25 32 30  65 6e 63 6f 64 65 64 25  |PUT /%20encoded%|
00000010: 32 30 20 48 54 54 50 2f  31 2e 32 0d 0d 0a 48 6f  |20 HTTP/1.2...Ho|
00000020: 73 74 3a 20 65 78 61 6d  70 6c 65 2e 63 6f 6d 0d  |st: example.com.|
00000030: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `30 / 51`
- **Parsed Method:** `PUT`
- **Parsed URI:** `/%20encoded%20`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 047: mutated_cl_te_rand_13

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (0) vs TE with payload len (12)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 30 0d  |ntent-Length: 0.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 63  |ng: chunked....c|
00000060: 0d 0a 30 31 32 33 34 35  36 37 38 39 30 31 0d 0a  |..012345678901..|
00000070: 30 0d 0a 0d 0a                                    |0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `117 / 117`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `12 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `17 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 12 bytes, HAProxy: 17 bytes)

---

### Finding 048: mutated_cl_te_rand_14

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (13) vs TE with payload len (9)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 33  |ntent-Length: 13|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 39 0d 0a 30 31 32 33 34  35 36 37 38 0d 0a 30 0d  |9..012345678..0.|
00000070: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `115 / 115`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `9 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `14 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 9 bytes, HAProxy: 14 bytes)

---

### Finding 049: mutated_pipelined_pair_15

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 35 20 48 54 54 50 2f  |GET /p1_15 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 31 35 20 48  |....GET /p2_15 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_15`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_15`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 050: mutated_base_16_te_leading_identity

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in te_leading_identity

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 20 65  61 64 69 6e 67 2d 69 64  |POST / eading-id|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 54 72  | example.com..Tr|
00000030: 61 6e 73 66 65 72 2d 45  6e 63 6f 64 69 6e 67 3a  |ansfer-Encoding:|
00000040: 20 69 64 65 6e 74 69 74  79 2c 20 63 68 75 6e 6b  | identity, chunk|
00000050: 65 64 0d 0a 0d 0a 35 0d  0a 68 65 6c 6c 6f 0d 0a  |ed....5..hello..|
00000060: 30 0d 0a 0d 0a                                    |0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `101 / 101`
- **Parsed Method:** `POST`
- **Parsed URI:** `/`
- **Body Length:** `5 bytes`
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

### Finding 051: mutated_headers_ws_17

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  20 3a 20 76 61 6c 75 65  |Header-0 : value|
00000040: 5f 30 0d 0a 58 2d 48 65  61 64 65 72 2d 31 3a 20  |_0..X-Header-1: |
00000050: 76 61 6c 75 65 5f 31 0d  0a 58 2d 48 65 61 64 65  |value_1..X-Heade|
00000060: 72 2d 32 3a 20 76 61 6c  75 65 5f 32 0d 0a 58 2d  |r-2: value_2..X-|
00000070: 48 65 61 64 65 72 2d 33  20 3a 20 76 61 6c 75 65  |Header-3 : value|
00000080: 5f 33 0d 0a 58 2d 48 65  61 64 65 72 2d 34 3a 20  |_3..X-Header-4: |
00000090: 76 61 6c 75 65 5f 34 0d  0a 0d 0a                 |value_4....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `155 / 155`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 052: mutated_pipelined_pair_18

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 38 20 48 54 54 50 2f  |GET /p1_18 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 31 38 20 48  |....GET /p2_18 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_18`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_18`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 053: mutated_base_19_duplicate_cl_conflicting_values

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in duplicate_cl_conflicting_values

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 3a 2f 63 6f  6e 66 6c 69 63 74 2d 63  |POST:/conflict-c|
00000010: 6c 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  |l HTTP/1.1..Host|
00000020: 3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 43  |: example.com..C|
00000030: 6f 6e 74 65 6e 74 2d 4c  65 6e 67 74 68 3a 20 35  |ontent-Length: 5|
00000040: 0d 0a 43 6f 6e 74 65 6e  74 2d 4c 65 6e 67 74 68  |..Content-Length|
00000050: 3a 20 31 30 0d 0a 0d 0a  68 65 6c 6c 6f 77 6f 72  |: 10....hellowor|
00000060: 6c 64                                             |ld|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `93 / 98`
- **Parsed Method:** `POST:/conflict-cl`
- **Parsed URI:** `HTTP/1.1`
- **Body Length:** `5 bytes`
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

### Finding 054: mutated_headers_ws_20

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  20 3a 20 20 76 61 6c 75  |Header-0 :  valu|
00000040: 65 5f 30 0d 0a 58 2d 48  65 61 64 65 72 2d 31 20  |e_0..X-Header-1 |
00000050: 3a 20 76 61 6c 75 65 5f  31 0d 0a 0d 0a           |: value_1....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `93 / 93`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 055: mutated_headers_ws_21

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 20 76 61 6c 75 65  |Header-0:  value|
00000040: 5f 30 0d 0a 58 2d 48 65  61 64 65 72 2d 31 20 3a  |_0..X-Header-1 :|
00000050: 20 20 76 61 6c 75 65 5f  31 0d 0a 58 2d 48 65 61  |  value_1..X-Hea|
00000060: 64 65 72 2d 32 3a 20 76  61 6c 75 65 5f 32 0d 0a  |der-2: value_2..|
00000070: 58 2d 48 65 61 64 65 72  2d 33 20 3a 20 76 61 6c  |X-Header-3 : val|
00000080: 75 65 5f 33 0d 0a 58 2d  48 65 61 64 65 72 2d 34  |ue_3..X-Header-4|
00000090: 3a 20 20 76 61 6c 75 65  5f 34 0d 0a 0d 0a        |:  value_4....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `158 / 158`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 056: mutated_chunked_22

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 1 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 31 30 0d 0a 61  |chunked....10..a|
00000050: 62 63 64 65 66 67 68 69  6a 6b 6c 6d 6e 6f 70 0d  |bcdefghijklmnop.|
00000060: 0a 30 0d 0a 0d 0a                                 |.0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `102 / 102`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `16 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `22 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 16 bytes, HAProxy: 22 bytes)

---

### Finding 057: mutated_chunked_23

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 2 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 43 0d 0a 61 62  |chunked....C..ab|
00000050: 63 64 65 66 67 68 69 6a  6b 6c 0d 0a 35 0d 0a 61  |cdefghijkl..5..a|
00000060: 62 63 64 65 0d 0a 30 0d  0a 0d 0a                 |bcde..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `107 / 107`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `17 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `23 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 17 bytes, HAProxy: 23 bytes)

---

### Finding 058: mutated_pipelined_pair_24

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  32 34 20 48 54 54 50 2f  |GET /p1_24 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 32 34 20 48  |....GET /p2_24 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_24`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_24`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 059: mutated_chunked_25

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 31 0d 0a 61 0d  |chunked....1..a.|
00000050: 0a 32 0d 0a 61 62 0d 0a  61 0d 0a 61 62 63 64 65  |.2..ab..a..abcde|
00000060: 66 67 68 69 6a 0d 0a 37  0d 0a 61 62 63 64 65 66  |fghij..7..abcdef|
00000070: 67 0d 0a 62 0d 0a 61 62  63 64 65 66 67 68 69 6a  |g..b..abcdefghij|
00000080: 6b 0d 0a 30 0d 0a 0d 0a                           |k..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `136 / 136`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `31 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `37 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 31 bytes, HAProxy: 37 bytes)

---

### Finding 060: mutated_cl_te_rand_26

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (5) vs TE with payload len (3)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 35 0d  |ntent-Length: 5.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 33  |ng: chunked....3|
00000060: 0d 0a 30 31 32 0d 0a 30  0d 0a 0d 0a              |..012..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `108 / 108`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `3 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `8 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 3 bytes, HAProxy: 8 bytes)

---

### Finding 061: mutated_headers_ws_27

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  20 3a 20 20 76 61 6c 75  |Header-0 :  valu|
00000040: 65 5f 30 0d 0a 58 2d 48  65 61 64 65 72 2d 31 3a  |e_0..X-Header-1:|
00000050: 20 20 76 61 6c 75 65 5f  31 0d 0a 58 2d 48 65 61  |  value_1..X-Hea|
00000060: 64 65 72 2d 32 3a 20 20  76 61 6c 75 65 5f 32 0d  |der-2:  value_2.|
00000070: 0a 58 2d 48 65 61 64 65  72 2d 33 3a 20 76 61 6c  |.X-Header-3: val|
00000080: 75 65 5f 33 0d 0a 58 2d  48 65 61 64 65 72 2d 34  |ue_3..X-Header-4|
00000090: 3a 20 76 61 6c 75 65 5f  34 0d 0a 58 2d 48 65 61  |: value_4..X-Hea|
000000a0: 64 65 72 2d 35 20 3a 20  20 76 61 6c 75 65 5f 35  |der-5 :  value_5|
000000b0: 0d 0a 0d 0a                                       |....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `180 / 180`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 062: mutated_startline_28

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line GET /%20encoded%20 

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 25 32 30  65 6e 63 6f 64 65 64 25  |GET /%20encoded%|
00000010: 32 30 0d 0d 0a 48 6f 73  74 3a 20 65 78 61 6d 70  |20...Host: examp|
00000020: 6c 65 2e 63 6f 6d 0d 0a  0d 0a                    |le.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `21 / 42`
- **Parsed Method:** `GET`
- **Parsed URI:** `/%20encoded%20`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 063: mutated_headers_ws_29

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 76 61 6c 75 65 5f  |Header-0: value_|
00000040: 30 0d 0a 58 2d 48 65 61  64 65 72 2d 31 3a 20 76  |0..X-Header-1: v|
00000050: 61 6c 75 65 5f 31 0d 0a  58 2d 48 65 61 64 65 72  |alue_1..X-Header|
00000060: 2d 32 3a 20 20 76 61 6c  75 65 5f 32 0d 0a 58 2d  |-2:  value_2..X-|
00000070: 48 65 61 64 65 72 2d 33  20 3a 20 76 61 6c 75 65  |Header-3 : value|
00000080: 5f 33 0d 0a 0d 0a                                 |_3....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `134 / 134`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 064: mutated_chunked_31

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 38 0d 0a 61 62  |chunked....8..ab|
00000050: 63 64 65 66 67 68 0d 0a  32 0d 0a 61 62 0d 0a 61  |cdefgh..2..ab..a|
00000060: 0d 0a 61 62 63 64 65 66  67 68 69 6a 0d 0a 36 0d  |..abcdefghij..6.|
00000070: 0a 61 62 63 64 65 66 0d  0a 42 0d 0a 61 62 63 64  |.abcdef..B..abcd|
00000080: 65 66 67 68 69 6a 6b 0d  0a 30 0d 0a 0d 0a        |efghijk..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `142 / 142`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `37 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `43 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 37 bytes, HAProxy: 43 bytes)

---

### Finding 065: mutated_cl_te_rand_32

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (1) vs TE with payload len (16)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 0d  |ntent-Length: 1.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 31  |ng: chunked....1|
00000060: 30 0d 0a 30 31 32 33 34  35 36 37 38 39 30 31 32  |0..0123456789012|
00000070: 33 34 35 0d 0a 30 0d 0a  0d 0a                    |345..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `122 / 122`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `16 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `22 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 16 bytes, HAProxy: 22 bytes)

---

### Finding 066: mutated_pipelined_pair_34

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  33 34 20 48 54 54 50 2f  |GET /p1_34 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 33 34 20 48  |....GET /p2_34 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_34`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_34`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 067: mutated_pipelined_pair_37

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  33 37 20 48 54 54 50 2f  |GET /p1_37 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 33 37 20 48  |....GET /p2_37 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_37`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_37`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 068: mutated_pipelined_pair_40

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  34 30 20 48 54 54 50 2f  |GET /p1_40 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 34 30 20 48  |....GET /p2_40 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_40`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_40`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 069: mutated_headers_ws_42

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  20 3a 20 20 76 61 6c 75  |Header-0 :  valu|
00000040: 65 5f 30 0d 0a 58 2d 48  65 61 64 65 72 2d 31 3a  |e_0..X-Header-1:|
00000050: 20 76 61 6c 75 65 5f 31  0d 0a 58 2d 48 65 61 64  | value_1..X-Head|
00000060: 65 72 2d 32 3a 20 20 76  61 6c 75 65 5f 32 0d 0a  |er-2:  value_2..|
00000070: 0d 0a                                             |..|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `114 / 114`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 070: mutated_headers_ws_43

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  20 3a 20 76 61 6c 75 65  |Header-0 : value|
00000040: 5f 30 0d 0a 58 2d 48 65  61 64 65 72 2d 31 20 3a  |_0..X-Header-1 :|
00000050: 20 76 61 6c 75 65 5f 31  0d 0a 58 2d 48 65 61 64  | value_1..X-Head|
00000060: 65 72 2d 32 3a 20 20 76  61 6c 75 65 5f 32 0d 0a  |er-2:  value_2..|
00000070: 58 2d 48 65 61 64 65 72  2d 33 3a 20 20 76 61 6c  |X-Header-3:  val|
00000080: 75 65 5f 33 0d 0a 58 2d  48 65 61 64 65 72 2d 34  |ue_3..X-Header-4|
00000090: 3a 20 76 61 6c 75 65 5f  34 0d 0a 0d 0a           |: value_4....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `157 / 157`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 071: mutated_pipelined_pair_44

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  34 34 20 48 54 54 50 2f  |GET /p1_44 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 34 34 20 48  |....GET /p2_44 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_44`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_44`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 072: mutated_headers_ws_45

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 20 76 61 6c 75 65  |Header-0:  value|
00000040: 5f 30 0d 0a 58 2d 48 65  61 64 65 72 2d 31 20 3a  |_0..X-Header-1 :|
00000050: 20 76 61 6c 75 65 5f 31  0d 0a 58 2d 48 65 61 64  | value_1..X-Head|
00000060: 65 72 2d 32 3a 20 20 76  61 6c 75 65 5f 32 0d 0a  |er-2:  value_2..|
00000070: 58 2d 48 65 61 64 65 72  2d 33 3a 20 20 76 61 6c  |X-Header-3:  val|
00000080: 75 65 5f 33 0d 0a 58 2d  48 65 61 64 65 72 2d 34  |ue_3..X-Header-4|
00000090: 20 3a 20 20 76 61 6c 75  65 5f 34 0d 0a 58 2d 48  | :  value_4..X-H|
000000a0: 65 61 64 65 72 2d 35 20  3a 20 76 61 6c 75 65 5f  |eader-5 : value_|
000000b0: 35 0d 0a 0d 0a                                    |5....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `181 / 181`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 073: mutated_chunked_47

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 31 0d 0a 61 0d  |chunked....1..a.|
00000050: 0a 34 0d 0a 61 62 63 64  0d 0a 39 0d 0a 61 62 63  |.4..abcd..9..abc|
00000060: 64 65 66 67 68 69 0d 0a  34 0d 0a 61 62 63 64 0d  |defghi..4..abcd.|
00000070: 0a 32 0d 0a 61 62 0d 0a  30 0d 0a 0d 0a           |.2..ab..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `125 / 125`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `20 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `26 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 20 bytes, HAProxy: 26 bytes)

---

### Finding 074: mutated_cl_te_rand_49

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (0) vs TE with payload len (5)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 30 0d  |ntent-Length: 0.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 35  |ng: chunked....5|
00000060: 0d 0a 30 31 32 33 34 0d  0a 30 0d 0a 0d 0a        |..01234..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `110 / 110`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 075: mutated_base_50_chunk_signed_plus

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in chunk_signed_plus

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 68  75 6e 6b 2d 70 6c 75 73  |POST /chunk-plus|
00000010: 20 48 54 54 50 2f 31 2e  3a 0d 0a 48 6f 73 74 3a  | HTTP/1.:..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 54 72  | example.com..Tr|
00000030: 61 6e 73 66 65 72 2d 45  6e 63 6f 64 69 6e 67 3a  |ansfer-Encoding:|
00000040: 20 63 68 75 6e 6b 65 64  0d 0a 0d 0a 2b 35 0d 0a  | chunked....+5..|
00000050: 68 65 6c 6c 6f 0d 0a 30  0d 0a 0d 0a              |hello..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `92 / 92`
- **Parsed Method:** `POST`
- **Parsed URI:** `/chunk-plus`
- **Body Length:** `5 bytes`
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

### Finding 076: mutated_cl_te_rand_51

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (16) vs TE with payload len (17)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 36  |ntent-Length: 16|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 31 31 0d 0a 30 31 32 33  34 35 36 37 38 39 30 31  |11..012345678901|
00000070: 32 33 34 35 36 0d 0a 30  0d 0a 0d 0a              |23456..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `124 / 124`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `17 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `23 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 17 bytes, HAProxy: 23 bytes)

---

### Finding 077: mutated_startline_52

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line POST / HTTP/0.9

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 20 48  54 54 50 2f 30 2e 39 0d  |POST / HTTP/0.9.|
00000010: 0d 0a 48 6f 73 74 3a 20  65 78 61 6d 70 6c 65 2e  |..Host: example.|
00000020: 63 6f 6d 0d 0a 0d 0a                              |com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `18 / 39`
- **Parsed Method:** `POST`
- **Parsed URI:** `/`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 078: mutated_startline_53

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line PUT /index.html HTTP/1.1

#### Raw Input Hex Dump

```text
00000000: 50 55 54 20 2f 69 6e 64  65 78 2e 68 74 6d 6c 20  |PUT /index.html |
00000010: 48 54 54 50 2f 31 2e 31  0d 0d 0a 48 6f 73 74 3a  |HTTP/1.1...Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 0d 0a  | example.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `27 / 48`
- **Parsed Method:** `PUT`
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

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 079: mutated_chunked_54

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 2 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 46 0d 0a 61 62  |chunked....F..ab|
00000050: 63 64 65 66 67 68 69 6a  6b 6c 6d 6e 6f 0d 0a 66  |cdefghijklmno..f|
00000060: 0d 0a 61 62 63 64 65 66  67 68 69 6a 6b 6c 6d 6e  |..abcdefghijklmn|
00000070: 6f 0d 0a 30 0d 0a 0d 0a                           |o..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `120 / 120`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `30 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `36 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 30 bytes, HAProxy: 36 bytes)

---

### Finding 080: mutated_chunked_55

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 2 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 32 0d 0a 61 62  |chunked....2..ab|
00000050: 0d 0a 46 0d 0a 61 62 63  64 65 66 67 68 69 6a 6b  |..F..abcdefghijk|
00000060: 6c 6d 6e 6f 0d 0a 30 0d  0a 0d 0a                 |lmno..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `107 / 107`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `17 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `23 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 17 bytes, HAProxy: 23 bytes)

---

### Finding 081: mutated_chunked_56

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 3 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 31 30 0d 0a 61  |chunked....10..a|
00000050: 62 63 64 65 66 67 68 69  6a 6b 6c 6d 6e 6f 70 0d  |bcdefghijklmnop.|
00000060: 0a 43 0d 0a 61 62 63 64  65 66 67 68 69 6a 6b 6c  |.C..abcdefghijkl|
00000070: 0d 0a 45 0d 0a 61 62 63  64 65 66 67 68 69 6a 6b  |..E..abcdefghijk|
00000080: 6c 6d 6e 0d 0a 30 0d 0a  0d 0a                    |lmn..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `138 / 138`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `42 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `48 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 42 bytes, HAProxy: 48 bytes)

---

### Finding 082: mutated_cl_te_rand_57

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (6) vs TE with payload len (2)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 36 0d  |ntent-Length: 6.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 32  |ng: chunked....2|
00000060: 0d 0a 30 31 0d 0a 30 0d  0a 0d 0a                 |..01..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `107 / 107`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `2 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `7 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 2 bytes, HAProxy: 7 bytes)

---

### Finding 083: mutated_chunked_59

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 2 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 45 0d 0a 61 62  |chunked....E..ab|
00000050: 63 64 65 66 67 68 69 6a  6b 6c 6d 6e 0d 0a 32 0d  |cdefghijklmn..2.|
00000060: 0a 61 62 0d 0a 30 0d 0a  0d 0a                    |.ab..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `106 / 106`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `16 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `22 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 16 bytes, HAProxy: 22 bytes)

---

### Finding 084: mutated_chunked_61

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 34 0d 0a 61 62  |chunked....4..ab|
00000050: 63 64 0d 0a 34 0d 0a 61  62 63 64 0d 0a 32 0d 0a  |cd..4..abcd..2..|
00000060: 61 62 0d 0a 64 0d 0a 61  62 63 64 65 66 67 68 69  |ab..d..abcdefghi|
00000070: 6a 6b 6c 6d 0d 0a 37 0d  0a 61 62 63 64 65 66 67  |jklm..7..abcdefg|
00000080: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `135 / 135`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `30 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `36 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 30 bytes, HAProxy: 36 bytes)

---

### Finding 085: mutated_base_62_te_tab_whitespace

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in te_tab_whitespace

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 74 65  2d 74 61 62 20 48 54 54  |POST /te-tab HTT|
00000010: 50 2f 31 2e 31 0d 0a 48  6f 73 74 3a 20 65 78 61  |P/1.1..Host: exa|
00000020: 6d 70 6c 65 2e 63 6f 6d  0d 0a 54 72 61 6e 73 66  |mple.com..Transf|
00000030: 65 72 2d 45 6e 63 6f 64  69 6e 67 3a 09 63 68 75  |er-Encoding:.chu|
00000040: 6e 6b 65 64 0d 0a 0d 0a  35 0d 0a 68 65 6c 6c 20  |nked....5..hell |
00000050: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `87 / 87`
- **Parsed Method:** `POST`
- **Parsed URI:** `/te-tab`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/te-tab`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 086: mutated_pipelined_pair_63

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  36 33 20 48 54 54 50 2f  |GET /p1_63 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 36 33 20 48  |....GET /p2_63 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_63`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_63`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 087: mutated_pipelined_pair_64

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  36 34 20 48 54 54 50 2f  |GET /p1_64 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 36 34 20 48  |....GET /p2_64 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_64`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_64`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 088: mutated_cl_te_rand_65

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (1) vs TE with payload len (4)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 0d  |ntent-Length: 1.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 34  |ng: chunked....4|
00000060: 0d 0a 30 31 32 33 0d 0a  30 0d 0a 0d 0a           |..0123..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `109 / 109`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `4 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `9 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 4 bytes, HAProxy: 9 bytes)

---

### Finding 089: mutated_chunked_66

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 4 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 36 0d 0a 61 62  |chunked....6..ab|
00000050: 63 64 65 66 0d 0a 31 0d  0a 61 0d 0a 43 0d 0a 61  |cdef..1..a..C..a|
00000060: 62 63 64 65 66 67 68 69  6a 6b 6c 0d 0a 33 0d 0a  |bcdefghijkl..3..|
00000070: 61 62 63 0d 0a 30 0d 0a  0d 0a                    |abc..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `122 / 122`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `22 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `28 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 22 bytes, HAProxy: 28 bytes)

---

### Finding 090: mutated_headers_ws_67

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 20 76 61 6c 75 65  |Header-0:  value|
00000040: 5f 30 0d 0a 58 2d 48 65  61 64 65 72 2d 31 20 3a  |_0..X-Header-1 :|
00000050: 20 20 76 61 6c 75 65 5f  31 0d 0a 0d 0a           |  value_1....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `93 / 93`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 091: mutated_headers_ws_68

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 76 61 6c 75 65 5f  |Header-0: value_|
00000040: 30 0d 0a 58 2d 48 65 61  64 65 72 2d 31 20 3a 20  |0..X-Header-1 : |
00000050: 20 76 61 6c 75 65 5f 31  0d 0a 58 2d 48 65 61 64  | value_1..X-Head|
00000060: 65 72 2d 32 3a 20 76 61  6c 75 65 5f 32 0d 0a 0d  |er-2: value_2...|
00000070: 0a                                                |.|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `113 / 113`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 092: mutated_startline_69

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line GET /api/v1/resource HTTP/1.2

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 61 70 69  2f 76 31 2f 72 65 73 6f  |GET /api/v1/reso|
00000010: 75 72 63 65 20 48 54 54  50 2f 31 2e 32 0d 0d 0a  |urce HTTP/1.2...|
00000020: 48 6f 73 74 3a 20 65 78  61 6d 70 6c 65 2e 63 6f  |Host: example.co|
00000030: 6d 0d 0a 0d 0a                                    |m....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `32 / 53`
- **Parsed Method:** `GET`
- **Parsed URI:** `/api/v1/resource`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 093: mutated_chunked_70

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 4 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 35 0d 0a 61 62  |chunked....5..ab|
00000050: 63 64 65 0d 0a 42 0d 0a  61 62 63 64 65 66 67 68  |cde..B..abcdefgh|
00000060: 69 6a 6b 0d 0a 64 0d 0a  61 62 63 64 65 66 67 68  |ijk..d..abcdefgh|
00000070: 69 6a 6b 6c 6d 0d 0a 36  0d 0a 61 62 63 64 65 66  |ijklm..6..abcdef|
00000080: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `135 / 135`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `35 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `41 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 35 bytes, HAProxy: 41 bytes)

---

### Finding 094: mutated_base_71_chunk_extension_quoted_semicolon

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in chunk_extension_quoted_semicolon

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 68  75 6e 6b 2d 71 75 6f 74  |POST /chunk-quot|
00000010: 65 64 20 48 54 54 50 2f  31 2e 31 0d 0a 48 6f 73  |ed HTTP/1.1..Hos|
00000020: 74 3a 20 65 78 61 6d 70  6c 65 2e 63 6f 6d 0d 0a  |t: example.com..|
00000030: 54 72 61 6e 73 66 65 72  2d 45 6e 63 6f 64 69 6e  |Transfer-Encodin|
00000040: 67 3a 20 63 68 75 6e 6b  65 64 0d 0a 0d 0a 35 3b  |g: chunked....5;|
00000050: 65 78 74 3d 22 71 75 6f  74 65 64 3b 77 69 74 68  |ext="quoted;with|
00000060: 3b 73 65 6d 69 73 22 0d  0a 68 65 6c 6c 20 0d 0a  |;semis"..hell ..|
00000070: 30 0d 0a 0d 0a                                    |0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `117 / 117`
- **Parsed Method:** `POST`
- **Parsed URI:** `/chunk-quoted`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/chunk-quoted`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 095: mutated_chunked_73

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 4 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 38 0d 0a 61 62  |chunked....8..ab|
00000050: 63 64 65 66 67 68 0d 0a  31 0d 0a 61 0d 0a 38 0d  |cdefgh..1..a..8.|
00000060: 0a 61 62 63 64 65 66 67  68 0d 0a 46 0d 0a 61 62  |.abcdefgh..F..ab|
00000070: 63 64 65 66 67 68 69 6a  6b 6c 6d 6e 6f 0d 0a 30  |cdefghijklmno..0|
00000080: 0d 0a 0d 0a                                       |....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `132 / 132`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `32 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `38 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 32 bytes, HAProxy: 38 bytes)

---

### Finding 096: mutated_headers_ws_74

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 76 61 6c 75 65 5f  |Header-0: value_|
00000040: 30 0d 0a 58 2d 48 65 61  64 65 72 2d 31 20 3a 20  |0..X-Header-1 : |
00000050: 20 76 61 6c 75 65 5f 31  0d 0a 58 2d 48 65 61 64  | value_1..X-Head|
00000060: 65 72 2d 32 3a 20 76 61  6c 75 65 5f 32 0d 0a 58  |er-2: value_2..X|
00000070: 2d 48 65 61 64 65 72 2d  33 20 3a 20 76 61 6c 75  |-Header-3 : valu|
00000080: 65 5f 33 0d 0a 58 2d 48  65 61 64 65 72 2d 34 20  |e_3..X-Header-4 |
00000090: 3a 20 76 61 6c 75 65 5f  34 0d 0a 0d 0a           |: value_4....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `157 / 157`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 097: mutated_chunked_75

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 4 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 66 0d 0a 61 62  |chunked....f..ab|
00000050: 63 64 65 66 67 68 69 6a  6b 6c 6d 6e 6f 0d 0a 44  |cdefghijklmno..D|
00000060: 0d 0a 61 62 63 64 65 66  67 68 69 6a 6b 6c 6d 0d  |..abcdefghijklm.|
00000070: 0a 62 0d 0a 61 62 63 64  65 66 67 68 69 6a 6b 0d  |.b..abcdefghijk.|
00000080: 0a 37 0d 0a 61 62 63 64  65 66 67 0d 0a 30 0d 0a  |.7..abcdefg..0..|
00000090: 0d 0a                                             |..|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `146 / 146`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `46 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `52 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 46 bytes, HAProxy: 52 bytes)

---

### Finding 098: mutated_base_76_oversized_uri_4k

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

### Finding 099: mutated_pipelined_pair_78

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  37 38 20 48 54 54 50 2f  |GET /p1_78 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 37 38 20 48  |....GET /p2_78 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_78`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_78`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 100: mutated_chunked_79

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 4 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 36 0d 0a 61 62  |chunked....6..ab|
00000050: 63 64 65 66 0d 0a 66 0d  0a 61 62 63 64 65 66 67  |cdef..f..abcdefg|
00000060: 68 69 6a 6b 6c 6d 6e 6f  0d 0a 31 0d 0a 61 0d 0a  |hijklmno..1..a..|
00000070: 31 0d 0a 61 0d 0a 30 0d  0a 0d 0a                 |1..a..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `123 / 123`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `23 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `29 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 23 bytes, HAProxy: 29 bytes)

---

### Finding 101: mutated_cl_te_rand_80

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (11) vs TE with payload len (11)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 31  |ntent-Length: 11|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 62 0d 0a 30 31 32 33 34  35 36 37 38 39 30 0d 0a  |b..01234567890..|
00000070: 30 0d 0a 0d 0a                                    |0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `117 / 117`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `11 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `16 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 11 bytes, HAProxy: 16 bytes)

---

### Finding 102: mutated_cl_te_rand_81

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (10) vs TE with payload len (15)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 30  |ntent-Length: 10|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 66 0d 0a 30 31 32 33 34  35 36 37 38 39 30 31 32  |f..0123456789012|
00000070: 33 34 0d 0a 30 0d 0a 0d  0a                       |34..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `121 / 121`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `15 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `20 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 15 bytes, HAProxy: 20 bytes)

---

### Finding 103: mutated_startline_82

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line INVALID_METHOD / bad HTTP/9.9

#### Raw Input Hex Dump

```text
00000000: 49 4e 56 41 4c 49 44 5f  4d 45 54 48 4f 44 20 2f  |INVALID_METHOD /|
00000010: 00 62 61 64 20 48 54 54  50 2f 39 2e 39 0d 0d 0a  |.bad HTTP/9.9...|
00000020: 48 6f 73 74 3a 20 65 78  61 6d 70 6c 65 2e 63 6f  |Host: example.co|
00000030: 6d 0d 0a 0d 0a                                    |m....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `32 / 53`
- **Parsed Method:** `INVALID_METHOD`
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

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 104: mutated_chunked_83

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 3 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 32 0d 0a 61 62  |chunked....2..ab|
00000050: 0d 0a 31 0d 0a 61 0d 0a  65 0d 0a 61 62 63 64 65  |..1..a..e..abcde|
00000060: 66 67 68 69 6a 6b 6c 6d  6e 0d 0a 30 0d 0a 0d 0a  |fghijklmn..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `112 / 112`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `17 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `23 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 17 bytes, HAProxy: 23 bytes)

---

### Finding 105: mutated_cl_te_rand_84

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (14) vs TE with payload len (3)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 34  |ntent-Length: 14|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 33 0d 0a 30 31 32 0d 0a  30 0d 0a 0d 0a           |3..012..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `109 / 109`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `3 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `8 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 3 bytes, HAProxy: 8 bytes)

---

### Finding 106: mutated_cl_te_rand_85

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (13) vs TE with payload len (5)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 33  |ntent-Length: 13|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 35 0d 0a 30 31 32 33 34  0d 0a 30 0d 0a 0d 0a     |5..01234..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `111 / 111`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 107: mutated_pipelined_pair_86

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  38 36 20 48 54 54 50 2f  |GET /p1_86 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 38 36 20 48  |....GET /p2_86 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_86`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_86`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 108: mutated_startline_87

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line DELETE /index.html HTTP/2.0

#### Raw Input Hex Dump

```text
00000000: 44 45 4c 45 54 45 20 2f  69 6e 64 65 78 2e 68 74  |DELETE /index.ht|
00000010: 6d 6c 20 48 54 54 50 2f  32 2e 30 0d 48 6f 73 74  |ml HTTP/2.0.Host|
00000020: 3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 0d  |: example.com...|
00000030: 0a                                                |.|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `49 / 49`
- **Parsed Method:** `DELETE`
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

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 109: mutated_base_88_te_prefix_unknown_encoding

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in te_prefix_unknown_encoding

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 74 65  2d 75 6e 6b 6e 6f 77 6e  |POST /te-unknown|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 54 72  | example.com..Tr|
00000030: 61 6e 73 66 65 72 2d 45  6e 63 6f 64 69 6e 67 3a  |ansfer-Encoding:|
00000040: 20 6e 6f 74 00 63 68 75  6e 6b 65 64 0d 0a 0d 0a  | not.chunked....|
00000050: 35 0d 0a 68 65 6c 6c 6f  0d 0a 30 0d 0a 0d 0a     |5..hello..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `95 / 95`
- **Parsed Method:** `POST`
- **Parsed URI:** `/te-unknown`
- **Body Length:** `5 bytes`
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

### Finding 110: mutated_pipelined_pair_89

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  38 39 20 48 54 54 50 2f  |GET /p1_89 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 38 39 20 48  |....GET /p2_89 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_89`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_89`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 111: mutated_chunked_90

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 1 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 64 0d 0a 61 62  |chunked....d..ab|
00000050: 63 64 65 66 67 68 69 6a  6b 6c 6d 0d 0a 30 0d 0a  |cdefghijklm..0..|
00000060: 0d 0a                                             |..|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `98 / 98`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `13 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `18 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 13 bytes, HAProxy: 18 bytes)

---

### Finding 112: mutated_cl_te_rand_91

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (6) vs TE with payload len (9)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 36 0d  |ntent-Length: 6.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 39  |ng: chunked....9|
00000060: 0d 0a 30 31 32 33 34 35  36 37 38 0d 0a 30 0d 0a  |..012345678..0..|
00000070: 0d 0a                                             |..|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `114 / 114`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `9 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `14 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 9 bytes, HAProxy: 14 bytes)

---

### Finding 113: mutated_cl_te_rand_92

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (7) vs TE with payload len (16)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 37 0d  |ntent-Length: 7.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 31  |ng: chunked....1|
00000060: 30 0d 0a 30 31 32 33 34  35 36 37 38 39 30 31 32  |0..0123456789012|
00000070: 33 34 35 0d 0a 30 0d 0a  0d 0a                    |345..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `122 / 122`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `16 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `22 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 16 bytes, HAProxy: 22 bytes)

---

### Finding 114: mutated_pipelined_pair_93

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  39 33 20 48 54 54 50 2f  |GET /p1_93 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 39 33 20 48  |....GET /p2_93 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_93`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_93`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 115: mutated_pipelined_pair_94

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  39 34 20 48 54 54 50 2f  |GET /p1_94 HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 61 2e 63 6f 6d  |1.1..Host: a.com|
00000020: 0d 0a 0d 0a 47 45 54 20  2f 70 32 5f 39 34 20 48  |....GET /p2_94 H|
00000030: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 62  |TTP/1.1..Host: b|
00000040: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `36 / 72`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_94`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_94`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 116: mutated_startline_95

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line PUT / bad HTTP/1.2

#### Raw Input Hex Dump

```text
00000000: 50 55 54 20 2f 00 62 61  64 20 48 54 54 50 2f 31  |PUT /.bad HTTP/1|
00000010: 2e 32 0d 0d 0a 48 6f 73  74 3a 20 65 78 61 6d 70  |.2...Host: examp|
00000020: 6c 65 2e 63 6f 6d 0d 0a  0d 0a                    |le.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `21 / 42`
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

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 117: mutated_cl_te_rand_98

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (2) vs TE with payload len (6)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 32 0d  |ntent-Length: 2.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 36  |ng: chunked....6|
00000060: 0d 0a 30 31 32 33 34 35  0d 0a 30 0d 0a 0d 0a     |..012345..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `111 / 111`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `6 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `11 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 6 bytes, HAProxy: 11 bytes)

---

### Finding 118: mutated_chunked_99

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 33 0d 0a 61 62  |chunked....3..ab|
00000050: 63 0d 0a 31 30 0d 0a 61  62 63 64 65 66 67 68 69  |c..10..abcdefghi|
00000060: 6a 6b 6c 6d 6e 6f 70 0d  0a 63 0d 0a 61 62 63 64  |jklmnop..c..abcd|
00000070: 65 66 67 68 69 6a 6b 6c  0d 0a 32 0d 0a 61 62 0d  |efghijkl..2..ab.|
00000080: 0a 31 0d 0a 61 0d 0a 30  0d 0a 0d 0a              |.1..a..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `140 / 140`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `34 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `40 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 34 bytes, HAProxy: 40 bytes)

---

### Finding 119: mutated_chunked_100

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 3 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 31 30 0d 0a 61  |chunked....10..a|
00000050: 62 63 64 65 66 67 68 69  6a 6b 6c 6d 6e 6f 70 0d  |bcdefghijklmnop.|
00000060: 0a 38 0d 0a 61 62 63 64  65 66 67 68 0d 0a 31 30  |.8..abcdefgh..10|
00000070: 0d 0a 61 62 63 64 65 66  67 68 69 6a 6b 6c 6d 6e  |..abcdefghijklmn|
00000080: 6f 70 0d 0a 30 0d 0a 0d  0a                       |op..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `137 / 137`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `40 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `46 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 40 bytes, HAProxy: 46 bytes)

---

### Finding 120: mutated_cl_te_rand_101

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (15) vs TE with payload len (1)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 35  |ntent-Length: 15|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 31 0d 0a 30 0d 0a 30 0d  0a 0d 0a                 |1..0..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `107 / 107`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `1 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `6 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 1 bytes, HAProxy: 6 bytes)

---

### Finding 121: mutated_base_102_line_term_lf_only

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in line_term_lf_only

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6c 66 2d  6f 6e 6c 79 20 48 54 54  |GET /lf-only HTT|
00000010: 50 2f 31 2e 31 0a 48 6f  73 74 3a 20 65 78 61 6d  |P/1.1.Host: exam|
00000020: 70 6c 65 2e 63 6f 6d 0a  58 2d 48 65 61 64 20 72  |ple.com.X-Head r|
00000030: 3a 20 76 61 6c 75 65 0a  0a                       |: value..|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `57 / 57`
- **Parsed Method:** `GET`
- **Parsed URI:** `/lf-only`
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

### Finding 122: mutated_pipelined_pair_103

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 30 33 20 48 54 54 50  |GET /p1_103 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 30 33  |m....GET /p2_103|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_103`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_103`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 123: mutated_pipelined_pair_104

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 30 34 20 48 54 54 50  |GET /p1_104 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 30 34  |m....GET /p2_104|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_104`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_104`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 124: mutated_headers_ws_105

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  20 3a 20 20 76 61 6c 75  |Header-0 :  valu|
00000040: 65 5f 30 0d 0a 58 2d 48  65 61 64 65 72 2d 31 20  |e_0..X-Header-1 |
00000050: 3a 20 76 61 6c 75 65 5f  31 0d 0a 0d 0a           |: value_1....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `93 / 93`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 125: mutated_cl_te_rand_106

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (7) vs TE with payload len (15)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 37 0d  |ntent-Length: 7.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 66  |ng: chunked....f|
00000060: 0d 0a 30 31 32 33 34 35  36 37 38 39 30 31 32 33  |..01234567890123|
00000070: 34 0d 0a 30 0d 0a 0d 0a                           |4..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `120 / 120`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `15 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `20 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 15 bytes, HAProxy: 20 bytes)

---

### Finding 126: mutated_base_107_line_term_doubled_crlf_before_headers

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
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

Ibex: accepted=true, phase="Done", err=None. HAProxy: accepted=false, status=Some(400), err=None

---

### Finding 127: mutated_headers_ws_108

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 20 76 61 6c 75 65  |Header-0:  value|
00000040: 5f 30 0d 0a 58 2d 48 65  61 64 65 72 2d 31 20 3a  |_0..X-Header-1 :|
00000050: 20 76 61 6c 75 65 5f 31  0d 0a 58 2d 48 65 61 64  | value_1..X-Head|
00000060: 65 72 2d 32 20 3a 20 20  76 61 6c 75 65 5f 32 0d  |er-2 :  value_2.|
00000070: 0a 58 2d 48 65 61 64 65  72 2d 33 20 3a 20 20 76  |.X-Header-3 :  v|
00000080: 61 6c 75 65 5f 33 0d 0a  58 2d 48 65 61 64 65 72  |alue_3..X-Header|
00000090: 2d 34 20 3a 20 76 61 6c  75 65 5f 34 0d 0a 58 2d  |-4 : value_4..X-|
000000a0: 48 65 61 64 65 72 2d 35  3a 20 20 76 61 6c 75 65  |Header-5:  value|
000000b0: 5f 35 0d 0a 58 2d 48 65  61 64 65 72 2d 36 20 3a  |_5..X-Header-6 :|
000000c0: 20 76 61 6c 75 65 5f 36  0d 0a 0d 0a              | value_6....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `204 / 204`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 128: mutated_startline_109

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line POST /index.html 

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 69 6e  64 65 78 2e 68 74 6d 6c  |POST /index.html|
00000010: 0d 0d 0a 48 6f 73 74 3a  20 65 78 61 6d 70 6c 65  |...Host: example|
00000020: 2e 63 6f 6d 0d 0a 0d 0a                           |.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `19 / 40`
- **Parsed Method:** `POST`
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

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 129: mutated_startline_110

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

### Finding 130: mutated_headers_ws_112

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 20 76 61 6c 75 65  |Header-0:  value|
00000040: 5f 30 0d 0a 58 2d 48 65  61 64 65 72 2d 31 3a 20  |_0..X-Header-1: |
00000050: 76 61 6c 75 65 5f 31 0d  0a 58 2d 48 65 61 64 65  |value_1..X-Heade|
00000060: 72 2d 32 3a 20 20 76 61  6c 75 65 5f 32 0d 0a 58  |r-2:  value_2..X|
00000070: 2d 48 65 61 64 65 72 2d  33 20 3a 20 76 61 6c 75  |-Header-3 : valu|
00000080: 65 5f 33 0d 0a 58 2d 48  65 61 64 65 72 2d 34 3a  |e_3..X-Header-4:|
00000090: 20 20 76 61 6c 75 65 5f  34 0d 0a 0d 0a           |  value_4....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `157 / 157`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 131: mutated_cl_te_rand_113

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (12) vs TE with payload len (5)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 32  |ntent-Length: 12|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 35 0d 0a 30 31 32 33 34  0d 0a 30 0d 0a 0d 0a     |5..01234..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `111 / 111`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 132: mutated_cl_te_rand_114

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (1) vs TE with payload len (9)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 0d  |ntent-Length: 1.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 39  |ng: chunked....9|
00000060: 0d 0a 30 31 32 33 34 35  36 37 38 0d 0a 30 0d 0a  |..012345678..0..|
00000070: 0d 0a                                             |..|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `114 / 114`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `9 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `14 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 9 bytes, HAProxy: 14 bytes)

---

### Finding 133: mutated_base_115_baseline_simple_get

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

### Finding 134: mutated_chunked_116

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 62 0d 0a 61 62  |chunked....b..ab|
00000050: 63 64 65 66 67 68 69 6a  6b 0d 0a 33 0d 0a 61 62  |cdefghijk..3..ab|
00000060: 63 0d 0a 63 0d 0a 61 62  63 64 65 66 67 68 69 6a  |c..c..abcdefghij|
00000070: 6b 6c 0d 0a 44 0d 0a 61  62 63 64 65 66 67 68 69  |kl..D..abcdefghi|
00000080: 6a 6b 6c 6d 0d 0a 35 0d  0a 61 62 63 64 65 0d 0a  |jklm..5..abcde..|
00000090: 30 0d 0a 0d 0a                                    |0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `149 / 149`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `44 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `50 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 44 bytes, HAProxy: 50 bytes)

---

### Finding 135: mutated_startline_117

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line PROPFIND /index.html HTTP/1.2

#### Raw Input Hex Dump

```text
00000000: 50 52 4f 50 46 49 4e 44  20 2f 69 6e 64 65 78 2e  |PROPFIND /index.|
00000010: 68 74 6d 6c 20 48 54 54  50 2f 31 2e 32 0d 0d 0a  |html HTTP/1.2...|
00000020: 48 6f 73 74 3a 20 65 78  61 6d 70 6c 65 2e 63 6f  |Host: example.co|
00000030: 6d 0d 0a 0d 0a                                    |m....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `32 / 53`
- **Parsed Method:** `PROPFIND`
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

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 136: mutated_headers_ws_118

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  20 3a 20 76 61 6c 75 65  |Header-0 : value|
00000040: 5f 30 0d 0a 58 2d 48 65  61 64 65 72 2d 31 20 3a  |_0..X-Header-1 :|
00000050: 20 20 76 61 6c 75 65 5f  31 0d 0a 0d 0a           |  value_1....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `93 / 93`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 137: mutated_pipelined_pair_119

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 31 39 20 48 54 54 50  |GET /p1_119 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 31 39  |m....GET /p2_119|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_119`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_119`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 138: mutated_chunked_120

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 4 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 62 0d 0a 61 62  |chunked....b..ab|
00000050: 63 64 65 66 67 68 69 6a  6b 0d 0a 41 0d 0a 61 62  |cdefghijk..A..ab|
00000060: 63 64 65 66 67 68 69 6a  0d 0a 36 0d 0a 61 62 63  |cdefghij..6..abc|
00000070: 64 65 66 0d 0a 36 0d 0a  61 62 63 64 65 66 0d 0a  |def..6..abcdef..|
00000080: 30 0d 0a 0d 0a                                    |0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `133 / 133`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `33 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `39 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 33 bytes, HAProxy: 39 bytes)

---

### Finding 139: mutated_chunked_121

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 2 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 31 0d 0a 61 0d  |chunked....1..a.|
00000050: 0a 34 0d 0a 61 62 63 64  0d 0a 30 0d 0a 0d 0a     |.4..abcd..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `95 / 95`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 140: mutated_chunked_122

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 3 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 61 0d 0a 61 62  |chunked....a..ab|
00000050: 63 64 65 66 67 68 69 6a  0d 0a 34 0d 0a 61 62 63  |cdefghij..4..abc|
00000060: 64 0d 0a 36 0d 0a 61 62  63 64 65 66 0d 0a 30 0d  |d..6..abcdef..0.|
00000070: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `115 / 115`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `20 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `26 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 20 bytes, HAProxy: 26 bytes)

---

### Finding 141: mutated_startline_123

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line HEAD /%20encoded%20 

#### Raw Input Hex Dump

```text
00000000: 48 45 41 44 20 2f 25 32  30 65 6e 63 6f 64 65 64  |HEAD /%20encoded|
00000010: 25 32 30 0d 0d 0a 48 6f  73 74 3a 20 65 78 61 6d  |%20...Host: exam|
00000020: 70 6c 65 2e 63 6f 6d 0d  0a 0d 0a                 |ple.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `22 / 43`
- **Parsed Method:** `HEAD`
- **Parsed URI:** `/%20encoded%20`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 142: mutated_cl_te_rand_124

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (11) vs TE with payload len (18)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 31  |ntent-Length: 11|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 31 32 0d 0a 30 31 32 33  34 35 36 37 38 39 30 31  |12..012345678901|
00000070: 32 33 34 35 36 37 0d 0a  30 0d 0a 0d 0a           |234567..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `125 / 125`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `18 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `24 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 18 bytes, HAProxy: 24 bytes)

---

### Finding 143: mutated_base_126_header_tab_before_colon

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in header_tab_before_colon

#### Raw Input Hex Dump

```text
00000000: 47 45 54 00 2f 74 61 62  2d 62 65 66 6f 72 65 2d  |GET./tab-before-|
00000010: 63 6f 6c 6f 6e 20 48 54  54 50 2f 31 2e 31 0d 0a  |colon HTTP/1.1..|
00000020: 48 6f 73 74 3a 20 65 78  61 6d 70 6c 65 2e 63 6f  |Host: example.co|
00000030: 6d 0d 0a 58 2d 48 65 61  64 65 72 09 3a 20 76 61  |m..X-Header.: va|
00000040: 6c 75 65 0d 0a 0d 0a                              |lue....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `71 / 71`
- **Parsed Method:** `GET /tab-before-colon`
- **Parsed URI:** `HTTP/1.1`
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

### Finding 144: mutated_cl_te_rand_128

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (3) vs TE with payload len (14)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 33 0d  |ntent-Length: 3.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 65  |ng: chunked....e|
00000060: 0d 0a 30 31 32 33 34 35  36 37 38 39 30 31 32 33  |..01234567890123|
00000070: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `119 / 119`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `14 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `19 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 14 bytes, HAProxy: 19 bytes)

---

### Finding 145: mutated_pipelined_pair_129

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 32 39 20 48 54 54 50  |GET /p1_129 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 32 39  |m....GET /p2_129|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_129`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_129`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 146: mutated_chunked_130

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 37 0d 0a 61 62  |chunked....7..ab|
00000050: 63 64 65 66 67 0d 0a 32  0d 0a 61 62 0d 0a 41 0d  |cdefg..2..ab..A.|
00000060: 0a 61 62 63 64 65 66 67  68 69 6a 0d 0a 31 0d 0a  |.abcdefghij..1..|
00000070: 61 0d 0a 43 0d 0a 61 62  63 64 65 66 67 68 69 6a  |a..C..abcdefghij|
00000080: 6b 6c 0d 0a 30 0d 0a 0d  0a                       |kl..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `137 / 137`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `32 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `38 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 32 bytes, HAProxy: 38 bytes)

---

### Finding 147: mutated_cl_te_rand_131

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (9) vs TE with payload len (10)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 39 0d  |ntent-Length: 9.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 61  |ng: chunked....a|
00000060: 0d 0a 30 31 32 33 34 35  36 37 38 39 0d 0a 30 0d  |..0123456789..0.|
00000070: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `115 / 115`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `10 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `15 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 10 bytes, HAProxy: 15 bytes)

---

### Finding 148: mutated_cl_te_rand_132

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (11) vs TE with payload len (14)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 31  |ntent-Length: 11|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 65 0d 0a 30 31 32 33 34  35 36 37 38 39 30 31 32  |e..0123456789012|
00000070: 33 0d 0a 30 0d 0a 0d 0a                           |3..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `120 / 120`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `14 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `19 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 14 bytes, HAProxy: 19 bytes)

---

### Finding 149: mutated_pipelined_pair_133

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 33 33 20 48 54 54 50  |GET /p1_133 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 33 33  |m....GET /p2_133|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_133`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_133`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 150: mutated_base_134_header_nul_in_value

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in header_nul_in_value

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6e 75 6c  2d 69 6e 2d 76 61 6c 75  |GET /nul-in-valu|
00000010: 65 20 48 54 54 50 2f 31  2e 00 0d 0a 48 6f 73 74  |e HTTP/1....Host|
00000020: 3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 58  |: example.com..X|
00000030: 2d 48 65 61 64 65 72 3a  20 76 61 6c 00 75 65 0d  |-Header: val.ue.|
00000040: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `67 / 67`
- **Parsed Method:** `GET`
- **Parsed URI:** `/nul-in-value`
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

### Finding 151: mutated_chunked_135

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 1 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 35 0d 0a 61 62  |chunked....5..ab|
00000050: 63 64 65 0d 0a 30 0d 0a  0d 0a                    |cde..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `90 / 90`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 152: mutated_cl_te_rand_136

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (2) vs TE with payload len (5)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 32 0d  |ntent-Length: 2.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 35  |ng: chunked....5|
00000060: 0d 0a 30 31 32 33 34 0d  0a 30 0d 0a 0d 0a        |..01234..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `110 / 110`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 153: mutated_chunked_137

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 4 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 32 0d 0a 61 62  |chunked....2..ab|
00000050: 0d 0a 44 0d 0a 61 62 63  64 65 66 67 68 69 6a 6b  |..D..abcdefghijk|
00000060: 6c 6d 0d 0a 41 0d 0a 61  62 63 64 65 66 67 68 69  |lm..A..abcdefghi|
00000070: 6a 0d 0a 35 0d 0a 61 62  63 64 65 0d 0a 30 0d 0a  |j..5..abcde..0..|
00000080: 0d 0a                                             |..|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `130 / 130`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `30 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `36 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 30 bytes, HAProxy: 36 bytes)

---

### Finding 154: mutated_startline_139

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line DELETE /index.html HTTP/9.9

#### Raw Input Hex Dump

```text
00000000: 44 45 4c 45 54 45 20 2f  69 6e 64 65 78 2e 68 74  |DELETE /index.ht|
00000010: 6d 6c 20 48 54 54 50 2f  39 2e 39 0d 0d 0a 48 6f  |ml HTTP/9.9...Ho|
00000020: 73 74 3a 20 65 78 61 6d  70 6c 65 2e 63 6f 6d 0d  |st: example.com.|
00000030: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `30 / 51`
- **Parsed Method:** `DELETE`
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

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 155: mutated_pipelined_pair_140

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 34 30 20 48 54 54 50  |GET /p1_140 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 34 30  |m....GET /p2_140|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_140`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_140`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 156: mutated_startline_141

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line HEAD /index.html HTTP/0.9

#### Raw Input Hex Dump

```text
00000000: 48 45 41 44 20 2f 69 6e  64 65 78 2e 68 74 6d 6c  |HEAD /index.html|
00000010: 20 48 54 54 50 2f 30 2e  39 0d 48 6f 73 74 3a 20  | HTTP/0.9.Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 0d 0a     |example.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `47 / 47`
- **Parsed Method:** `HEAD`
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

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 157: mutated_chunked_142

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 34 0d 0a 61 62  |chunked....4..ab|
00000050: 63 64 0d 0a 62 0d 0a 61  62 63 64 65 66 67 68 69  |cd..b..abcdefghi|
00000060: 6a 6b 0d 0a 32 0d 0a 61  62 0d 0a 46 0d 0a 61 62  |jk..2..ab..F..ab|
00000070: 63 64 65 66 67 68 69 6a  6b 6c 6d 6e 6f 0d 0a 32  |cdefghijklmno..2|
00000080: 0d 0a 61 62 0d 0a 30 0d  0a 0d 0a                 |..ab..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `139 / 139`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `34 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `40 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 34 bytes, HAProxy: 40 bytes)

---

### Finding 158: mutated_chunked_143

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 64 0d 0a 61 62  |chunked....d..ab|
00000050: 63 64 65 66 67 68 69 6a  6b 6c 6d 0d 0a 35 0d 0a  |cdefghijklm..5..|
00000060: 61 62 63 64 65 0d 0a 63  0d 0a 61 62 63 64 65 66  |abcde..c..abcdef|
00000070: 67 68 69 6a 6b 6c 0d 0a  62 0d 0a 61 62 63 64 65  |ghijkl..b..abcde|
00000080: 66 67 68 69 6a 6b 0d 0a  43 0d 0a 61 62 63 64 65  |fghijk..C..abcde|
00000090: 66 67 68 69 6a 6b 6c 0d  0a 30 0d 0a 0d 0a        |fghijkl..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `158 / 158`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `53 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `59 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 53 bytes, HAProxy: 59 bytes)

---

### Finding 159: mutated_headers_ws_144

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 20 76 61 6c 75 65  |Header-0:  value|
00000040: 5f 30 0d 0a 58 2d 48 65  61 64 65 72 2d 31 3a 20  |_0..X-Header-1: |
00000050: 20 76 61 6c 75 65 5f 31  0d 0a 58 2d 48 65 61 64  | value_1..X-Head|
00000060: 65 72 2d 32 3a 20 20 76  61 6c 75 65 5f 32 0d 0a  |er-2:  value_2..|
00000070: 58 2d 48 65 61 64 65 72  2d 33 3a 20 20 76 61 6c  |X-Header-3:  val|
00000080: 75 65 5f 33 0d 0a 58 2d  48 65 61 64 65 72 2d 34  |ue_3..X-Header-4|
00000090: 20 3a 20 76 61 6c 75 65  5f 34 0d 0a 0d 0a        | : value_4....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `158 / 158`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 160: mutated_chunked_145

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 2 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 35 0d 0a 61 62  |chunked....5..ab|
00000050: 63 64 65 0d 0a 64 0d 0a  61 62 63 64 65 66 67 68  |cde..d..abcdefgh|
00000060: 69 6a 6b 6c 6d 0d 0a 30  0d 0a 0d 0a              |ijklm..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `108 / 108`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `18 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `24 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 18 bytes, HAProxy: 24 bytes)

---

### Finding 161: mutated_base_147_duplicate_cl_identical

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in duplicate_cl_identical

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 64 75  70 2d 63 6c 20 48 54 54  |POST /dup-cl HTT|
00000010: 50 2f 31 2e 31 0d 0a 48  6f 73 74 3a 20 65 78 61  |P/1.1..Host: exa|
00000020: 6d 70 6c 65 2e 63 6f 6d  0d 0a 43 6f 6e 74 65 6e  |mple.com..Conten|
00000030: 74 2d 4c 65 6e 67 74 68  3a 20 35 3a 0a 43 6f 6e  |t-Length: 5:.Con|
00000040: 74 65 6e 74 2d 4c 65 6e  67 74 68 3a 20 35 0d 0a  |tent-Length: 5..|
00000050: 0d 0a 68 65 6c 6c 6f                              |..hello|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `82 / 87`
- **Parsed Method:** `POST`
- **Parsed URI:** `/dup-cl`
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

### Finding 162: mutated_cl_te_rand_149

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (5) vs TE with payload len (3)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 35 0d  |ntent-Length: 5.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 33  |ng: chunked....3|
00000060: 0d 0a 30 31 32 0d 0a 30  0d 0a 0d 0a              |..012..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `108 / 108`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `3 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `8 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 3 bytes, HAProxy: 8 bytes)

---

### Finding 163: mutated_cl_te_rand_150

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (14) vs TE with payload len (6)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 34  |ntent-Length: 14|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 36 0d 0a 30 31 32 33 34  35 0d 0a 30 0d 0a 0d 0a  |6..012345..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `112 / 112`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `6 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `11 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 6 bytes, HAProxy: 11 bytes)

---

### Finding 164: mutated_chunked_151

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 37 0d 0a 61 62  |chunked....7..ab|
00000050: 63 64 65 66 67 0d 0a 43  0d 0a 61 62 63 64 65 66  |cdefg..C..abcdef|
00000060: 67 68 69 6a 6b 6c 0d 0a  33 0d 0a 61 62 63 0d 0a  |ghijkl..3..abc..|
00000070: 33 0d 0a 61 62 63 0d 0a  31 30 0d 0a 61 62 63 64  |3..abc..10..abcd|
00000080: 65 66 67 68 69 6a 6b 6c  6d 6e 6f 70 0d 0a 30 0d  |efghijklmnop..0.|
00000090: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `147 / 147`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `41 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `47 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 41 bytes, HAProxy: 47 bytes)

---

### Finding 165: mutated_pipelined_pair_153

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 35 33 20 48 54 54 50  |GET /p1_153 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 35 33  |m....GET /p2_153|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_153`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_153`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 166: mutated_cl_te_rand_155

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (13) vs TE with payload len (4)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 33  |ntent-Length: 13|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 34 0d 0a 30 31 32 33 0d  0a 30 0d 0a 0d 0a        |4..0123..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `110 / 110`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `4 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `9 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 4 bytes, HAProxy: 9 bytes)

---

### Finding 167: mutated_cl_te_rand_156

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (11) vs TE with payload len (9)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 31  |ntent-Length: 11|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 39 0d 0a 30 31 32 33 34  35 36 37 38 0d 0a 30 0d  |9..012345678..0.|
00000070: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `115 / 115`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `9 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `14 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 9 bytes, HAProxy: 14 bytes)

---

### Finding 168: mutated_pipelined_pair_158

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 35 38 20 48 54 54 50  |GET /p1_158 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 35 38  |m....GET /p2_158|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_158`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_158`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 169: mutated_cl_te_rand_159

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (12) vs TE with payload len (19)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 32  |ntent-Length: 12|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 31 33 0d 0a 30 31 32 33  34 35 36 37 38 39 30 31  |13..012345678901|
00000070: 32 33 34 35 36 37 38 0d  0a 30 0d 0a 0d 0a        |2345678..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `126 / 126`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `19 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `25 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 19 bytes, HAProxy: 25 bytes)

---

### Finding 170: mutated_base_160_pipelined_chunked_premature_end

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
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

### Finding 171: mutated_cl_te_rand_161

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (11) vs TE with payload len (10)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 31  |ntent-Length: 11|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 61 0d 0a 30 31 32 33 34  35 36 37 38 39 0d 0a 30  |a..0123456789..0|
00000070: 0d 0a 0d 0a                                       |....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `116 / 116`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `10 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `15 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 10 bytes, HAProxy: 15 bytes)

---

### Finding 172: mutated_chunked_162

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 33 0d 0a 61 62  |chunked....3..ab|
00000050: 63 0d 0a 33 0d 0a 61 62  63 0d 0a 31 0d 0a 61 0d  |c..3..abc..1..a.|
00000060: 0a 37 0d 0a 61 62 63 64  65 66 67 0d 0a 63 0d 0a  |.7..abcdefg..c..|
00000070: 61 62 63 64 65 66 67 68  69 6a 6b 6c 0d 0a 30 0d  |abcdefghijkl..0.|
00000080: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `131 / 131`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `26 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `32 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 26 bytes, HAProxy: 32 bytes)

---

### Finding 173: mutated_startline_163

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line GET /deep/nested/path?q=1&v=2 HTTP/1.1

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 64 65 65  70 2f 6e 65 73 74 65 64  |GET /deep/nested|
00000010: 2f 70 61 74 68 3f 71 3d  31 26 76 3d 32 20 48 54  |/path?q=1&v=2 HT|
00000020: 54 50 2f 31 2e 31 0d 48  6f 73 74 3a 20 65 78 61  |TP/1.1.Host: exa|
00000030: 6d 70 6c 65 2e 63 6f 6d  0d 0a 0d 0a              |mple.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `60 / 60`
- **Parsed Method:** `GET`
- **Parsed URI:** `/deep/nested/path?q=1&v=2`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 174: mutated_base_164_chunk_signed_plus

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in chunk_signed_plus

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 3a 2f 63 68  75 6e 6b 2d 70 6c 75 73  |POST:/chunk-plus|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 54 72  | example.com..Tr|
00000030: 61 6e 73 66 65 72 2d 45  6e 63 6f 64 69 6e 67 3a  |ansfer-Encoding:|
00000040: 20 63 68 75 6e 6b 65 64  0d 0a 0d 0a 2b 35 0d 0a  | chunked....+5..|
00000050: 68 65 6c 6c 6f 0d 0a 30  0d 0a 0d 0a              |hello..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `92 / 92`
- **Parsed Method:** `POST:/chunk-plus`
- **Parsed URI:** `HTTP/1.1`
- **Body Length:** `5 bytes`
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

### Finding 175: mutated_cl_te_rand_165

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (17) vs TE with payload len (3)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 37  |ntent-Length: 17|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 33 0d 0a 30 31 32 0d 0a  30 0d 0a 0d 0a           |3..012..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `109 / 109`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `3 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `8 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 3 bytes, HAProxy: 8 bytes)

---

### Finding 176: mutated_cl_te_rand_166

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (15) vs TE with payload len (18)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 35  |ntent-Length: 15|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 31 32 0d 0a 30 31 32 33  34 35 36 37 38 39 30 31  |12..012345678901|
00000070: 32 33 34 35 36 37 0d 0a  30 0d 0a 0d 0a           |234567..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `125 / 125`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `18 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `24 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 18 bytes, HAProxy: 24 bytes)

---

### Finding 177: mutated_startline_167

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line HEAD /deep/nested/path?q=1&v=2 HTTP/9.9

#### Raw Input Hex Dump

```text
00000000: 48 45 41 44 20 2f 64 65  65 70 2f 6e 65 73 74 65  |HEAD /deep/neste|
00000010: 64 2f 70 61 74 68 3f 71  3d 31 26 76 3d 32 20 48  |d/path?q=1&v=2 H|
00000020: 54 54 50 2f 39 2e 39 0d  0d 0a 48 6f 73 74 3a 20  |TTP/9.9...Host: |
00000030: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 0d 0a     |example.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `42 / 63`
- **Parsed Method:** `HEAD`
- **Parsed URI:** `/deep/nested/path?q=1&v=2`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 178: mutated_cl_te_rand_168

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (2) vs TE with payload len (9)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 32 0d  |ntent-Length: 2.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 39  |ng: chunked....9|
00000060: 0d 0a 30 31 32 33 34 35  36 37 38 0d 0a 30 0d 0a  |..012345678..0..|
00000070: 0d 0a                                             |..|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `114 / 114`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `9 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `14 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 9 bytes, HAProxy: 14 bytes)

---

### Finding 179: mutated_pipelined_pair_169

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 36 39 20 48 54 54 50  |GET /p1_169 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 36 39  |m....GET /p2_169|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_169`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_169`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 180: mutated_startline_171

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line INVALID_METHOD /index.html HTTP/1.0

#### Raw Input Hex Dump

```text
00000000: 49 4e 56 41 4c 49 44 5f  4d 45 54 48 4f 44 20 2f  |INVALID_METHOD /|
00000010: 69 6e 64 65 78 2e 68 74  6d 6c 20 48 54 54 50 2f  |index.html HTTP/|
00000020: 31 2e 30 0d 48 6f 73 74  3a 20 65 78 61 6d 70 6c  |1.0.Host: exampl|
00000030: 65 2e 63 6f 6d 0d 0a 0d  0a                       |e.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `57 / 57`
- **Parsed Method:** `INVALID_METHOD`
- **Parsed URI:** `/index.html`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `true`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 181: mutated_chunked_172

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 3 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 31 0d 0a 61 0d  |chunked....1..a.|
00000050: 0a 66 0d 0a 61 62 63 64  65 66 67 68 69 6a 6b 6c  |.f..abcdefghijkl|
00000060: 6d 6e 6f 0d 0a 37 0d 0a  61 62 63 64 65 66 67 0d  |mno..7..abcdefg.|
00000070: 0a 30 0d 0a 0d 0a                                 |.0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `118 / 118`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `23 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `29 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 23 bytes, HAProxy: 29 bytes)

---

### Finding 182: mutated_base_173_cl_te_conflicting_lengths_te_cl_smuggle

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in cl_te_conflicting_lengths_te_cl_smuggle

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 74 72  61 6e 73 66 65 72 20 48  |POST /transfer H|
00000010: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 65  |TTP/1.1..Host: e|
00000020: 78 61 6d 70 6c 65 2e 63  6f 6d 0d 0a 43 6f 6e 74  |xample.com..Cont|
00000030: 65 6e 74 2d 4c 65 6e 67  74 68 3a 20 34 0d 0a 54  |ent-Length: 4..T|
00000040: 72 61 6e 73 66 65 72 00  45 6e 63 6f 64 69 6e 67  |ransfer.Encoding|
00000050: 3a 20 63 68 75 6e 6b 65  64 0d 0a 0d 0a 35 0d 0a  |: chunked....5..|
00000060: 68 65 6c 6c 6f 0d 0a 36  0d 0a 20 77 6f 72 6c 64  |hello..6.. world|
00000070: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `97 / 119`
- **Parsed Method:** `POST`
- **Parsed URI:** `/transfer`
- **Body Length:** `4 bytes`
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

### Finding 183: mutated_cl_te_rand_174

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (1) vs TE with payload len (5)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 0d  |ntent-Length: 1.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 35  |ng: chunked....5|
00000060: 0d 0a 30 31 32 33 34 0d  0a 30 0d 0a 0d 0a        |..01234..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `110 / 110`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `5 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `10 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 5 bytes, HAProxy: 10 bytes)

---

### Finding 184: mutated_cl_te_rand_175

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (14) vs TE with payload len (18)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 34  |ntent-Length: 14|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 31 32 0d 0a 30 31 32 33  34 35 36 37 38 39 30 31  |12..012345678901|
00000070: 32 33 34 35 36 37 0d 0a  30 0d 0a 0d 0a           |234567..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `125 / 125`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `18 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `24 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 18 bytes, HAProxy: 24 bytes)

---

### Finding 185: mutated_pipelined_pair_176

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 37 36 20 48 54 54 50  |GET /p1_176 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 37 36  |m....GET /p2_176|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_176`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_176`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 186: mutated_cl_te_rand_177

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (17) vs TE with payload len (10)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 37  |ntent-Length: 17|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 61 0d 0a 30 31 32 33 34  35 36 37 38 39 0d 0a 30  |a..0123456789..0|
00000070: 0d 0a 0d 0a                                       |....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `116 / 116`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `10 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `15 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 10 bytes, HAProxy: 15 bytes)

---

### Finding 187: mutated_chunked_178

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 3 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 32 0d 0a 61 62  |chunked....2..ab|
00000050: 0d 0a 31 30 0d 0a 61 62  63 64 65 66 67 68 69 6a  |..10..abcdefghij|
00000060: 6b 6c 6d 6e 6f 70 0d 0a  45 0d 0a 61 62 63 64 65  |klmnop..E..abcde|
00000070: 66 67 68 69 6a 6b 6c 6d  6e 0d 0a 30 0d 0a 0d 0a  |fghijklmn..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `128 / 128`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `32 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `38 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 32 bytes, HAProxy: 38 bytes)

---

### Finding 188: mutated_chunked_179

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 3 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 37 0d 0a 61 62  |chunked....7..ab|
00000050: 63 64 65 66 67 0d 0a 38  0d 0a 61 62 63 64 65 66  |cdefg..8..abcdef|
00000060: 67 68 0d 0a 61 0d 0a 61  62 63 64 65 66 67 68 69  |gh..a..abcdefghi|
00000070: 6a 0d 0a 30 0d 0a 0d 0a                           |j..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `120 / 120`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `25 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `31 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 25 bytes, HAProxy: 31 bytes)

---

### Finding 189: mutated_pipelined_pair_180

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 38 30 20 48 54 54 50  |GET /p1_180 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 38 30  |m....GET /p2_180|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_180`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_180`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 190: mutated_chunked_181

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 2 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 38 0d 0a 61 62  |chunked....8..ab|
00000050: 63 64 65 66 67 68 0d 0a  39 0d 0a 61 62 63 64 65  |cdefgh..9..abcde|
00000060: 66 67 68 69 0d 0a 30 0d  0a 0d 0a                 |fghi..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `107 / 107`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `17 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `23 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 17 bytes, HAProxy: 23 bytes)

---

### Finding 191: mutated_cl_te_rand_182

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (13) vs TE with payload len (17)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 33  |ntent-Length: 13|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 31 31 0d 0a 30 31 32 33  34 35 36 37 38 39 30 31  |11..012345678901|
00000070: 32 33 34 35 36 0d 0a 30  0d 0a 0d 0a              |23456..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `124 / 124`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `17 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `23 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 17 bytes, HAProxy: 23 bytes)

---

### Finding 192: mutated_chunked_183

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 44 0d 0a 61 62  |chunked....D..ab|
00000050: 63 64 65 66 67 68 69 6a  6b 6c 6d 0d 0a 39 0d 0a  |cdefghijklm..9..|
00000060: 61 62 63 64 65 66 67 68  69 0d 0a 61 0d 0a 61 62  |abcdefghi..a..ab|
00000070: 63 64 65 66 67 68 69 6a  0d 0a 36 0d 0a 61 62 63  |cdefghij..6..abc|
00000080: 64 65 66 0d 0a 31 0d 0a  61 0d 0a 30 0d 0a 0d 0a  |def..1..a..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `144 / 144`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `39 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `45 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 39 bytes, HAProxy: 45 bytes)

---

### Finding 193: mutated_pipelined_pair_184

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 38 34 20 48 54 54 50  |GET /p1_184 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 38 34  |m....GET /p2_184|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_184`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_184`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 194: mutated_startline_185

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line PUT /%20encoded%20 HTTP/2.0

#### Raw Input Hex Dump

```text
00000000: 50 55 54 20 2f 25 32 30  65 6e 63 6f 64 65 64 25  |PUT /%20encoded%|
00000010: 32 30 20 48 54 54 50 2f  32 2e 30 0d 0d 0a 48 6f  |20 HTTP/2.0...Ho|
00000020: 73 74 3a 20 65 78 61 6d  70 6c 65 2e 63 6f 6d 0d  |st: example.com.|
00000030: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `30 / 51`
- **Parsed Method:** `PUT`
- **Parsed URI:** `/%20encoded%20`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 195: mutated_cl_te_rand_186

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (5) vs TE with payload len (2)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 35 0d  |ntent-Length: 5.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 32  |ng: chunked....2|
00000060: 0d 0a 30 31 0d 0a 30 0d  0a 0d 0a                 |..01..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `107 / 107`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `2 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `7 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 2 bytes, HAProxy: 7 bytes)

---

### Finding 196: mutated_cl_te_rand_187

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (1) vs TE with payload len (14)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 0d  |ntent-Length: 1.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 65  |ng: chunked....e|
00000060: 0d 0a 30 31 32 33 34 35  36 37 38 39 30 31 32 33  |..01234567890123|
00000070: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `119 / 119`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `14 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `19 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 14 bytes, HAProxy: 19 bytes)

---

### Finding 197: mutated_cl_te_rand_188

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (18) vs TE with payload len (14)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 38  |ntent-Length: 18|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 65 0d 0a 30 31 32 33 34  35 36 37 38 39 30 31 32  |e..0123456789012|
00000070: 33 0d 0a 30 0d 0a 0d 0a                           |3..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `120 / 120`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `14 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `19 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 14 bytes, HAProxy: 19 bytes)

---

### Finding 198: mutated_pipelined_pair_189

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  31 38 39 20 48 54 54 50  |GET /p1_189 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 31 38 39  |m....GET /p2_189|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_189`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_189`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 199: mutated_base_190_obs_fold_first_line

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in obs_fold_first_line

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6f 62 73  2d 66 69 72 73 74 20 48  |GET /obs-first H|
00000010: 54 54 50 2f 31 2e 31 0d  0a 20 66 6f 6c 64 65 64  |TTP/1.1.. folded|
00000020: 2d 77 69 20 68 6f 75 74  2d 68 65 61 64 65 72 3a  |-wi hout-header:|
00000030: 20 76 61 6c 75 65 0d 0a  48 6f 73 74 3a 20 65 78  | value..Host: ex|
00000040: 61 6d 70 6c 65 2e 63 6f  6d 0d 0a 0d 0a           |ample.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `77 / 77`
- **Parsed Method:** `GET`
- **Parsed URI:** `/obs-first`
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

### Finding 200: mutated_base_191_cl_te_multiple_te_headers

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in cl_te_multiple_te_headers

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 64 61  74 61 20 48 54 54 50 2f  |POST /data HTTP/|
00000010: 31 2e 31 0d 0a 48 6f 73  74 3a 20 65 78 61 6d 70  |1.1..Host: examp|
00000020: 6c 65 2e 63 6f 6d 0d 0a  43 6f 6e 74 65 6e 74 2d  |le.com..Content-|
00000030: 4c 65 6e 67 74 68 3a 20  31 30 0d 0a 54 72 61 6e  |Length: 10..Tran|
00000040: 73 66 65 72 2d 45 6e 63  6f 64 69 6e 67 3a 20 69  |sfer-Encoding: i|
00000050: 64 65 6e 74 69 74 79 0d  0a 54 72 61 6e 73 66 65  |dentity..Transfe|
00000060: 72 2d 45 6e 63 6f 64 69  6e 67 3a 20 63 68 75 6e  |r-Encoding: chun|
00000070: 6b 65 64 0d 0a 0d 0a 35  0d 0a 68 00 6c 6c 6f 0d  |ked....5..h.llo.|
00000080: 0a 30 0d 0a 0d 0a                                 |.0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `129 / 134`
- **Parsed Method:** `POST`
- **Parsed URI:** `/data`
- **Body Length:** `10 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(422)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Ibex: accepted=true, phase="Done", err=None. HAProxy: accepted=false, status=Some(422), err=None

---

### Finding 201: mutated_cl_te_rand_192

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (16) vs TE with payload len (15)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 36  |ntent-Length: 16|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 66 0d 0a 30 31 32 33 34  35 36 37 38 39 30 31 32  |f..0123456789012|
00000070: 33 34 0d 0a 30 0d 0a 0d  0a                       |34..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `121 / 121`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `15 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `20 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 15 bytes, HAProxy: 20 bytes)

---

### Finding 202: mutated_cl_te_rand_193

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (19) vs TE with payload len (4)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 39  |ntent-Length: 19|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 34 0d 0a 30 31 32 33 0d  0a 30 0d 0a 0d 0a        |4..0123..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `110 / 110`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `4 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `9 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 4 bytes, HAProxy: 9 bytes)

---

### Finding 203: mutated_chunked_194

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 4 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 32 0d 0a 61 62  |chunked....2..ab|
00000050: 0d 0a 63 0d 0a 61 62 63  64 65 66 67 68 69 6a 6b  |..c..abcdefghijk|
00000060: 6c 0d 0a 45 0d 0a 61 62  63 64 65 66 67 68 69 6a  |l..E..abcdefghij|
00000070: 6b 6c 6d 6e 0d 0a 31 0d  0a 61 0d 0a 30 0d 0a 0d  |klmn..1..a..0...|
00000080: 0a                                                |.|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `129 / 129`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `29 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `35 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 29 bytes, HAProxy: 35 bytes)

---

### Finding 204: mutated_chunked_195

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 4 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 64 0d 0a 61 62  |chunked....d..ab|
00000050: 63 64 65 66 67 68 69 6a  6b 6c 6d 0d 0a 39 0d 0a  |cdefghijklm..9..|
00000060: 61 62 63 64 65 66 67 68  69 0d 0a 35 0d 0a 61 62  |abcdefghi..5..ab|
00000070: 63 64 65 0d 0a 36 0d 0a  61 62 63 64 65 66 0d 0a  |cde..6..abcdef..|
00000080: 30 0d 0a 0d 0a                                    |0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `133 / 133`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `33 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `39 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 33 bytes, HAProxy: 39 bytes)

---

### Finding 205: mutated_cl_te_rand_197

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (2) vs TE with payload len (4)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 32 0d  |ntent-Length: 2.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 34  |ng: chunked....4|
00000060: 0d 0a 30 31 32 33 0d 0a  30 0d 0a 0d 0a           |..0123..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `109 / 109`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `4 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `9 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 4 bytes, HAProxy: 9 bytes)

---

### Finding 206: mutated_base_198_header_nul_in_name

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in header_nul_in_name

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6e 75 6c  2d 69 6e 2d 6e 61 6d 65  |GET /nul-in-name|
00000010: 20 48 54 54 50 20 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP 1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 46 6f 6f 00 42 61 72 3a  20 76 61 6c 75 65 0d 0a  |Foo.Bar: value..|
00000040: 0d 0a                                             |..|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `66 / 66`
- **Parsed Method:** `GET`
- **Parsed URI:** `/nul-in-name`
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

### Finding 207: mutated_startline_200

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line DELETE /api/v1/resource HTTP/1.1

#### Raw Input Hex Dump

```text
00000000: 44 45 4c 45 54 45 20 2f  61 70 69 2f 76 31 2f 72  |DELETE /api/v1/r|
00000010: 65 73 6f 75 72 63 65 20  48 54 54 50 2f 31 2e 31  |esource HTTP/1.1|
00000020: 0d 48 6f 73 74 3a 20 65  78 61 6d 70 6c 65 2e 63  |.Host: example.c|
00000030: 6f 6d 0d 0a 0d 0a                                 |om....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `54 / 54`
- **Parsed Method:** `DELETE`
- **Parsed URI:** `/api/v1/resource`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 208: mutated_pipelined_pair_201

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  32 30 31 20 48 54 54 50  |GET /p1_201 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 32 30 31  |m....GET /p2_201|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_201`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_201`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 209: mutated_cl_te_rand_203

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (18) vs TE with payload len (15)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 38  |ntent-Length: 18|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 66 0d 0a 30 31 32 33 34  35 36 37 38 39 30 31 32  |f..0123456789012|
00000070: 33 34 0d 0a 30 0d 0a 0d  0a                       |34..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `121 / 121`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `15 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `20 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 15 bytes, HAProxy: 20 bytes)

---

### Finding 210: mutated_pipelined_pair_204

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  32 30 34 20 48 54 54 50  |GET /p1_204 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 32 30 34  |m....GET /p2_204|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_204`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_204`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 211: mutated_pipelined_pair_205

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  32 30 35 20 48 54 54 50  |GET /p1_205 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 32 30 35  |m....GET /p2_205|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_205`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_205`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 212: mutated_base_206_line_term_doubled_crlf_before_headers

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in line_term_doubled_crlf_before_headers

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 64 6f 75  62 6c 65 64 20 48 54 54  |GET /doubled HTT|
00000010: 50 2f 31 2e 31 0d 0a 20  0a 48 6f 73 74 3a 20 65  |P/1.1.. .Host: e|
00000020: 78 61 6d 70 6c 65 2e 63  6f 6d 0d 0a 0d 0a        |xample.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `46 / 46`
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

Ibex: accepted=true, phase="Done", err=None. HAProxy: accepted=false, status=Some(400), err=None

---

### Finding 213: mutated_pipelined_pair_207

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  32 30 37 20 48 54 54 50  |GET /p1_207 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 32 30 37  |m....GET /p2_207|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_207`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_207`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 214: mutated_base_208_obs_fold_tab_continuation

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in obs_fold_tab_continuation

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6f 62 73  2d 74 61 62 20 48 54 54  |GET /obs-tab HTT|
00000010: 50 2f 31 2e 31 0d 0a 48  6f 73 74 3a 20 65 78 61  |P/1.1..Host: exa|
00000020: 6d 70 6c 65 2e 63 6f 6d  0d 0a 58 2d 48 65 61 64  |mple.com..X-Head|
00000030: 65 72 3a 20 66 69 00 73  74 2d 6c 69 6e 65 0d 0a  |er: fi.st-line..|
00000040: 09 73 65 63 6f 6e 64 2d  6c 69 6e 65 0d 0a 0d 0a  |.second-line....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `80 / 80`
- **Parsed Method:** `GET`
- **Parsed URI:** `/obs-tab`
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

### Finding 215: mutated_base_209_oversized_header_count_120

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in oversized_header_count_120

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 61 6e  79 2d 68 65 61 64 65 72  |GET /many-header|
00000010: 73 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  |s HTTP/1.1..Host|
00000020: 3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 58  |: example.com..X|
00000030: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
00000040: 30 30 3a 20 76 61 6c 75  65 5f 30 0d 0a 58 2d 43  |00: value_0..X-C|
00000050: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 30 31  |ustom-Header-001|
00000060: 3a 20 76 61 6c 75 65 5f  31 0d 0a 58 2d 43 75 73  |: value_1..X-Cus|
00000070: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 30 32 3a 20  |tom-Header-002: |
00000080: 76 61 6c 75 65 5f 32 0d  0a 58 2d 43 75 73 74 6f  |value_2..X-Custo|
00000090: 6d 2d 48 65 61 64 65 72  2d 30 30 33 3a 20 76 61  |m-Header-003: va|
000000a0: 6c 75 65 5f 33 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |lue_3..X-Custom-|
000000b0: 48 65 61 64 65 72 2d 30  30 34 3a 20 76 61 6c 75  |Header-004: valu|
000000c0: 65 5f 34 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |e_4..X-Custom-He|
000000d0: 61 64 65 72 2d 30 30 35  3a 20 76 61 6c 75 65 5f  |ader-005: value_|
000000e0: 35 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |5..X-Custom-Head|
000000f0: 65 72 2d 30 30 36 3a 20  76 61 6c 75 65 5f 36 0d  |er-006: value_6.|
00000100: 0a 58 3a 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X:Custom-Header|
00000110: 2d 30 30 37 3a 20 76 61  6c 75 65 5f 37 0d 0a 58  |-007: value_7..X|
00000120: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
00000130: 30 38 3a 20 76 61 6c 75  65 5f 38 0d 0a 58 2d 43  |08: value_8..X-C|
00000140: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 30 39  |ustom-Header-009|
00000150: 3a 20 76 61 6c 75 65 5f  39 0d 0a 58 2d 43 75 73  |: value_9..X-Cus|
00000160: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 31 30 3a 20  |tom-Header-010: |
00000170: 76 61 6c 75 65 5f 31 30  0d 0a 58 2d 43 75 73 74  |value_10..X-Cust|
00000180: 6f 6d 2d 48 65 61 64 65  72 2d 30 31 31 3a 20 76  |om-Header-011: v|
00000190: 61 6c 75 65 5f 31 31 0d  0a 58 2d 43 75 73 74 6f  |alue_11..X-Custo|
000001a0: 6d 2d 48 65 61 64 65 72  2d 30 31 32 3a 20 76 61  |m-Header-012: va|
000001b0: 6c 75 65 5f 31 32 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_12..X-Custom|
000001c0: 2d 48 65 61 64 65 72 2d  30 31 33 3a 20 76 61 6c  |-Header-013: val|
000001d0: 75 65 5f 31 33 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_13..X-Custom-|
000001e0: 48 65 61 64 65 72 2d 30  31 34 3a 20 76 61 6c 75  |Header-014: valu|
000001f0: 65 5f 31 34 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_14..X-Custom-H|
00000200: 65 61 64 65 72 2d 30 31  35 3a 20 76 61 6c 75 65  |eader-015: value|
00000210: 5f 31 35 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_15..X-Custom-He|
00000220: 61 64 65 72 2d 30 31 36  3a 20 76 61 6c 75 65 5f  |ader-016: value_|
00000230: 31 36 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |16..X-Custom-Hea|
00000240: 64 65 72 2d 30 31 37 3a  20 76 61 6c 75 65 5f 31  |der-017: value_1|
00000250: 37 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |7..X-Custom-Head|
00000260: 65 72 2d 30 31 38 3a 20  76 61 6c 75 65 5f 31 38  |er-018: value_18|
00000270: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000280: 72 2d 30 31 39 3a 20 76  61 6c 75 65 5f 31 39 0d  |r-019: value_19.|
00000290: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
000002a0: 2d 30 32 30 3a 20 76 61  6c 75 65 5f 32 30 0d 0a  |-020: value_20..|
000002b0: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
000002c0: 30 32 31 3a 20 76 61 6c  75 65 5f 32 31 0d 0a 58  |021: value_21..X|
000002d0: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
000002e0: 32 32 3a 20 76 61 6c 75  65 5f 32 32 0d 0a 58 2d  |22: value_22..X-|
000002f0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 32  |Custom-Header-02|
00000300: 33 3a 20 76 61 6c 75 65  5f 32 33 0d 0a 58 2d 43  |3: value_23..X-C|
00000310: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 32 34  |ustom-Header-024|
00000320: 3a 20 76 61 6c 75 65 5f  32 34 0d 0a 58 2d 43 75  |: value_24..X-Cu|
00000330: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 32 35 3a  |stom-Header-025:|
00000340: 20 76 61 6c 75 65 5f 32  35 0d 0a 58 2d 43 75 73  | value_25..X-Cus|
00000350: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 32 36 3a 20  |tom-Header-026: |
00000360: 76 61 6c 75 65 5f 32 36  0d 0a 58 2d 43 75 73 74  |value_26..X-Cust|
00000370: 6f 6d 2d 48 65 61 64 65  72 2d 30 32 37 3a 20 76  |om-Header-027: v|
00000380: 61 6c 75 65 5f 32 37 0d  0a 58 2d 43 75 73 74 6f  |alue_27..X-Custo|
00000390: 6d 2d 48 65 61 64 65 72  2d 30 32 38 3a 20 76 61  |m-Header-028: va|
000003a0: 6c 75 65 5f 32 38 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_28..X-Custom|
000003b0: 2d 48 65 61 64 65 72 2d  30 32 39 3a 20 76 61 6c  |-Header-029: val|
000003c0: 75 65 5f 32 39 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_29..X-Custom-|
000003d0: 48 65 61 64 65 72 2d 30  33 30 3a 20 76 61 6c 75  |Header-030: valu|
000003e0: 65 5f 33 30 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_30..X-Custom-H|
000003f0: 65 61 64 65 72 2d 30 33  31 3a 20 76 61 6c 75 65  |eader-031: value|
00000400: 5f 33 31 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_31..X-Custom-He|
00000410: 61 64 65 72 2d 30 33 32  3a 20 76 61 6c 75 65 5f  |ader-032: value_|
00000420: 33 32 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |32..X-Custom-Hea|
00000430: 64 65 72 2d 30 33 33 3a  20 76 61 6c 75 65 5f 33  |der-033: value_3|
00000440: 33 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |3..X-Custom-Head|
00000450: 65 72 2d 30 33 34 3a 20  76 61 6c 75 65 5f 33 34  |er-034: value_34|
00000460: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000470: 72 2d 30 33 35 3a 20 76  61 6c 75 65 5f 33 35 0d  |r-035: value_35.|
00000480: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000490: 2d 30 33 36 3a 20 76 61  6c 75 65 5f 33 36 0d 0a  |-036: value_36..|
000004a0: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
000004b0: 30 33 37 3a 20 76 61 6c  75 65 5f 33 37 0d 0a 58  |037: value_37..X|
000004c0: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
000004d0: 33 38 3a 20 76 61 6c 75  65 5f 33 38 0d 0a 58 2d  |38: value_38..X-|
000004e0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 33  |Custom-Header-03|
000004f0: 39 3a 20 76 61 6c 75 65  5f 33 39 0d 0a 58 2d 43  |9: value_39..X-C|
00000500: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 34 30  |ustom-Header-040|
00000510: 3a 20 76 61 6c 75 65 5f  34 30 0d 0a 58 2d 43 75  |: value_40..X-Cu|
00000520: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 34 31 3a  |stom-Header-041:|
00000530: 20 76 61 6c 75 65 5f 34  31 0d 0a 58 2d 43 75 73  | value_41..X-Cus|
00000540: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 34 32 3a 20  |tom-Header-042: |
00000550: 76 61 6c 75 65 5f 34 32  0d 0a 58 2d 43 75 73 74  |value_42..X-Cust|
00000560: 6f 6d 2d 48 65 61 64 65  72 2d 30 34 33 3a 20 76  |om-Header-043: v|
00000570: 61 6c 75 65 5f 34 33 0d  0a 58 2d 43 75 73 74 6f  |alue_43..X-Custo|
00000580: 6d 2d 48 65 61 64 65 72  2d 30 34 34 3a 20 76 61  |m-Header-044: va|
00000590: 6c 75 65 5f 34 34 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_44..X-Custom|
000005a0: 2d 48 65 61 64 65 72 2d  30 34 35 3a 20 76 61 6c  |-Header-045: val|
000005b0: 75 65 5f 34 35 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_45..X-Custom-|
000005c0: 48 65 61 64 65 72 2d 30  34 36 3a 20 76 61 6c 75  |Header-046: valu|
000005d0: 65 5f 34 36 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_46..X-Custom-H|
000005e0: 65 61 64 65 72 2d 30 34  37 3a 20 76 61 6c 75 65  |eader-047: value|
000005f0: 5f 34 37 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_47..X-Custom-He|
00000600: 61 64 65 72 2d 30 34 38  3a 20 76 61 6c 75 65 5f  |ader-048: value_|
00000610: 34 38 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |48..X-Custom-Hea|
00000620: 64 65 72 2d 30 34 39 3a  20 76 61 6c 75 65 5f 34  |der-049: value_4|
00000630: 39 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |9..X-Custom-Head|
00000640: 65 72 2d 30 35 30 3a 20  76 61 6c 75 65 5f 35 30  |er-050: value_50|
00000650: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000660: 72 2d 30 35 31 3a 20 76  61 6c 75 65 5f 35 31 0d  |r-051: value_51.|
00000670: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000680: 2d 30 35 32 3a 20 76 61  6c 75 65 5f 35 32 0d 0a  |-052: value_52..|
00000690: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
000006a0: 30 35 33 3a 20 76 61 6c  75 65 5f 35 33 0d 0a 58  |053: value_53..X|
000006b0: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
000006c0: 35 34 3a 20 76 61 6c 75  65 5f 35 34 0d 0a 58 2d  |54: value_54..X-|
000006d0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 35  |Custom-Header-05|
000006e0: 35 3a 20 76 61 6c 75 65  5f 35 35 0d 0a 58 2d 43  |5: value_55..X-C|
000006f0: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 35 36  |ustom-Header-056|
00000700: 3a 20 76 61 6c 75 65 5f  35 36 0d 0a 58 2d 43 75  |: value_56..X-Cu|
00000710: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 35 37 3a  |stom-Header-057:|
00000720: 20 76 61 6c 75 65 5f 35  37 0d 0a 58 2d 43 75 73  | value_57..X-Cus|
00000730: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 35 38 3a 20  |tom-Header-058: |
00000740: 76 61 6c 75 65 5f 35 38  0d 0a 58 2d 43 75 73 74  |value_58..X-Cust|
00000750: 6f 6d 2d 48 65 61 64 65  72 2d 30 35 39 3a 20 76  |om-Header-059: v|
00000760: 61 6c 75 65 5f 35 39 0d  0a 58 2d 43 75 73 74 6f  |alue_59..X-Custo|
00000770: 6d 2d 48 65 61 64 65 72  2d 30 36 30 3a 20 76 61  |m-Header-060: va|
00000780: 6c 75 65 5f 36 30 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_60..X-Custom|
00000790: 2d 48 65 61 64 65 72 2d  30 36 31 3a 20 76 61 6c  |-Header-061: val|
000007a0: 75 65 5f 36 31 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_61..X-Custom-|
000007b0: 48 65 61 64 65 72 2d 30  36 32 3a 20 76 61 6c 75  |Header-062: valu|
000007c0: 65 5f 36 32 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_62..X-Custom-H|
000007d0: 65 61 64 65 72 2d 30 36  33 3a 20 76 61 6c 75 65  |eader-063: value|
000007e0: 5f 36 33 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_63..X-Custom-He|
000007f0: 61 64 65 72 2d 30 36 34  3a 20 76 61 6c 75 65 5f  |ader-064: value_|
00000800: 36 34 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |64..X-Custom-Hea|
00000810: 64 65 72 2d 30 36 35 3a  20 76 61 6c 75 65 5f 36  |der-065: value_6|
00000820: 35 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |5..X-Custom-Head|
00000830: 65 72 2d 30 36 36 3a 20  76 61 6c 75 65 5f 36 36  |er-066: value_66|
00000840: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000850: 72 2d 30 36 37 3a 20 76  61 6c 75 65 5f 36 37 0d  |r-067: value_67.|
00000860: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000870: 2d 30 36 38 3a 20 76 61  6c 75 65 5f 36 38 0d 0a  |-068: value_68..|
00000880: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
00000890: 30 36 39 3a 20 76 61 6c  75 65 5f 36 39 0d 0a 58  |069: value_69..X|
000008a0: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
000008b0: 37 30 3a 20 76 61 6c 75  65 5f 37 30 0d 0a 58 2d  |70: value_70..X-|
000008c0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 37  |Custom-Header-07|
000008d0: 31 3a 20 76 61 6c 75 65  5f 37 31 0d 0a 58 2d 43  |1: value_71..X-C|
000008e0: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 37 32  |ustom-Header-072|
000008f0: 3a 20 76 61 6c 75 65 5f  37 32 0d 0a 58 2d 43 75  |: value_72..X-Cu|
00000900: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 37 33 3a  |stom-Header-073:|
00000910: 20 76 61 6c 75 65 5f 37  33 0d 0a 58 2d 43 75 73  | value_73..X-Cus|
00000920: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 37 34 3a 20  |tom-Header-074: |
00000930: 76 61 6c 75 65 5f 37 34  0d 0a 58 2d 43 75 73 74  |value_74..X-Cust|
00000940: 6f 6d 2d 48 65 61 64 65  72 2d 30 37 35 3a 20 76  |om-Header-075: v|
00000950: 61 6c 75 65 5f 37 35 0d  0a 58 2d 43 75 73 74 6f  |alue_75..X-Custo|
00000960: 6d 2d 48 65 61 64 65 72  2d 30 37 36 3a 20 76 61  |m-Header-076: va|
00000970: 6c 75 65 5f 37 36 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_76..X-Custom|
00000980: 2d 48 65 61 64 65 72 2d  30 37 37 3a 20 76 61 6c  |-Header-077: val|
00000990: 75 65 5f 37 37 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_77..X-Custom-|
000009a0: 48 65 61 64 65 72 2d 30  37 38 3a 20 76 61 6c 75  |Header-078: valu|
000009b0: 65 5f 37 38 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_78..X-Custom-H|
000009c0: 65 61 64 65 72 2d 30 37  39 3a 20 76 61 6c 75 65  |eader-079: value|
000009d0: 5f 37 39 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_79..X-Custom-He|
000009e0: 61 64 65 72 2d 30 38 30  3a 20 76 61 6c 75 65 5f  |ader-080: value_|
000009f0: 38 30 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |80..X-Custom-Hea|
00000a00: 64 65 72 2d 30 38 31 3a  20 76 61 6c 75 65 5f 38  |der-081: value_8|
00000a10: 31 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |1..X-Custom-Head|
00000a20: 65 72 2d 30 38 32 3a 20  76 61 6c 75 65 5f 38 32  |er-082: value_82|
00000a30: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000a40: 72 2d 30 38 33 3a 20 76  61 6c 75 65 5f 38 33 0d  |r-083: value_83.|
00000a50: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000a60: 2d 30 38 34 3a 20 76 61  6c 75 65 5f 38 34 0d 0a  |-084: value_84..|
00000a70: 58 2d 43 75 73 74 6f 6d  2d 48 65 61 64 65 72 2d  |X-Custom-Header-|
00000a80: 30 38 35 3a 20 76 61 6c  75 65 5f 38 35 0d 0a 58  |085: value_85..X|
00000a90: 2d 43 75 73 74 6f 6d 2d  48 65 61 64 65 72 2d 30  |-Custom-Header-0|
00000aa0: 38 36 3a 20 76 61 6c 75  65 5f 38 36 0d 0a 58 2d  |86: value_86..X-|
00000ab0: 43 75 73 74 6f 6d 2d 48  65 61 64 65 72 2d 30 38  |Custom-Header-08|
00000ac0: 37 3a 20 76 61 6c 75 65  5f 38 37 0d 0a 58 2d 43  |7: value_87..X-C|
00000ad0: 75 73 74 6f 6d 2d 48 65  61 64 65 72 2d 30 38 38  |ustom-Header-088|
00000ae0: 3a 20 76 61 6c 75 65 5f  38 38 0d 0a 58 2d 43 75  |: value_88..X-Cu|
00000af0: 73 74 6f 6d 2d 48 65 61  64 65 72 2d 30 38 39 3a  |stom-Header-089:|
00000b00: 20 76 61 6c 75 65 5f 38  39 0d 0a 58 2d 43 75 73  | value_89..X-Cus|
00000b10: 74 6f 6d 2d 48 65 61 64  65 72 2d 30 39 30 3a 20  |tom-Header-090: |
00000b20: 76 61 6c 75 65 5f 39 30  0d 0a 58 2d 43 75 73 74  |value_90..X-Cust|
00000b30: 6f 6d 2d 48 65 61 64 65  72 2d 30 39 31 3a 20 76  |om-Header-091: v|
00000b40: 61 6c 75 65 5f 39 31 0d  0a 58 2d 43 75 73 74 6f  |alue_91..X-Custo|
00000b50: 6d 2d 48 65 61 64 65 72  2d 30 39 32 3a 20 76 61  |m-Header-092: va|
00000b60: 6c 75 65 5f 39 32 0d 0a  58 2d 43 75 73 74 6f 6d  |lue_92..X-Custom|
00000b70: 2d 48 65 61 64 65 72 2d  30 39 33 3a 20 76 61 6c  |-Header-093: val|
00000b80: 75 65 5f 39 33 0d 0a 58  2d 43 75 73 74 6f 6d 2d  |ue_93..X-Custom-|
00000b90: 48 65 61 64 65 72 2d 30  39 34 3a 20 76 61 6c 75  |Header-094: valu|
00000ba0: 65 5f 39 34 0d 0a 58 2d  43 75 73 74 6f 6d 2d 48  |e_94..X-Custom-H|
00000bb0: 65 61 64 65 72 2d 30 39  35 3a 20 76 61 6c 75 65  |eader-095: value|
00000bc0: 5f 39 35 0d 0a 58 2d 43  75 73 74 6f 6d 2d 48 65  |_95..X-Custom-He|
00000bd0: 61 64 65 72 2d 30 39 36  3a 20 76 61 6c 75 65 5f  |ader-096: value_|
00000be0: 39 36 0d 0a 58 2d 43 75  73 74 6f 6d 2d 48 65 61  |96..X-Custom-Hea|
00000bf0: 64 65 72 2d 30 39 37 3a  20 76 61 6c 75 65 5f 39  |der-097: value_9|
00000c00: 37 0d 0a 58 2d 43 75 73  74 6f 6d 2d 48 65 61 64  |7..X-Custom-Head|
00000c10: 65 72 2d 30 39 38 3a 20  76 61 6c 75 65 5f 39 38  |er-098: value_98|
00000c20: 0d 0a 58 2d 43 75 73 74  6f 6d 2d 48 65 61 64 65  |..X-Custom-Heade|
00000c30: 72 2d 30 39 39 3a 20 76  61 6c 75 65 5f 39 39 0d  |r-099: value_99.|
00000c40: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000c50: 2d 31 30 30 3a 20 76 61  6c 75 65 5f 31 30 30 0d  |-100: value_100.|
00000c60: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000c70: 2d 31 30 31 3a 20 76 61  6c 75 65 5f 31 30 31 0d  |-101: value_101.|
00000c80: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000c90: 2d 31 30 32 3a 20 76 61  6c 75 65 5f 31 30 32 0d  |-102: value_102.|
00000ca0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000cb0: 2d 31 30 33 3a 20 76 61  6c 75 65 5f 31 30 33 0d  |-103: value_103.|
00000cc0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000cd0: 2d 31 30 34 3a 20 76 61  6c 75 65 5f 31 30 34 0d  |-104: value_104.|
00000ce0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000cf0: 2d 31 30 35 3a 20 76 61  6c 75 65 5f 31 30 35 0d  |-105: value_105.|
00000d00: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d10: 2d 31 30 36 3a 20 76 61  6c 75 65 5f 31 30 36 0d  |-106: value_106.|
00000d20: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d30: 2d 31 30 37 3a 20 76 61  6c 75 65 5f 31 30 37 0d  |-107: value_107.|
00000d40: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d50: 2d 31 30 38 3a 20 76 61  6c 75 65 5f 31 30 38 0d  |-108: value_108.|
00000d60: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d70: 2d 31 30 39 3a 20 76 61  6c 75 65 5f 31 30 39 0d  |-109: value_109.|
00000d80: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000d90: 2d 31 31 30 3a 20 76 61  6c 75 65 5f 31 31 30 0d  |-110: value_110.|
00000da0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000db0: 2d 31 31 31 3a 20 76 61  6c 75 65 5f 31 31 31 0d  |-111: value_111.|
00000dc0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000dd0: 2d 31 31 32 3a 20 76 61  6c 75 65 5f 31 31 32 0d  |-112: value_112.|
00000de0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000df0: 2d 31 31 33 3a 20 76 61  6c 75 65 5f 31 31 33 0d  |-113: value_113.|
00000e00: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e10: 2d 31 31 34 3a 20 76 61  6c 75 65 5f 31 31 34 0d  |-114: value_114.|
00000e20: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e30: 2d 31 31 35 3a 20 76 61  6c 75 65 5f 31 31 35 0d  |-115: value_115.|
00000e40: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e50: 2d 31 31 36 3a 20 76 61  6c 75 65 5f 31 31 36 0d  |-116: value_116.|
00000e60: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e70: 2d 31 31 37 3a 20 76 61  6c 75 65 5f 31 31 37 0d  |-117: value_117.|
00000e80: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000e90: 2d 31 31 38 3a 20 76 61  6c 75 65 5f 31 31 38 0d  |-118: value_118.|
00000ea0: 0a 58 2d 43 75 73 74 6f  6d 2d 48 65 61 64 65 72  |.X-Custom-Header|
00000eb0: 2d 31 31 39 3a 20 76 61  6c 75 65 5f 31 31 39 0d  |-119: value_119.|
00000ec0: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `3779 / 3779`
- **Parsed Method:** `GET`
- **Parsed URI:** `/many-headers`
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

### Finding 216: mutated_base_211_duplicate_cl_identical

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

### Finding 217: mutated_chunked_212

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 5 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 66 0d 0a 61 62  |chunked....f..ab|
00000050: 63 64 65 66 67 68 69 6a  6b 6c 6d 6e 6f 0d 0a 31  |cdefghijklmno..1|
00000060: 30 0d 0a 61 62 63 64 65  66 67 68 69 6a 6b 6c 6d  |0..abcdefghijklm|
00000070: 6e 6f 70 0d 0a 31 30 0d  0a 61 62 63 64 65 66 67  |nop..10..abcdefg|
00000080: 68 69 6a 6b 6c 6d 6e 6f  70 0d 0a 33 0d 0a 61 62  |hijklmnop..3..ab|
00000090: 63 0d 0a 33 0d 0a 61 62  63 0d 0a 30 0d 0a 0d 0a  |c..3..abc..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `160 / 160`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `53 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `59 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 53 bytes, HAProxy: 59 bytes)

---

### Finding 218: mutated_cl_te_rand_213

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (14) vs TE with payload len (19)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 34  |ntent-Length: 14|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 31 33 0d 0a 30 31 32 33  34 35 36 37 38 39 30 31  |13..012345678901|
00000070: 32 33 34 35 36 37 38 0d  0a 30 0d 0a 0d 0a        |2345678..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `126 / 126`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `19 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `25 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 19 bytes, HAProxy: 25 bytes)

---

### Finding 219: mutated_pipelined_pair_214

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  32 31 34 20 48 54 54 50  |GET /p1_214 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 32 31 34  |m....GET /p2_214|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_214`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_214`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 220: mutated_headers_ws_215

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 76 61 6c 75 65 5f  |Header-0: value_|
00000040: 30 0d 0a 58 2d 48 65 61  64 65 72 2d 31 20 3a 20  |0..X-Header-1 : |
00000050: 20 76 61 6c 75 65 5f 31  0d 0a 58 2d 48 65 61 64  | value_1..X-Head|
00000060: 65 72 2d 32 3a 20 20 76  61 6c 75 65 5f 32 0d 0a  |er-2:  value_2..|
00000070: 58 2d 48 65 61 64 65 72  2d 33 20 3a 20 76 61 6c  |X-Header-3 : val|
00000080: 75 65 5f 33 0d 0a 0d 0a                           |ue_3....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `136 / 136`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 221: mutated_cl_te_rand_216

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (19) vs TE with payload len (19)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 39  |ntent-Length: 19|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 31 33 0d 0a 30 31 32 33  34 35 36 37 38 39 30 31  |13..012345678901|
00000070: 32 33 34 35 36 37 38 0d  0a 30 0d 0a 0d 0a        |2345678..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `126 / 126`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `19 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `25 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 19 bytes, HAProxy: 25 bytes)

---

### Finding 222: mutated_startline_217

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line PATCH /api/v1/resource HTTP/1.1

#### Raw Input Hex Dump

```text
00000000: 50 41 54 43 48 20 2f 61  70 69 2f 76 31 2f 72 65  |PATCH /api/v1/re|
00000010: 73 6f 75 72 63 65 20 48  54 54 50 2f 31 2e 31 0d  |source HTTP/1.1.|
00000020: 48 6f 73 74 3a 20 65 78  61 6d 70 6c 65 2e 63 6f  |Host: example.co|
00000030: 6d 0d 0a 0d 0a                                    |m....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `53 / 53`
- **Parsed Method:** `PATCH`
- **Parsed URI:** `/api/v1/resource`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 223: mutated_startline_218

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line DELETE /index.html HTTP/1.0

#### Raw Input Hex Dump

```text
00000000: 44 45 4c 45 54 45 20 2f  69 6e 64 65 78 2e 68 74  |DELETE /index.ht|
00000010: 6d 6c 20 48 54 54 50 2f  31 2e 30 0d 0d 0a 48 6f  |ml HTTP/1.0...Ho|
00000020: 73 74 3a 20 65 78 61 6d  70 6c 65 2e 63 6f 6d 0d  |st: example.com.|
00000030: 0a 0d 0a                                          |...|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `30 / 51`
- **Parsed Method:** `DELETE`
- **Parsed URI:** `/index.html`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `true`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 224: mutated_chunked_219

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 1 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 38 0d 0a 61 62  |chunked....8..ab|
00000050: 63 64 65 66 67 68 0d 0a  30 0d 0a 0d 0a           |cdefgh..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `93 / 93`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `8 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `13 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 8 bytes, HAProxy: 13 bytes)

---

### Finding 225: mutated_startline_220

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line DELETE / HTTP/9.9

#### Raw Input Hex Dump

```text
00000000: 44 45 4c 45 54 45 20 2f  20 48 54 54 50 2f 39 2e  |DELETE / HTTP/9.|
00000010: 39 0d 48 6f 73 74 3a 20  65 78 61 6d 70 6c 65 2e  |9.Host: example.|
00000020: 63 6f 6d 0d 0a 0d 0a                              |com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `39 / 39`
- **Parsed Method:** `DELETE`
- **Parsed URI:** `/`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 226: mutated_base_221_cl_te_both_present_te_first

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in cl_te_both_present_te_first

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 73 6d  75 67 67 6c 65 20 48 54  |POST /smuggle HT|
00000010: 54 50 2f 31 2e 31 0d 0a  48 6f 73 74 3a 20 65 78  |TP/1.1..Host: ex|
00000020: 61 6d 70 6c 65 2e 63 6f  6d 0d 0a 54 72 61 6e 73  |ample.com..Trans|
00000030: 66 65 72 2d 45 6e 63 6f  64 69 6e 67 3a 20 63 68  |fer-Encoding: ch|
00000040: 75 6e 6b 00 64 0d 0a 43  6f 6e 74 65 6e 74 2d 4c  |unk.d..Content-L|
00000050: 65 6e 67 74 68 3a 20 36  0d 0a 0d 0a 30 0d 0a 0d  |ength: 6....0...|
00000060: 0a 58                                             |.X|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `98 / 98`
- **Parsed Method:** `POST`
- **Parsed URI:** `/smuggle`
- **Body Length:** `6 bytes`
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

### Finding 227: mutated_chunked_222

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 2 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 33 0d 0a 61 62  |chunked....3..ab|
00000050: 63 0d 0a 39 0d 0a 61 62  63 64 65 66 67 68 69 0d  |c..9..abcdefghi.|
00000060: 0a 30 0d 0a 0d 0a                                 |.0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `102 / 102`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `12 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `17 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 12 bytes, HAProxy: 17 bytes)

---

### Finding 228: mutated_pipelined_pair_223

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  32 32 33 20 48 54 54 50  |GET /p1_223 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 32 32 33  |m....GET /p2_223|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_223`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_223`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 229: mutated_cl_te_rand_224

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (10) vs TE with payload len (13)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 30  |ntent-Length: 10|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 64 0d 0a 30 31 32 33 34  35 36 37 38 39 30 31 32  |d..0123456789012|
00000070: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `119 / 119`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `13 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `18 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 13 bytes, HAProxy: 18 bytes)

---

### Finding 230: mutated_cl_te_rand_225

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (7) vs TE with payload len (19)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 37 0d  |ntent-Length: 7.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 31  |ng: chunked....1|
00000060: 33 0d 0a 30 31 32 33 34  35 36 37 38 39 30 31 32  |3..0123456789012|
00000070: 33 34 35 36 37 38 0d 0a  30 0d 0a 0d 0a           |345678..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `125 / 125`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `19 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `25 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 19 bytes, HAProxy: 25 bytes)

---

### Finding 231: mutated_base_226_duplicate_cl_identical

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in duplicate_cl_identical

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 64 75  70 2d 63 6c 20 48 54 54  |POST /dup-cl HTT|
00000010: 50 2f 31 2e 31 0d 0a 48  6f 73 74 3a 20 65 78 61  |P/1.1..Host: exa|
00000020: 6d 70 6c 65 2e 63 6f 6d  0d 00 43 6f 6e 74 65 6e  |mple.com..Conten|
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
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 232: mutated_base_227_te_prefix_unknown_encoding

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Mutated byte in te_prefix_unknown_encoding

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 74 65  2d 75 6e 6b 6e 6f 77 6e  |POST /te-unknown|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 54 72  | example.com..Tr|
00000030: 61 6e 73 66 65 20 2d 45  6e 63 6f 64 69 6e 67 3a  |ansfe -Encoding:|
00000040: 20 6e 6f 74 2d 63 68 75  6e 6b 65 64 0d 0a 0d 0a  | not-chunked....|
00000050: 35 0d 0a 68 65 6c 6c 6f  0d 0a 30 0d 0a 0d 0a     |5..hello..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `80 / 95`
- **Parsed Method:** `POST`
- **Parsed URI:** `/te-unknown`
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

### Finding 233: mutated_pipelined_pair_229

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  32 32 39 20 48 54 54 50  |GET /p1_229 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 32 32 39  |m....GET /p2_229|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_229`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_229`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 234: mutated_headers_ws_230

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 76 61 6c 75 65 5f  |Header-0: value_|
00000040: 30 0d 0a 58 2d 48 65 61  64 65 72 2d 31 3a 20 20  |0..X-Header-1:  |
00000050: 76 61 6c 75 65 5f 31 0d  0a 58 2d 48 65 61 64 65  |value_1..X-Heade|
00000060: 72 2d 32 20 3a 20 20 76  61 6c 75 65 5f 32 0d 0a  |r-2 :  value_2..|
00000070: 58 2d 48 65 61 64 65 72  2d 33 3a 20 76 61 6c 75  |X-Header-3: valu|
00000080: 65 5f 33 0d 0a 58 2d 48  65 61 64 65 72 2d 34 3a  |e_3..X-Header-4:|
00000090: 20 20 76 61 6c 75 65 5f  34 0d 0a 58 2d 48 65 61  |  value_4..X-Hea|
000000a0: 64 65 72 2d 35 20 3a 20  20 76 61 6c 75 65 5f 35  |der-5 :  value_5|
000000b0: 0d 0a 58 2d 48 65 61 64  65 72 2d 36 3a 20 76 61  |..X-Header-6: va|
000000c0: 6c 75 65 5f 36 0d 0a 0d  0a                       |lue_6....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `201 / 201`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 235: mutated_pipelined_pair_231

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  32 33 31 20 48 54 54 50  |GET /p1_231 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 32 33 31  |m....GET /p2_231|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_231`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_231`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 236: mutated_headers_ws_233

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 76 61 6c 75 65 5f  |Header-0: value_|
00000040: 30 0d 0a 58 2d 48 65 61  64 65 72 2d 31 3a 20 20  |0..X-Header-1:  |
00000050: 76 61 6c 75 65 5f 31 0d  0a 58 2d 48 65 61 64 65  |value_1..X-Heade|
00000060: 72 2d 32 20 3a 20 76 61  6c 75 65 5f 32 0d 0a 58  |r-2 : value_2..X|
00000070: 2d 48 65 61 64 65 72 2d  33 3a 20 76 61 6c 75 65  |-Header-3: value|
00000080: 5f 33 0d 0a 58 2d 48 65  61 64 65 72 2d 34 3a 20  |_3..X-Header-4: |
00000090: 76 61 6c 75 65 5f 34 0d  0a 0d 0a                 |value_4....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `155 / 155`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 237: mutated_cl_te_rand_235

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (6) vs TE with payload len (14)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 36 0d  |ntent-Length: 6.|
00000040: 0a 54 72 61 6e 73 66 65  72 2d 45 6e 63 6f 64 69  |.Transfer-Encodi|
00000050: 6e 67 3a 20 63 68 75 6e  6b 65 64 0d 0a 0d 0a 65  |ng: chunked....e|
00000060: 0d 0a 30 31 32 33 34 35  36 37 38 39 30 31 32 33  |..01234567890123|
00000070: 0d 0a 30 0d 0a 0d 0a                              |..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `119 / 119`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `14 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `19 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 14 bytes, HAProxy: 19 bytes)

---

### Finding 238: mutated_cl_te_rand_236

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (10) vs TE with payload len (11)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 30  |ntent-Length: 10|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 62 0d 0a 30 31 32 33 34  35 36 37 38 39 30 0d 0a  |b..01234567890..|
00000070: 30 0d 0a 0d 0a                                    |0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `117 / 117`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `11 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `16 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 11 bytes, HAProxy: 16 bytes)

---

### Finding 239: mutated_pipelined_pair_237

- **Category:** Category 3: Request Smuggling Boundary Finding (Next Request Desync)
- **Ambiguity Class:** Pipelined Request Boundaries
- **Description:** Randomized pipelined pair

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 70 31 5f  32 33 37 20 48 54 54 50  |GET /p1_237 HTTP|
00000010: 2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 61 2e 63 6f  |/1.1..Host: a.co|
00000020: 6d 0d 0a 0d 0a 47 45 54  20 2f 70 32 5f 32 33 37  |m....GET /p2_237|
00000030: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000040: 20 62 2e 63 6f 6d 0d 0a  0d 0a                    | b.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `37 / 74`
- **Parsed Method:** `GET`
- **Parsed URI:** `/p1_237`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `GET`
- **Forwarded URI:** `/p1_237`
- **Forwarded Body Length:** `0 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 240: mutated_startline_240

- **Category:** Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized start-line DELETE /deep/nested/path?q=1&v=2 HTTP/0.9

#### Raw Input Hex Dump

```text
00000000: 44 45 4c 45 54 45 20 2f  64 65 65 70 2f 6e 65 73  |DELETE /deep/nes|
00000010: 74 65 64 2f 70 61 74 68  3f 71 3d 31 26 76 3d 32  |ted/path?q=1&v=2|
00000020: 20 48 54 54 50 2f 30 2e  39 0d 48 6f 73 74 3a 20  | HTTP/0.9.Host: |
00000030: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 0d 0a     |example.com....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `63 / 63`
- **Parsed Method:** `DELETE`
- **Parsed URI:** `/deep/nested/path?q=1&v=2`
- **Body Length:** `0 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `false`
- **HTTP Status Code:** `Some(400)`
- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.

---

### Finding 241: mutated_chunked_241

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 2 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 37 0d 0a 61 62  |chunked....7..ab|
00000050: 63 64 65 66 67 0d 0a 35  0d 0a 61 62 63 64 65 0d  |cdefg..5..abcde.|
00000060: 0a 30 0d 0a 0d 0a                                 |.0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `102 / 102`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `12 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `17 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 12 bytes, HAProxy: 17 bytes)

---

### Finding 242: mutated_chunked_243

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized chunked sequence of 1 chunks

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 6d 75  74 2d 63 68 75 6e 6b 20  |POST /mut-chunk |
00000010: 48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |
00000020: 65 78 61 6d 70 6c 65 2e  63 6f 6d 0d 0a 54 72 61  |example.com..Tra|
00000030: 6e 73 66 65 72 2d 45 6e  63 6f 64 69 6e 67 3a 20  |nsfer-Encoding: |
00000040: 63 68 75 6e 6b 65 64 0d  0a 0d 0a 38 0d 0a 61 62  |chunked....8..ab|
00000050: 63 64 65 66 67 68 0d 0a  30 0d 0a 0d 0a           |cdefgh..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `93 / 93`
- **Parsed Method:** `POST`
- **Parsed URI:** `/mut-chunk`
- **Body Length:** `8 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/mut-chunk`
- **Forwarded Body Length:** `13 bytes`
- **Saw Sentinel Next Request:** `true`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 8 bytes, HAProxy: 13 bytes)

---

### Finding 243: mutated_headers_ws_245

- **Category:** Category 1: Acceptance Disagreement (Accepted vs Rejected)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Randomized header whitespace permutations

#### Raw Input Hex Dump

```text
00000000: 47 45 54 20 2f 6d 75 74  2d 68 65 61 64 65 72 73  |GET /mut-headers|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 58 2d  | example.com..X-|
00000030: 48 65 61 64 65 72 2d 30  3a 20 20 76 61 6c 75 65  |Header-0:  value|
00000040: 5f 30 0d 0a 58 2d 48 65  61 64 65 72 2d 31 3a 20  |_0..X-Header-1: |
00000050: 76 61 6c 75 65 5f 31 0d  0a 58 2d 48 65 61 64 65  |value_1..X-Heade|
00000060: 72 2d 32 3a 20 20 76 61  6c 75 65 5f 32 0d 0a 58  |r-2:  value_2..X|
00000070: 2d 48 65 61 64 65 72 2d  33 3a 20 76 61 6c 75 65  |-Header-3: value|
00000080: 5f 33 0d 0a 58 2d 48 65  61 64 65 72 2d 34 20 3a  |_3..X-Header-4 :|
00000090: 20 20 76 61 6c 75 65 5f  34 0d 0a 58 2d 48 65 61  |  value_4..X-Hea|
000000a0: 64 65 72 2d 35 3a 20 76  61 6c 75 65 5f 35 0d 0a  |der-5: value_5..|
000000b0: 0d 0a                                             |..|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `178 / 178`
- **Parsed Method:** `GET`
- **Parsed URI:** `/mut-headers`
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

### Finding 244: mutated_base_247_pipelined_standard_two_requests

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
- **Next Request Smuggled / Desynced:** `true`

#### Security Analysis & Root Cause

HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.

---

### Finding 245: mutated_cl_te_rand_249

- **Category:** Category 2: Request Framing Disagreement (Method/Path/Headers/Body)
- **Ambiguity Class:** Combinatorial Mutations
- **Description:** Combinatorial CL (13) vs TE with payload len (4)

#### Raw Input Hex Dump

```text
00000000: 50 4f 53 54 20 2f 63 6c  2d 74 65 2d 72 61 6e 64  |POST /cl-te-rand|
00000010: 20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020: 20 65 78 61 6d 70 6c 65  2e 63 6f 6d 0d 0a 43 6f  | example.com..Co|
00000030: 6e 74 65 6e 74 2d 4c 65  6e 67 74 68 3a 20 31 33  |ntent-Length: 13|
00000040: 0d 0a 54 72 61 6e 73 66  65 72 2d 45 6e 63 6f 64  |..Transfer-Encod|
00000050: 69 6e 67 3a 20 63 68 75  6e 6b 65 64 0d 0a 0d 0a  |ing: chunked....|
00000060: 34 0d 0a 30 31 32 33 0d  0a 30 0d 0a 0d 0a        |4..0123..0....|
```

#### Ibex Behavior

- **Accepted:** `true`
- **Phase:** `Done`
- **Consumed Bytes:** `110 / 110`
- **Parsed Method:** `POST`
- **Parsed URI:** `/cl-te-rand`
- **Body Length:** `4 bytes`
- **Connection Close Set:** `false`

#### HAProxy Behavior

- **Accepted:** `true`
- **HTTP Status Code:** `Some(200)`
- **Forwarded Method:** `POST`
- **Forwarded URI:** `/cl-te-rand`
- **Forwarded Body Length:** `9 bytes`
- **Saw Sentinel Next Request:** `false`
- **Next Request Smuggled / Desynced:** `false`

#### Security Analysis & Root Cause

Body length mismatch (Ibex: 4 bytes, HAProxy: 9 bytes)

---

