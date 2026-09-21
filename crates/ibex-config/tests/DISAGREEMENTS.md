# HAProxy 1.0.2 Parser Disagreements and Oracle Discrepancies

This document details all test cases where `ibex-config` and the HAProxy 1.0.2 reference binary (`/home/bhenc/reference/haproxy-1.0.2/haproxy102`) produce different verdicts (accept vs. reject).

In HAProxy 1.0.2 (`haproxy.c`), several parsing decisions rely on standard C library functions (`atol()`, `htons()`, unvalidated string slicing) that silently accepted malformed inputs or produced undefined/unintended runtime states. In `ibex-config`, untrusted configuration input is parsed into a strongly-typed AST, rejecting malformed data with actionable errors indicating line and column.

---

## Disagreement 1: Non-numeric integer arguments (`retries abc`, `maxconn xyz`)

- **File**: `tests/corpus/34_non_numeric_retries.cfg`
- **Config input**:
  ```haproxy
  listen p1 0.0.0.0:8001
      retries abc
  ```
- **HAProxy 1.0.2 Behavior**:
  - Verdict: **ACCEPT** (Exit code 0, stays running).
  - Diagnostic: None.
  - Cause: In `haproxy.c:2664`:
    ```c
    curproxy->conn_retries = atol(args[1]);
    ```
    `atol("abc")` returns `0`. HAProxy silently sets `conn_retries = 0` without reporting an error.
- **Ibex Behavior**:
  - Verdict: **REJECT**
  - Error: `line 2, col 10: 'retries' expects an integer, found "abc"`
- **Assessment**:
  - **Ibex is correct**. Silently treating invalid non-numeric text as `0` retries masks operational configuration mistakes. Strong validation prevents accidental misconfiguration.

---

## Disagreement 2: Negative integer arguments (`retries -5`)

- **File**: `tests/corpus/35_negative_retries.cfg`
- **Config input**:
  ```haproxy
  listen p1 0.0.0.0:8001
      retries -5
  ```
- **HAProxy 1.0.2 Behavior**:
  - Verdict: **ACCEPT** (Exit code 0, stays running).
  - Diagnostic: None.
  - Cause: In `haproxy.c:2664`:
    `atol("-5")` returns `-5`. `curproxy->conn_retries` is a signed `int` in C, storing `-5`.
- **Ibex Behavior**:
  - Verdict: **REJECT**
  - Error: `line 2, col 10: 'retries' expects an integer, found "-5"`
- **Assessment**:
  - **Ibex is correct**. Retry counts and connection limits cannot be negative. Requiring non-negative unsigned integers (`u32`) adheres to the domain semantics of networking timeouts and limits.

---

## Disagreement 3: Non-numeric timeouts (`contimeout xyz`, `clitimeout bad`)

- **File**: `tests/corpus/36_non_numeric_contimeout.cfg`
- **Config input**:
  ```haproxy
  listen p1 0.0.0.0:8001
      contimeout xyz
  ```
- **HAProxy 1.0.2 Behavior**:
  - Verdict: **ACCEPT** (Exit code 0, stays running).
  - Diagnostic: None.
  - Cause: In `haproxy.c:2630`:
    ```c
    curproxy->contimeout = atol(args[1]);
    ```
    `atol("xyz")` returns `0`. `contimeout` is set to 0 (no timeout).
- **Ibex Behavior**:
  - Verdict: **REJECT**
  - Error: `line 2, col 13: 'contimeout' expects an integer, found "xyz"`
- **Assessment**:
  - **Ibex is correct**. Timeouts must be valid millisecond counts. A typo in a timeout should fail fast at configuration parse time rather than leaving sockets without timeouts.

---

## Disagreement 4: Out-of-range TCP port numbers (`listen p1 0.0.0.0:70000`)

- **File**: `tests/corpus/37_out_of_range_port.cfg`
- **Config input**:
  ```haproxy
  listen p1 0.0.0.0:70000
      mode tcp
  ```
- **HAProxy 1.0.2 Behavior**:
  - Verdict: **ACCEPT** at parse time (Exit code 0, attempts to bind).
  - Diagnostic: None at config parse time.
  - Cause: In `haproxy.c:469-492` (`str2sa`):
    ```c
    port = atol(c);
    sa.sin_port = htons(port);
    ```
    `htons(70000)` truncates the 32-bit `atol` result into a 16-bit unsigned short (`70000 & 0xFFFF = 4464`). HAProxy silently binds to port `4464` instead of 70000!
- **Ibex Behavior**:
  - Verdict: **REJECT**
  - Error: `line 1, col 19: invalid port '70000' (must be 0..=65535)`
- **Assessment**:
  - **Ibex is correct**. TCP port numbers above 65535 are invalid in IPv4/IPv6 networking. Silently truncating `70000` to `4464` is a serious 2001-era C overflow bug.

---

## Summary of Corpus Results

- Total corpus test cases: **39**
- **Agreed with HAProxy 1.0.2 Oracle**: **35 / 39 (89.7%)**
  - 12 valid configs accepted by both.
  - 23 invalid configs rejected by both with matching verdicts.
- **Documented Disagreements**: **4 / 39 (10.3%)**
  - All 4 disagreements represent invalid input (non-numeric integers, negative numbers, out-of-range ports) where HAProxy 1.0.2 silently accepted invalid input due to `atol()` / `htons()` truncation bugs.
