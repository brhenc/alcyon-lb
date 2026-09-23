# Reg-Test Scoreboard

Generated 2026-09-23 against HAProxy 3.5-dev7 reg-tests.

**7 of 171 in-scope tests passing** — 164 failing, 89 skipped, 52 out of scope.

The raw figure is 7 of 312. The denominator that means something is 171: the suite contains
114 tests for features declined in `tradeoff.md` §4.2, and 89 more gated off or asserting
nothing. Counting either as debt measures a decision rather than a gap.

**Three of the ten previously-reported passes were vacuous** and are now skips —
`cache/caching_rules.vtc`, `mcli/mcli_show_info.vtc` and
`webstats/missing-stats-fields.vtc`. The worst of them declares 93 `expect` statements;
the run started two mock servers, never launched the proxy, never ran a client, evaluated
nothing, and finished PASS in 0.00 s.

The cause was the guard that was supposed to prevent exactly this. It checked which
directives the file *declared* rather than what ran, so declaring a `server` block was
enough. It now requires that at least one assertion was actually evaluated. Two of the
three were found by spot-checking the out-of-scope passes; the third the guard found on its
own.

Previous run, 2026-09-22: **14 / 212 / 86**.

Run: `python3 harness/vtc_runner.py /home/bhenc/reference/haproxy/reg-tests/ --json /tmp/rt.json`

## The number that matters

Between these two runs the project landed `tcp-request` connection/session/content rules,
the HTX flat representation on the data path, HTTP/2 reachability, the pool allocator and
the allocation work. **The board moved −4.**

Three tests were gained and seven lost:

| Directory | was | now |
|---|---:|---:|
| converter | 0 | 1 |
| http-messaging | 1 | 2 |
| sample_fetches | 0 | 1 |
| http-rules | 3 | 2 |
| server | 3 | **0** |
| startup | 1 | 0 |
| stats | 1 | 0 |
| stick-table | 1 | 0 |

That is not an argument against the work — none of it was aimed here. It is an argument
that conformance has not been anybody's oracle for two days, and a suite nobody runs stops
being a measurement.

## Why the 216 fail

Categorised from each result's `error_message`, not by pattern-matching the whole record.
An earlier revision of this file reported 142 behavioural and ~70 config-surface; those
numbers came from a categoriser that searched the serialised row and mis-attributed
several buckets. These are the corrected counts.

| Cause | Count |
|---|---:|
| **Behavioural**: parses, runs, wrong answer | **107** |
| Config surface, total | **103** |
| CLI: `Unknown command` from the runtime socket | 6 |

Breaking the 103 down:

| Config-surface cause | Count | Example |
|---|---:|---|
| `unknown http-request action <cache-use>` | 13 | `cache/basic.vtc` |
| address form `stream+${h1_ssl_sock}` | 14 | `ssl/add_ssl_crt-list.vtc` |
| `unknown keyword <log-format>` | 8 | `http-messaging/h1_authority_fragment_char.vtc` |
| `unknown keyword <http-check>` | 5 | `checks/4be_1srv_smtpchk_httpchk_layer47errors.vtc` |
| `invalid IP address` | 5 | `log/log_backend.vtc` |
| `unknown keyword <tcp-check>` | 3 | `checks/tcp-check-ssl.vtc` |
| `unknown keyword <capture>` | 3 | `http-capture/multiple_headers.vtc` |
| address form `from` | 3 | `http-rules/default_rules.vtc` |
| `unknown balance algorithm` | 3 | `server/cli_add_server.vtc` |
| ~14 further keywords and actions | 1–2 each | `hash-preserve-affinity`, `unique-id-format`, `wait-for-body`, `set-retries`, `set-dst-port`, `do-resolve`, `reject`, … |

So the split is close to even: **roughly half the board never reaches Ibex's behaviour**,
and the other half is genuine behavioural debt. That is a better position than the raw
10/312 suggests, and a worse one than "it is all parser stubs" would.

**That inflation is now fixed.** The harness consults the `OUT_OF_SCOPE` triage in
`data/regtests.json` and reports a fourth status, `[SCOPE]`, for the 52 failures that were
only measuring declined features — 13 of them `cache-use`. Failures fall 216 → 164.

Out-of-scope tests are still **run**, not skipped. This project has been bitten once by a
status meaning "nobody asked", when 84 tests hid behind a skip and the board read better
than the truth. Running them costs a second and buys two things: the failure text stays
available, and a declined feature that passes anyway gets reported instead of hidden.

Three do pass and are flagged: `cache/caching_rules.vtc`,
`http-messaging/http_bodyless_response.vtc` and `mcli/mcli_show_info.vtc`. A cache test
passing against a daemon with no cache is more likely vacuous than good news, and is worth
a look.

## The honest denominator

`data/regtests.json` triages 312 tests as 114 `OUT_OF_SCOPE` (Lua, QUIC, filters, cache,
SPOE, FCGI — declined in `tradeoff.md` §4.2), 147 `REACHABLE_LATER`, 51 `REACHABLE_NOW`.

Against a reachable denominator of 198, 10 passing is 5%. Against 51 triaged as reachable
with what already exists, it is 20%. Quoting 10/312 understates the position; quoting
10/51 overstates it. Both numbers belong next to each other.

## Specific findings from this run

**The `server` directory lost all three passes**, and several of its tests now fail with
`Unknown command. Please enter 'help' for a list` from the runtime socket — `add server`,
`del server` and the dynamic-server family. Either those CLI commands regressed or they
were never implemented and something else used to carry the test.

**`startup/default_rules.vtc`: "Config check unexpectedly succeeded (-conf-BAD)."** Ibex
accepted a configuration HAProxy rejects. That is the direction that matters — a parser
that is too permissive is how a typo becomes a silent production difference.

**`startup/check_condition.vtc`: `/bin/sh: line 3: -cc: command not found`.** A harness
bug, not an Ibex one: the shell block is executed without the binary path prepended.

**`stats/clear_counters_server.vtc`** expects `No such backend` and Ibex says
`No such proxy.` — a one-word message difference, and the cheapest pass on the board.

## Caveat on an earlier reading

An intermediate analysis of this data concluded that 36 of the 51 `REACHABLE_NOW` tests
failed because Ibex does not expand `${VAR-default}` in configuration files. **That was
wrong.** It came from extracting the raw `-conf` block and running `ibex -c` on it
directly, which skips the substitution the harness does at `vtc_runner.py:619`. The real
run shows no such failures. Recorded because the wrong number was nearly the headline.

## T17 Config Surface Run

**Pass count before:** 7
**Pass count after:** 7
**Failing before:** 164
**Failing after:** 164

No tests that passed before are failing now.

- `missing port in address` failures (31 tests) on prefixes like `unix@`, `fd@`, `abns@` were correctly changed to fail with `address prefix <prefix> is not implemented`.
- `startup/default_rules.vtc` still reports "Config check unexpectedly succeeded". The underlying parser flaws (closing unknown keywords in `global` and `defaults` sections, refusing `http-request`/`http-response`/`http-after-request`/`tcp-response` in `defaults`, refusing `defaults <name>`, and refusing inline `from`) were fixed. The remaining failure is blocked by a harness bug where `vtc_runner.py`'s manual block parser incorrectly extracts an empty configuration for `haproxy h1 -conf-BAD {} {`, which `ibex` correctly parses as a valid empty configuration (returning 0).
- Keywords `log-format`, `capture`, `http-check`, `tcp-check` etc. were left unimplemented and continue to fail with `unknown keyword`. Implementing them would require changes to `ibex-rt` to evaluate them on the data path, which is out of bounds for this session. Accepting them without implementing them would violate Rule 5.
- `stats/clear_counters_server.vtc` is blocked because the required string `No such proxy.` resides in `crates/ibex-rt/src/applet.rs` which is strictly out of bounds.
