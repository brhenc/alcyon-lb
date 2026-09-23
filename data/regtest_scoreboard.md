# Reg-Test Scoreboard

Generated 2026-09-23 against HAProxy 3.5-dev7 reg-tests.

**10 of 312 passing** (216 failing, 86 skipped).

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

| Cause | Count | Nature |
|---|---:|---|
| Behavioural: parses, runs, wrong answer | **142** | the genuine debt |
| Address forms: `fd@`, `unix@`, ABNS | 31 | config surface, mechanical |
| Unknown keyword, ~18 distinct directives | ~40 | config surface, mechanical |
| vtest `${PORT}` not substituted | 2 | harness |

The unknown keywords, by how many tests each blocks: `log-format` 8, `http-check` 5,
`tcp-check` 3, `capture` 3, then `use-server`, `unique-id-format`, `tcp-response`,
`errorfile`, `ring`, `guid`, `hash-preserve-affinity`, `force-be-switch`, `monitor-uri`,
`http-error`, `external-check`, `unique-id-header` at one or two apiece.

So roughly **70 of the 216 never reach Ibex's behaviour at all** — they die at the config
parser or on an address form. That part is mechanical and unblocks a third of the board.
The remaining 142 are real.

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
