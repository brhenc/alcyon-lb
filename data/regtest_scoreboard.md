# Reg-Test Scoreboard

Generated 2026-09-21 against HAProxy 3.5-dev7 reg-tests.

**11 of 312 passing** (131 failing, 170 skipped).

Run: `python3 harness/vtc_runner.py /home/bhenc/reference/haproxy/reg-tests/ --json out.json`

| Directory | Pass | Fail | Skip |
|---|---:|---:|---:|
| balance | 1 | 4 | 0 |
| cache | 1 | 13 | 0 |
| checks | 0 | 20 | 5 |
| compression | 0 | 0 | 5 |
| connection | 0 | 10 | 9 |
| contrib | 0 | 0 | 1 |
| converter | 0 | 13 | 12 |
| decompression | 0 | 0 | 5 |
| filters | 0 | 0 | 1 |
| http-capture | 0 | 1 | 0 |
| http-cookies | 0 | 2 | 0 |
| http-errorfiles | 0 | 5 | 0 |
| http-messaging | 1 | 12 | 11 |
| http-rules | 0 | 15 | 7 |
| jwt | 0 | 0 | 2 |
| log | 0 | 7 | 4 |
| lua | 0 | 0 | 10 |
| mailers | 0 | 0 | 1 |
| mcli | 2 | 1 | 0 |
| peers | 0 | 2 | 2 |
| protobuf | 0 | 0 | 1 |
| proxy | 0 | 3 | 0 |
| qmux | 0 | 0 | 2 |
| quic | 0 | 0 | 30 |
| resolvers | 0 | 1 | 0 |
| sample_fetches | 0 | 7 | 5 |
| seamless-reload | 0 | 1 | 0 |
| server | 2 | 4 | 5 |
| spoe | 1 | 0 | 0 |
| ssl | 0 | 0 | 47 |
| startup | 0 | 0 | 3 |
| stats | 1 | 1 | 1 |
| stick-table | 2 | 1 | 0 |
| stickiness | 0 | 2 | 0 |
| stream | 0 | 4 | 0 |
| tcp-rules | 0 | 0 | 1 |
| webstats | 0 | 2 | 0 |

## Top config-keyword blockers

Each line is a keyword whose absence stops the proxy starting, and how many
tests it blocks. This is the cheapest win list, ordered.

| Keyword | Tests blocked |
|---|---:|
| `log` | 15 |
| `http-reuse` | 9 |
| `option` | 8 |
| `hash-preserve-affinity` | 2 |
| `errorfile` | 2 |
| `force-be-switch` | 2 |
| `monitor-uri` | 1 |
| `unique-id-header` | 1 |
| `http-error` | 1 |
| `errorfiles` | 1 |
| `capture` | 1 |
| `log-format` | 1 |

## Reading this

The 170 skips are mostly feature conditions the runner cannot satisfy
(`version_atleast`, SSL/Lua/QUIC requirements). They are not failures, but they
are also not passes -- the reachable ceiling is lower than 312.

Passing tests span 8 directories (balance, cache, http-messaging, mcli, server,
spoe, stats, stick-table), so the core data path works for some real cases. The
dominant failure mode is still missing config vocabulary rather than wrong
proxying behaviour.
