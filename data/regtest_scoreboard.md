# Reg-Test Scoreboard

Generated 2026-09-22 against HAProxy 3.5-dev7 reg-tests, after `-cc` was
implemented and the harness stopped passing tests that executed nothing.

**14 of 312 passing** (212 failing, 86 skipped).

Previous run read 12 / 130 / 170. Failures rose because 84 tests came out from
behind a skip: every `-cc` gate failed against a binary that did not implement
`-cc`, and every `include`-only file parsed to zero directives and was scored a
pass. Both are fixed, so the board now counts things Ibex cannot do rather than
things nobody asked it to do.

Run: `python3 harness/vtc_runner.py /home/bhenc/reference/haproxy/reg-tests/ --json out.json`

| Directory | Pass | Fail | Skip |
|---|---:|---:|---:|
| balance | 1 | 4 | 0 |
| cache | 1 | 13 | 0 |
| checks | 0 | 24 | 1 |
| compression | 0 | 0 | 5 |
| connection | 0 | 17 | 2 |
| contrib | 0 | 0 | 1 |
| converter | 0 | 25 | 0 |
| decompression | 0 | 0 | 5 |
| filters | 0 | 0 | 1 |
| http-capture | 0 | 1 | 0 |
| http-cookies | 0 | 2 | 0 |
| http-errorfiles | 0 | 5 | 0 |
| http-messaging | 1 | 19 | 4 |
| http-rules | 3 | 18 | 1 |
| jwt | 0 | 1 | 1 |
| log | 0 | 11 | 0 |
| lua | 0 | 0 | 10 |
| mailers | 0 | 0 | 1 |
| mcli | 1 | 2 | 0 |
| peers | 0 | 4 | 0 |
| protobuf | 0 | 1 | 0 |
| proxy | 0 | 3 | 0 |
| qmux | 0 | 0 | 2 |
| quic | 0 | 0 | 30 |
| resolvers | 0 | 1 | 0 |
| sample_fetches | 0 | 12 | 0 |
| seamless-reload | 0 | 1 | 0 |
| server | 3 | 8 | 0 |
| spoe | 0 | 1 | 0 |
| ssl | 0 | 25 | 22 |
| startup | 1 | 2 | 0 |
| stats | 1 | 2 | 0 |
| stick-table | 1 | 2 | 0 |
| stickiness | 0 | 2 | 0 |
| stream | 0 | 4 | 0 |
| tcp-rules | 0 | 1 | 0 |
| webstats | 1 | 1 | 0 |

## Why the failures

Cause of *first* failure; a config error masks everything behind it.

| Count | Cause |
|---:|---|
| 45 | runtime: assertion mismatch |
| 21 | runtime: client got EOF |
| 19 | cfg: invalid IP address 'stderr' |
| 15 | cfg: <tcp-request> expects 'connection <action>' |
| 10 | cfg: unknown http-request action <cache-use> |
| 10 | cfg: unknown log facility <len> |
| 9 | cfg: unknown keyword `http-reuse` |
| 8 | runtime: client could not connect |
| 8 | runtime: other |
| 8 | cfg: unknown keyword `log-format` |
| 7 | runtime: syslog expectation unmet |
| 3 | cfg: unknown keyword `capture` |
| 3 | cfg: missing port in address 'from' |
| 3 | cfg: invalid IP address 'ring@myring' |
| 3 | cfg: unknown balance algorithm <random> |
| 2 | cfg: unknown keyword `hash-preserve-affinity` |
| 2 | cfg: missing port in address 'rhttp@' |
| 2 | cfg: unknown keyword `errorfile` |
| 2 | cfg: unknown http-request action <wait-for-body> |
| 2 | cfg: unknown keyword `use-server` |

## Passing

- `balance/balance-rr.vtc`
- `cache/caching_rules.vtc`
- `http-messaging/http_bodyless_response.vtc`
- `http-rules/del_header.vtc`
- `http-rules/set_timeout.vtc`
- `http-rules/strict_rw_mode.vtc`
- `mcli/mcli_show_info.vtc`
- `server/cli_set_fqdn.vtc`
- `server/cli_set_ssl.vtc`
- `server/from_keyword.vtc`
- `startup/automatic_maxconn.vtc`
- `stats/clear_counters_server.vtc`
- `stick-table/converteers_ref_cnt_never_dec.vtc`
- `webstats/missing-stats-fields.vtc`
