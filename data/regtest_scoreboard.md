# Reg-Test Scoreboard

Generated 2026-09-22 against HAProxy 3.5-dev7 reg-tests.

**12 of 312 passing** (130 failing, 170 skipped).

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
| http-rules | 3 | 12 | 7 |
| jwt | 0 | 0 | 2 |
| log | 0 | 7 | 4 |
| lua | 0 | 0 | 10 |
| mailers | 0 | 0 | 1 |
| mcli | 1 | 2 | 0 |
| peers | 0 | 2 | 2 |
| protobuf | 0 | 0 | 1 |
| proxy | 0 | 3 | 0 |
| qmux | 0 | 0 | 2 |
| quic | 0 | 0 | 30 |
| resolvers | 0 | 1 | 0 |
| sample_fetches | 0 | 7 | 5 |
| seamless-reload | 0 | 1 | 0 |
| server | 2 | 4 | 5 |
| spoe | 0 | 1 | 0 |
| ssl | 0 | 0 | 47 |
| startup | 0 | 0 | 3 |
| stats | 1 | 1 | 1 |
| stick-table | 1 | 2 | 0 |
| stickiness | 0 | 2 | 0 |
| stream | 0 | 4 | 0 |
| tcp-rules | 0 | 0 | 1 |
| webstats | 1 | 1 | 0 |

## Passing

- `balance/balance-rr.vtc`
- `cache/caching_rules.vtc`
- `http-messaging/http_bodyless_response.vtc`
- `http-rules/del_header.vtc`
- `http-rules/set_timeout.vtc`
- `http-rules/strict_rw_mode.vtc`
- `mcli/mcli_show_info.vtc`
- `server/cli_set_fqdn.vtc`
- `server/from_keyword.vtc`
- `stats/clear_counters_server.vtc`
- `stick-table/converteers_ref_cnt_never_dec.vtc`
- `webstats/missing-stats-fields.vtc`
