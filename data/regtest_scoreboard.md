# Reg-Test Scoreboard

Generated 2026-11-21 on main `9198f414`, against the reg-tests of HAProxy 3.5-dev11 (`ce79f339c`,
`~/reference/haproxy/reg-tests`, 424 files). Binary: the gate's `release-perf` build of that commit.

**181 of 261 tests that ran pass (69%).** 80 fail, 94 are skipped and 69 are out of scope.

- The denominator is the 261 tests that ran. A skip is a test whose `feature`/`REQUIRE` gate is
  off, or that asserts nothing. Out of scope is `data/regtests.json`'s OUT_OF_SCOPE triage
  (Lua, cache, peers, QUIC parts, ...). Counting either as debt measures a decision, not a gap.
- **Not yet checked against the oracle.** Some failures also fail on HAProxy under this runner
  (`sample_fetches/h2_stream_state.vtc` is a known one, T642), so 80 is an upper bound on Alcyon
  defects. Next step: run the 80 with the oracle binary and split runner gaps from real ones.

Previous run, 2026-09-23 on 3.5-dev7 (312 files): 7 of 171 in-scope passing. The two runs differ
in suite version, runner and triage, so the change is not directly comparable. Each earlier
report is in this file's git history.

Run (≈3 min):

    python3 harness/vtc_runner.py --binary $CARGO_TARGET_DIR/release-perf/alcyon \
        --json /tmp/rt.json ~/reference/haproxy/reg-tests/

## By area

| Area | Pass | Fail | Skip | Out of scope |
|---|---|---|---|---|
| ssl | 2 | 24 | 27 | 0 |
| http-messaging | 17 | 14 | 4 | 11 |
| server | 1 | 9 | 2 | 2 |
| filters | 0 | 5 | 13 | 0 |
| checks | 19 | 4 | 2 | 2 |
| sample_fetches | 18 | 4 | 0 | 0 |
| proxy | 4 | 4 | 0 | 0 |
| http-rules | 26 | 3 | 1 | 2 |
| log | 13 | 2 | 0 | 0 |
| cli | 3 | 2 | 0 | 0 |
| jwt | 0 | 2 | 2 | 0 |
| connection | 13 | 1 | 1 | 6 |
| balance | 3 | 1 | 0 | 1 |
| quic | 2 | 1 | 10 | 20 |
| startup | 2 | 1 | 0 | 0 |
| stats | 2 | 1 | 0 | 0 |
| spoe | 1 | 1 | 0 | 0 |
| compression | 0 | 1 | 11 | 0 |
| converter | 30 | 0 | 0 | 0 |
| http-errorfiles | 6 | 0 | 0 | 0 |
| stick-table | 5 | 0 | 0 | 0 |
| stream | 4 | 0 | 0 | 0 |
| tcp-rules | 4 | 0 | 0 | 0 |
| protobuf | 2 | 0 | 0 | 0 |
| webstats | 2 | 0 | 0 | 0 |
| http-capture | 1 | 0 | 0 | 0 |
| http-cookies | 1 | 0 | 0 | 1 |
| cache | 0 | 0 | 0 | 14 |
| contrib | 0 | 0 | 1 | 0 |
| decompression | 0 | 0 | 5 | 0 |
| lua | 0 | 0 | 11 | 0 |
| mailers | 0 | 0 | 1 | 0 |
| mcli | 0 | 0 | 1 | 2 |
| peers | 0 | 0 | 0 | 4 |
| qmux | 0 | 0 | 2 | 0 |
| resolvers | 0 | 0 | 0 | 1 |
| seamless-reload | 0 | 0 | 0 | 1 |
| stickiness | 0 | 0 | 0 | 2 |

## Why the 80 fail

**54 are refused at load.** Alcyon refuses a keyword it does not implement rather than ignoring it
(AGENTS.md rule 5), so these tests stop at `-c`. Grouped by what is missing:

| Missing | Tests | Note |
|---|---|---|
| TLS `bind` keywords: `ca-file` (client certificates), `strict-sni`, `crt-list`, `crt-store`, `ssl-load-extra-del-ext`, server `ciphers` | 17 | The largest single gap: client-certificate auth and SNI control. `ciphers` has no rustls equivalent (tradeoff). |
| `unix@` address prefix | 4 | ssl_dh, ssl_generate_certificate, show_ssl_sni_filter, verifyhost_san (stats/CLI sockets on unix paths) |
| Filters (`filter`, `filter-config`, `filter-api`), SPOE | 7 | Out of scope (docs/differences.md); the triage should move these to OUT_OF_SCOPE. |
| `http-hardening` (4), `early-hint`, `wait-for-body ... no-fail`, `set-vars-from-map`, `curve2name`, `jwt.allow_none_alg`, `default-path` | 10 | Mostly new in 3.5-dev: declined for the 3.6 LTS target (tradeoff 6.36) unless 3.6 keeps them. Check each. |
| Fetches: `fc_unacked`/`fc_rtt` family (2, case TCPINFO queued 11-21), `fs.id` (T642), `term_events` (T642) | 4 | |
| Server keywords: `from`, `init-state`, `pool-conn-name`, `hash-preserve-affinity maxqueue`, `addr` with a port, `http-check connect default` | 6 | |
| Other: `external-check`, `healthcheck` section, `log backend@`, `thread-groups` > 1, `stats-file`, a client-cert PEM the loader rejects | 6 | |

**24 fail at run time and 2 time out.** These are the ones to look at first:

| Kind | Tests |
|---|---|
| Missing CLI commands: `add server`, `add backend`, `get map`/`acl`, `show ssl ...`, `show env` | cli_add_check_server, cli_delete_dynamic_server, cli_add_ssl_server, cli_add_backend, cli_acl_map, show_commands |
| CLI text or field mismatch | cli_del_backend (other error text), cli_add_track_server, cli_set_ssl, 1be_40srv_odd_health_checks (`show servers state` columns), runtime_settings (stats CSV), automatic_maxconn and quic/retry_wildcard (`show info` says `Name: Alcyon`) |
| CLI purge commands | cli_purge_backend, cli_purge_server, cli_purge_all_servers |
| HTTP/1 messaging | h1_big_chunk_size_line (log line), h1_ws_1xx_101_same_read (EOF), h2_1xx_clen_to_h1 (103 lost), httpclose, truncated_response, http_no_delay (runner lacks `resp.chunklen`), connect_aborted_inflight and http_abortonclose (time out) |
| Other | converters_ipmask_concat_strcmp_field_word (EOF), conn_addresses (`dst_conn` 0, T644 #5) |

The `show info` name (`Name: Alcyon`) fails two tests that match `Name: HAProxy`; whether to
answer `HAProxy` there is a compatibility decision, not a defect.

Per-test results: `~/ibex-targets/rt-9198f414.json` (not in the repository).
