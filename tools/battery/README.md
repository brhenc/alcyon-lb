# Hostile-client battery (T247)

Ibex vs HAProxy under abusive clients and backends, on devtest7. Bar: safe to serve a small
blog (no crash, leak, deadlock, hang). Not a performance test.

    tools/battery/run.sh <path-to-ibex-release-binary> [seconds=60] [scenario ...]

Takes about 45 minutes for all 11 scenarios x 2 proxies at 60 s (each scenario is the
attack time plus up to 45 s of recovery polling). A scenario with no new result line for
5 minutes is stuck. Results land in `tools/battery/results/<timestamp>/` (git-ignored):
`raw.jsonl`, one JSON per run, `table.md`.

Needs on devtest7: `/root/ibex-test/{haterm,haload,haproxy}` (read, never modified), python3,
curl. Our files live in `/root/battery` only. HAProxy binary: `HAPROXY_REMOTE=...` to change.

## Setup per scenario
Same config for both proxies (`battery.py` `CFG`): nbthread 4, maxconn 2000, timeouts
connect 5s, client/server 30s, http-request 5s; h1 bind :10080, h2c prior-knowledge bind
:10081; default backend haterm; `/hang`, `/drip`, `/reset` go to the misbehaving backends
(`clients.py backend`). CPU pinning: proxy 0-3, haterm 16-31, legit haload 32-35, attackers 40-47.
A legit `haload` (4 users, 50 req/s, `/?s=1k`; h2c for the h2 scenarios) runs for the whole
scenario; the attack starts 3 s in. A 1 Hz sampler reads the proxy's `/proc` RSS, CPU, fds.

## Scenarios
| name | what it does |
|---|---|
| slowloris | 1800 connections, partial header block, one more header line every 1.5 s |
| slow_post | 500 POSTs declaring 1 MB, 1 byte per second |
| nonreader | 300 requests for a 1 GB response, 4 KiB receive buffer, never read |
| h2_rapid_reset | 4 threads: batches of 200 x (HEADERS + RST_STREAM) on h2c |
| h2_flood | 8 threads: SETTINGS + PING floods (half read the ACKs, half do not) |
| h2_window0 | 100 connections, INITIAL_WINDOW_SIZE 0, 20 streams each for a 10 MB body, no WINDOW_UPDATE |
| hdr_storm | 16 h1 workers (8 KiB header / 90 x 80 B headers / 40 KB header that must be refused) + 16 h2 workers with 8000-byte header values |
| churn | 2500 idle connections held (above maxconn 2000) plus 50 connect/close workers |
| be_hang | 400 connections to a backend that accepts and never answers |
| be_drip | 400 connections to a backend that sends headers then 1 byte/s |
| be_reset | 50 workers to a backend that sends part of the body then RSTs |

## Protocol-spam scenarios (red team, 2026-10-11)
Same harness, same config (plus a TLS bind `127.0.0.1:10443 ssl crt /root/ibex-test/lab.pem alpn h2,http/1.1`
when that cert exists; make one with `openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=lab.local`
and `cat crt key > lab.pem`). Run them on reproducer2 with
`BATTERY_HOST=root@192.168.122.138 tools/battery/run.sh <ibex> 60 <scenario ...>`; the machine needs
`/root/ibex-test/{haterm,haload,haproxy,lab.pem}` like devtest7. Every attack is rate-capped (haload `-R`,
per-worker sleeps, one Python process per attack line) and pinned to cores 40-47.

| name | what it does | cap |
|---|---|---|
| hoic_h1_ka | HOIC-style GET flood, keep-alive (haload, 200 users) | 20000 req/s |
| hoic_h1_conn | same, one connection per request | 5000 conn/s |
| hoic_h2 | same over h2c, 50 connections x 50 streams | 20000 req/s |
| hoic_rand | 4 x 32 keep-alive workers, randomised path/query/headers/UA, 10 % POST, reconnect every 50 req | ~100 req/s/worker |
| h1_pipeline | 2 x 32 workers, 100 pipelined GETs per write, responses read | 20 batches/s/worker |
| h1_range | 64 workers, GET 1 MB with 1000 overlapping ranges in one Range header | 100 req/s/worker |
| h2_continuation | 2 x 16 connections: HEADERS without END_HEADERS then endless 1 KiB CONTINUATION frames (1 in 4 on the wrong stream id) | ~1 MB/s/conn |
| h2_cont_drip | 400 connections, one 1 KiB CONTINUATION every 0.5 s, never END_HEADERS | 2 KB/s/conn |
| h2_hpack_bomb | 2 x 16 connections: 4 KB header into the dynamic table then HEADERS of 4000 indexed refs (16 MB decoded) / table-size update above the maximum / SETTINGS_HEADER_TABLE_SIZE 2^32-1 | 200 frames/s/conn |
| h2_madeyoureset | 4 threads, batches of 200 x (request for 1 MB + a frame that makes the server reset the stream: WINDOW_UPDATE 0, self-dependent PRIORITY, DATA after END_STREAM, window overflow, HEADERS after END_STREAM) | python speed, 5 ms between batches |
| h2_priority_flood | 8 threads, batches of 1000 PRIORITY frames on idle streams | 2 ms between batches |
| h2_empty_data | 8 threads, open POST stream then batches of 1000 zero-length DATA frames | 2 ms between batches |
| h2_wu_storm | 8 threads, request 10 MB then batches of 1000 WINDOW_UPDATE +1 (stream and connection) | 2 ms between batches |
| h2_streams | 200 connections x 300 POST streams never finished (3x SETTINGS_MAX_CONCURRENT_STREAMS), held | - |
| h2_preface_idle | 3000 connections (above maxconn 2000) send preface + SETTINGS, then nothing | - |
| tls_hs_full | haload over TLS, one connection per request, no session reuse (full handshakes) | 2000 hs/s |
| tls_hs_resume | same with session reuse | 4000 hs/s |
| tls_hello_only | 2500 connections (above maxconn): full ClientHello then silence / half a ClientHello / ClientHello with bogus SNI, 100 ALPN entries, 8 KB padding | - |
| tls_reneg | 50 openssl s_client TLS 1.2 sessions asking for renegotiation 20 times/s | 20/s/conn |
| maxconn_full | 2500 complete requests to a backend that never answers (above maxconn): what a new client sees | - |
| mixed | slowloris 1000 + h2_rapid_reset 2 threads + 5000 req/s h1 flood + 500 full TLS handshakes/s | as listed |

Legit stream for the TLS rows: haload h2 over TLS; `mid` probes use curl over the same protocol and the
result JSON carries `mid_probe_detail` (HTTP code, or `curlN`: 7 refused, 28 timeout, 56 reset).

## Columns
`RSS peak->end`, `cpu avg%/peak%` of one core over the attack, `fds peak->end`, legit
`p99` (ttlb) and counts (ok = 2xx, bad = 4xx/5xx, err = connection errors), `mid` = probes
during the attack that got a 200, `recovered` = after the attack both binds answer a probe
within 45 s and fds are within 30 of the baseline (and the process is alive).

## Reproducers
Anything where Ibex is clearly worse than HAProxy gets a minimal command under
`repro/` (a `clients.py attack` line plus config notes).

## Results, Ibex main 36c022b vs HAProxy 3.5-dev8 (2026-10-10, 60 s)
| scenario | haproxy | ibex |
|---|---|---|
| slowloris | RSS 54M->54M, cpu 4%/14%, fds 1823->20, p99 1.2ms, ok 3028 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 52M->52M, cpu 4%/8%, fds 1828->23, p99 0.8ms, ok 3047 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| slow_post | RSS 27M->27M, cpu 4%/18%, fds 1022->20, p99 2.6ms, ok 3051 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 23M->23M, cpu 4%/15%, fds 1028->27, p99 3.1ms, ok 3036 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| nonreader | RSS 29M->29M, cpu 6%/99%, fds 625->20, p99 6.1ms, ok 3042 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 16M->16M, cpu 17%/387%, fds 629->28, p99 16.2ms, ok 3006 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| h2_rapid_reset | RSS 32M->32M, cpu 243%/301%, fds 30->20, p99 3.5ms, ok 3035 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 173M->173M, cpu 191%/204%, fds 37->33, p99 4.3ms, ok 1633 bad 0 err 10, mid 4/6, recovered y (0.0s) |
| h2_flood | RSS 29M->29M, cpu 266%/393%, fds 34->27, p99 21.3ms, ok 3054 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 15M->15M, cpu 5%/9%, fds 28->23, p99 0.7ms, ok 3030 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| h2_window0 | RSS 159M->155M, cpu 12%/134%, fds 2723->20, p99 16.6ms, ok 3032 bad 0 err 0, mid 6/6, recovered y (27.5s) | RSS 69M->69M, cpu 379%/403%, fds 2428->824, p99 4.7ms, ok 3048 bad 0 err 0, mid 6/6, recovered N |
| hdr_storm | RSS 58M->58M, cpu 29%/35%, fds 1656->28, p99 0.9ms, ok 3055 bad 0 err 0, mid 6/6, recovered y (4.1s) | RSS 39M->39M, cpu 362%/402%, fds 92->55, p99 0.5ms, ok 3041 bad 0 err 0, mid 6/6, recovered N |
| churn | RSS 25M->25M, cpu 5%/20%, fds 2019->30, p99 1.2ms, ok 3053 bad 0 err 0, mid 1/5, recovered y (0.0s) | RSS 17M->17M, cpu 7%/71%, fds 2024->38, p99 1.5ms, ok 3037 bad 0 err 0, mid 2/5, recovered y (0.0s) |
| be_hang | RSS 25M->25M, cpu 7%/26%, fds 825->21, p99 6.2ms, ok 3041 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 22M->22M, cpu 6%/21%, fds 829->24, p99 5.0ms, ok 3025 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| be_drip | RSS 28M->28M, cpu 7%/15%, fds 826->21, p99 5.2ms, ok 3038 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 21M->21M, cpu 7%/21%, fds 828->24, p99 4.6ms, ok 3050 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| be_reset | RSS 23M->23M, cpu 23%/30%, fds 126->20, p99 1.2ms, ok 3026 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 18M->18M, cpu 19%/30%, fds 128->24, p99 1.5ms, ok 3037 bad 0 err 0, mid 6/6, recovered y (0.0s) |

Ibex clearly worse (reproducers in `repro/`):
- h2_window0: 379% CPU during the attack (HAProxy 13%). The 824 fds at +45 s are not a leak: re-run with `RECOVER_MAX=150` shows Ibex fds back to baseline 57.5 s after the clients left (about 2x timeout client, matching T248), HAProxy at 27.8 s. So the fd finding is slower release; the CPU burn is the real difference. Reproducer in `repro/`.
- hdr_storm: 362% CPU (HAProxy 29%); 55 fds left after 45 s (HAProxy 28).
- h2_rapid_reset: peak RSS 173 MB (HAProxy 32 MB), 10 legit connection errors and 2/6 mid-attack probes failed (HAProxy none).
Ibex better or equal: everything else; h2_flood costs Ibex 5% CPU against 266% (it presumably drops the connection early; not checked). No crashes or panics in either.

## Results, Ibex main 94cc644 vs HAProxy 3.5-dev8 (2026-10-10 night, 60 s)
| scenario | haproxy | ibex |
|---|---|---|
| slowloris | RSS 56M->56M, cpu 5%/17%, fds 1823->20, p99 1.7ms, ok 3040 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 44M->44M, cpu 4%/9%, fds 1828->24, p99 1.0ms, ok 3053 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| slow_post | RSS 25M->25M, cpu 4%/9%, fds 1022->20, p99 2.1ms, ok 3027 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 25M->25M, cpu 7%/23%, fds 1030->23, p99 4.8ms, ok 3044 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| nonreader | RSS 28M->28M, cpu 2%/58%, fds 626->21, p99 0.8ms, ok 3052 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 22M->22M, cpu 3%/74%, fds 628->29, p99 1.4ms, ok 3032 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| h2_rapid_reset | RSS 32M->32M, cpu 176%/239%, fds 30->20, p99 4.6ms, ok 3041 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 13M->13M, cpu 58%/71%, fds 36->23, p99 2.8ms, ok 3053 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| h2_flood | RSS 25M->25M, cpu 247%/302%, fds 34->23, p99 25.0ms, ok 3035 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 15M->15M, cpu 6%/9%, fds 29->22, p99 1.2ms, ok 3040 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| h2_window0 | RSS 149M->142M, cpu 13%/70%, fds 2722->20, p99 19.6ms, ok 3017 bad 0 err 0, mid 6/6, recovered y (27.6s) | RSS 73M->73M, cpu 148%/403%, fds 2428->823, p99 4.0ms, ok 3022 bad 0 err 0, mid 6/6, recovered N |
| hdr_storm | RSS 57M->57M, cpu 55%/128%, fds 1656->30, p99 5.1ms, ok 3054 bad 0 err 0, mid 6/6, recovered y (4.1s) | RSS 33M->33M, cpu 57%/401%, fds 92->56, p99 1.2ms, ok 3053 bad 0 err 0, mid 6/6, recovered N |
| churn | RSS 27M->27M, cpu 6%/31%, fds 2018->36, p99 2.0ms, ok 3046 bad 0 err 0, mid 1/5, recovered y (0.0s) | RSS 20M->20M, cpu 9%/96%, fds 2024->30, p99 1.0ms, ok 3035 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| be_hang | RSS 27M->27M, cpu 3%/13%, fds 826->20, p99 1.1ms, ok 3041 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 24M->24M, cpu 4%/13%, fds 829->24, p99 1.7ms, ok 3026 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| be_drip | RSS 26M->26M, cpu 3%/7%, fds 826->21, p99 0.8ms, ok 3033 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 19M->19M, cpu 4%/9%, fds 829->24, p99 0.8ms, ok 3051 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| be_reset | RSS 24M->24M, cpu 32%/41%, fds 126->22, p99 0.7ms, ok 3024 bad 0 err 0, mid 6/6, recovered y (0.0s) | RSS 14M->14M, cpu 26%/33%, fds 128->23, p99 0.8ms, ok 3041 bad 0 err 0, mid 6/6, recovered y (0.0s) |

Against 36c022b: h2_rapid_reset fixed (RSS 173M -> 13M, no legit errors, mid 6/6). Still worse than HAProxy: h2_window0 (cpu 148%/403% vs 13%/70%, not recovered within 45 s; T269) and hdr_storm (average cpu now equal, 57% vs 55%, but peak 401% vs 128% and 56 fds left vs recovered at 4.1 s; T270). Everything else equal or better; no crash or panic.

## Results, integration branch batch/1011 a65fedf (main + T269 + T270 + the night batch) vs HAProxy 3.5-dev8 (2026-10-11, 60 s)
| scenario | haproxy | ibex |
|---|---|---|
| h2_window0 | RSS 148M->120M, cpu 12%/59%, fds 2723->21, p99 11.5ms, ok 3037 bad 0 err 0, mid 6/6, recovered y (27.7s) | RSS 22M->22M, cpu 3%/10%, fds 228->27, p99 0.8ms, ok 3051 bad 0 err 0, mid 6/6, recovered y (0.0s) |
| hdr_storm | RSS 56M->56M, cpu 40%/60%, fds 1656->31, p99 0.8ms, ok 3047 bad 0 err 0, mid 6/6, recovered y (4.1s) | RSS 26M->26M, cpu 56%/100%, fds 92->28, p99 3.4ms, ok 3026 bad 0 err 0, mid 6/6, recovered y (0.0s) |

Both now recover: h2_window0 cpu 3%/10% (was 148%/403% on 94cc644), fds released at once (HAProxy 27.7 s); hdr_storm no more 4-core spin (peak 100% vs HAProxy 60%, average 56% vs 40%: roughly comparable), fds back to baseline at once (HAProxy 4.1 s). T269 (h2 FIN with window 0, epoll removal of idle fds) and T270 (server-wide idle-connection purge).
