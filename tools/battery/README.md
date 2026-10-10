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

## Columns
`RSS peak->end`, `cpu avg%/peak%` of one core over the attack, `fds peak->end`, legit
`p99` (ttlb) and counts (ok = 2xx, bad = 4xx/5xx, err = connection errors), `mid` = probes
during the attack that got a 200, `recovered` = after the attack both binds answer a probe
within 45 s and fds are within 30 of the baseline (and the process is alive).

## Reproducers
Anything where Ibex is clearly worse than HAProxy gets a minimal command under
`repro/` (a `clients.py attack` line plus config notes).
