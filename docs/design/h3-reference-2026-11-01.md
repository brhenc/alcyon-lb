# Is there a leaner HTTP/3 server than HAProxy? (T556)

User 2026-10-31 (T545 D1): "measure against haproxy, or find a better oracle: is pingora leaner?
who has the leanest h3 implementation?" HAProxy stays the **behaviour** oracle (AGENTS.md); this
note is about the **performance reference** for h3 instructions per request.

Method: `tools/measure/insreq.sh <label> <bin> <body> h3c1 4000 4` for every server: h2load
`-c 1 -m 1 --alpn-list=h3`, one QUIC connection, one stream at a time, `perf stat -e instructions:u`
on the server pid, 4 rounds of 4000 requests after 2000 warm-up. Response body is `ok` (2 bytes).
The 4000 includes the handshake (~0.5k ins/req: alcyon 110.9k at N=20000 vs 111.5k at 4000;
HAProxy 73.6k vs 74.1k). N is 4000 because nginx 1.30.6 drops the connection after about 5.5k to 8.4k
requests from this client (error log: `quic flood detected while preparing ack`); h2load then
fails the rest, so no nginx figure at 20000 is valid.

**Datagram rule (T539/T545): ins/req depends on the client's ACK-only datagrams.** Each row records
h2load's `UDP datagram: N sent` per request. HAProxy always gets 1.97. T545's fit on Alcyon/HAProxy
is about 6k ins per extra inbound datagram; the "at 1.97" column applies that slope to every row,
so it is an estimate for the stacks other than HAProxy (their own slope is unmeasured).

## Measured

Host: slot B (`flock -x /tmp/ibex-load-n1.lock`, CPUs 12,13,14 for server, client, backend),
governor `performance`, no `wwm.exe`. Fedora 44, 2026-11-01 00:00 CET. Alcyon = main aa87cb3a,
`--profile release-perf`. HAProxy = 3.5-dev10-38e65c-10 (`~/reference/haproxy-quic`).

| server | mode | ins/req (mean of 4) | client dgrams/req | at 1.97 (est.) | vs HAProxy |
|---|---|---|---|---|---|
| HAProxy dev10 | proxy to h1 backend | 74,150 | 1.97 | 74,150 | 1.00 |
| Alcyon main | proxy to h1 backend | 111,400 | 1.38 | ~119,800 | 1.50 to 1.62 |
| nginx 1.30.6 | `proxy_pass` to h1 backend | 66,600 | 1.45 | ~70,800 | 0.90 raw, 0.95 est. |
| nginx 1.30.6 | `return 200 "ok"` (no backend) | 45,650 | 1.00 | ~51,500 | 0.62 raw, 0.69 est. |
| h2o 2.3.0-DEV@94dd3bedc (podman) | proxy.reverse.url to h1 | 147,600 | 3.97 | ~135,400 | 1.8 to 2.0 (3.97 dgrams: ACK per packet) |
| h2o (podman) | file.file (static) | 128,700 | 3.00 | ~122,100 | 1.65 to 1.74 |
| lsquic 2f4cd42 http_server (podman) | static docroot (bare example) | 323,100 | 1.92 | ~322,000 | 4.3 |

VM (`ssh claude`, Debian 13, vCPUs pinned to host node 3; every process under `taskset -c 1,2,3`, so within 0-7;
`kernel.perf_event_paranoid` set to 1 for the run and back to 3 after). Binaries run via the host's
`ld.so` and libs (copied). Comparable only inside the VM; HAProxy there is 74,450 (host 74,150), Alcyon
112,500 (host 111,400), so the VM tracks the host to 0.5% to 1%.

| server | mode | ins/req (mean of 4) | client dgrams/req | at 1.97 (est.) | vs HAProxy (same VM) |
|---|---|---|---|---|---|
| HAProxy dev10 | proxy | 74,450 | 1.97 | 74,450 | 1.00 |
| Alcyon main aa87cb3a | proxy | 112,500 | 1.5 | ~118,000 | 1.51 to 1.59 |
| ngtcp2 1.22.1 osslserver (OpenSSL 3.5.7) | static docroot | 56,700 | 1.09 | ~62,000 | 0.76 raw, 0.83 est. |
| picoquic ca4dbce (picotls ... e446233) `picoquicdemo` | static docroot | 58,000 | 1.93 | ~58,200 | 0.78 |
| quiche ba8c528 `quiche-server` (BoringSSL) | static docroot | 112,100 | 1.95 | ~112,100 | 1.51 |
| neqo 7622a23 `neqo-server` (NSS built from source) | generated 2-byte response `/2` | 103,100 | 2.09 | ~102,000 | 1.38 |

Not measured: msquic (a transport library; no HTTP/3 server in the tree, its sample is a raw QUIC
echo), Pingora (below), s2n-quic (a library; its h3 is a separate crate and no server binary).
Versions: ngtcp2 1.22.1 and nghttp3 60becbe (autoreconf, `--with-openssl`); the git master of ngtcp2
needs a submodule `third-party/urlparse` that did not clone, the 1.22.1 release tarball was used.
neqo needs NSS >= 3.126 (Debian has 3.110): `NSS_NO_PKG_CONFIG=1` makes `nss-rs` build NSS from
source (2 min, needs `mercurial gyp`), rustc 1.95.0 for neqo (1.91 on the VM is too old).
Containers: debian:stable `sha256:d8448c2392b6bf1751577134d6789493803387856a1ef1a4c90171f44e1794d8`;
h2o image `sha256:0c2e5aa6f447d7405ef2e9cc17b0f5981adada63497b60bedeb288681ee9028b` (h2o
94dd3bedc2cc440ed9da90164138c74a3c0d155a, system OpenSSL 3.x, `-DWITH_MRUBY=OFF`); lsquic image
`sha256:e3d8ddef3a3e611db4de5907bc52e42fe63e3066d4622b2bb82ee8f0a54f4fbe` (lsquic
2f4cd42f27cf8e9b0a0f43e376a618ec8ce4a7ff, BoringSSL ed9209cff8b5a2fbc6c10050f29b3355048bda85).
nginx: Fedora package, `--with-http_v3_module`, OpenSSL 3.5.9 with kTLS, `worker_processes 1;
master_process off; keepalive_requests 1000000;` (the default 1000 closes the connection early).
Containers ran `--network host`, pinned to CPU 12 with `taskset -a -cp` after start (rootless podman
has no cpuset delegation), `perf stat -p` on the container's host pid.

## Caveats on each row

- **lsquic**: the figure is the `http_server` example with default (BBR) settings, `-L warn`, not a
  tuned build; 323k looks like pacing/timer work per request, not the frame path. It needs
  `--sni=localhost` on the client (no SNI means no certificate). Do not read it as "lsquic is slow";
  it is "the example is not a lean reference".
- **h2o**: the client sends 3 to 4 datagrams per request because h2o's ACK policy makes h2load ack
  nearly every packet. The 6k slope was fitted on HAProxy/Alcyon; with a different ACK path the "at
  1.97" estimate is weak. Even at the raw figure h2o is not lean. Container adds no instructions
  to the server pid (host `perf -p`).
- **nginx**: client datagrams are 1.0 (return) and 1.45 (proxy), so the raw figures flatter it; the
  estimate is rough. `return` serves from memory, the HAProxy and Alcyon rows go through a proxy and
  backend, so the `return` row is a floor for an h3 *stack*, not a peer. The `proxy_pass` row is a
  peer: same shape, no rules, no logging, no stats, access log off.
- **ngtcp2, picoquic, quiche, neqo**: bare static servers (file read per request in ngtcp2/picoquic/
  quiche; generated bytes in neqo). They carry no HTTP rules, logging or stats.
- All rows: one connection, one stream at a time, 2-byte body. Nothing here says anything about
  throughput with many streams or connections.

## Survey (what is known without a measurement)

| server | language, TLS | h3 server in tree | notes |
|---|---|---|---|
| Pingora (Cloudflare) | Rust, OpenSSL/BoringSSL/rustls | no | HTTP/1 and HTTP/2 only as of the checked tree; Cloudflare's h3 edge runs on quiche. Not a candidate. |
| quiche (Cloudflare) | Rust, BoringSSL | yes, `quiche-server` (apps) | measured: 112k, same as Alcyon. Its production use is inside Cloudflare's proxy, not this example. |
| neqo (Mozilla) | Rust, NSS | yes, `neqo-server` | measured 103k. NSS is C; building it here needs a source build. |
| s2n-quic (AWS) | Rust, s2n-tls/rustls | library; h3 via `s2n-quic-h3` crate | no server binary to measure. |
| quinn / h3 (Rust) | Rust, rustls | library + `h3` crate | the engine Alcyon uses; it is the thing being compared, not a reference. |
| h2o + quicly | C, OpenSSL | yes | measured: 129k to 148k. Strong for throughput (many streams, GSO); not lean per request on this benchmark. |
| lsquic (LiteSpeed) | C, BoringSSL | `http_server` example | measured 323k; see caveat. OpenLiteSpeed would be the production form (not tried). |
| nginx QUIC | C, OpenSSL 3.5 | yes | measured; leanest *proxy* shape and the leanest full server. Closes the connection after ~5.5k-8.4k requests from h2load. |
| ngtcp2 + nghttp3 | C, OpenSSL/GnuTLS/BoringSSL/picotls | yes, examples | measured 56.7k; the examples are bare reference servers. |
| picoquic | C, picotls | yes, `picoquicdemo` | measured 58.0k; bare. |
| msquic (Microsoft) | C, schannel/OpenSSL | transport only | no h3 server to measure here. |

The survey rows without a number rest on the trees as they are on disk or on the project READMEs; I
did not search for published instruction counts, and found none for per-request h3 instructions.

## Recommendation

1. **Keep HAProxy dev10 as the h3 performance reference.** It is the behaviour oracle, it has the same feature
   set (rules, logs, stats) and the same shape (proxy to an h1 backend), it is already in the
   harness, and nothing measured is leaner *in the same shape* by more than the noise of the
   datagram rate: nginx `proxy_pass` is 0.90 raw and about 0.95 with the datagram adjustment.
   Alcyon main is 1.5x HAProxy; that gap is real in every column, on host and VM.
2. **Add nginx 1.30.6 as a second "peer" row, optional.** One config, packaged on this host,
   same shape, no new build. It adds nothing HAProxy does not tell us, but it tells us the 74k is not
   a HAProxy-specific inefficiency. Use N=4000.
3. **Add a "floor" row from a bare server, once, not in every batch: picoquic or ngtcp2 (~57k to
   58k) and nginx `return` (45.6k).** The floor says what the transport + h3 framing + TLS cost
   with no proxy work: roughly 46k to 58k. HAProxy's 74k is 16k to 28k above it for the proxy path
   (h1 backend, rules, log). If the T545 projection (h3 89k to 98k) is reached, Alcyon is about 1.2x
   to 1.3x HAProxy and 1.6x to 2x the floor. A floor target below HAProxy for Alcyon is not defensible:
   the floors have no backend hop.
4. Do not use h2o, lsquic's example, quiche or neqo as references: either not lean or not
   comparable on this client.
5. When T555's deterministic client lands, rerun this table with it: the "at 1.97" column is an
   estimate, the deterministic client removes the need for it.

## Reproducing

Scripts and configs are in `/tmp/t556` (host) and `/tmp/vmpk` (VM), not in the repository: the
nginx shim is `exec nginx -c cfg -g 'daemon off; master_process off;'`; the container runs use a copy
of `insreq.sh` whose launch line is replaced by a shim that does `podman run -d --network host
--userns=keep-id --security-opt label=disable` and writes `podman inspect -f '{{.State.Pid}}'`
to the pid file; lsquic's client needs `--sni=localhost`; neqo's request path is `/2`.
