# Alcyon Continuous Measurement Suite (`tools/measure/`)

Continuous performance, allocation, binary size, and regression tracking for Alcyon.

## Usage

```bash
# Fast mode: runs in < 60s (allocations, binary size, 1-conn throughput)
tools/measure/run.sh --fast

# Full mode: comprehensive verification (adds VTC board, 50-conn throughput, 60k backend memory, HAProxy side-by-side)
tools/measure/run.sh --full

# Flamegraph profiling mode: 30-second load run with perf and inferno
tools/measure/run.sh --flame
```

## Metrics & Archive

Each run appends a JSON record to `data/measurements.jsonl` keyed by git commit SHA and ISO timestamp:

```json
{
  "sha": "a1b2c3d4...",
  "at": "2026-09-24T06:45:00Z",
  "dirty": false,
  "allocs_per_request": 5,
  "bytes_per_request": 132,
  "rps_1conn": 10094,
  "rps_50conn": 28187,
  "cpu_pct_50conn": 60.9,
  "board": {"pass": 7, "fail": 164, "skip": 89, "scope": 52},
  "binary_bytes": 107720288,
  "text_bytes": 4055257,
  "mem_60k_backends_mb": 15.84,
  "haproxy_rps_1conn": 11117,
  "haproxy_rps_50conn": 277503,
  "load_1min": 1.25,
  "agy_count": 2
}
```

## Regression Detection Thresholds

Every run compares against historical runs and exits with non-zero exit code if regressions occur:

| Metric | Threshold | Rationale |
|---|---|---|
| **Allocations / req** | Any increase (`> 0`) | Hot path is strictly pinned at 5 allocations. Any bump is an immediate regression. |
| **Bytes / req** | `> 10%` increase | Guards against buffer bloat while allowing minor struct padding changes. |
| **VTC Pass Count** | Any decrease (`< 0`) | Conformance regressions must never be silently masked. |
| **Throughput (1-conn / 50-conn)** | `> 15%` drop | Accounts for multi-tenant CPU variance (`pgrep -c agy` load) while flagging real regressions. |
| **Binary / Text Size** | `> 5%` increase | Prevents unexpected code bloat and unoptimized dependencies. |
| **60k Backends Memory** | `> 10%` increase / `> 20 MB` | Keeps per-backend footprint bounded well below HAProxy's 207 MB baseline. |

## Integration with `tools/checkin.sh`

To integrate continuous measurement into supervisor check-in, add these lines to `tools/checkin.sh`:

```bash
echo "=== continuous measurement ==="
tools/measure/run.sh --fast
```

## `insreq-quick`: the gate's short ins/req count

`tools/checkin.sh` stage `insreq-quick` (`tools/measure/insreq_gate.py`) runs in every gate
except the exclusive measuring one (`tools/gate.sh --exclusive`, whose `measure` stage counts
in full, N=30000 x 5, ab1 and mb50). It was added on 2026-11-21, after 32 merges went into
main unmeasured and the next measured gate found keepalive +1.8% and rules +2.5%.

- **Candidate:** `cargo build --profile release-perf --bin alcyon` of the tree, in the gate's
  plain target and env.
- **Reference:** `ALCYON_MEASURE_REF`, else the last row of `data/measurements.jsonl` that
  counted ins/req on a clean ancestor of HEAD *and* passed its own check (within
  `INS_MAX_RISE_PCT` of its own ref): a failed measurement is never the baseline. Built from
  `git archive` and cached in `$ALCYON_INSREQ_REF_DIR` (default `$ALCYON_TARGETS/insreq-ref`)
  by commit **and** `rustc -vV`, so a toolchain bump rebuilds it (1.100 moved c246669a's
  keepalive from 35,062 to 35,135-35,176).
- **Count:** `insreq.sh` ab1, keepalive and rules, N=10000 x 3 rounds, minimum of the rounds,
  user-space instructions; counts slot B (`/tmp/alcyon-load-n1.lock`, CPUs 12-14), waiting
  up to 30 min for it. FAIL over **+0.5%** (AGENTS.md section 8) on either scenario; exit 2
  (also a FAIL in the gate) when it could not measure.
- **Skip:** `ALCYON_GATE_SKIP_INSREQ=1`, recorded as the stage's skip and part of the gate
  state's key. A running `wwm.exe` is noted in the output and changes nothing.
- **Cost (measured 2026-11-21):** the release-perf build of the tree ~306 s (fat LTO) is
  started by checkin.sh in the background before the first stage (nice 19, `-j
  ALCYON_INSREQ_BUILD_JOBS`, default 8, target `$CARGO_TARGET_DIR/insreq-quick`, its own process
  group, killed on exit), so it overlaps the suite: in a full gate it took 236 s and the stage
  waited 0 s for it. Then the reference's build, ~300-313 s once per (commit, rustc), and the
  counting ~11 s. A failed background build fails the stage with its log's path.

Spread on 2026-11-21 (a65a069d against c246669a, the same two binaries):

| N x rounds | keepalive | rules | max-min between rounds | wall (counting) |
|---|---|---|---|---|
| 2000 x 3 | +1.82% | +2.55% | <= 0.01% | 4 s |
| 5000 x 3 | +1.81% | +2.55% | <= 0.03% | 6 s |
| 10000 x 3 (the stage) | +1.82% | +2.55% | <= 0.05% | 11 s |
| 30000 x 5 (the full figure) | +1.80% | +2.56% | <= 0.18% | 41 s |

c246669a against itself at 10000 x 3: +0.00% and +0.00%.
