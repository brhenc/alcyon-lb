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
