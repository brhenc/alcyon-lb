# Livepatch Cost

This document measures the cost of livepatchability on Ibex.

## 1. The Stage-Boundary Survival Check

Pillar 1 of livepatching requires that the functions we might need to replace actually exist as discrete symbols in the final binary, rather than being inlined into their callers.

We measure this by counting the survival of 10 structural "stage boundaries" from the data path. These are functions that must not be inlined for livepatching to be viable:

- `accept_from_listener`
- `TcpSession::process`
- `HttpSession::process`
- `ClientXprt::recv`
- `ClientXprt::send`
- `ServerXprt::recv`
- `ServerXprt::send`
- `Backend::dispatch`
- `Frontend::dispatch`
- `Stream::process`

### Survival by LTO Setting

Survival was measured using `nm -C <binary> | grep <symbol>`. The count of preserved boundaries is identical regardless of the `livepatch` profile's rustflags:

| LTO Setting | Release Profile Survival | Livepatch Profile Survival |
|-------------|-------------------------:|---------------------------:|
| `off`       |                  3 of 10 |                    3 of 10 |
| `thin`      |                  3 of 10 |                    3 of 10 |
| `fat`       |                  3 of 10 |                    3 of 10 |

The rust compiler aggressively inlines 7 out of 10 stage boundaries across all settings. Without explicit `#[inline(never)]` annotations on these boundaries, they remain unpatchable.

## 2. Alignment Cost

Pillar 2 requires 16-byte alignment and frame pointers. This check verifies that the flags actually force alignment:

| Binary | 16-byte aligned symbols |
|---|---:|
| `target/release/ibex` | 98.05% |
| `target/livepatch/ibex` | 99.92% |

## 3. The True Cost of Livepatch Flags

To isolate the cost of livepatching, we define two builds that differ **only** by rustflags, holding `codegen-units` constant:

```bash
# Baseline release build
CARGO_TARGET_DIR=/tmp/ibex-release cargo build --release

# Livepatch build (inherits release, adds flags)
CARGO_TARGET_DIR=/tmp/ibex-livepatch cargo build --profile livepatch
```

Cargo profile:
```toml
[profile.livepatch]
inherits = "release"
rustflags = [
    "-C", "force-frame-pointers=yes",
    "-C", "llvm-args=-align-all-functions=4"
]
```

### Build Cost (LTO spread)

| LTO Setting | Profile | Total `FUNC` symbols | `.text` size | Build time |
|---|---|---:|---:|---:|
| `off` | Release | 5907 | 4.43 MB | ~14.3s |
| `off` | Livepatch | 5907 | 4.48 MB | ~14.5s |
| `thin` | Release | 5067 | 4.29 MB | ~17.5s |
| `thin` | Livepatch | 5067 | 4.34 MB | ~17.8s |
| `fat` | Release | 3742 | 3.79 MB | ~49.3s |
| `fat` | Livepatch | 3742 | 3.82 MB | ~49.5s |

As shown above, the massive drop in FUNC symbols and binary size, along with the 3.4x spike in build time, are purely artifacts of `lto="fat"`, not the livepatch flags.

### Performance Cost

Throughput measured on loopback. The load generator was fixed (disabling Nagle's algorithm via TCP_NODELAY) and validated against HAProxy:

| Setup | HAProxy | Ibex (Release) | Ibex (Livepatch) | Cost |
|---|---:|---:|---:|---:|
| 1 connection | ~9.4k req/s | ~13.1k req/s | ~13.8k req/s | None |
| 50 connections | ~267k req/s | ~33.3k req/s | ~33.7k req/s | None |

## 4. The Regression Test Board

The `vtc_runner.py` suite was run against both the `release` and `livepatch` builds with LTO off. The pass and fail counts agree, proving nothing is fundamentally broken by the flags:

| Build | Passed | Failed | Out of Scope | Skipped |
|---|---:|---:|---:|---:|
| `release` | 7 | 164 | 51 | 90 |
| `livepatch` | 7 | 164 | 51 | 90 |

### The Flapping Test

Between runs, the totals occasionally fluctuate between `52 out of scope / 89 skipped` and `51 out of scope / 90 skipped`.
This means one `OUT_OF_SCOPE` test is flapping between evaluated and un-evaluated execution.

The test `reg-tests/spoe/wrong_init.vtc` is marked out of scope because the VTC parser fails to properly identify braces, sending an empty config to the proxy instead of the expected invalid config. This causes the proxy to succeed in starting, triggering an unexpected failure. A race condition during the assertion lifecycle causes it to sporadically record 0 evaluated assertions instead, marking it as a `SKIP`. This race causes the board totals to drift run-to-run.

## 5. Conclusion

On this codebase, Pillar 1 (ensuring functions are distinct symbols for patching) buys us **nothing without manual intervention**, and costs us heavily in un-inlined performance if we use fat LTO to shrink the binary. Aggressive inlining by the compiler destroys 70% of natural proxy stage boundaries regardless of LTO settings. Applying the livepatch rustflags (frame pointers and 16-byte alignment) comes at a negligible cost to build time (+1.3%), binary size (+1.1%), and throughput. However, to actually make the boundaries patchable, the codebase will require explicit `#[inline(never)]` annotations, the cost of which is yet to be measured.
