# Project Alcyon - Principal Architect Review

## 1. Overview
This report details the findings of an adversarial code review of Project Alcyon's core crates (`ebtree`, `alcyon-sched`, `alcyon-proto`, `alcyon-sample`, `alcyon-stick-table`, `alcyon-config`, and `alcyon-rt`), assessing compliance with NASA JPL Power of 10 safety guidelines, scheduler invariants, and robust error handling.

## 2. Strengths and Positive Invariants
* **Scheduler Anti-DDoS Guarantees:** `alcyon-sched` implements robust anti-starvation mechanisms. Tasks re-queueing themselves are correctly delayed until the next scheduler pass, preventing runaway tasks from monopolizing the CPU (`last_run == self.loops` check).
* **Timer Accuracy:** Clock wrap in `alcyon-sched/src/tick.rs` is handled correctly via signed 32-bit arithmetic difference (`wrapping_sub(now.0) as i32 <= 0`), which properly handles wrapping over 49.7 days without integer anomalies.
* **Safety Contract Base:** The `#![forbid(unsafe_code)]` directive is correctly applied across most workspace crates (excepting `alcyon-core`).

## 3. Critical Findings & Policy Violations

### A. Zero Heap Allocation on Hot Paths (NASA JPL Rule 3)
* **Violation in `alcyon-rt/src/engine.rs`:** In the engine's main event loop tick (`run_once`/`step`), `let mut events = Vec::new();` dynamically allocates a vector for polling events *on every tick*. This is a critical violation of soft-realtime constraints and JPL Rule 3.
* **Violation in `alcyon-rt/src/proxy.rs`:** Header parsing allocates vectors (`let mut hdrs = Vec::new()`) and strings (`to_string()`) on every request rather than using zero-copy references or pre-allocated arenas.
* **Violation in `alcyon-stick-table/src/table.rs`:** The stick table uses a standard `RwLock<HashMap>`. Hash maps trigger heap allocations upon resizing and node creation, violating zero-allocation invariants.
* **Violation in `alcyon-sample/src/registry.rs`:** Request matching creates new `String`s (`Sample::Str(path_only.to_string())`) rather than referencing memory in the `HTX` buffer.

### B. Scheduler Anti-DDoS and Latency Guarantees
* **Latency Spike in `alcyon-stick-table/src/table.rs`:** When the stick table hits its `max_size`, `update_entry` performs an O(N) scan (`map.retain(...)`) to evict expired entries *while holding a write lock*. If max capacity is large (e.g., 100k+), this blocks all worker threads and causes massive latency spikes (a potential algorithmic DDoS vector).

### C. Strict `#![forbid(unsafe_code)]` Compliance
* **Missing in `alcyon-core`:** While the target crates forbid unsafe code, the foundational `alcyon-core` crate relies heavily on `unsafe` blocks for `FixedPool` and `StaticArena`. Though justified for low-level ring buffers, `alcyon-core/src/lib.rs` is missing strict documentation and review of these blocks, and it lacks the crate-level `#![deny(unsafe_code)]` outside those specific implementations.

### D. Robust Error Handling (No Unwraps)
* **Panics in `alcyon-rt/src/engine.rs`:** The engine code makes heavy use of `.unwrap()` on internal object pool lookups (e.g., `self.sessions.free(session_idx).unwrap()`, `entry.stream.as_ref().unwrap()`). While these *should* be protected by internal logic invariants, any bug in index lifecycle management will result in a fatal panic of the entire proxy rather than graceful error handling.

## 4. Remediation Plan

1. **Eliminate Engine Allocations:**
   * Pre-allocate the `events` buffer in `Engine` (e.g., `mio::Events::with_capacity(1024)` or a fixed slice) and reuse it in the polling loop.
   * Rewrite `proxy.rs` and `alcyon-sample` to use zero-copy slice references (`&[u8]` or `&str`) backed by the `StaticArena` instead of allocating strings and vectors.

2. **Refactor Stick Tables:**
   * Replace `HashMap` with an LRU cache backed by a fixed-capacity static array or `FixedPool` to achieve O(1) eviction and zero heap allocations.
   * Avoid `map.retain` under a global lock. Evict lazily or use a background cleanup task.

3. **Audit Unwraps:**
   * Replace all `.unwrap()` and `.expect()` calls in `alcyon-rt` with proper `Result` propagation or safe fallback mechanisms to prevent crashes from internal state corruption.

4. **Isolate `unsafe`:**
   * Enforce a stricter boundary on `alcyon-core`'s unsafe code. Add JPL-style `Safety` doc comments to all unsafe blocks, proving why they cannot be subverted.
