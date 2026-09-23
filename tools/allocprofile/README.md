# allocprofile

Answers "which call sites allocate, per request", which the counting allocator in
`ibex-alloc` cannot: it counts allocations but does not attribute them.

```bash
cd tools/allocprofile && cargo run -q
```

Drives one warm-up request, arms a backtrace-capturing allocator, drives a second, and
prints the allocation sites ranked by count with the bytes each accounts for.

Standalone by design. It needs `unsafe` to install a `#[global_allocator]`, and every
crate in the main workspace is `#![forbid(unsafe_code)]`; keeping this outside the
workspace means that never has to be relaxed. It is a measuring instrument, not part of
the daemon, and nothing links it.
