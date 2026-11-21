# Checking a new Rust toolchain

The host's Rust comes from Fedora (`rustc`/`cargo` in /usr/bin), so it moves whenever the system is
updated. Rustup's cargo stays out of the gate's PATH (`~/.local/rustup-bin`). After every update,
before trusting a gate, measurement or coverage number:

1. **Read the whole release notes.** That means every version between the old toolchain and the new
   one, all sections, and above all **Cargo** and **Compatibility Notes**. Language and library
   features are only part of what changes.
   On 11-17, 1.100.0 was checked for library features only (`docs/rust-upstream-candidates.md`).
   Its Cargo note, "a new directory layout for intermediate build artifacts", broke covercheck
   on 11-21. Covercheck read 2 objects instead of ~340 and reported 142 lines as unexecuted
   (fixed by 58ebb50c). It also broke a test that looked for `alcyon` at `<exe>/../..` (fixed by
   9175ec12). The rest of the layout fallout is T648.
2. **Run one non-measuring gate on an unchanged, known-green commit** (`ALCYON_GATE_SKIP_MEASURE=1`)
   before gating any new work. A failure there comes from the toolchain, not from the branch.
   Check that the covercheck line reports hundreds of objects, and that the suite count matches the
   last gate.
3. **Rebuild the measuring reference** (`ALCYON_MEASURE_REF`) with the new compiler before the next
   measured gate. Instructions per request across two compilers measure the compiler, not the change.
4. **Check that llvm-tools match:** `rustc -vV` LLVM version = `llvm-profdata --version` (covercheck
   uses `/usr/bin/llvm-*`).
5. A first build under a new compiler is a full rebuild of every target dir. Expect it in the gate's
   time, and expect old artifacts to pile up in `~/ibex-targets` (the user deletes them).
6. Tell agy over the bridge. Its queue runs `checkin.sh` too, and a toolchain failure must not be counted
   against a model or "fixed" by one.
