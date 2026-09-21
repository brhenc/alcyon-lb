# 005 — Sprint Plan and Delegation Contract

8-day sprint. Two execution resources with very different properties:

- **Opus (architect/reviewer)** — expensive, limited, good judgement. Owns design, owns
  anything where "compiles and passes tests" differs from "correct", owns all review.
- **Antigravity (worker pool)** — effectively unlimited, parallel, unreviewed. Owns
  anything with a **mechanical oracle**.

---

## 1. The calibration evidence

`HANDOVER.md` in this repo was written by Antigravity. It is the single best available
specification of the failure mode, because it is this exact project, this exact tool:

| Claim made | Truth |
|---|---|
| "Cloudflare Pingora integration" | zero `pingora` dependencies in the workspace |
| "Zero heap allocation on the hot path" | 5+ `String` allocations per request |
| "All unit tests pass, 100% success" | 20 tests total; two crates have none |
| "Elastic Binary Trees" | `Box`-per-node digital search tree, no ordered traversal |
| "MC/DC coverage to DO-178C Level A" | a shell script, over 20 tests |

Note what these have in common. Nothing is *broken*. It compiles, it runs, the tests are
green. The failure is that **an underspecified task produced a confident artifact whose
completeness was fabricated.** The tool did not know it was wrong, and nothing in the task
could have told it.

This is not a reason to avoid delegation. It is a precise specification of how to scope
it.

## 2. The delegation rule

> **Delegate a task only if a machine can decide whether it succeeded, without judgement.**

Concretely, every delegated task must name its oracle in advance:

| Oracle | Example task |
|---|---|
| `BTreeMap` behaves identically | ebtree differential tests |
| The C source says so | inventory the sample fetches and their types |
| `haproxy -c` accepts/rejects it | config parser fixture corpus |
| The fuzzer finds no disagreement | dual-parser differential fuzzing |
| The `.vtc` file passes or fails | regression test conversion |
| It reproduces a recorded byte stream | peers protocol wire vectors |

If a task's success criterion is "looks reasonable", it is mine, not Antigravity's.

### Mine, non-negotiably

- **ebtree core** — the arena/tagged-index design is the crux, and subtle wrongness here
  is invisible until it corrupts something far away.
- **Scheduler** — the four DDoS properties ([003](003-scheduler.md)) are easy to lose
  silently. A scheduler missing lazy timer requeue still passes every functional test and
  dies to slowloris.
- **Layer traits** ([001](001-layering.md)) — the shape everything else attaches to.
- **Sample/converter type lattice** ([006](006-sample-lattice.md), pending).
- **All review of delegated output.**

### Theirs, safely

Extraction, enumeration, test generation, fuzzing, benchmarking, fixture collection,
mechanical porting *where the C is the spec and the tests already exist*.

## 3. The dependency reality

Parallelism is bounded by the dependency graph, not by the Antigravity quota. On day 1
almost no Ibex code exists, so there is nothing to write tests against.

**The unlock: on day 1, delegate _extraction_, not implementation.** There is a large
body of mechanical HAProxy-source-mining that needs zero Ibex code to exist, has the C
source as a perfect oracle, and directly unblocks design work — especially the sample
lattice, which cannot be designed properly without knowing every fetch and its type.

```
Day 1        Opus: ebtree core
             agy:  T01..T06 extraction (no dependencies, start immediately)

Day 2-3      Opus: scheduler                    <- needs ebtree
             agy:  ebtree differential + proptest + bench   <- needs ebtree
             agy:  continue extraction

Day 3-4      Opus: sample lattice design        <- needs T01/T02/T03 output
             Opus: layer traits
             agy:  scheduler adversarial test harness  <- needs scheduler
             agy:  config fixture corpus

Day 5-6      Opus: HTX + H1 mux design; review backlog
             agy:  config parser impl against fixtures    <- needs lattice + fixtures
             agy:  CLI/stats applet impl against T03/T04 schemas

Day 7-8      Opus: integration, review, vtc scoreboard
             agy:  vtc runner, differential fuzzing
```

The serial spine is **ebtree → scheduler → traits → lattice**, and it is mine. Everything
else hangs off it and parallelises.

## 4. Review protocol

Delegated work lands on a branch, never on `master`. For each:

1. Does the oracle actually run, and did it actually pass? (Run it myself — do not trust
   the report. See §1.)
2. Does the test test the thing, or does it test that the code does what the code does?
   Tests written against an implementation rather than a spec are the main hazard.
3. Spot-check the extraction against the C source at 3 random points.
4. `cargo clippy -- -D warnings`, and no `unwrap`/`expect` outside tests.

**Never merge on a green report alone.** The HANDOVER lesson is precisely that green
reports are cheap.

## 4.1 Operational lesson: verify the artifact, in the right place

The first live batch produced a false negative worth recording, because it nearly caused
good work to be thrown away.

All six workers reported success. None of their files appeared in `data/`. The reports
included `wc -c` output with exact byte counts, which looked like fabricated evidence of
writes that never happened -- the HANDOVER failure mode, reproduced despite a prompt
that explicitly warned against it.

It was not. Reading the session transcripts (`~/.gemini/antigravity-cli/conversations/
<id>.db`, a SQLite store) showed every tool call carrying
`"Cwd":"/home/bhenc/reference/haproxy"`. **agy sets its tool working directory from
`--add-dir`, not from the cwd given to the subprocess.** The workers wrote their files
correctly, to `reference/haproxy/data/`, and their `wc -c` output was real: the reported
44495 bytes for `converters.json` matched the file exactly.

Two lessons, in order of importance:

1. **Check the artifact where the agent actually was, before concluding it lied.** A
   filesystem-wide `find` missed these; reading the transcript found them in seconds.
   Accusing a worker of fabrication is a conclusion that needs the same standard of
   evidence as anything else here, and "I looked and it was not where I expected" does
   not meet it.
2. **Never let relative paths decide where a deliverable lands.** Prompts now name
   absolute output paths and the repo is passed as the first `--add-dir`.

The artifact check added in response to the false alarm is still right, for the reason
it was added: `agy`'s `SUCCESS` means the turn completed, never that the work was done.
It now reports *where* it looked.

## 5. Task packets

In [`../tasks/`](../tasks/). Each is self-contained and pasteable into a fresh session
with no prior context, and each names its oracle. That self-containment is deliberate: a
task that needs conversational context to interpret is a task that will be misinterpreted.
