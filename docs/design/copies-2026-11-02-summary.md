# Summary for the user: T610 (Fable), "why Alcyon copies" — 2026-11-02

Full design: `docs/design/copies-2026-11-02.md` (409 lines, merged 91e96523). Decisions: all six
§8 answers approved by the user 11-02 ~08:20 (`tasks/DECISIONS-pending.md`).

## The finding in one paragraph

HAProxy does *not* create the stream before decoding HEADERS either. It decodes HPACK/QPACK into
a stack list, writes HTX blocks straight into a buffer allocated for a stream that does not exist
yet, then creates the stream and hands it that buffer by value (later swapped into the channel).
Its intermediate *is* the final representation, in memory that moves. Alcyon's intermediate is a
private struct (`H2ReqHead`: `String`s and `Vec`s) that is later copied into blocks and
re-validated: one decode, three writes. So the fix is "the mux writes blocks into a pooled buffer
the stream adopts", not "streams live inside their connection".

## What costs what (ibs_op profiles, release-perf, user instructions per request)

| item | measured | verdict |
|---|---|---|
| request head copied via `H2ReqHead` into blocks | h2s1 2.5-4.7k, h3 2.2-2.6k deleted | **CP2**: -2..-3k h2s1, -1.5..-2k h3fit |
| response head: text -> `Vec<(String,String)>` -> rules -> text; facts walked twice | rules 5.6-7.5k | **X3b**: rules -3.5..-5k |
| backend h2 response written as h1 text and parsed back; `encode_if_modified` | h2backend 4.9-7.7k + 1-2.3k | **X3b**: h2backend -4.5..-8k |
| request rules borrow the whole session (`make_ctx!`, `mem::take` of vars, `res_caps.clone()`) | rules 0.7-0.9k | **CP4**: -0.5..-0.8k |
| text where bytes would do (vars `Slot`, spares, `render_into`, `request_line`) | rules ~0.5-1k | **CP6** |
| stream object after O1b; `StreamLog` clone; park/free moves; h3 links per pass | ~1k left | **CP3** (O1c-lite): -0.5..-0.9k h2s1, -0.6..-1.0k h3fit |
| moving streams into the connection (`Vec<Stream>`, the plan's O1c) | `get2_mut` 0.07-0.14k, `Scheduler::create` 0.02-0.04k, moves ~0.1k | **dropped** (decision 1) |
| `DecodedFields` (HPACK -> list) | 0.2-0.3k | not worth a slice |
| h3 gap vs HAProxy | QUIC listener serve + quinn: 22-23k inclusive per request | not copies: vendored-quinn ins/req work after this plan (decision 6) |

Ranges: two sampling periods disagreed by up to 40% on 1-2k functions; read every figure as
±30%. Estimates are the attributed instructions of the deleted functions minus what the
replacement still does, not operation counts (the last four count-based estimates ran 2-8x high).

## Expected landing (Fable's §6, ranges not added)

h2s1 53.8k -> -3..-5k; h3fit 83.7k -> -2.5..-4k; rules 55.3k -> -4.5..-7k; h2backend 121.4k ->
-4.5..-8k; keepalive unchanged.

## Order and status

CP1 (writer + pooled buffer, off the path, Sonnet) -> X3b and CP2 (Opus, after O1b merges) with
CP3 (Sonnet) beside -> CP4 (Opus, after X3b) -> CP6 (Sonnet). Fable's slice names S1-S6 are
filed as CP1-CP6 (S names are the memory slices).

## Where Rust helped, where it hurt (from Fable's doc and the O1b/R4 design notes)

- Hurt: an owned intermediate per layer because the final owner cannot be borrowed yet; a
  whole-session borrow (`make_ctx!`) forcing `mem::take` swaps; `String` as the spare/var type
  forcing UTF-8 checks HAProxy never does.
- Helped: lifetimes prove a borrowed sample ends before its buffer moves (HAProxy relies on
  `SMP_F_CONST` discipline); exhaustive destructuring makes a forgotten reset field a compile
  error (O1b); the adopt-by-move of a pooled buffer is a `Box` move with no aliasing to audit.
