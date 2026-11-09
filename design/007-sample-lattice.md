# 007 — The Sample / Converter / Matcher Lattice

Reference: `/home/bhenc/reference/haproxy` @ `e6f616af`. Grounded in the extracted
inventories in [`../data/`](../data/): **570 sample fetches**, **211 converters**, and
HAProxy's own `sample_casts` table.

This is the part of HAProxy worth stealing outright. `src` and `req.hdr(x)` are not
built-in keywords in a parser — they are entries in a registry, returning typed values
that flow through a chain of converters and end at a typed matcher. Everything
downstream is built on it: stick-table keys, `use_backend` conditions, log-format
strings, `http-request set-header`, `set-var`. Get it right and those are configuration;
get it wrong and each becomes bespoke code.

---

## 1. Three registries and a type system

```
  req.hdr(User-Agent)  ,lower  ,map_reg(ua.map)   -m found
  └──── fetch ───────┘ └─ converter chain ─────┘  └ matcher ┘
        STR                    STR -> STR              BOOL
```

| Registry | Count | Shape |
|---|---|---|
| Sample fetches | 570 | `(args, context) -> Sample` |
| Converters | 211 | `(Sample, args) -> Sample` |
| Matchers | ~15 | `(Sample, pattern) -> bool` |

Fetch output types, from `data/sample_fetches.json`:

| Type | Fetches |
|---|---|
| `SMP_T_SINT` | 325 |
| `SMP_T_STR` | 141 |
| `SMP_T_BIN` | 47 |
| `SMP_T_BOOL` | 37 |
| `SMP_T_ADDR` | 10 |
| `SMP_T_ANY` | 5 |
| `SMP_T_METH` | 2 |
| `SMP_T_IPV4` | 2 |
| `SMP_T_IPV6` | 1 |

## 2. Three of HAProxy's ten types are not types

`include/haproxy/sample-t.h:37`, with upstream's own comments:

```c
enum {
    SMP_T_ANY = 0,   /* pseudo type: any type */
    SMP_T_SAME,      /* special: output type hint for converters that don't alter input type */
    SMP_T_BOOL,
    SMP_T_SINT,
    SMP_T_ADDR,      /* pseudo type: could be ipv4 or ipv6 */
    SMP_T_IPV4,
    SMP_T_IPV6,
    SMP_T_STR,
    SMP_T_BIN,
    SMP_T_METH,
    SMP_TYPES
};
```

`ANY`, `SAME` and `ADDR` are annotated *in the source* as pseudo types. They describe
**signatures**, not values:

- `ANY` in a converter's input slot means "accepts whatever arrives".
- `SAME` in a converter's output slot means "whatever came in".
- `ADDR` means "IPv4 or IPv6, decided at runtime".

No sample is ever *of* these types at runtime. C puts them in the same enum anyway,
because C has one enum, and the cost of that conflation is visible in the cast table.

### 2.1 `c_pseudo` — the conflation, priced

`sample_casts[SMP_TYPES][SMP_TYPES]` is a 10×10 dispatch table (`src/sample.c`). Every
cell on an `ANY` or `ADDR` row holds `c_pseudo`:

```c
/* Reaching this is considered as a bug and should be fixed. To help spot this
 * kind of bug, the process will crash in this case. */
int c_pseudo(struct sample *smp)
{
    ABORT_NOW(); // die loudly
}
```

**HAProxy encodes "this cast cannot exist" as a deliberate runtime crash**, because the
type system cannot say it. That is not sloppiness — it is the correct engineering
response given the constraint, and the loud crash is better than silent corruption.

It is also exactly the class of thing a Rust rewrite should delete rather than
reproduce.

### 2.2 The split

```rust
/// A value. Seven variants, all inhabitable.
pub enum Sample {
    Bool(bool),
    Sint(i64),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Str(SampleStr),
    Bin(SampleBin),
    Meth(Method),
}

/// A signature slot. Never a value.
pub enum TypeSpec {
    Exact(SampleType),
    Any,                 // SMP_T_ANY
    Same,                // SMP_T_SAME
    Addr,                // SMP_T_ADDR: Ipv4 | Ipv6
}
```

The `ANY` and `ADDR` rows of the cast table **cease to exist as representable states**.
There is nothing to guard and nothing to crash on: 30 `ABORT_NOW()` cells become
uninhabitable rather than unreachable-by-convention.

This is the project's thesis at its cleanest. The design is preserved exactly — same
registries, same chaining, same semantics — and a whole category of runtime abort is
removed by expressing a distinction the original could not.

## 3. The cast table

HAProxy's real implicit-cast matrix (`src/sample.c`), reproduced from source. Rows are
source type, columns target:

|  | BOOL | SINT | IPV4 | IPV6 | STR | BIN | METH |
|---|---|---|---|---|---|---|---|
| **BOOL** | `c_none` | `c_none` | — | — | `c_int2str` | `c_bool2bin` | — |
| **SINT** | `c_none` | `c_none` | `c_int2ip` | `c_int2ipv6` | `c_int2str` | `c_int2bin` | — |
| **IPV4** | — | `c_ip2int` | `c_none` | `c_ip2ipv6` | `c_ip2str` | `c_addr2bin` | — |
| **IPV6** | — | — | `c_ipv62ip` | `c_none` | `c_ipv62str` | `c_addr2bin` | — |
| **STR** | `c_str2int` | `c_str2int` | `c_str2ip` | `c_str2ipv6` | `c_none` | `c_none` | `c_str2meth` |
| **BIN** | — | — | — | — | `c_bin2str` | `c_none` | `c_str2meth` |
| **METH** | — | — | — | — | `c_meth2str` | `c_meth2str` | `c_none` |

`c_none` means the representations coincide and the cast is a relabel: `BOOL`/`SINT`
share an integer, `STR`/`BIN` share bytes. Those stay zero-cost in Rust.

Two properties to preserve deliberately:

- **It is asymmetric.** `STR -> SINT` exists; `SINT -> BOOL` is free but `BOOL -> SINT`
  is too, while `IPV6 -> SINT` does not exist at all. The table is not a lattice in the
  algebraic sense and should not be "tidied" into one — each cell is a decision.
- **Casts are fallible.** `c_str2int` on `"abc"` fails. In C the cast functions return
  `int` and callers check; in Rust they return `Option<Sample>` and the compiler checks.

### 3.1 Where casts are applied

`src/sample.c:1355` and `:1752` — before invoking a converter, and when delivering a
sample to a consumer:

```c
sample_casts[smp->data.type][conv->in_type](smp)
```

The chain does not require exact type agreement; it inserts a cast. Reproducing that is
what makes `req.hdr(Content-Length),add(10) -m int gt 100` work without the user
thinking about types.

## 4. Fetch context validity

Fetches carry `SMP_VAL_*` bitmasks stating where they may be evaluated — a request
header fetch is meaningless in a `tcp-request connection` rule, because no header has
been read. HAProxy validates this at config-parse time, which is the right moment:
a misplaced fetch is a config error, not a runtime surprise.

Alcyon keeps that, with the check expressed as a set intersection between the fetch's
declared validity and the rule's evaluation context, performed during parsing.

## 5. Implementation plan

### 5.1 Crate: `alcyon-sample`

```
sample.rs     Sample, SampleType, TypeSpec, casts
registry.rs   FetchRegistry, ConvRegistry, MatchRegistry
expr.rs       parse "fetch(args),conv1,conv2" into a compiled Expr
eval.rs       evaluation against a context
matcher.rs    -m str|beg|sub|reg|ip|int|found|len ...
```

`Expr` compiles **once at config-parse time** into a small vector of ops resolved to
registry indices — no string lookups, no allocation per request. This mirrors HAProxy
and matters: an expression is evaluated per request, and parsing it per request would
be the single worst thing in the hot path.

```rust
pub struct Expr {
    fetch: FetchId,          // u16 registry index
    fetch_args: ArgsRef,     // into a per-config arena
    chain: Vec<ConvStep>,    // resolved converter ids + args
    out_type: SampleType,    // computed at parse time
}
```

### 5.2 Order of work

1. `Sample` + `SampleType` + `TypeSpec`, and the cast table as a `const` 7×7 of
   `Option<fn>`. Differential-test every cell against the C behaviour.
2. The three registries, with a declarative registration macro so adding a fetch is one
   entry rather than plumbing.
3. Expression parser: `fetch(a,b),conv(c) -m match pattern`, including the quoting and
   escaping rules.
4. Type resolution at parse time: walk the chain, insert casts, reject impossible ones
   **with a config error**.
5. Matchers.
6. Enough fetches for `mode tcp`: `src`, `dst`, `dst_port`, `src_port`,
   `sc_*` counters. HTTP fetches follow the H1 mux.

### 5.3 Validation

- **Differential casts.** Build a tiny C harness against the reference tree calling
  `sample_casts[i][j]` over a corpus, and assert Alcyon agrees on every cell including
  the failures. The reference binary is already built.
- **Expression corpus** from `data/regtests.json` — 312 reg-tests contain real
  expressions, which is a better corpus than anything hand-written.
- **Registry coverage** against `data/sample_fetches.json` and `data/converters.json`:
  a test that reports which of the 570 and 211 are implemented, so scope is measured
  rather than asserted.

## 6. Scope

Not all 570 fetches and 211 converters. The inventories exist to make coverage
*measurable*, not to imply a target. For `mode tcp` (see [008](008-tcp-first.md)) the
needed set is roughly a dozen fetches and a handful of converters; HTTP roughly triples
it. The registry shape is what matters — with it, adding a fetch is an entry in a table,
and without it every one is a change to the engine.
