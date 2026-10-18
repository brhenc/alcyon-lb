<!--
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
-->
# T364 plan: typed variables (design and slices), 2026-10-18

Design task. Nothing is implemented. Measured on HAProxy 3.5-dev8-885761-29
(`/home/bhenc/reference/haproxy/haproxy`) against Ibex main `1a86b96b` (T363a merged), built at
`/home/bhenc/ibex-targets/t364/release/ibex` from the scratch worktree `~/ibex-worktrees/t364`
(branch `design/t364`, no commits). Probe scripts and raw results: `~/ibex-worktrees/review/t364-probes/`
(`matrix.py` + `hi.json` is the matrix; `e2.py`..`e8.py` are the smaller probes; `hmal.py` is the
malloc count; `varalloc_probe.rs` is the in-process allocation probe, now deleted from the worktree).

## 0. Summary

- **HAProxy keeps the type.** For each of 20 stored values x 48 expressions, HAProxy gives the same
  result through a variable as straight from the fetch, in every scope (`txn`, `sess`, `proc`,
  var-to-var copy): 0 differences out of 960 cells that load. So "typed variables" means exactly this:
  `var()` gives back the `Sample` that was stored.
- **Ibex loses it everywhere, not only for `bin`.** Through a variable, Ibex differs from HAProxy in
  **109 cells where the same expression without a variable agrees, or where HAProxy refuses it
  without one** (the "type lost" column in §1). 99 of them leave out `-m bool`, which Ibex refuses
  everywhere (D2).
  The task file listed only the `bin -> str` NUL cut. Measured as well: `int`/`bool`/`ipv4`/`ipv6`
  variables fed to `hex`/`base64`/`crc32`/`sha1`/`bytes` hash the **decimal text** instead of the
  8-byte or 4/16-byte value; `ipv4` through `add`/`neg` gives `10` (the text "10.1.2.3" parsed)
  instead of `167838211`; an `int` through `ipmask` gives nothing instead of `0.0.0.0`; `bin`/`meth`
  variables match `-m int 0` and give `0` through `add` (HAProxy: no cast, no sample). `sess`,
  `proc` and var-to-var copies are identical to `txn` (0 extra differences).
- **The cost is far lower than §6.12's estimate.** The ~1,200 lines and ~290 test sites in §6.12 are
  T272 D2's cost of turning `Sample::Str(String)` into bytes (option A). Typed variables do not need
  that. `Sample` stays as it is. Only the variable store changes, from `String` to a typed value.
  Estimate: ~350-450 changed lines for the semantics (S2), and about 5 test files whose expectations
  encode today's lossy behaviour. None of the ~290 `Sample::Str` test constructions changes. The one
  frozen file (`crates/ibex-sample/tests/sample_semantics.rs`) uses `set_proc_var(&str, String)` and
  `get_proc_var(&str) -> Option<String>`. Both stay as shims with those signatures.
- **Allocation.** HAProxy itself mallocs for variables: 1 malloc per new variable (the name,
  `my_strndup`) plus 1 per `str`/`bin` value (LD_PRELOAD count, 4,000 keep-alive requests:
  0 / 1 / 2 / 5 mallocs per request for none / 1 int / 1 str / 5 ints). Ibex today: +4 per `int`
  variable and +6 per `str` variable on the shipped binary (7 -> 11 -> 13 -> 27). The design gets
  Ibex to **0 per request in steady state for storing**, which is better than HAProxy, and to 0 for
  reading scalars. Reading a `str`/`bin` variable still costs the one copy into an owned `Sample`,
  until the sample layer gets borrowed samples (§6.13 work, not T364).
- Reg-tests: `sample_fetches/hashes.vtc` fails on Ibex (c1 line 5, `x-len0`), `cond_set_var.vtc`
  fails at load (`ifgt`), `vars.vtc` passes. All three pass on HAProxy with `harness/vtc_runner.py`.
  `http-rules/set_vars_from_map.vtc` fails at load on `tune.vars.from-map.max`.

## 1. The measured cast matrix

Method (`matrix.py`): for each stored value `V`, one config per (binary, value, mode) with
`http-request set-var(txn.v) V` (also `sess.v`, `proc.v`, `txn.w` copied from `txn.v`, and
`set-var-fmt(txn.f) "%[V]"`). Each expression is evaluated in an `lf-string` of
`http-request return`. Each ACL `acl aN <src> -m ...` is read back through an `int` variable set
`if aN` / `unless aN`. That is safe because `int` agrees. Every cell is load-checked first with
`-c` on its own, so a refused expression is a "load error" cell and does not take the row down.
The **direct** mode (`V,<conv>` with no variable) is the control. It separates "the variable lost
the type" from "Ibex's cast or converter differs anyway".

Stored values: `bool(1)`, `bool(0)`, `int(5)`, `int(-3)`, `ipv4(10.1.2.3)`, `ipv6(2001:db8::1)`,
`ipv6(::ffff:10.1.2.3)`, `str(007)`, `str(Abc)`, `str(5)`, `str()`, `str(10.1.2.3)`, `bin(000102)`,
`bin(41424300ff)`, `bin(4162c3a9)` ("Abé" in UTF-8), `bin(80ff)`, `bin(416263)`, empty bin
(`str(),b64dec`; `bin()` is refused by HAProxy), `method` on a GET and on a `FOO` request.

Expressions, grouped by the input type they cast to:
- any: `(as is)` in the log-format.
- bool: `not`.
- sint: `add(0)`, `neg`, `bool`.
- addr: `ipmask(8)`, `ipmask(16,64)`.
- str: `length`, `lower`, `upper`, `json`, `concat(x)`, `field(1,b)`, `word(1,b)`, `ltrim(A)`,
  `url_dec`, `secure_memcmp(txn.k)`.
- bin: `hex`, `bytes(1)`, `base64`, `crc32`, `sha1,hex`.
- ACL `-m`: `found`, `bool`, `int 5`, `int gt 0`, `int 0`, `len 0/3/5`, `str 007/Abc/5/1/GET/10.1.2.3`,
  `bin 000102/41424300ff/416263/01`, `ip 10.1.2.3`, `ip 2001:db8::/32`, `beg A`, `sub b`, `reg ^A`,
  `end c`, `dom Abc`, `dir Abc`.

Each `txn` cell compared to HAProxy:

| stored in the variable | agree | differ: type lost | differ: cast or converter, also without a variable | agree through the variable, a load check differs without one |
|---|---|---|---|---|
| bool(1) | 40 | 0 * | 5 | 3 |
| bool(0) | 41 | 0 * | 5 | 2 |
| int(5) | 41 | 6 | 1 | 0 |
| int(-3) | 40 | 7 | 1 | 0 |
| ipv4 | 40 | 7 | 1 | 0 |
| ipv6 | 35 | 11 | 0 | 2 |
| ipv6 v4-mapped | 32 | 12 | 2 | 2 |
| str(007) / str(Abc) / str(5) / str() / str(10.1.2.3) | 47 each | 0 | 1 (`-m bool`) | 0 |
| bin(000102) | 26 | 18 | 0 | 4 |
| bin(41424300ff) | 27 | 17 | 0 | 4 |
| bin "Abé" | 36 | 6 | 2 | 4 |
| bin(80ff) | 37 | 6 | 1 | 4 |
| bin(416263) | 38 | 6 | 0 | 4 |
| bin empty | 42 | 1 | 0 | 5 |
| meth GET / FOO | 38 each | 6 | 0 | 4 |

\* `bool` also loses its type through a variable: `var(txn.b),hex` is `31` (the text "1") where
`bool(1),hex` is `01`. Both differ from HAProxy's `0000000000000001`, so the cell counts as a cast
difference. See D1 below.

`sess`, `proc` and var-to-var: identical to `txn` cell for cell (0 differences between modes, on
both binaries). `set-var-fmt` stores a `str` on both. Its only differences are the cast and converter
ones (D3, D4, D5).

### What the "type lost" cells are (T364 proper), by class
| class | example (stored, expression) | HAProxy | Ibex |
|---|---|---|---|
| T1 `bin -> str` NUL cut lost | `bin(000102)`, `length` / `-m len 0` / `lower,length` | `0` / match | `3` / no match |
| T1 | `bin(41424300ff)`, `concat(x)` / `ltrim(A)` / `-m len 3` | `ABCx` / `BC` / match | `ABC\0\xffx` / `BC\0\xff` / no |
| T2 scalar -> `bin` gives the text, not the value | `int(5),hex`; `ipv4,hex`; `ipv6,base64` | `0000000000000005`; `0A010203`; 16 bytes | `35`; `31302E312E322E33`; the text |
| T2 (hashes, so stick keys, `crc32`, `sha1`, `bytes`) | `int(-3),bytes(1)`; `ipv4,crc32` | `ÿÿÿÿÿÿý`; `3825493623` | `3`; `4128529761` |
| T3 `ipv4 -> sint` is `ip2int` | `ipv4,add(0)` / `neg` | `167838211` / `-167838211` | `10` / `-10` |
| T4 no cast in HAProxy, a parse of the text in Ibex | `ipv6,add(0)`; `bin,add(0)`; `meth,neg`; `ipv6,not` | no sample | `2001`; `0`; `0`; `0` |
| T4 (ACL) | `bin`/`meth`/v4-mapped `-m int 0`; `ipv6 -m int gt 0` | no match | match |
| T5 `sint -> addr` is `int2ip` | `int(5),ipmask(8)`; `int(-3),ipmask(16,64)` | `0.0.0.0`; `255.255.0.0` | no sample |
| T6 `ipv6 -> bin` | `ipv6(::ffff:…),bytes(1)` / `hex` | 16 raw bytes | the text |

Converter **arguments** that name a variable also cast from the stored type (`sample_conv_var2smp`,
src/sample.c 1981). Measured with `e8.py` (`int(1),add(txn.v)`, `str(),concat(<,txn.v,>)`,
`int(100),div(txn.v)`, `str(Abcdef),bytes(txn.v)`):
- `ipv4` in `add(txn.v)`: HAProxy `167838212`, Ibex no sample.
- `str(Abc)` in `add`/`div`/`bytes`: HAProxy reads it as 0 (`c_str2int` is lenient), giving `1`,
  `9223372036854775807` (division by 0) and the whole string. Ibex gives no sample: `resolve_var_int`
  uses `str::parse`.
- `bin(41626300ff)` in `concat`: HAProxy `<Abc>` (NUL cut), Ibex `<Abc\0\xff>`.

### Differences that are *not* about variables (found on the way; separate tasks)
| id | what | HAProxy | Ibex |
|---|---|---|---|
| D1 | `bool -> bin` cast (`c_bool2bin`) | 8 bytes: `bool(1),hex` = `0000000000000001` | 1 byte: `01` |
| D2 | `-m bool` matching method | accepted. `str(007)`, `int`, `ipv4` match; `str(Abc)`, `str()`, `ipv6`, `bin`, `meth` do not | refused at load: "unknown matching method 'bool'" (direct as well, so independent of T364) |
| D3 | an IPv4-mapped IPv6 into an addr converter or `-m ip` | `ipv6(::ffff:10.1.2.3),ipmask(8)` = `10.0.0.0`; `-m ip 10.1.2.3` matches | no sample / `::`; no match |
| D4 | `json` on bytes >= 0x80 (`bin -> str` input) | `Ã©` per byte | raw bytes |
| D5 | `upper` on bytes >= 0x80 | ASCII only (`Ã©` unchanged) | Unicode upper-casing (`é` -> `É`, byte `a9` -> `89`) |
| D6 | `strcmp` result | the raw difference (`12`, `16`, `7`, `-6`) | the sign (`1`, `-1`) |
| D7 | `json_query` result type | `bool`/`sint`: `json_query('$.a')` on `true` is `1`, `('$.n','int')` gives 8 bytes through `hex` | `str`: `true`, `35`. This is why `converter/json_query.vtc` fails (line 30), not variables |
| D8 | load-time type check of `-m` against the fetch | refuses `-m ip` on `bool`/`bin`/`meth` fetches, `-m int` on `ipv6`/`bin`/`meth`, `-m bin 01` on `bool` | accepts them, then never matches (AGENTS.md rule 5) |
| D9 | config lexer | refuses an unmatched `"` in `str(a"b)` and `$` in a double-quoted `json_query('$.a')` | accepts both |
| D10 | `tune.vars.*` (all 6 `-max-size`, `from-map.max`) | accepted, enforced (§2.4) | "unknown keyword" at load |

### Variable behaviour measured besides the casts
- **Conditions** (`e2.py`, `e3.py`; HAProxy src/vars.c `var_set` 628-790):
  - `ifgt`: sets only when the variable *and* the new sample are both `sint` and the stored value
    is greater (`a=5; set ifgt 3` gives 3; `ifgt 9` keeps 5). So `ifgt` keeps the minimum and
    `iflt` keeps the maximum.
  - With any other pair of types the condition is ignored and the variable is set: `str(5)` then
    `ifgt int(9)` gives 9; `int(5)` then `ifgt str(1)` gives `1`; `bool` with `iflt` is set.
  - An absent variable is set.
  - Same through the `set-var` converter.
  - Ibex refuses both at load.
  - `ifexists`/`ifnotset`/`ifempty`/`ifnotempty` with `unset-var` and scalar/empty samples: all
    7 probes agree on both. `unset-var` deletes a non-`proc` variable (it no longer "exists").
- **Accounting** (`e4.py`, `e5.py`):
  - A new variable costs **88 bytes** (`sizeof(struct var)` on this build): `txn-max-size 87`
    refuses one `int` variable and 88 takes it. A `str`/`bin` adds its length.
  - Limits nest: `txn` counts in `sess` and `proc`/`global`; `reqres` in `txn`. `sess-max-size 100`
    refuses a second 10-byte `txn` variable, `reqres-max-size 50` does not.
  - Failure: a new variable is not created. An **existing** variable that cannot take a new
    `str`/`bin` value **becomes `bool`**, and the union keeps the old integer: `int(7)` then a
    10-byte `str` under `txn-max-size 90` reads back as `7`, `add(1)` = `8`, `hex` =
    `0000000000000001`. Ibex: `tune.vars.*` is an unknown keyword.
- **`dump_all_vars`**:
  - HAProxy types each value: `txn.s="ab"`, `txn.m="GET"`, `txn.q=::1`, `txn.p=10.1.2.3`,
    `txn.b=41004243` (hex), `txn.i=5`, `txn.o=true`.
  - Ibex: `txn.b="A\0BC"`, `txn.o=1`, `txn.p="10.1.2.3"`, `txn.q="::1"`.
  - The order differs too. HAProxy walks a tree keyed by an XXH3 hash with a **random seed per
    process** (`var_name_hash_seed = ha_random64()`), so its order is not reproducible. Ibex sorting
    by name stays as is.
- **CLI `get var`**:
  - HAProxy prints `type=sint`, `type=bin value=<>` (printed up to the first NUL), `type=ipv4`.
  - Ibex guesses the type from the text: `type=ip`, and `type=str value=<\0\x01>` for a `bin`.
- **Global `set-var proc.p int(5)`**: `var(proc.p),hex` gives HAProxy `0000000000000005`, Ibex `35`.
  `set-var-fmt` gives `str` on both.
- **`var(txn.zz,77),add(1)`** (the default is a `str`): `78` on both.

## 2. Design

### 2.1 What a variable holds
A variable holds a `Sample`, the type Ibex already has
(`crates/ibex-sample/src/sample.rs`: `Bool`, `Sint`, `Ipv4`, `Ipv6`, `Str(String)`,
`Bin(Vec<u8>)`, `Meth(HttpMethod)`). No new value type and no change to `Sample`:
- `Str` stays bytetext (T363a), so a `str` variable round-trips as today.
- `Bin` keeps raw bytes. The NUL cut then comes for free from the existing `cast.rs` `c_bin2str`,
  because the cast now starts from `Bin`.
- `Meth(Other(String))` keeps the method text, as HAProxy keeps `meth.str`.

At rest, the store keeps a compact form (§2.5) and converts it to and from `Sample` at its edge, so
the rest of the code sees only `Sample`.

"Exists but unset" (HAProxy's `SMP_T_ANY`, only reachable for `proc` variables declared by the
configuration, `VF_PERMANENT`) is the store's own state. It is not a `Sample` variant.

### 2.2 Scopes and lifetimes (as HAProxy's `get_vars`)
| scope | lives in | lifetime | Ibex today | after |
|---|---|---|---|---|
| `proc` | process | process. Declared names exist from load (permanent) | `GLOBAL_PROC_VARS: RwLock<HashMap<String,String>>` | `RwLock<ProcVars>` of typed slots. `get_proc_var`/`set_proc_var` stay as `String` shims for the frozen test and the CLI |
| `sess` | the client connection | the connection; every request and H2 stream of it | `TcpSession.sess_vars` (H2 children get a clone and a merge on `h2_child_done`) | a typed store on the session. H2 sharing: §2.7 |
| `txn` | the stream | one request/response | `req_vars` with a `txn.` prefix | typed store, cleared at the end of the transaction, capacity kept |
| `req` / `res` | the stream's `vars_reqres` | `req.` until the response starts, then `res.` | `req_vars` with a prefix, `retain` at response start | one store with a current scope. Switching to `res` clears it, as `vars_prune` + `vars_init_head(SCOPE_RES)` do |
| `check` | the health check run | one check | `check.rs` `run.vars: HashMap<String,String>` | the same typed store type |

`psess`/`ptxn`/`preq`/`pres` (parent stream, `VDF_PARENT_CTX`) are accepted by `vars_check` today.
Without Lua/SPOE sub-streams HAProxy has no parent either, so they give no sample. Keep that.

The thread-local `CURRENT_VARS` stays as the way converters (which get no context) reach the
running stream's variables. It changes from "drain the session's maps into a thread map and back"
(rehashes and allocates every run, `stream_vars_enter`/`leave`) to **`mem::swap` of one
`StreamVars { sess, txn, reqres }` value in and out**: O(1), no allocation. Its comment already
claims "no allocation". With `HashMap::extend` that claim is false. With a swap it becomes true.

### 2.3 `var_set`: one port, one place
Today there are five copies of the store logic: `store_var_smp`, `store_var`, `set_var_from_expr`,
the `set-var` converter, and `write_var` in registry.rs. All become
`vars::set(desc, &Sample, conds) -> bool`, a line-for-line port of `var_set`:
- conditions in HAProxy's order: `ifexists`/`ifnotexists`, then accounting for a new variable,
  `ifset`/`ifnotset`, `ifempty` on scalars, `ifgt`/`iflt` only for `sint`/`sint`,
  `ifempty`/`ifnotempty` on `str`/`bin` length;
- the accounting failure that turns an existing variable into `bool`.

`unset-var` is `vars::unset`, the port of `var_unset`/`var_clear`: a permanent `proc` variable goes
back to "exists, unset", any other variable is removed, and its bytes come back out of the
accounting.

Conditions are parsed once, at load, into a `u8` bitmask. Today the condition text is re-split and
`args.join(",")` is allocated on every call of the converter.

### 2.4 Memory accounting `tune.vars.*` (HAProxy's numbers)
- Parse `tune.vars.global-max-size`, `proc-max-size`, `sess-max-size`, `txn-max-size`,
  `reqres-max-size`, `check-max-size` (sizes), and `tune.vars.from-map.max` (accept, and refuse
  `set-vars-from-map` until it is implemented, rule 5).
- Each store carries `size: u64`. The proc/global total is one process `AtomicU64`.
  `var_accounting_add` and `var_accounting_diff` port as written: reqres -> txn -> sess -> proc,
  checked when a limit is set.
- Cost: `VAR_STRUCT_COST = 88` per created variable, plus the bytes of a `str`/`bin`/`Meth::Other`.
  Ibex's own structures are smaller (§2.5), but the accounting uses HAProxy's numbers so that a
  configuration's limits mean the same thing. Pin the 88 in a test with the measured 87/88 boundary.
- Failure behaviour as measured: not created, or "becomes `bool`". On the second, Ibex cannot keep
  HAProxy's union value (a `bool` that prints `7`). See the open question in §4.

### 2.5 Storage with no allocation on the request path
1. **Names are interned.** Every variable name the configuration writes (`set-var`, `var()`, a
   converter argument that `vars_check` accepts, `unset-var`, global `set-var`) gets a
   `VarId { scope, idx: u16 }` in a process-wide table.
   - The table is built at load when the parser checks the name, and for runtime-parsed expressions
     when `Expr::cached` first compiles the text, which is the warm-up request.
   - A store is a `Vec<Slot>` indexed by `idx`, sized to the scope's name count when it is created.
     Lookup is an index, with no hashing and no `String` key per insert.
   - The table only grows. An index past a store's length grows that store, which can only happen
     on a name first seen at run time, so on warm-up.
   - Today every insert allocates the name twice (`name.to_string()` into the session map and into
     `CURRENT_VARS`) and clones the value.
2. **Slot.** `enum Slot { Absent, Unset, Bool(bool), Sint(i64), Ipv4(..), Ipv6(..), Meth(u8), Str(Span),
   Bin(Span), MethOther(Span) }`, where `Span = (u32 off, u32 len)` points into the store's
   `bytes: Vec<u8>` arena. Scalars take no arena bytes.
3. **Arena.**
   - A set appends the value's bytes. An overwrite whose new value fits in the old span writes in
     place.
   - When the arena's capacity would be exceeded, it is compacted first (live spans moved down,
     no allocation). Only if that is not enough does it grow, with `try_reserve`. On failure the set
     behaves as HAProxy's failed `malloc`: the variable becomes `bool`. No abort
     (RUST-FOOTGUNS.md §2).
   - Growth is bounded by the `tune.vars` limit when one is set, and by `tune.bufsize` x the number
     of `set-var` rules otherwise. A value comes from one sample, and a sample is bounded by the
     trash size, which `truncate_to_trash` already enforces for `set-var-fmt`.
4. **Reuse.**
   - End of transaction: `txn`/`reqres` slots go back to `Absent` and the arena length to 0, with
     the capacity kept. Keep-alive requests then store with no allocation.
   - A new connection takes its `sess` store and its first `txn` store from a **per-thread free
     list** (at most 256 spares; an arena whose capacity is over 4 KiB is shrunk on return). So
     new connections in steady state also allocate nothing.
   - This is a pool of the kind §6.13 plans, small and private to the variables. If the §6.13 pool
     design lands first with a generic per-thread pool, use that one.
5. **Reads.**
   - Scalars: `Sample::Sint(..)` and the others are built from the slot with no allocation.
   - `str`/`bin`: `Sample::Str(String)`/`Bin(Vec<u8>)` own their bytes, so a read copies once
     (1 allocation). HAProxy copies too (`smp_dup` into a trash chunk), but into a pre-allocated
     chunk.
   - Removing that copy needs a borrowed sample in the evaluator, which is part of the zero-malloc
     work on the whole sample layer. `Expr::eval_sample` itself allocates a `Vec` and clones every
     converter's arguments on each evaluation (expr.rs 305-311), which costs more than the variable
     read.
   - Record it in tradeoff §6.13. Do not do it in T364.
6. **What it costs.** About 250 lines for the store (interner, slots, arena, free list), plus the
   wiring in S6. Memory per `txn` store: 16 bytes x names in scope, plus the arena. With 50 names
   that is under 1 KiB, and it is reused.

### 2.6 Where values cross boundaries
| boundary | today | after |
|---|---|---|
| `var()` fetch | `out_type: Str`, returns `Sample::Str(clone)` | out type **any** (HAProxy `SMP_T_ANY`): returns the stored `Sample`. The load-time converter check treats *any* as "cast at run time". `FetchDesc.out_type` gains an `Any` (or `TypeSpec`) |
| converter input | cast from `Str` | the existing `cast()` from the stored type: the matrix rows T1-T6 follow with no converter change |
| converter variable arguments (`add`/`sub`/`mul`/`div`/`mod`/`and`/`or`/`xor`/`bytes`/`concat`/`strcmp`/`secure_memcmp`/`hmac`/`jwt_verify`/`aes_gcm_*`/`b64_arg`) | `resolve_var_int` (`str::parse`), `resolve_var_str`, `read_var` -> `String` | one `var_arg(name, SampleType) -> Option<Sample>` = `sample_conv_var2smp`: get, then `cast` (lenient `c_str2int`: `Abc` -> 0). `jwt_verify` keeps its own `chunk_printf("%.*s")` NUL cut |
| ACL | the matcher gets `Str` | the matcher gets the typed sample, as with any fetch (direct mode already agrees) |
| log-format `%[var()]`, `set-header`, `lf-string` | `sample_to_string` | unchanged: `sample_to_string` of the typed sample. `bin` is already raw bytes as bytetext, and the matrix "as is" column agrees except for the NUL cut |
| `set-var-fmt` | `Str` | `Str` (as HAProxy: `SMP_T_STR`), truncated to trash |
| global `set-var` / `set-var-fmt` | `String` | typed `proc` slot; `set-var-fmt` gives `Str` |
| CLI `get var` / `set var` (applet.rs) | prints a guessed type | prints the stored type with HAProxy's names (`sint`, `bool`, `ipv4`, `ipv6`, `str`, `bin`, `meth`) and HAProxy's value formatting (`%.*s` up to NUL for `bin`) |
| `dump_all_vars` | one quoted format | HAProxy's per-type format (`"str"`, hex for `bin`, `true`/`false`, bare addresses, `"GET"`) |
| stick tables `sc-set-gpt*` `var()` | `resolve_gpt0_val` on the evaluated `Sample` | unchanged. GPT values are separate storage (ibex-stick-table) and share nothing with variables |
| health checks `check.` | `HashMap<String,String>`, `SampleContext.vars` | the same store type. `SampleContext.vars` becomes `Option<&StreamVars>` |

### 2.7 HTTP/2: `sess` variables shared between streams
Today a child stream gets a clone of the connection's `sess_vars` plus a second clone
(`sess_vars_at_start`), and its changes are merged back when it finishes (proxy.rs 866-904). That is
2 map clones per H2 stream, and a sibling sees a write only after the writer finishes. In HAProxy
all streams of a session share `sess->vars`, under a lock.

Design: the `sess` store moves behind `Rc<RefCell<VarStore>>`, shared by the owner and its
children on the owner's thread. Every borrow is `try_borrow`/`try_borrow_mut`, scoped to one get or
set. A failed borrow reads as "no variable" or "not set", never a panic (RUST-FOOTGUNS.md §3,
`RefCell::borrow_mut`).

This is a behaviour change (live sharing instead of merge on finish). It needs its own measurement
on the oracle with two concurrent streams. It is a separate slice (S7) and may be dropped (§4).

### 2.8 Migration from `String`
- **ibex-sample/registry.rs:**
  - `CURRENT_VARS` becomes `RefCell<StreamVars>`. `set_current_vars` keeps a test-only
    `HashMap<String,String>` adapter for converters_bulk.rs (4 sites), or those sites move to
    `set_current_var(name, Sample)`.
  - `read_var`/`write_var`/`resolve_var_int`/`resolve_var_str`, the `var` fetch, the `set-var` and
    `unset-var` converters, `dump_all_vars`, and the `hmac`/`jwt_verify`/`b64_arg` key readers go
    through `vars::{get,set,unset,var_arg}`.
  - `get_proc_var`/`set_proc_var`/`unset_proc_var` keep their signatures. `get_proc_var` gives
    `sample_to_string` of the value.
  - `var_conds_hold` is replaced by the parsed bitmask.
- **ibex-rt/engine.rs:**
  - `store_var`, `store_var_smp`, `set_var_from_expr`, `unset_var`, `sample_is_empty` and
    `with_stream_vars`/`stream_vars_enter`/`stream_vars_leave` collapse onto the store.
  - The `sample_to_string` calls on the set-var paths go: lines 5991, 6244, 6418, 11082, 13350,
    13450 and `init_global_vars` 3914-3927.
  - The `req.`-prefix `retain` at the response start (10044-10045, 13509-13510) becomes the
    reqres scope switch.
  - About 85 lines reference `sess_vars`/`req_vars`. They are compile-driven.
- **ibex-rt/proxy.rs:** `TcpSession.sess_vars`/`req_vars` (597-598), the H2 child copy/merge
  (866-904), and `reset_for_next_request` (1701).
- **check.rs:** `run.vars` (263-300, 732-805). **applet.rs:** CLI `get var`/`set var`.
- **ibex-config:** `check_set_var_conds` stops refusing `ifgt`/`iflt` (parser/mod.rs 1992), and the
  parser emits the condition bitmask. New `tune.vars.*` keywords.
- **Tests:**
  - The ~290 `Sample::Str` test sites do not move.
  - Internal-API test sites: converters_bulk.rs 4, proptest_expr.rs 7, t136_edges.rs 2,
    tcp_request_rules.rs 1, cli_get_var.rs 1, plus about 6 in registry.rs unit tests. They stay
    compiling through the shims, or move mechanically.
  - Tests whose expectations encode the lossy behaviour (grep: a typed `set-var` followed by
    `var(),hex|base64|crc32|sha|length|bytes|add|ipmask|...`): fetch_edge_cases.rs (2),
    converter_edge_cases.rs, converter_aes_language.rs, binary_var_bytes.rs. Each changed
    expectation is re-measured on the oracle, not reasoned.
  - The frozen sample_semantics.rs compiles unchanged and must stay green.

## 3. Slices, in gate order

Each slice is one branch, gated alone. "Failing first" is the test that must be seen red on the
current code before the fix (AGENTS.md rule 1). Sizes are changed lines, tests included.
Assignee key: **Muse** = a single-function port only, **Sonnet** = ordinary wiring, **Opus** = state
and design-critical.

| # | slice | goal | files | failing-first test | size | assignee |
|---|---|---|---|---|---|---|
| S1 | `-m bool` (D2) | implement `PAT_MATCH_BOOL`: cast the sample to `sint`/`bool` and match when non-zero. The measured table: `str(007)` yes, `str(Abc)`/`str()` no, `ipv4` yes, `ipv6`/`bin`/`meth` no | matcher.rs, the method table | `acl x str(007) -m bool` matches, `str(Abc) -m bool` does not (today: load error) | ~40 | Muse |
| S2 | **typed values** (T364 core semantics) | the variable store holds `Sample` instead of `String` (still `HashMap<String, Sample>` keyed by name, to keep the slice compile-driven). `var()` out type *any*; `var_arg()` = `sample_conv_var2smp` with lenient `c_str2int`; `set-var-fmt` -> `Str`; global typed proc vars; `String` shims for proc vars | registry.rs, engine.rs, proxy.rs, check.rs, applet.rs, expr.rs (load-time *any*) | the task file's table (`var(txn.b),length` = 0, `-m len 0` matches, `b2` length 0); one cell per class T1-T6 from §1 (`int(5),hex` = `0000000000000005`, `ipv4,add(0)` = `167838211`, `int(5),ipmask(8)` = `0.0.0.0`, `bin -m int 0` no match, `ipv6,add(0)` no sample, `ipv6,hex` 16 bytes); `int(1),add(txn.v)` with `ipv4` and `str(Abc)`; reg-test `sample_fetches/hashes.vtc` | ~400 | Opus |
| S3 | `ifgt`/`iflt` | port the `sint`/`sint`-only compare; stop refusing at load | registry.rs (condition), parser/mod.rs | `e2.py`'s rule set gives `a=3 b=5 c=9 d=5 e=9 f=1 g=1 h=2 i=0` and the converter form `a=3`; reg-test `sample_fetches/cond_set_var.vtc` | ~60 | Muse (the compare is a pure function `(stored: Option<&Sample>, new: &Sample, flags) -> bool`); Sonnet for the parser line |
| S4 | outputs | CLI `get var` type names and `%.*s` value; `dump_all_vars` per-type format | applet.rs, registry.rs `dump_var_value` | `get var proc.q` (bin 0001) = `type=bin value=<>`; `proc.r` = `type=ipv4`; `dump_all_vars(txn)` items `txn.b=41004243`, `txn.o=true`, `txn.p=10.1.2.3` | ~80 | Muse, two cases (one function each) |
| S5 | `tune.vars.*` accounting (D10) | parse the 6 limits + `from-map.max`; 88-byte cost; nested limits; the HAProxy failure behaviour | ibex-config global, the variable store, engine | `e4.py`/`e5.py`: `txn-max-size 87` refuses one `int` var and 88 takes it; under 90, `int(7)` then a 10-byte `str` reads `7`, `add(1)` = 8 (or the §4 choice); `sess-max-size 100` refuses the second `txn` var; `reqres-max-size 50` does not limit `txn`; `set_vars_from_map.vtc` then fails on the action, not the keyword | ~200 | Sonnet (brief: the two HAProxy functions + this table) |
| S6 | **no allocation** | interned `VarId`, slot store + arena + `try_reserve`, `mem::swap` instead of drain/extend, per-thread free list, condition bitmask parsed at load | new `ibex-sample/src/vars.rs`, registry.rs, engine.rs, proxy.rs | an allocation test (own `[[test]]`: counting allocator; or a new case in `request_allocations.rs`): a keep-alive request with `set-var(txn.a) int(5)` + `set-var(txn.s) str(hello)` + `set-var(sess.c) int(1)` allocates **the same count as without them** (today +4/+6 each: 10 -> 15/17 in-process; 7 -> 11/13 per request on the shipped binary under LD_PRELOAD); re-measure with `hmal.py` on the binary | ~400 | Opus |
| S7 | H2 `sess` sharing (optional, §2.7) | shared `sess` store across a connection's streams; drop the clones and the merge | proxy.rs, engine.rs | first measure on the oracle: two concurrent H2 streams, A sets `sess.x`, B reads it before A finishes. Only if HAProxy shows B seeing it: that test, plus 0 allocations per H2 stream for `sess` | ~150 | Opus |

Order: S1 is independent and can go any time. S2 comes before S3, S4 and S5, which all read typed
values. S6 comes after S2 to S5, because it rewrites the store underneath them without changing
behaviour; their tests are its regression net. S7 comes last.

Not T364 (separate tasks, each with its failing-first cell from §1):
- D1 `c_bool2bin` 8 bytes (Muse, ~10 lines).
- D3 v4-mapped addresses into addr converters and `-m ip` (Sonnet).
- D4 `json` escaping per byte (Muse).
- D5 `upper`/`lower` ASCII-only (Muse).
- D6 `strcmp` raw difference (Muse).
- D7 `json_query` output types (Sonnet; `converter/json_query.vtc`).
- D8 load-time `-m` type check (Sonnet).
- D9 lexer quote/`$` (Sonnet).

## 4. Risks, open questions, and what stays in tradeoff.md

Risks:
- **Hash and stick-table keys change.** After S2, `var(txn.ip),crc32` and the `sha1`/`bytes` of
  typed variables change value (to HAProxy's). A running Ibex whose stick-table keys or cookies were
  built from such hashes sees different keys after the upgrade. Note this in the release notes.
  It is the fix, not a regression.
- **Load-time typing.** With `var()` typed *any*, some expressions Ibex now refuses at load because
  `str` cannot reach the converter's input type will load and fail at run time instead, as in
  HAProxy. Check the T331/T341 converter-type tests: they must still pass for non-`var` fetches.
- **`RefCell` in `CURRENT_VARS`.** A converter that reads a variable while the store is mutably
  borrowed is a panic, which aborts the whole proxy. Keep every borrow inside one `vars::` function,
  and use `try_borrow*` with the "no variable" fallback.
- **Interner growth at run time.** Only from expressions compiled lazily (`Expr::cached`) and
  `set-vars-from-map` (refused today). Bound it: the table is capped at 65,535 names per scope, and
  past that a set fails.
- **The free list keeps memory.** Bounded per thread (256 stores, arenas capped at 4 KiB when
  returned). It belongs in the §6.13 RSS figures.

Open questions for the user:
1. The accounting-failure "becomes `bool`" case: reproduce HAProxy's union artefact (a `bool` that
   prints `7` and adds as 7), or store `Bool(old != 0)` and record the difference in tradeoff.md?
   Reproducing it needs a `Bool` that carries an `i64`, a type no other sample has.
   Recommendation: don't reproduce it, and record it.
2. S7: is live sharing of `sess` variables between H2 streams wanted, given that it needs `Rc<RefCell>`
   on the session? Or is "visible after the writer finishes" acceptable and recorded?
3. The variable store's private free list (S6): fine before the generic §6.13 pools exist, or should
   S6 wait for them?
4. D1-D9 are outside T364. Should they be queued as T364b... tasks now, or left for later?

What stays in tradeoff.md:
- §6.12 is rewritten. The "type" half is done by S2. The "bytes in `str`" half (`Sample::Str` as
  bytes, `concat` 16383 vs 16382, regex on non-UTF-8) stays as decided on 2026-10-10. The
  1,200-line / 290-site cost belongs to that half only.
- §6.13 gains one line: reading a `str`/`bin` variable copies it into an owned `Sample` (1
  allocation), and so do `Expr::eval_sample`'s argument clones. These go away only with borrowed
  samples in the evaluator.
- New entries: the `dump_all_vars` order (sorted by name in Ibex, random per process in HAProxy);
  the 88-byte accounting constant taken from HAProxy's x86-64 build; the "becomes `bool`" value, if
  question 1 says not to reproduce it; `psess`/`ptxn`/... giving no sample (no sub-streams).

## 5. What I ran and what I reasoned

Ran:
- `matrix.py`: 20 values x 48 expressions x 6 modes, both binaries, every cell load-checked with
  `-c`. A sanity run with HAProxy on both sides gave 0 direct-vs-variable differences in HAProxy.
- `e2.py`/`e3.py` (conditions), `e4.py`/`e5.py` (accounting, the 87/88 boundary), `e6.py`
  (`dump_all_vars`, global `set-var`, CLI `get var`/`set var`), `e7.py` (`json_query`), `e8.py`
  (variable arguments of converters).
- `hmal.py`: LD_PRELOAD malloc counts with the existing `/tmp/pools-w/shim.so`, 2 x 2,000
  keep-alive requests, `nbthread 1`, on both binaries.
- `varalloc_probe.rs`: in-process counting allocator, `cargo test --release`. It measured
  10 / 15 / 17 / 32 allocations for none / 1 int / 1 str / 5 ints, and +9 for one `str` variable
  read into `set-header`.
- `harness/vtc_runner.py` on `hashes`, `cond_set_var` and `vars` with both binaries, and on the 18
  variable-using reg-tests that fail on board `785c5a21`, with the current Ibex. Only `hashes` and
  `cond_set_var` fail because of variables. The others fail on unrelated keywords or on D7.
- No timing runs (none were needed).
- No `gate.sh`/`checkin.sh` (design task, nothing changed in the tree).

Reasoned, not measured:
- the line estimates;
- the H2 sharing semantics in HAProxy (S7 starts by measuring it);
- that S6 reaches 0 allocations. It is a design claim until S6's test is green.

## Appendix: every cell that differs through a variable (`txn` mode)
"type lost" = the same expression without a variable agrees, or HAProxy refuses it at load without
one. "cast/converter" = Ibex differs without a variable too. Values truncated to 30 characters.
Full data in `t364-probes/hi.json`.

| stored | expression on `var(txn.v)` | HAProxy | Ibex | class |
|---|---|---|---|---|
| bool1 | `,base64` | `AAAAAAAAAAE=` | `MQ==` | cast/converter (direct too: Ibex `AQ==`) |
| bool1 | `,crc32` | `304476159` | `2212294583` | cast/converter (direct too: Ibex `2768625435`) |
| bool1 | `,hex` | `0000000000000001` | `31` | cast/converter (direct too: Ibex `01`) |
| bool1 | `,sha1,hex` | `CB473678976F425D6EC1339838F110…` | `356A192B7913B04C54574D18C28D46…` | cast/converter (direct too: Ibex `BF8B4530D8D246DD74AC53A13471BB…`) |
| bool1 | `acl -m bool` | `1` | load error | cast/converter (direct too: Ibex load error) |
| bool0 | `,base64` | `AAAAAAAAAAA=` | `MA==` | cast/converter (direct too: Ibex `AA==`) |
| bool0 | `,crc32` | `1696784233` | `4108050209` | cast/converter (direct too: Ibex `3523407757`) |
| bool0 | `,hex` | `0000000000000000` | `30` | cast/converter (direct too: Ibex `00`) |
| bool0 | `,sha1,hex` | `05FE405753166F125559E7C9AC5586…` | `B6589FC6AB0DC82CF12099D1C2D40A…` | cast/converter (direct too: Ibex `5BA93C9DB0CFF93F52B521D7420E43…`) |
| bool0 | `acl -m bool` | `0` | load error | cast/converter (direct too: Ibex load error) |
| int5 | `,base64` | `AAAAAAAAAAU=` | `NQ==` | type lost |
| int5 | `,crc32` | `357051366` | `2226203566` | type lost |
| int5 | `,hex` | `0000000000000005` | `35` | type lost |
| int5 | `,ipmask(16,64)` | `0.0.0.0` | (empty) | type lost |
| int5 | `,ipmask(8)` | `0.0.0.0` | (empty) | type lost |
| int5 | `,sha1,hex` | `216A788021417AD345B1B1EE107531…` | `AC3478D69A3C81FA62E60F5C369616…` | type lost |
| int5 | `acl -m bool` | `1` | load error | cast/converter (direct too: Ibex load error) |
| intneg | `,base64` | `//////////0=` | `LTM=` | type lost |
| intneg | `,bytes(1)` | `ÿÿÿÿÿÿý` | `3` | type lost |
| intneg | `,crc32` | `3477782064` | `3726846214` | type lost |
| intneg | `,hex` | `FFFFFFFFFFFFFFFD` | `2D33` | type lost |
| intneg | `,ipmask(16,64)` | `255.255.0.0` | (empty) | type lost |
| intneg | `,ipmask(8)` | `255.0.0.0` | (empty) | type lost |
| intneg | `,sha1,hex` | `F0EDC1C4B514819F798FF4229BFC97…` | `DEF03A29BF06DDA7BEFAC55709C21A…` | type lost |
| intneg | `acl -m bool` | `1` | load error | cast/converter (direct too: Ibex load error) |
| ipv4 | `,add(0)` | `167838211` | `10` | type lost |
| ipv4 | `,base64` | `CgECAw==` | `MTAuMS4yLjM=` | type lost |
| ipv4 | `,bytes(1)` | `\x01\x02\x03` | `0.1.2.3` | type lost |
| ipv4 | `,crc32` | `3825493623` | `4128529761` | type lost |
| ipv4 | `,hex` | `0A010203` | `31302E312E322E33` | type lost |
| ipv4 | `,neg` | `-167838211` | `-10` | type lost |
| ipv4 | `,sha1,hex` | `584374E649449A264AE2100250D457…` | `6D500FA55AD9A18FE6FC2AD0B85887…` | type lost |
| ipv4 | `acl -m bool` | `1` | load error | cast/converter (direct too: Ibex load error) |
| ipv6 | `,add(0)` | (empty) | `2001` | type lost |
| ipv6 | `,base64` | `IAENuAAAAAAAAAAAAAAAAQ==` | `MjAwMTpkYjg6OjE=` | type lost |
| ipv6 | `,bool` | (empty) | `1` | type lost |
| ipv6 | `,bytes(1)` | `\x01\r¸` | `001:db8::1` | type lost |
| ipv6 | `,crc32` | `2140319832` | `11841294` | type lost |
| ipv6 | `,hex` | `20010DB80000000000000000000000…` | `323030313A6462383A3A31` | type lost |
| ipv6 | `,neg` | (empty) | `-2001` | type lost |
| ipv6 | `,not` | (empty) | `0` | type lost |
| ipv6 | `,sha1,hex` | `D744A7BC2D153D099DD70AAF417C16…` | `1EEC14053D99B7EBEC4E559B4B2D4C…` | type lost |
| ipv6 | `acl -m bool` | `0` | load error | type lost |
| ipv6 | `acl -m int gt 0` | `0` | `1` | type lost |
| ipv6map | `,add(0)` | (empty) | `0` | type lost |
| ipv6map | `,base64` | `AAAAAAAAAAAAAP//CgECAw==` | `OjpmZmZmOjEwLjEuMi4z` | type lost |
| ipv6map | `,bool` | (empty) | `0` | type lost |
| ipv6map | `,bytes(1)` | (empty) | `:ffff:10.1.2.3` | type lost |
| ipv6map | `,crc32` | `123444862` | `542272876` | type lost |
| ipv6map | `,hex` | `00000000000000000000FFFF0A0102…` | `3A3A666666663A31302E312E322E33` | type lost |
| ipv6map | `,ipmask(16,64)` | `10.1.0.0` | `::` | cast/converter (direct too: Ibex `::`) |
| ipv6map | `,ipmask(8)` | `10.0.0.0` | (empty) | cast/converter (direct too: Ibex (empty)) |
| ipv6map | `,neg` | (empty) | `0` | type lost |
| ipv6map | `,not` | (empty) | `1` | type lost |
| ipv6map | `,sha1,hex` | `376E2D2F68546EA1608B364C01CA3D…` | `F115C9912712C5EA190DA7D985167E…` | type lost |
| ipv6map | `acl -m bool` | `0` | load error | type lost |
| ipv6map | `acl -m int 0` | `0` | `1` | type lost |
| ipv6map | `acl -m ip 10.1.2.3` | `1` | `0` | type lost |
| str007 | `acl -m bool` | `1` | load error | cast/converter (direct too: Ibex load error) |
| strAbc | `acl -m bool` | `0` | load error | cast/converter (direct too: Ibex load error) |
| str5 | `acl -m bool` | `1` | load error | cast/converter (direct too: Ibex load error) |
| strE | `acl -m bool` | `0` | load error | cast/converter (direct too: Ibex load error) |
| strip | `acl -m bool` | `1` | load error | cast/converter (direct too: Ibex load error) |
| bin000102 | `(as is)` | (empty) | `\x00\x01\x02` | type lost |
| bin000102 | `,add(0)` | (empty) | `0` | type lost |
| bin000102 | `,bool` | (empty) | `0` | type lost |
| bin000102 | `,concat(x)` | `x` | `\x00\x01\x02x` | type lost |
| bin000102 | `,field(1,b)` | (empty) | `\x00\x01\x02` | type lost |
| bin000102 | `,json` | (empty) | `\\u0000\\u0001\\u0002` | type lost |
| bin000102 | `,length` | `0` | `3` | type lost |
| bin000102 | `,lower` | (empty) | `\x00\x01\x02` | type lost |
| bin000102 | `,ltrim(A)` | (empty) | `\x00\x01\x02` | type lost |
| bin000102 | `,neg` | (empty) | `0` | type lost |
| bin000102 | `,not` | (empty) | `1` | type lost |
| bin000102 | `,upper` | (empty) | `\x00\x01\x02` | type lost |
| bin000102 | `,url_dec` | (empty) | `\x00\x01\x02` | type lost |
| bin000102 | `,word(1,b)` | (empty) | `\x00\x01\x02` | type lost |
| bin000102 | `acl -m bool` | `0` | load error | type lost |
| bin000102 | `acl -m int 0` | `0` | `1` | type lost |
| bin000102 | `acl -m len 0` | `1` | `0` | type lost |
| bin000102 | `acl -m len 3` | `0` | `1` | type lost |
| binABC00ff | `(as is)` | `ABC` | `ABC\x00ÿ` | type lost |
| binABC00ff | `,add(0)` | (empty) | `0` | type lost |
| binABC00ff | `,bool` | (empty) | `0` | type lost |
| binABC00ff | `,concat(x)` | `ABCx` | `ABC\x00ÿx` | type lost |
| binABC00ff | `,field(1,b)` | `ABC` | `ABC\x00ÿ` | type lost |
| binABC00ff | `,json` | `ABC` | `ABC\\u0000ÿ` | type lost |
| binABC00ff | `,length` | `3` | `5` | type lost |
| binABC00ff | `,lower` | `abc` | `abc\x00ÿ` | type lost |
| binABC00ff | `,ltrim(A)` | `BC` | `BC\x00ÿ` | type lost |
| binABC00ff | `,neg` | (empty) | `0` | type lost |
| binABC00ff | `,not` | (empty) | `1` | type lost |
| binABC00ff | `,upper` | `ABC` | `ABC\x00ÿ` | type lost |
| binABC00ff | `,url_dec` | `ABC` | `ABC\x00ÿ` | type lost |
| binABC00ff | `,word(1,b)` | `ABC` | `ABC\x00ÿ` | type lost |
| binABC00ff | `acl -m bool` | `0` | load error | type lost |
| binABC00ff | `acl -m int 0` | `0` | `1` | type lost |
| binABC00ff | `acl -m len 3` | `1` | `0` | type lost |
| binUTF8 | `,add(0)` | (empty) | `0` | type lost |
| binUTF8 | `,bool` | (empty) | `0` | type lost |
| binUTF8 | `,json` | `Ab\\u00c3\\u00a9` | `AbÃ©` | cast/converter (direct too: Ibex `AbÃ©`) |
| binUTF8 | `,neg` | (empty) | `0` | type lost |
| binUTF8 | `,not` | (empty) | `1` | type lost |
| binUTF8 | `,upper` | `ABÃ©` | `ABÃ\x89` | cast/converter (direct too: Ibex `ABÃ\x89`) |
| binUTF8 | `acl -m bool` | `0` | load error | type lost |
| binUTF8 | `acl -m int 0` | `0` | `1` | type lost |
| bin80ff | `,add(0)` | (empty) | `0` | type lost |
| bin80ff | `,bool` | (empty) | `0` | type lost |
| bin80ff | `,json` | `\\u0080\\u00ff` | `\x80ÿ` | cast/converter (direct too: Ibex `\x80ÿ`) |
| bin80ff | `,neg` | (empty) | `0` | type lost |
| bin80ff | `,not` | (empty) | `1` | type lost |
| bin80ff | `acl -m bool` | `0` | load error | type lost |
| bin80ff | `acl -m int 0` | `0` | `1` | type lost |
| binAbc | `,add(0)` | (empty) | `0` | type lost |
| binAbc | `,bool` | (empty) | `0` | type lost |
| binAbc | `,neg` | (empty) | `0` | type lost |
| binAbc | `,not` | (empty) | `1` | type lost |
| binAbc | `acl -m bool` | `0` | load error | type lost |
| binAbc | `acl -m int 0` | `0` | `1` | type lost |
| binE | `acl -m bool` | `0` | load error | type lost |
| methGET | `,add(0)` | (empty) | `0` | type lost |
| methGET | `,bool` | (empty) | `0` | type lost |
| methGET | `,neg` | (empty) | `0` | type lost |
| methGET | `,not` | (empty) | `1` | type lost |
| methGET | `acl -m bool` | `0` | load error | type lost |
| methGET | `acl -m int 0` | `0` | `1` | type lost |
| methFOO | `,add(0)` | (empty) | `0` | type lost |
| methFOO | `,bool` | (empty) | `0` | type lost |
| methFOO | `,neg` | (empty) | `0` | type lost |
| methFOO | `,not` | (empty) | `1` | type lost |
| methFOO | `acl -m bool` | `0` | load error | type lost |
| methFOO | `acl -m int 0` | `0` | `1` | type lost |
