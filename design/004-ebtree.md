# 004 — Elastic Binary Trees

Reference: `/home/bhenc/reference/haproxy` @ `e6f616af`, `include/import/ebtree-t.h`,
`include/import/eb32tree.h`, `src/eb32tree.c`. Original: Willy Tarreau, ebtree 6.0.6.

ebtree is the structure the whole system rests on: scheduler run queue, timer wait queue,
stick tables, server queues, map/ACL storage, and the pattern cache all use it.

---

## 1. What makes it "elastic"

A classic PATRICIA / critical-bit trie stores data only at leaves and needs internal nodes
to hold the branch points: N items require N leaves **plus** N−1 internal nodes, usually
separately allocated.

ebtree's trick is that **every node is simultaneously a leaf and an internal link**:

```c
struct eb_node {
    struct eb_root branches; /* used when acting as an internal link */
    eb_troot_t    *node_p;   /* parent, when acting as a link        */
    eb_troot_t    *leaf_p;   /* parent, when acting as a leaf        */
    short int      bit;      /* which bit this link discriminates on */
    short unsigned int pfx;
} __attribute__((packed));
```

Each item carries one `eb_node`. Its leaf half always participates; its link half is used
only if the item happens to also be a branch point. The first node inserted uses only its
leaf half. **N items, N nodes, zero separate internal-node allocation.** That is the
elasticity.

Two consequences that matter for Ibex:

- **Intrusive.** The node is embedded in the payload (`struct task` embeds *two*:
  `rq` and `wq`). Insertion allocates nothing. For a no-allocation-in-the-data-path
  proxy, this is the entire ballgame.
- **Multi-membership.** One object can sit in several trees at once through different
  embedded nodes. A task being simultaneously in the run queue and the wait queue is not a
  special case — it is just two nodes.

## 2. Tagged pointers

```c
typedef void eb_troot_t;  /* an eb_node pointer with the low bit used as a tag */
```

The tag has two meanings depending on which field holds it:

| Field | Tag 0 | Tag 1 |
|---|---|---|
| `branches.b[]` | `EB_LEAF` — points to a leaf | `EB_NODE` — points to a link |
| `node_p`, `leaf_p` | `EB_LEFT` | `EB_RGHT` |

Plus a tree-level flag: `root->b[EB_RGHT]` carries `EB_UNIQUE` vs `EB_NORMAL`, and the
root is detected by its right branch being NULL.

This is pointer arithmetic standing in for a type system. It works because C pointers are
opaque machine words and the author is careful. It is also exactly the kind of thing that
makes C rewrites worth doing.

## 3. The insert algorithm

From `__eb32_insert()`, `include/import/eb32tree.h:226`. Descend until one of three
stopping conditions:

```c
if (eb_gettag(troot) == EB_LEAF) {
    /* reached a leaf: insert above it */
    break;
}

old_node_bit = old->node.bit;

if ((old_node_bit < 0) ||                                      /* duplicate subtree */
    (((new->key ^ old->key) >> old_node_bit) >= EB_NODE_BRANCHES)) {
    /* keys diverge above this node's bit: insert here */
    break;
}

side  = (newkey >> old_node_bit) & EB_NODE_BRANCH_MASK;        /* walk down */
troot = side ? old->node.branches.b[1] : old->node.branches.b[0];
root  = &old->node.branches;
```

Three things to carry across:

- **`bit` is the discriminating bit position** of a link, and descent goes to
  `(key >> bit) & 1`.
- **The divergence test** `((new->key ^ old->key) >> old_node_bit) >= 2` asks "do these
  keys differ at any bit *above* this node's bit?" If so, the new key does not belong in
  this subtree and must be inserted above it.
- **`bit < 0` marks a duplicate subtree.** Equal keys are stored as a *sub-tree*, not a
  list (`eb_insert_dup`). `EB_UNIQUE` trees refuse duplicates and return the existing node
  instead. The timer tree needs duplicates — many tasks share an expiry millisecond.

## 4. Why Ibex wants it, specifically

| Property | Why it matters here |
|---|---|
| Depth ≤ key width | O(32) worst case on adversarial input — no HashDoS, no degenerate BST. See [003 §5](003-scheduler.md). |
| No rebalancing | Insert/delete touch O(1) nodes plus descent. No write amplification on a hot path. |
| Ordered traversal | `first`/`next`/`lookup_ge` — required by the timer queue and by stick-table LRU expiry. A hash map cannot do this at all. |
| Intrusive | Zero allocation per insert. |
| Prefix support | `ebmb`/`ebst` do longest-prefix match, which is what ACL IP matching and `map_beg` need. |

That last row is worth noting: the same family covers scalar keys, strings, and
longest-prefix-match on binary blobs, so ACL IP matching and map lookups reuse the
structure rather than introducing a second one.

---

## 5. Translation: tagged indices over an arena

**Decision D3.** The C design needs tagged pointers because a C pointer is an opaque
word. Rust has a strictly better option available: an arena with tagged `u32` indices.

```rust
/// A tagged reference into the node arena.
/// bit 0 = tag, bits 1..=31 = arena index. All-ones = none.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TRef(u32);

impl TRef {
    const NONE: TRef = TRef(u32::MAX);
    #[inline] fn new(idx: u32, tag: bool) -> Self { TRef((idx << 1) | tag as u32) }
    #[inline] fn index(self) -> usize { (self.0 >> 1) as usize }
    #[inline] fn tag(self) -> bool    { self.0 & 1 != 0 }
    #[inline] fn is_none(self) -> bool { self == Self::NONE }
}

pub struct Node {
    branches: [TRef; 2],
    node_p:   TRef,
    leaf_p:   TRef,
    bit:      i16,
    key:      u32,
}

pub struct Eb32Tree {
    nodes: Vec<Node>,    // the arena: one allocation, grown at boot
    free:  Vec<u32>,     // free-slot list
    root:  [TRef; 2],
    unique: bool,
}
```

This is not a compromise against the C version — on several axes it is better:

| | C (tagged pointers) | Rust (tagged indices) |
|---|---|---|
| Reference size | 8 bytes | **4 bytes** — ~2× more nodes per cache line |
| Node size (eb32) | 8+8+8+2+2+4 ≈ 32 B | 4+4+4+4+2+4 ≈ **24 B** |
| Bounds checking | none | every deref, elided in release where provable |
| Tag correctness | pointer arithmetic by convention | explicit in the accessor |
| Allocation | pool per node | one `Vec`, no per-insert allocation |
| `unsafe` required | n/a (it is C) | **none** |
| Use-after-free | undefined behaviour | a stale index: wrong answer, not memory corruption |

That last row is the whole project in one line. A bug in this code in C is a potential
RCE; the same bug in the arena version is a logic error that returns the wrong node. The
design is preserved exactly; the failure mode is downgraded from catastrophic to merely
incorrect.

The cache-density win is real and worth stating plainly: because `u32` indices are half
the size of pointers, the Rust version fits meaningfully more of the tree in L1 than the C
original. Descending a 32-level tree is pointer-chasing bound, so this is the axis that
matters.

### Trade-offs to accept

- **Max 2^31 nodes per tree.** Irrelevant — HAProxy's own `rqueue_ticks` is 32-bit.
- **Deletion leaves holes**, so a free list is needed. HAProxy returns nodes to a pool;
  same cost.
- **Stale indices are possible.** Mitigation: generation counters in `debug_assertions`
  builds only, compiled out in release. Catches the bug class in test without paying for
  it in production.
- **Arena growth invalidates nothing** (indices, not pointers) — which is a genuine
  advantage over the C version when the tree must grow.

### Scope for the first implementation

Needed by the scheduler, and nothing more:

```
eb32: insert, delete, lookup, lookup_ge, first, next
      duplicate-key support (the timer tree requires it)
      EB_UNIQUE mode
```

Deferred until their consumers exist: `eb64` (stick-table expiry), `ebmb`/`ebst`
(ACL/map longest-prefix match), `eb32sc` (scope-tagged — HAProxy uses it for thread-group
visibility in the shared run queue; not needed with a single group).

### Testing

- **Differential against `BTreeMap`** — same operation sequence, identical results for
  `lookup`/`lookup_ge`/`first`/`next` ordering. This is the main correctness net.
- **Property tests** (proptest): insert/delete permutations; assert the tree invariants
  hold after every op — every leaf reachable, `node_p`/`leaf_p` consistent with actual
  parents, `bit` strictly decreasing down any path.
- **Adversarial depth** — keys chosen to maximise depth; assert ≤ 32.
- **Duplicate storms** — N items with identical keys; assert ordered traversal still
  yields all N.
- **Bench vs. `BTreeMap` and `HashMap`** on the scheduler's actual access pattern
  (monotonic-ish keys, insert/pop-min dominated). Worth knowing honestly where it wins
  and where it does not.
