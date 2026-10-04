# Where Ibex differs from HAProxy

What an operator can see: HAProxy 3.5-dev8-885761-29 does one thing, Ibex does another or
refuses. Each entry says what to do instead.

## `userlist`: hashed passwords (`user <u> password <hash>`)

HAProxy hands the hash to glibc `crypt(3)`. Ibex has no `crypt(3)` (it needs `unsafe` or a C
library) and verifies the formats it can in safe Rust, with the `ibex-crypt` crate.

| format | prefix | HAProxy (glibc) | Ibex |
|---|---|---|---|
| MD5-crypt | `$1$` | verifies | verifies |
| SHA-256-crypt | `$5$` (`rounds=1000..999999999`) | verifies | verifies |
| SHA-512-crypt | `$6$` (`rounds=1000..999999999`) | verifies | verifies |
| bcrypt | `$2a$`, `$2b$`, `$2y$` (cost 04..31) | verifies | verifies |
| bcrypt, buggy 2x variant | `$2x$` | verifies | refused at load, names the format |
| yescrypt | `$y$` | verifies (warns it takes ~25 ms) | refused at load, names the format |
| DES, BSDi extended DES | `ab...`, `_...` | verifies | refused at load, names the format |
| SunMD5, sha1crypt, NT-hash | `$md5$`, `$sha1$`, `$3$` | verifies | refused at load, names the format |
| anything glibc refuses (unknown id, malformed salt, rounds out of range, ...) | | alert "not supported by crypt(3)" | the same alert |

Refused at load, the message is
`the encrypted password used for user 'u' is in the yescrypt ($y$) format, which Ibex cannot verify
(it verifies $1$, $5$, $6$, $2a$, $2b$ and $2y$); rehash it with one of those or use 'insecure-password'.`
Rehash with `mkpasswd -m sha-512` (or `openssl passwd -6`), `mkpasswd -m bcrypt` or
`htpasswd -B`.

Same as HAProxy:

- the hash is recomputed on every request that carries an `Authorization: Basic` header for a
  user of the list; nothing is cached (HAProxy has no `tune.*` setting for it either), so the
  cost of the algorithm is paid per request, on the worker that serves it;
- at load, a hash that takes 10 ms or more to verify is warned about with HAProxy's text;
- a well formed setting whose hash part is cut short loads and never matches;
- the password is read as a C string (it ends at a NUL).

Measured here (release build, `secret`, one core): `$1$` 0.15 ms, `$5$` 0.5 ms, `$6$` default
5000 rounds 1.8 ms, `$6$rounds=100000` 35 ms, bcrypt cost 5 2 ms, cost 10 64 ms, cost 12 256 ms
(glibc `crypt`, process start included: 52 ms, 63 ms, 249 ms for the same three). A cost-12 bcrypt user blocks a
worker for a quarter of a second per request, in both; choose `$6$` with default rounds or
bcrypt at cost 5 to 8 for a hash on the request path.

Known gap against glibc: the characters allowed in a `$1$`/`$5$`/`$6$` salt were measured on a
sample (`:`, space and non-ASCII bytes are refused by glibc, printable ASCII else is accepted);
Ibex applies that rule and has not been compared on every byte. The 900 verdicts of
`crates/ibex-crypt/tests/vectors.txt` (salts, rounds, password lengths, malformed settings) agree
with glibc.

## Regular expressions

HAProxy compiles every regular expression with PCRE2 (or the C library's POSIX regex).
Ibex is memory-safe Rust and links no C regex library, by decision (T154, 2026-10-04):
`pcre2` and its C bindings are out. Ibex compiles a pattern with the `regex` crate first and,
only when `regex` refuses it, with the pure-Rust `fancy-regex` crate (crate `ibex-regex`,
type `UserRegex`). An ordinary pattern keeps `regex`'s guarantee of matching in time linear in
the input and costs what it did before; a pattern with a PCRE-only feature is slower and can
backtrack. This covers every place a configuration regex is used: ACL `-m reg` and the `*_reg`
fetches, `replace-header`, `replace-value`, `replace-path`, `replace-pathq`, `replace-uri`,
`map_reg`, `map_regm`, `regsub`, `http-check expect rstring`/`rstatus`, `reqrep`-style rewrites.

### What works (`fancy-regex`)

Look-ahead and look-behind (`(?=..)`, `(?!..)`, `(?<=..)`, `(?<!..)`), back-references (`\1`,
`\k<name>`, `(?P=name)`, `\g1`), atomic groups (`(?>..)`), possessive quantifiers (`a++`,
`a*+`, `a?+`, `a{1,2}+`), named groups (`(?<n>..)`, `(?P<n>..)`), inline flags (`(?i)`,
`(?s)`, `(?m)`, `(?x)`), conditionals (`(?(1)a|b)`), `\K`, `\G`, `\Z`, `\h`, `\R`, `\N`.
Each of the first group was measured on HAProxy and is a test in
`crates/ibex-rt/tests/pcre_regex.rs`, in an ACL, in `replace-header` and in `regsub`.

### What is refused at load

A pattern with a PCRE feature `fancy-regex` lacks is refused when the configuration is read
(`ibex -c` fails; HAProxy accepts all of these), with a message that names the feature:

```
bad regular expression <(?R)>: PCRE feature not supported by Ibex: recursion and subroutine calls (see docs/differences.md)
```

- recursion and subroutine calls: `(?R)`, `(?1)`, `(?-1)`, `(?+1)`, `(?&name)`, `(?P>name)`,
- callouts `(?C)`,
- branch reset groups `(?|..)`,
- `\X` (extended grapheme cluster),
- `\Q..\E` literal quoting,
- the other escapes `fancy-regex` does not parse, refused with its own "unrecognized escape
  sequence": `\g{n}`, `\cX`, `\o{..}`, an octal `\012`, the `(?J)` flag and `(*VERB)` start-of-pattern
  options such as `(*UTF8)`.

Some Unicode properties (`\p{..}` scripts and categories) are those of the `regex` crate's
tables, not PCRE2's; a name PCRE2 knows and `regex` does not is refused as a syntax error.

An ACL pattern is now checked at load too, in `acl` lines and in inline `{ ... }` terms
(before T154 an inline ACL with a bad regex loaded and never matched).

### One difference in what loads

HAProxy compiles an ACL regex with PCRE2_NO_AUTO_CAPTURE: only named groups capture, so
`path_reg (a)b\1` is a load error on HAProxy ("reference to non-existent subpattern"), and
`(?<n>a)b\1` works. Ibex numbers every group, so the first loads and matches. A configuration
HAProxy accepts is accepted by Ibex; the reverse is not guaranteed here.

### The backtrack limit

A `fancy-regex` match runs under a limit of 1,000,000 backtracking steps
(`ibex_regex::BACKTRACK_LIMIT`). A match that exceeds it is a non-match, silently: nothing is
logged per request. This is HAProxy's outcome, measured with `^/(a+)+(?=$)` against
`/aaaa...ab` (28, 48, 100 and 3000 `a`): PCRE2 gives up and the ACL does not match. Ibex
answers in about 15 ms in a debug build, whatever the length. The limit bounds the cost of a
hostile request, not the answer a legitimate pattern gets: a pattern that needs more than a
million steps on a real header is a pattern to rewrite.

The plain pattern `^/(a+)+$`, with no PCRE-only feature, is not backtracking at all on Ibex
(it runs in `regex`, linear time) and gives the answer PCRE2 gives.
