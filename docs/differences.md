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
