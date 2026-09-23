# libslz oracle

`libslz` is Willy Tarreau's stateless compressor, vendored in HAProxy at `src/slz.c` and
**enabled by default** (`USE_SLZ = default`; the Makefile says "SLZ is always supported
unless explicitly disabled"). It emits standard RFC 1951 / 1952 / 1950 streams that any gzip
or zlib client can read, but keeps no window.

Measured on this machine, with `state_size.c`:

```
sizeof(struct slz_stream)                        40 bytes
zlib deflate state, windowBits=15, memLevel=8   262,144 bytes
```

**6,500×.** At 60,000 concurrent compressing streams that is 2.4 MB against 15.7 GB, which
is why HAProxy made it the default and why it belongs in a proxy whose stated claim is
60,000 backends per process.

## Regenerating the vectors

```
H=/home/bhenc/reference/haproxy-quic
gcc -I$H/include -o /tmp/gen tools/slz-oracle/gen_vectors.c $H/src/slz.c $H/src/slz_common.c
/tmp/gen > /tmp/vectors.json
```

`data/slz_vectors.json` holds 30 of them: five inputs (empty, a short string, 4 KB of one
byte, an HTTP response, and 1 KB of a repeating byte ramp) across three formats and two
levels, each recording the input, the exact compressed bytes libslz produced, the lengths and
the CRC32.

Every one has been verified to decompress back to its input through **stock zlib**
(`zlib.decompress` with `wbits` -15, 15 and 31), so the vectors pin interoperability, not
just self-consistency.
