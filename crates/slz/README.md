# slz

A stateless deflate/gzip/zlib compressor in safe Rust, ported from Willy Tarreau's `libslz` (which is vendored in [HAProxy](https://github.com/haproxy/haproxy)).

`slz` is a stateless compressor. It keeps no sliding window and performs no allocations. It trades a slight compression ratio reduction against an enormous memory saving (costing ~40 bytes per stream instead of ~256 KB for zlib/flate2). It emits standard RFC 1951, 1952, and 1950 streams that any compliant client can decode.

### Scope and Limitations

Phase 1 of this port implements the **compressor only**. 

`libslz` also contains a newer, separate decoder (`src/uslz.c`), which is **not** in scope for this crate at this time. Only compression is supported.

### Usage

```rust
use slz::{Encoder, Format, Level};

let input = b"Hello, world!";
let mut out = vec![0; 1000];

// Create an encoder with no internal allocations
let mut encoder = Encoder::new(Format::Gzip, Level::Compression);
let mut pos = 0;

// Compress data (caller-provided buffer)
pos += encoder.encode(input, &mut out[pos..], false).unwrap();
pos += encoder.finish(&mut out[pos..]).unwrap();

assert!(pos > 0);
```

### Safety and Validation

- `#![forbid(unsafe_code)]`
- Bit-exact output: `slz` generates the exact same byte-for-byte output as HAProxy's C `libslz`.
- Fully verified via round-trip tests against standard `zlib`/`flate2`.
- Tables are code-generated from the original `slz-tables.h` (see `gen_tables.sh`).

### License

This crate is a port of Willy Tarreau's `libslz`.

MIT License

Copyright (C) 2013-2015 Willy Tarreau <w@1wt.eu>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
