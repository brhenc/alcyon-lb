#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Run the vendored quinn-proto's own unit tests (`--lib`) offline (T542, vendor/README.md).
# Its dev-dependencies are not all in the registry cache: `assert_matches` and `hex-literal`
# are replaced by small local shims, `rcgen` 0.14 and `wasm-bindgen-test` are dropped, and with
# them `src/tests/` (the end-to-end suite, which needs rcgen); `bloom` (fastbloom, not cached)
# is off. Works on a copy in /tmp; the vendored tree is not touched.
#
# Usage: [QP_FEATURES=ibex-pools] tools/quinn-proto-tests.sh [test filter...]
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
work=${QP_WORK:-/tmp/ibex-quinn-proto-tests}
rm -rf "$work"
mkdir -p "$work/shims/assert_matches/src" "$work/shims/hex-literal/src"
cp -a "$here/vendor/quinn-proto" "$work/quinn-proto"
cp "$here/Cargo.lock" "$work/quinn-proto/Cargo.lock"
# P1: the optional ibex-alloc dependency (feature ibex-pools) is a path outside the copy
sed -i "s|path = \"../../crates/ibex-alloc\"|path = \"$here/crates/ibex-alloc\"|" "$work/quinn-proto/Cargo.toml"

cat > "$work/shims/assert_matches/Cargo.toml" <<'EOF'
[package]
name = "assert_matches"
version = "1.5.0"
edition = "2021"
EOF
cat > "$work/shims/assert_matches/src/lib.rs" <<'EOF'
#[macro_export]
macro_rules! assert_matches {
    ($e:expr, $($p:pat_param)|+ $(if $g:expr)? $(,)?) => {
        match $e {
            $($p)|+ $(if $g)? => {}
            ref v => panic!("assertion failed: {:?} does not match {}", v,
                stringify!($($p)|+ $(if $g)?)),
        }
    };
    ($e:expr, $($p:pat_param)|+ $(if $g:expr)?, $($arg:tt)+) => {
        match $e {
            $($p)|+ $(if $g)? => {}
            ref v => panic!("assertion failed: {:?}: {}", v, format_args!($($arg)+)),
        }
    };
}
EOF
cat > "$work/shims/hex-literal/Cargo.toml" <<'EOF'
[package]
name = "hex-literal"
version = "1.0.0"
edition = "2021"
[lib]
proc-macro = true
EOF
cat > "$work/shims/hex-literal/src/lib.rs" <<'EOF'
use proc_macro::TokenStream;
/// `hex!("0a 0b" "0c")` -> `[0x0au8, 0x0bu8, 0x0cu8]`.
#[proc_macro]
pub fn hex(input: TokenStream) -> TokenStream {
    let mut digits = String::new();
    for tt in input {
        let s = tt.to_string();
        let s = s.trim_matches('"');
        digits.extend(s.chars().filter(|c| c.is_ascii_hexdigit()));
    }
    assert!(digits.len() % 2 == 0, "odd number of hex digits");
    let bytes: Vec<String> = (0..digits.len())
        .step_by(2)
        .map(|i| format!("0x{}u8", &digits[i..i + 2]))
        .collect();
    format!("[{}]", bytes.join(", ")).parse().unwrap()
}
EOF

cd "$work/quinn-proto" || exit 1
python3 - "$work" <<'EOF'
import re, sys
work = sys.argv[1]
s = open("Cargo.toml").read()
for dep in ("rcgen", "wasm-bindgen-test"):
    s = re.sub(r"\n\[dev-dependencies\.%s\]\n(?:[^\[\n][^\n]*\n)*" % re.escape(dep), "\n", s)
s = re.sub(r"\n\[dev-dependencies\.assert_matches\]\n(?:[^\[\n][^\n]*\n)*",
           '\n[dev-dependencies.assert_matches]\npath = "%s/shims/assert_matches"\n' % work, s)
s = re.sub(r"\n\[dev-dependencies\.hex-literal\]\n(?:[^\[\n][^\n]*\n)*",
           '\n[dev-dependencies.hex-literal]\npath = "%s/shims/hex-literal"\n' % work, s)
# Optional dependencies not in the registry cache: the lock resolves them even when off.
for dep in ("fastbloom", "qlog", "aws-lc-rs", "rustls-platform-verifier", "arbitrary"):
    s = re.sub(r"\n\[dependencies\.%s\]\n(?:[^\[\n][^\n]*\n)*" % re.escape(dep), "\n", s)
    s = re.sub(r'\n\s*"(?:dep:)?%s[?/][^"]*",' % re.escape(dep), "", s)
    s = s.replace('"dep:%s"' % dep, "")
s = re.sub(r"\n(bloom|qlog|platform-verifier|aws-lc-rs|aws-lc-rs-fips|rustls-aws-lc-rs|rustls-aws-lc-rs-fips) = \[[^\]]*\]", "", s)
s = s.replace('"bloom",', "")
# tracing-subscriber's `time`/`local-time` need time-macros, not cached; only src/tests uses them.
s = re.sub(r"\n\[dev-dependencies\.tracing-subscriber\]\n(?:[^\[\n][^\n]*\n)*",
           '\n[dev-dependencies.tracing-subscriber]\nversion = "0.3.0"\ndefault-features = false\n'
           'features = ["env-filter", "fmt"]\n', s)
s += "\n[workspace]\n"
open("Cargo.toml", "w").write(s)
l = open("src/lib.rs").read()
l2 = l.replace("\nmod tests;\n", "\n#[cfg(any())] // T542 offline run: src/tests needs rcgen 0.14\nmod tests;\n", 1)
assert l2 != l, "mod tests; not found"
open("src/lib.rs", "w").write(l2)
EOF
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$work/target}
cargo test --offline --lib --no-default-features --features "rustls-ring,log${QP_FEATURES:+,$QP_FEATURES}" -- "$@"
