// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T507: a `bind ... ssl` is built under a tight `RLIMIT_DATA` (what `-m` sets) without
//! reserving the whole session-ID cache (`tune.ssl.cachesize` 20000 entries, 480000 bytes in
//! rustls's cache) up front, which aborted the process. This file is its own test binary
//! because the limit is process-wide and irreversible for the tests sharing the process.

use ibex_tls::tcp::BindTls;
use ibex_tls::tcp::rustls24::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

fn vm_data_bytes() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("status");
    let kb: u64 = status.lines().find_map(|l| l.strip_prefix("VmData:")).expect("VmData").trim().trim_end_matches("kB").trim().parse().expect("kB");
    kb * 1024
}

#[test]
fn a_bind_is_built_with_little_headroom_and_never_reserves_the_session_cache() {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let der = c.cert.der().to_vec();
    let key = c.key_pair.serialize_der();
    // 300 kB of headroom: under the 480000 bytes the whole cache needs up front.
    let limit = vm_data_bytes() + 300 * 1024;
    rustix::process::setrlimit(rustix::process::Resource::Data, rustix::process::Rlimit { current: Some(limit), maximum: Some(limit) }).expect("setrlimit");
    let bind = BindTls::single(
        vec![ibex_tls::tcp::rustls24::pki_types::CertificateDer::from(der)],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        vec![],
    );
    assert!(bind.is_ok(), "{:?}", bind.err());
}
