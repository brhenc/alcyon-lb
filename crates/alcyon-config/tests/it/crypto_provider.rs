// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.alcyon.crypto-provider ring|ring-alcyon` (T460), an Alcyon-only keyword: `HAProxy` 3.5-dev8
//! refuses it as unknown. `HAProxy`'s `ssl-provider` (OpenSSL providers, loaded additively) means
//! something else and stays refused (`m1_scope_refusals`).

use alcyon_config::{parse_str, TlsCryptoProvider};

#[test]
fn crypto_provider_is_kept_and_unset_means_none() {
    let g = |text: &str| parse_str(text).expect("accepted").global.expect("global").crypto_provider;
    assert_eq!(g("global\n  tune.alcyon.crypto-provider ring\n"), Some(TlsCryptoProvider::Ring));
    assert_eq!(g("global\n  tune.alcyon.crypto-provider ring-alcyon\n"), Some(TlsCryptoProvider::RingAlcyon));
    assert_eq!(g("global\n  maxconn 10\n"), None);
    assert_eq!(TlsCryptoProvider::default(), TlsCryptoProvider::Ring, "vanilla ring is the default");
}

#[test]
fn crypto_provider_wants_one_known_name() {
    for (text, want) in [
        ("global\n  tune.alcyon.crypto-provider\n", "expects 'ring' or 'ring-alcyon'"),
        ("global\n  tune.alcyon.crypto-provider openssl\n", "expects 'ring' or 'ring-alcyon', got 'openssl'"),
        ("global\n  tune.alcyon.crypto-provider ring now\n", "cannot handle unexpected argument 'now'"),
    ] {
        let e = parse_str(text).expect_err("refused");
        assert!(e.message.contains(want), "{text:?}: {}", e.message);
    }
}

#[test]
fn haproxy_ssl_provider_keywords_stay_refused() {
    for k in ["ssl-provider default", "ssl-provider-path /tmp", "ssl-propquery fips=yes"] {
        let e = parse_str(&format!("global\n  {k}\n")).expect_err(k);
        assert!(e.message.contains("not supported by Alcyon"), "{k}: {}", e.message);
    }
}
