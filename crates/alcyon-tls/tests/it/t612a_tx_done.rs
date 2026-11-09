// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T612a (ALCYON-XPRT-TXDONE-OVERFLOW-001): `tx_done(usize::MAX)` is how the handshake path
//! discards all queued ciphertext; after a partial write (`tx_sent > 0`) it must not overflow.

use crate::common::{client_trusting, TestCert};

#[test]
fn discarding_everything_after_a_partial_write_does_not_overflow() {
    let cert = TestCert::new(vec!["localhost".into()]);
    let cfg = client_trusting(&cert.cert_pem, vec![]);
    let mut p = crate::common::Pair::new(cert.bind(vec![]), &cfg, "localhost");
    p.complete();
    let data = vec![b'x'; 1000];
    p.srv.write_plain(&data).expect("write");
    let queued = p.srv.pending_tx().len();
    assert!(queued > 10);
    p.srv.tx_done(10);
    assert_eq!(p.srv.pending_tx().len(), queued - 10);
    p.srv.tx_done(usize::MAX);
    assert!(p.srv.pending_tx().is_empty(), "everything discarded");
    assert!(!p.srv.wants_write());
}
