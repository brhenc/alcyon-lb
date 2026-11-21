// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The per-server and per-proxy structs are paid for 60,000 times over
//! (`request_allocations::sixty_thousand_backends_memory_bounded`). A field that grows one
//! of them must move behind a `Box` unless every server uses it; raise a bound here only
//! after that has been considered.

use std::mem::size_of;

#[test]
fn server_stays_184_bytes() {
    assert!(
        size_of::<alcyon_config::Server>() <= 184,
        "alcyon_config::Server grew to {} bytes (bound 184): box the new field",
        size_of::<alcyon_config::Server>()
    );
}

#[test]
fn proxy_stays_1656_bytes() {
    assert!(
        size_of::<alcyon_rt::engine::Proxy>() <= 1656,
        "Proxy grew to {} bytes (bound 1656): box the new field",
        size_of::<alcyon_rt::engine::Proxy>()
    );
}

#[test]
fn per_server_check_config_is_boxed() {
    assert!(
        size_of::<Option<std::sync::Arc<alcyon_rt::check::ServerCheckConfig>>>() == 8,
        "the per-server check config must stay one pointer"
    );
}

#[test]
fn server_check_state_stays_small() {
    let n = size_of::<alcyon_rt::check::ServerCheckState>();
    // 440 before T304, which moved the state of a running check into `CheckRun` (held only
    // while the check runs), shares the check parameters per backend, and keeps the indexes
    // as `u32`. T540 added 8: `ServerXprt`'s third variant (`H2`) costs it a tag; two boxes
    // leave no niche.
    assert!(n <= 208, "ServerCheckState grew to {n} bytes (bound 208): one is held per checked server, box the new field or put it in CheckRun");
}

/// A session is held for every client connection, idle ones included, in the worker's
/// arena (T183: HAProxy keeps ~1 KB per idle client). Box what only some connections use
/// (`h2_ctx`, `proxy_info`, `pending_resp` are). T442 added 8: the boxed chunk parser of a
/// response whose rules removed its `Transfer-Encoding` (`HttpTxn::rsp_dechunk`).
/// T515 added 40: `fc_src`/`fc_dst`/`bc_src` are plain `Option<SocketAddr>` again (T474 had
/// packed them; unpacking them for every sample context cost ~700 instructions a request on
/// `rules`, 0.86%). Boxing them would be an allocation per connection.
/// T489 added 8: `TcpSession::dr_wait`, a `u32` (the waiting `tcp-request content do-resolve`
/// rule and its cache mark, packed); no padding was left, and a box would be 8 as well and an
/// allocation per wait.
/// T540 added 8: `ServerXprt::H2` (HTTP/2 to servers), a third variant that costs the enum a
/// tag, two boxes leaving no niche; boxing the transport itself would be an allocation per
/// server connection.
/// T599 added 8: `rare_armed`, the one bit that keeps the rare per-run checks (timeouts, drain,
/// soft stop) off a pass; the bools before it filled their word. A box would be 8 and an
/// allocation.
/// The client-gone body-wait flag added 8: `HttpTxn::wait_client_gone`, the one byte a
/// request's `wait-for-body` leaves behind when the client is gone before the body is, read
/// at routing in place of the log's `CR` (which was control state, not a record). It took a
/// new word: the one-byte holes of `HttpTxn` are the `Option`s' niches. A box would be 8 as
/// well and an allocation per request.
/// The fold of `l7_off` into `L7Retry` gave back the word `wait_client_gone` took: the byte
/// it frees is the one that pushed `HttpTxn`'s small fields over 40. The dataless `Disabled`
/// variant that `http-request disable-l7-retry` now sets costs the enum nothing -- it is 16
/// bytes with or without it (its own tag, no niche in `Saved(L7Box)`;
/// `l7_retry_stays_16_bytes`).
/// The session's `src`/`dst` (`TcpSession::sess_addr`, `HAProxy`'s `sess->src`/`sess->dst`:
/// `tcp-request session set-src` writes them, a received PROXY header does, each new
/// request's stream inherits from them in `reset_for_next_request`) are one
/// `Option<Box<SessAddr>>`: 8 bytes, unset and unallocated on a connection with neither. Two
/// plain `Option<SocketAddr>` cost every connection 64 bytes for what few use. The 8 bytes
/// do not fit under the old 1664 (the session was exactly 1664 before), so the bound is the
/// measured 1672. Folding them into the `proxy_info` box instead would save them, but
/// `tcp-request session set-src` writes them while the rule context borrows that box's TLVs.
/// `res_inspect` (`TcpSession::res_inspect`: `pending`, `exp`, `armed`) moved into a
/// `ColdBox<ResInspect>` (8 bytes, `None` until TCP `tcp-response content` rules arm it),
/// ratcheting `SessionEntry` down from 1672 to 1664.
/// G2 PACKFLAGS packed `TcpSession`'s 30 `bool` flags into `SessFlags(u64)`, combined
/// `accept_proxy`/`accept_proxy_v2`/`proxy_handshake_done` into `AcceptProxy` and
/// `proto_h2`/`h3` into `ClientProto`, and converted `so_id` (`u32`, sentinel `0`) and
/// `inspect_exp` (`Tick`, sentinel `Tick::ETERNITY`), shrinking `TcpSession` from 1560 to
/// 1528 bytes and ratcheting `SessionEntry` down from 1664 to 1632.
#[test]
fn session_entry_stays_small() {
    let sess = size_of::<alcyon_rt::proxy::TcpSession>();
    assert!(sess <= 1528, "TcpSession grew to {sess} bytes (bound 1528): one is held per client connection, box the new field");
    let n = size_of::<alcyon_rt::engine::SessionEntry>();
    assert!(n <= 1632, "SessionEntry grew to {n} bytes (bound 1632): one is held per client connection, box the new field");
}

/// `L7Retry` is 16 bytes: its own tag (the niche of `Saved(L7Box)`'s `Option` is inside the
/// newtype, so the enum cannot use it) and the 8-byte `L7Box` payload. A dataless variant
/// costs it nothing -- `Disabled` was folded into it for that reason.
#[test]
fn l7_retry_stays_16_bytes() {
    let n = size_of::<alcyon_rt::txn::L7Retry>();
    assert_eq!(n, 16, "L7Retry is {n} bytes (bound 16): a dataless variant must not grow it");
}
