// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Tests for the layer model's structural claims.
//!
//! These assert properties of the *shape* rather than of any behaviour, because the
//! shape is what the rest of the project is built on. If a stream can distinguish a mux
//! from an applet, the CLI and stats page stop being ordinary endpoints and become
//! special cases wired around the engine — which is the outcome design/001 exists to
//! prevent.

use alcyon_proto::conn::{conn_flags, ConnId};
use alcyon_proto::endpoint::{se_flags, Endpoint, ScState, StConn};
use alcyon_proto::session::Session;
use alcyon_proto::stream::{stream_flags, Stream};
use alcyon_proto::{Connection, SessionId, TransportKind};
use alcyon_sched::Tick;

// ---- the pivot --------------------------------------------------------------------

#[test]
fn a_stream_reaches_both_endpoint_kinds_identically() {
    // The load-bearing claim: driving a stream whose backend is an applet uses exactly
    // the same calls as one whose backend is a mux on a socket.
    let mut via_mux = Stream::new(SessionId(0));
    let mut via_applet = Stream::new(SessionId(0));

    via_mux.scb.attach(Endpoint::MuxStream {
        conn: ConnId(7),
        stream: 0,
    });
    via_applet.scb.attach(Endpoint::Applet { appctx: 3 });

    for s in [&via_mux, &via_applet] {
        assert!(
            s.scb.sedesc.flags.has(se_flags::ATTACHED),
            "both endpoint kinds attach through the same path"
        );
        assert!(!s.scb.sedesc.endpoint.is_none());
    }

    // The *only* difference visible to the stream is whether a connection exists,
    // and that is asked for explicitly rather than assumed.
    assert_eq!(via_mux.scb.sedesc.endpoint.conn(), Some(ConnId(7)));
    assert_eq!(
        via_applet.scb.sedesc.endpoint.conn(),
        None,
        "an applet has no connection; that is the abstraction working"
    );
}

#[test]
fn a_stream_holds_no_connection_reference() {
    // If Stream ever gains a Connection field, the applet path breaks. This test is
    // here to make that a deliberate decision rather than an accident.
    let s = Stream::new(SessionId(1));
    assert_eq!(s.scf.sedesc.endpoint, Endpoint::None);
    assert_eq!(s.scb.sedesc.endpoint, Endpoint::None);
    // Reaching a connection requires going through the endpoint, and may fail.
    assert_eq!(s.scf.sedesc.endpoint.conn(), None);
}

#[test]
fn detaching_an_endpoint_leaves_the_connector_reusable() {
    // This is what lets a mux return a connection to the idle pool while the stream
    // lives on.
    let mut sc = StConn::new();
    sc.attach(Endpoint::MuxStream {
        conn: ConnId(1),
        stream: 4,
    });
    assert!(sc.sedesc.flags.has(se_flags::ATTACHED));

    sc.detach();
    assert!(!sc.sedesc.flags.has(se_flags::ATTACHED));
    assert_eq!(sc.sedesc.endpoint, Endpoint::None);

    sc.attach(Endpoint::Applet { appctx: 9 });
    assert_eq!(sc.sedesc.endpoint, Endpoint::Applet { appctx: 9 });
}

// ---- session : stream is 1:N -------------------------------------------------------

#[test]
fn a_session_can_carry_several_streams() {
    // Looks 1:1 under H1. The field exists so H2 is a change of value, not of shape.
    let mut sess = Session::new(0, 0, ConnId(2), Tick(1000));
    let a = Stream::new(SessionId(0));
    let b = Stream::new(SessionId(0));
    sess.stream_count = 2;

    assert_eq!(a.session, b.session, "both streams share one session");
    assert_eq!(sess.stream_count, 2);
    assert_eq!(
        sess.origin,
        ConnId(2),
        "the connection belongs to the session"
    );
}

// ---- connection --------------------------------------------------------------------

#[test]
fn a_connection_is_unusable_until_handshaking_completes() {
    let mut c = Connection::new(9, TransportKind::Rustls, 0);
    assert!(!c.usable(), "a fresh connection is not usable");

    c.flags.set(conn_flags::CONNECTED);
    c.flags.set(conn_flags::HANDSHAKE);
    assert!(
        !c.usable(),
        "connected but mid-handshake is still not usable"
    );
    assert!(c.handshake_pending());

    c.flags.clear(conn_flags::HANDSHAKE);
    assert!(c.usable());

    c.flags.set(conn_flags::ERROR);
    assert!(!c.usable(), "an errored connection is never usable");
}

#[test]
fn transport_is_a_selector_not_an_owned_object() {
    // Connections carry a TransportKind, not a Box<dyn Transport>. At 60k connections
    // the boxed form would be 60k heap allocations to answer a question with three
    // possible answers. See design/006 §2.
    let raw = Connection::new(1, TransportKind::Raw, 0);
    let tls = Connection::new(2, TransportKind::Rustls, 0);
    assert_ne!(raw.transport, tls.transport);
    assert_eq!(core::mem::size_of::<TransportKind>(), 1);
}

// ---- stream lifecycle ---------------------------------------------------------------

#[test]
fn a_stream_is_complete_only_when_both_directions_finish() {
    let mut s = Stream::new(SessionId(0));
    assert!(!s.is_complete());
    s.flags |= stream_flags::REQ_DONE;
    assert!(!s.is_complete(), "request alone is not enough");
    s.flags |= stream_flags::RES_DONE;
    assert!(s.is_complete());
}

#[test]
fn connector_state_starts_disconnected() {
    let s = Stream::new(SessionId(0));
    assert_eq!(s.scf.state, ScState::Init);
    assert_eq!(s.scb.state, ScState::Init);
    assert!(!s.scb.is_established());
}
