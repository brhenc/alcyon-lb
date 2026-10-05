// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Which `Connection` tokens are removed, kept or added, in both directions (T190).
//!
//! Measured on HAProxy 3.5-dev8-885761-29: one listener per connection mode
//! (`option http-keep-alive`, `httpclose`, `http-server-close`), an HTTP/1.0 or 1.1 client
//! sending `Connection: <token>`, a backend answering HTTP/1.0 or 1.1 with its own
//! `Connection: <token>` (or none) and `Keep-Alive: timeout=5`. HAProxy takes `keep-alive` and
//! `close` out of every `Connection` header (it drops the header when nothing else is in
//! it), drops an `upgrade` token from a request that has no `Upgrade` header, and then
//! adds back the one `Connection: keep-alive` or `close` its own decision calls for. The
//! table is `(mode, client version, server version, client token, server token, lines the server
//! saw, lines the client got, client connection still open)`; `Keep-Alive:` is passed on both ways
//! and is not in it. A server's `close` does not close the client connection (T71). Names are compared
//! in lower case (their case is T104).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

type Row = (&'static str, &'static str, &'static str, Option<&'static str>, Option<&'static str>, &'static [&'static str], &'static [&'static str], bool);

const ROWS: &[Row] = &[
    ("http-keep-alive", "1.1", "1.1", None, None, &[], &[], true),
    ("http-keep-alive", "1.1", "1.1", None, Some("keep-alive"), &[], &[], true),
    ("http-keep-alive", "1.1", "1.1", None, Some("close"), &[], &[], true),
    ("http-keep-alive", "1.1", "1.1", None, Some("upgrade"), &[], &["connection: upgrade"], true),
    ("http-keep-alive", "1.1", "1.1", None, Some("x-foo, keep-alive"), &[], &["connection: x-foo"], true),
    ("http-keep-alive", "1.1", "1.1", Some("keep-alive"), None, &[], &[], true),
    ("http-keep-alive", "1.1", "1.1", Some("keep-alive"), Some("keep-alive"), &[], &[], true),
    ("http-keep-alive", "1.1", "1.1", Some("keep-alive"), Some("close"), &[], &[], true),
    ("http-keep-alive", "1.1", "1.1", Some("keep-alive"), Some("upgrade"), &[], &["connection: upgrade"], true),
    ("http-keep-alive", "1.1", "1.1", Some("keep-alive"), Some("x-foo, keep-alive"), &[], &["connection: x-foo"], true),
    ("http-keep-alive", "1.1", "1.1", Some("close"), None, &[], &["connection: close"], false),
    ("http-keep-alive", "1.1", "1.1", Some("close"), Some("keep-alive"), &[], &["connection: close"], false),
    ("http-keep-alive", "1.1", "1.1", Some("close"), Some("close"), &[], &["connection: close"], false),
    ("http-keep-alive", "1.1", "1.1", Some("close"), Some("upgrade"), &[], &["connection: upgrade"], false),
    ("http-keep-alive", "1.1", "1.1", Some("close"), Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: close"], false),
    ("http-keep-alive", "1.1", "1.1", Some("upgrade"), None, &[], &[], true),
    ("http-keep-alive", "1.1", "1.1", Some("upgrade"), Some("keep-alive"), &[], &[], true),
    ("http-keep-alive", "1.1", "1.1", Some("upgrade"), Some("close"), &[], &[], true),
    ("http-keep-alive", "1.1", "1.1", Some("upgrade"), Some("upgrade"), &[], &["connection: upgrade"], true),
    ("http-keep-alive", "1.1", "1.1", Some("upgrade"), Some("x-foo, keep-alive"), &[], &["connection: x-foo"], true),
    ("http-keep-alive", "1.1", "1.0", None, None, &[], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.1", "1.0", None, Some("keep-alive"), &[], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.1", "1.0", None, Some("close"), &[], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.1", "1.0", None, Some("upgrade"), &[], &["connection: upgrade"], true),
    ("http-keep-alive", "1.1", "1.0", None, Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: keep-alive"], true),
    ("http-keep-alive", "1.1", "1.0", Some("keep-alive"), None, &[], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.1", "1.0", Some("keep-alive"), Some("keep-alive"), &[], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.1", "1.0", Some("keep-alive"), Some("close"), &[], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.1", "1.0", Some("keep-alive"), Some("upgrade"), &[], &["connection: upgrade"], true),
    ("http-keep-alive", "1.1", "1.0", Some("keep-alive"), Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: keep-alive"], true),
    ("http-keep-alive", "1.1", "1.0", Some("close"), None, &[], &[], false),
    ("http-keep-alive", "1.1", "1.0", Some("close"), Some("keep-alive"), &[], &[], false),
    ("http-keep-alive", "1.1", "1.0", Some("close"), Some("close"), &[], &[], false),
    ("http-keep-alive", "1.1", "1.0", Some("close"), Some("upgrade"), &[], &["connection: upgrade"], false),
    ("http-keep-alive", "1.1", "1.0", Some("close"), Some("x-foo, keep-alive"), &[], &["connection: x-foo"], false),
    ("http-keep-alive", "1.1", "1.0", Some("upgrade"), None, &[], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.1", "1.0", Some("upgrade"), Some("keep-alive"), &[], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.1", "1.0", Some("upgrade"), Some("close"), &[], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.1", "1.0", Some("upgrade"), Some("upgrade"), &[], &["connection: upgrade"], true),
    ("http-keep-alive", "1.1", "1.0", Some("upgrade"), Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: keep-alive"], true),
    ("http-keep-alive", "1.0", "1.1", None, None, &["connection: keep-alive"], &["connection: close"], false),
    ("http-keep-alive", "1.0", "1.1", None, Some("keep-alive"), &["connection: keep-alive"], &["connection: close"], false),
    ("http-keep-alive", "1.0", "1.1", None, Some("close"), &["connection: keep-alive"], &["connection: close"], false),
    ("http-keep-alive", "1.0", "1.1", None, Some("upgrade"), &["connection: keep-alive"], &["connection: upgrade"], false),
    ("http-keep-alive", "1.0", "1.1", None, Some("x-foo, keep-alive"), &["connection: keep-alive"], &["connection: x-foo", "connection: close"], false),
    ("http-keep-alive", "1.0", "1.1", Some("keep-alive"), None, &["connection: keep-alive"], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.0", "1.1", Some("keep-alive"), Some("keep-alive"), &["connection: keep-alive"], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.0", "1.1", Some("keep-alive"), Some("close"), &["connection: keep-alive"], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.0", "1.1", Some("keep-alive"), Some("upgrade"), &["connection: keep-alive"], &["connection: upgrade"], true),
    ("http-keep-alive", "1.0", "1.1", Some("keep-alive"), Some("x-foo, keep-alive"), &["connection: keep-alive"], &["connection: x-foo", "connection: keep-alive"], true),
    ("http-keep-alive", "1.0", "1.1", Some("close"), None, &["connection: keep-alive"], &["connection: close"], false),
    ("http-keep-alive", "1.0", "1.1", Some("close"), Some("keep-alive"), &["connection: keep-alive"], &["connection: close"], false),
    ("http-keep-alive", "1.0", "1.1", Some("close"), Some("close"), &["connection: keep-alive"], &["connection: close"], false),
    ("http-keep-alive", "1.0", "1.1", Some("close"), Some("upgrade"), &["connection: keep-alive"], &["connection: upgrade"], false),
    ("http-keep-alive", "1.0", "1.1", Some("close"), Some("x-foo, keep-alive"), &["connection: keep-alive"], &["connection: x-foo", "connection: close"], false),
    ("http-keep-alive", "1.0", "1.1", Some("upgrade"), None, &["connection: keep-alive"], &["connection: close"], false),
    ("http-keep-alive", "1.0", "1.1", Some("upgrade"), Some("keep-alive"), &["connection: keep-alive"], &["connection: close"], false),
    ("http-keep-alive", "1.0", "1.1", Some("upgrade"), Some("close"), &["connection: keep-alive"], &["connection: close"], false),
    ("http-keep-alive", "1.0", "1.1", Some("upgrade"), Some("upgrade"), &["connection: keep-alive"], &["connection: upgrade"], false),
    ("http-keep-alive", "1.0", "1.1", Some("upgrade"), Some("x-foo, keep-alive"), &["connection: keep-alive"], &["connection: x-foo", "connection: close"], false),
    ("http-keep-alive", "1.0", "1.0", None, None, &["connection: keep-alive"], &[], false),
    ("http-keep-alive", "1.0", "1.0", None, Some("keep-alive"), &["connection: keep-alive"], &[], false),
    ("http-keep-alive", "1.0", "1.0", None, Some("close"), &["connection: keep-alive"], &[], false),
    ("http-keep-alive", "1.0", "1.0", None, Some("upgrade"), &["connection: keep-alive"], &["connection: upgrade"], false),
    ("http-keep-alive", "1.0", "1.0", None, Some("x-foo, keep-alive"), &["connection: keep-alive"], &["connection: x-foo"], false),
    ("http-keep-alive", "1.0", "1.0", Some("keep-alive"), None, &["connection: keep-alive"], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.0", "1.0", Some("keep-alive"), Some("keep-alive"), &["connection: keep-alive"], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.0", "1.0", Some("keep-alive"), Some("close"), &["connection: keep-alive"], &["connection: keep-alive"], true),
    ("http-keep-alive", "1.0", "1.0", Some("keep-alive"), Some("upgrade"), &["connection: keep-alive"], &["connection: upgrade"], true),
    ("http-keep-alive", "1.0", "1.0", Some("keep-alive"), Some("x-foo, keep-alive"), &["connection: keep-alive"], &["connection: x-foo", "connection: keep-alive"], true),
    ("http-keep-alive", "1.0", "1.0", Some("close"), None, &["connection: keep-alive"], &[], false),
    ("http-keep-alive", "1.0", "1.0", Some("close"), Some("keep-alive"), &["connection: keep-alive"], &[], false),
    ("http-keep-alive", "1.0", "1.0", Some("close"), Some("close"), &["connection: keep-alive"], &[], false),
    ("http-keep-alive", "1.0", "1.0", Some("close"), Some("upgrade"), &["connection: keep-alive"], &["connection: upgrade"], false),
    ("http-keep-alive", "1.0", "1.0", Some("close"), Some("x-foo, keep-alive"), &["connection: keep-alive"], &["connection: x-foo"], false),
    ("http-keep-alive", "1.0", "1.0", Some("upgrade"), None, &["connection: keep-alive"], &[], false),
    ("http-keep-alive", "1.0", "1.0", Some("upgrade"), Some("keep-alive"), &["connection: keep-alive"], &[], false),
    ("http-keep-alive", "1.0", "1.0", Some("upgrade"), Some("close"), &["connection: keep-alive"], &[], false),
    ("http-keep-alive", "1.0", "1.0", Some("upgrade"), Some("upgrade"), &["connection: keep-alive"], &["connection: upgrade"], false),
    ("http-keep-alive", "1.0", "1.0", Some("upgrade"), Some("x-foo, keep-alive"), &["connection: keep-alive"], &["connection: x-foo"], false),
    ("httpclose", "1.1", "1.1", None, None, &["connection: close"], &["connection: close"], false),
    ("httpclose", "1.1", "1.1", None, Some("keep-alive"), &["connection: close"], &["connection: close"], false),
    ("httpclose", "1.1", "1.1", None, Some("close"), &["connection: close"], &["connection: close"], false),
    ("httpclose", "1.1", "1.1", None, Some("upgrade"), &["connection: close"], &["connection: upgrade"], false),
    ("httpclose", "1.1", "1.1", None, Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo", "connection: close"], false),
    ("httpclose", "1.1", "1.1", Some("keep-alive"), None, &["connection: close"], &["connection: close"], false),
    ("httpclose", "1.1", "1.1", Some("keep-alive"), Some("keep-alive"), &["connection: close"], &["connection: close"], false),
    ("httpclose", "1.1", "1.1", Some("keep-alive"), Some("close"), &["connection: close"], &["connection: close"], false),
    ("httpclose", "1.1", "1.1", Some("keep-alive"), Some("upgrade"), &["connection: close"], &["connection: upgrade"], false),
    ("httpclose", "1.1", "1.1", Some("keep-alive"), Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo", "connection: close"], false),
    ("httpclose", "1.1", "1.1", Some("close"), None, &["connection: close"], &["connection: close"], false),
    ("httpclose", "1.1", "1.1", Some("close"), Some("keep-alive"), &["connection: close"], &["connection: close"], false),
    ("httpclose", "1.1", "1.1", Some("close"), Some("close"), &["connection: close"], &["connection: close"], false),
    ("httpclose", "1.1", "1.1", Some("close"), Some("upgrade"), &["connection: close"], &["connection: upgrade"], false),
    ("httpclose", "1.1", "1.1", Some("close"), Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo", "connection: close"], false),
    ("httpclose", "1.1", "1.1", Some("upgrade"), None, &["connection: close"], &["connection: close"], false),
    ("httpclose", "1.1", "1.1", Some("upgrade"), Some("keep-alive"), &["connection: close"], &["connection: close"], false),
    ("httpclose", "1.1", "1.1", Some("upgrade"), Some("close"), &["connection: close"], &["connection: close"], false),
    ("httpclose", "1.1", "1.1", Some("upgrade"), Some("upgrade"), &["connection: close"], &["connection: upgrade"], false),
    ("httpclose", "1.1", "1.1", Some("upgrade"), Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo", "connection: close"], false),
    ("httpclose", "1.1", "1.0", None, None, &["connection: close"], &[], false),
    ("httpclose", "1.1", "1.0", None, Some("keep-alive"), &["connection: close"], &[], false),
    ("httpclose", "1.1", "1.0", None, Some("close"), &["connection: close"], &[], false),
    ("httpclose", "1.1", "1.0", None, Some("upgrade"), &["connection: close"], &["connection: upgrade"], false),
    ("httpclose", "1.1", "1.0", None, Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo"], false),
    ("httpclose", "1.1", "1.0", Some("keep-alive"), None, &["connection: close"], &[], false),
    ("httpclose", "1.1", "1.0", Some("keep-alive"), Some("keep-alive"), &["connection: close"], &[], false),
    ("httpclose", "1.1", "1.0", Some("keep-alive"), Some("close"), &["connection: close"], &[], false),
    ("httpclose", "1.1", "1.0", Some("keep-alive"), Some("upgrade"), &["connection: close"], &["connection: upgrade"], false),
    ("httpclose", "1.1", "1.0", Some("keep-alive"), Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo"], false),
    ("httpclose", "1.1", "1.0", Some("close"), None, &["connection: close"], &[], false),
    ("httpclose", "1.1", "1.0", Some("close"), Some("keep-alive"), &["connection: close"], &[], false),
    ("httpclose", "1.1", "1.0", Some("close"), Some("close"), &["connection: close"], &[], false),
    ("httpclose", "1.1", "1.0", Some("close"), Some("upgrade"), &["connection: close"], &["connection: upgrade"], false),
    ("httpclose", "1.1", "1.0", Some("close"), Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo"], false),
    ("httpclose", "1.1", "1.0", Some("upgrade"), None, &["connection: close"], &[], false),
    ("httpclose", "1.1", "1.0", Some("upgrade"), Some("keep-alive"), &["connection: close"], &[], false),
    ("httpclose", "1.1", "1.0", Some("upgrade"), Some("close"), &["connection: close"], &[], false),
    ("httpclose", "1.1", "1.0", Some("upgrade"), Some("upgrade"), &["connection: close"], &["connection: upgrade"], false),
    ("httpclose", "1.1", "1.0", Some("upgrade"), Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo"], false),
    ("httpclose", "1.0", "1.1", None, None, &[], &["connection: close"], false),
    ("httpclose", "1.0", "1.1", None, Some("keep-alive"), &[], &["connection: close"], false),
    ("httpclose", "1.0", "1.1", None, Some("close"), &[], &["connection: close"], false),
    ("httpclose", "1.0", "1.1", None, Some("upgrade"), &[], &["connection: upgrade"], false),
    ("httpclose", "1.0", "1.1", None, Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: close"], false),
    ("httpclose", "1.0", "1.1", Some("keep-alive"), None, &[], &["connection: close"], false),
    ("httpclose", "1.0", "1.1", Some("keep-alive"), Some("keep-alive"), &[], &["connection: close"], false),
    ("httpclose", "1.0", "1.1", Some("keep-alive"), Some("close"), &[], &["connection: close"], false),
    ("httpclose", "1.0", "1.1", Some("keep-alive"), Some("upgrade"), &[], &["connection: upgrade"], false),
    ("httpclose", "1.0", "1.1", Some("keep-alive"), Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: close"], false),
    ("httpclose", "1.0", "1.1", Some("close"), None, &[], &["connection: close"], false),
    ("httpclose", "1.0", "1.1", Some("close"), Some("keep-alive"), &[], &["connection: close"], false),
    ("httpclose", "1.0", "1.1", Some("close"), Some("close"), &[], &["connection: close"], false),
    ("httpclose", "1.0", "1.1", Some("close"), Some("upgrade"), &[], &["connection: upgrade"], false),
    ("httpclose", "1.0", "1.1", Some("close"), Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: close"], false),
    ("httpclose", "1.0", "1.1", Some("upgrade"), None, &[], &["connection: close"], false),
    ("httpclose", "1.0", "1.1", Some("upgrade"), Some("keep-alive"), &[], &["connection: close"], false),
    ("httpclose", "1.0", "1.1", Some("upgrade"), Some("close"), &[], &["connection: close"], false),
    ("httpclose", "1.0", "1.1", Some("upgrade"), Some("upgrade"), &[], &["connection: upgrade"], false),
    ("httpclose", "1.0", "1.1", Some("upgrade"), Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: close"], false),
    ("httpclose", "1.0", "1.0", None, None, &[], &[], false),
    ("httpclose", "1.0", "1.0", None, Some("keep-alive"), &[], &[], false),
    ("httpclose", "1.0", "1.0", None, Some("close"), &[], &[], false),
    ("httpclose", "1.0", "1.0", None, Some("upgrade"), &[], &["connection: upgrade"], false),
    ("httpclose", "1.0", "1.0", None, Some("x-foo, keep-alive"), &[], &["connection: x-foo"], false),
    ("httpclose", "1.0", "1.0", Some("keep-alive"), None, &[], &[], false),
    ("httpclose", "1.0", "1.0", Some("keep-alive"), Some("keep-alive"), &[], &[], false),
    ("httpclose", "1.0", "1.0", Some("keep-alive"), Some("close"), &[], &[], false),
    ("httpclose", "1.0", "1.0", Some("keep-alive"), Some("upgrade"), &[], &["connection: upgrade"], false),
    ("httpclose", "1.0", "1.0", Some("keep-alive"), Some("x-foo, keep-alive"), &[], &["connection: x-foo"], false),
    ("httpclose", "1.0", "1.0", Some("close"), None, &[], &[], false),
    ("httpclose", "1.0", "1.0", Some("close"), Some("keep-alive"), &[], &[], false),
    ("httpclose", "1.0", "1.0", Some("close"), Some("close"), &[], &[], false),
    ("httpclose", "1.0", "1.0", Some("close"), Some("upgrade"), &[], &["connection: upgrade"], false),
    ("httpclose", "1.0", "1.0", Some("close"), Some("x-foo, keep-alive"), &[], &["connection: x-foo"], false),
    ("httpclose", "1.0", "1.0", Some("upgrade"), None, &[], &[], false),
    ("httpclose", "1.0", "1.0", Some("upgrade"), Some("keep-alive"), &[], &[], false),
    ("httpclose", "1.0", "1.0", Some("upgrade"), Some("close"), &[], &[], false),
    ("httpclose", "1.0", "1.0", Some("upgrade"), Some("upgrade"), &[], &["connection: upgrade"], false),
    ("httpclose", "1.0", "1.0", Some("upgrade"), Some("x-foo, keep-alive"), &[], &["connection: x-foo"], false),
    ("http-server-close", "1.1", "1.1", None, None, &["connection: close"], &[], true),
    ("http-server-close", "1.1", "1.1", None, Some("keep-alive"), &["connection: close"], &[], true),
    ("http-server-close", "1.1", "1.1", None, Some("close"), &["connection: close"], &[], true),
    ("http-server-close", "1.1", "1.1", None, Some("upgrade"), &["connection: close"], &["connection: upgrade"], true),
    ("http-server-close", "1.1", "1.1", None, Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo"], true),
    ("http-server-close", "1.1", "1.1", Some("keep-alive"), None, &["connection: close"], &[], true),
    ("http-server-close", "1.1", "1.1", Some("keep-alive"), Some("keep-alive"), &["connection: close"], &[], true),
    ("http-server-close", "1.1", "1.1", Some("keep-alive"), Some("close"), &["connection: close"], &[], true),
    ("http-server-close", "1.1", "1.1", Some("keep-alive"), Some("upgrade"), &["connection: close"], &["connection: upgrade"], true),
    ("http-server-close", "1.1", "1.1", Some("keep-alive"), Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo"], true),
    ("http-server-close", "1.1", "1.1", Some("close"), None, &["connection: close"], &["connection: close"], false),
    ("http-server-close", "1.1", "1.1", Some("close"), Some("keep-alive"), &["connection: close"], &["connection: close"], false),
    ("http-server-close", "1.1", "1.1", Some("close"), Some("close"), &["connection: close"], &["connection: close"], false),
    ("http-server-close", "1.1", "1.1", Some("close"), Some("upgrade"), &["connection: close"], &["connection: upgrade"], false),
    ("http-server-close", "1.1", "1.1", Some("close"), Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo", "connection: close"], false),
    ("http-server-close", "1.1", "1.1", Some("upgrade"), None, &["connection: close"], &[], true),
    ("http-server-close", "1.1", "1.1", Some("upgrade"), Some("keep-alive"), &["connection: close"], &[], true),
    ("http-server-close", "1.1", "1.1", Some("upgrade"), Some("close"), &["connection: close"], &[], true),
    ("http-server-close", "1.1", "1.1", Some("upgrade"), Some("upgrade"), &["connection: close"], &["connection: upgrade"], true),
    ("http-server-close", "1.1", "1.1", Some("upgrade"), Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo"], true),
    ("http-server-close", "1.1", "1.0", None, None, &["connection: close"], &["connection: keep-alive"], true),
    ("http-server-close", "1.1", "1.0", None, Some("keep-alive"), &["connection: close"], &["connection: keep-alive"], true),
    ("http-server-close", "1.1", "1.0", None, Some("close"), &["connection: close"], &["connection: keep-alive"], true),
    ("http-server-close", "1.1", "1.0", None, Some("upgrade"), &["connection: close"], &["connection: upgrade"], true),
    ("http-server-close", "1.1", "1.0", None, Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo", "connection: keep-alive"], true),
    ("http-server-close", "1.1", "1.0", Some("keep-alive"), None, &["connection: close"], &["connection: keep-alive"], true),
    ("http-server-close", "1.1", "1.0", Some("keep-alive"), Some("keep-alive"), &["connection: close"], &["connection: keep-alive"], true),
    ("http-server-close", "1.1", "1.0", Some("keep-alive"), Some("close"), &["connection: close"], &["connection: keep-alive"], true),
    ("http-server-close", "1.1", "1.0", Some("keep-alive"), Some("upgrade"), &["connection: close"], &["connection: upgrade"], true),
    ("http-server-close", "1.1", "1.0", Some("keep-alive"), Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo", "connection: keep-alive"], true),
    ("http-server-close", "1.1", "1.0", Some("close"), None, &["connection: close"], &[], false),
    ("http-server-close", "1.1", "1.0", Some("close"), Some("keep-alive"), &["connection: close"], &[], false),
    ("http-server-close", "1.1", "1.0", Some("close"), Some("close"), &["connection: close"], &[], false),
    ("http-server-close", "1.1", "1.0", Some("close"), Some("upgrade"), &["connection: close"], &["connection: upgrade"], false),
    ("http-server-close", "1.1", "1.0", Some("close"), Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo"], false),
    ("http-server-close", "1.1", "1.0", Some("upgrade"), None, &["connection: close"], &["connection: keep-alive"], true),
    ("http-server-close", "1.1", "1.0", Some("upgrade"), Some("keep-alive"), &["connection: close"], &["connection: keep-alive"], true),
    ("http-server-close", "1.1", "1.0", Some("upgrade"), Some("close"), &["connection: close"], &["connection: keep-alive"], true),
    ("http-server-close", "1.1", "1.0", Some("upgrade"), Some("upgrade"), &["connection: close"], &["connection: upgrade"], true),
    ("http-server-close", "1.1", "1.0", Some("upgrade"), Some("x-foo, keep-alive"), &["connection: close"], &["connection: x-foo", "connection: keep-alive"], true),
    ("http-server-close", "1.0", "1.1", None, None, &[], &["connection: close"], false),
    ("http-server-close", "1.0", "1.1", None, Some("keep-alive"), &[], &["connection: close"], false),
    ("http-server-close", "1.0", "1.1", None, Some("close"), &[], &["connection: close"], false),
    ("http-server-close", "1.0", "1.1", None, Some("upgrade"), &[], &["connection: upgrade"], false),
    ("http-server-close", "1.0", "1.1", None, Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: close"], false),
    ("http-server-close", "1.0", "1.1", Some("keep-alive"), None, &[], &["connection: keep-alive"], true),
    ("http-server-close", "1.0", "1.1", Some("keep-alive"), Some("keep-alive"), &[], &["connection: keep-alive"], true),
    ("http-server-close", "1.0", "1.1", Some("keep-alive"), Some("close"), &[], &["connection: keep-alive"], true),
    ("http-server-close", "1.0", "1.1", Some("keep-alive"), Some("upgrade"), &[], &["connection: upgrade"], true),
    ("http-server-close", "1.0", "1.1", Some("keep-alive"), Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: keep-alive"], true),
    ("http-server-close", "1.0", "1.1", Some("close"), None, &[], &["connection: close"], false),
    ("http-server-close", "1.0", "1.1", Some("close"), Some("keep-alive"), &[], &["connection: close"], false),
    ("http-server-close", "1.0", "1.1", Some("close"), Some("close"), &[], &["connection: close"], false),
    ("http-server-close", "1.0", "1.1", Some("close"), Some("upgrade"), &[], &["connection: upgrade"], false),
    ("http-server-close", "1.0", "1.1", Some("close"), Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: close"], false),
    ("http-server-close", "1.0", "1.1", Some("upgrade"), None, &[], &["connection: close"], false),
    ("http-server-close", "1.0", "1.1", Some("upgrade"), Some("keep-alive"), &[], &["connection: close"], false),
    ("http-server-close", "1.0", "1.1", Some("upgrade"), Some("close"), &[], &["connection: close"], false),
    ("http-server-close", "1.0", "1.1", Some("upgrade"), Some("upgrade"), &[], &["connection: upgrade"], false),
    ("http-server-close", "1.0", "1.1", Some("upgrade"), Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: close"], false),
    ("http-server-close", "1.0", "1.0", None, None, &[], &[], false),
    ("http-server-close", "1.0", "1.0", None, Some("keep-alive"), &[], &[], false),
    ("http-server-close", "1.0", "1.0", None, Some("close"), &[], &[], false),
    ("http-server-close", "1.0", "1.0", None, Some("upgrade"), &[], &["connection: upgrade"], false),
    ("http-server-close", "1.0", "1.0", None, Some("x-foo, keep-alive"), &[], &["connection: x-foo"], false),
    ("http-server-close", "1.0", "1.0", Some("keep-alive"), None, &[], &["connection: keep-alive"], true),
    ("http-server-close", "1.0", "1.0", Some("keep-alive"), Some("keep-alive"), &[], &["connection: keep-alive"], true),
    ("http-server-close", "1.0", "1.0", Some("keep-alive"), Some("close"), &[], &["connection: keep-alive"], true),
    ("http-server-close", "1.0", "1.0", Some("keep-alive"), Some("upgrade"), &[], &["connection: upgrade"], true),
    ("http-server-close", "1.0", "1.0", Some("keep-alive"), Some("x-foo, keep-alive"), &[], &["connection: x-foo", "connection: keep-alive"], true),
    ("http-server-close", "1.0", "1.0", Some("close"), None, &[], &[], false),
    ("http-server-close", "1.0", "1.0", Some("close"), Some("keep-alive"), &[], &[], false),
    ("http-server-close", "1.0", "1.0", Some("close"), Some("close"), &[], &[], false),
    ("http-server-close", "1.0", "1.0", Some("close"), Some("upgrade"), &[], &["connection: upgrade"], false),
    ("http-server-close", "1.0", "1.0", Some("close"), Some("x-foo, keep-alive"), &[], &["connection: x-foo"], false),
    ("http-server-close", "1.0", "1.0", Some("upgrade"), None, &[], &[], false),
    ("http-server-close", "1.0", "1.0", Some("upgrade"), Some("keep-alive"), &[], &[], false),
    ("http-server-close", "1.0", "1.0", Some("upgrade"), Some("close"), &[], &[], false),
    ("http-server-close", "1.0", "1.0", Some("upgrade"), Some("upgrade"), &[], &["connection: upgrade"], false),
    ("http-server-close", "1.0", "1.0", Some("upgrade"), Some("x-foo, keep-alive"), &[], &["connection: x-foo"], false),
];

/// A backend that answers the request for `/<n>` as ROWS[n] says and reports the
/// `Connection`-ish lines it received in `x-seen`.
fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let Ok(n) = s.read(&mut buf) else { return };
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let n: usize = req.split(' ').nth(1).and_then(|p| p.trim_start_matches('/').parse().ok()).unwrap_or(0);
                let (_, _, sver, _, token, _, _, _) = ROWS[n];
                let seen: Vec<String> = req
                    .split("\r\n")
                    .skip(1)
                    .filter(|l| {
                        let l = l.to_ascii_lowercase();
                        l.starts_with("connection:") || l.starts_with("proxy-connection:")
                    })
                    .map(str::to_ascii_lowercase)
                    .collect();
                let conn = token.map_or(String::new(), |t| format!("Connection: {t}\r\n"));
                let rsp = format!(
                    "HTTP/{sver} 200 OK\r\n{}Keep-Alive: timeout=5\r\nX-Seen: {}\r\nContent-Length: 2\r\n\r\nhi",
                    conn,
                    seen.join("|")
                );
                let _ = s.write_all(rsp.as_bytes());
                thread::sleep(Duration::from_millis(200));
            });
        }
    });
    addr
}

/// The lines of the answer, lower case, and whether the client connection is still open
/// after it (nothing arrives within 600 ms) rather than closed.
fn get(fe: SocketAddr, n: usize) -> (Vec<String>, bool) {
    let (_, cver, _, token, _, _, _, _) = ROWS[n];
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let conn = token.map_or(String::new(), |t| format!("Connection: {t}\r\n"));
    write!(c, "GET /{n} HTTP/{cver}\r\nHost: x\r\n{conn}\r\n").expect("send");
    let mut got = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let end = got.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 6);
        if end.is_some_and(|e| got.len() >= e) {
            break;
        }
        match c.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(k) => got.extend_from_slice(&tmp[..k]),
        }
    }
    c.set_read_timeout(Some(Duration::from_millis(600))).expect("timeout");
    let open = matches!(c.read(&mut tmp), Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut));
    let lines = String::from_utf8_lossy(&got).to_ascii_lowercase().split("\r\n").skip(1).take_while(|l| !l.is_empty()).map(str::to_string).collect();
    (lines, open)
}

/// With an `http-response` rule the response is rewritten as a list of headers rather than in
/// place; HAProxy's answer is the same (measured: the table below is identical with one).
#[test]
fn connection_tokens_match_haproxy() {
    run("");
}

#[test]
fn connection_tokens_match_haproxy_with_a_response_rule() {
    run("    http-response add-header x-rule 1\n");
}

fn run(rule: &str) {
    let be = backend();
    let fes: Vec<(&str, SocketAddr)> = ["http-keep-alive", "httpclose", "http-server-close"].iter().map(|m| (*m, common::reserve_addr())).collect();
    let mut cfg = String::from("global\n\n");
    for (mode, fe) in &fes {
        cfg += &format!(
            "listen {mode}\n    mode http\n    bind {fe}\n    timeout client 5s\n    timeout server 5s\n    timeout connect 2s\n    option {mode}\n{rule}    server s {be}\n\n"
        );
    }
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    for (_, fe) in &fes {
        while TcpStream::connect(fe).is_err() {
            assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
            thread::sleep(Duration::from_millis(20));
        }
    }
    // Every case on its own connection, all at once: the wait for "still open" is 600 ms each.
    let answers: Vec<(Vec<String>, bool)> = thread::scope(|sc| {
        let jobs: Vec<_> = ROWS
            .iter()
            .enumerate()
            .map(|(n, row)| {
                let fe = fes.iter().find(|(m, _)| *m == row.0).expect("mode").1;
                sc.spawn(move || get(fe, n))
            })
            .collect();
        jobs.into_iter().map(|j| j.join().expect("client")).collect()
    });
    let mut bad = Vec::new();
    for (n, (mode, cver, sver, ctoken, stoken, want_srv, want_cli, want_open)) in ROWS.iter().enumerate() {
        let (lines, open) = answers[n].clone();
        let seen: Vec<String> = lines
            .iter()
            .find_map(|l| l.strip_prefix("x-seen:"))
            .map(|v| v.trim().split('|').filter(|x| !x.is_empty()).map(str::to_string).collect())
            .unwrap_or_default();
        let cli: Vec<String> = lines.iter().filter(|l| l.starts_with("connection:")).cloned().collect();
        let norm = |v: &[String]| v.iter().map(|l| l.replace(": ", ":")).collect::<Vec<_>>();
        let want = |w: &[&str]| w.iter().map(|l| l.replace(": ", ":")).collect::<Vec<_>>();
        if norm(&seen) != want(want_srv) || norm(&cli) != want(want_cli) || open != *want_open {
            bad.push(format!(
                "{mode} client {cver} {ctoken:?} server {sver} {stoken:?}: server saw {seen:?} (want {want_srv:?}), client got {cli:?} (want {want_cli:?}), connection open {open} (want {want_open})"
            ));
        }
    }
    common::stop(&mut child);
    assert!(bad.is_empty(), "{} of {} cases differ from HAProxy:\n{}", bad.len(), ROWS.len(), bad.join("\n"));
}
