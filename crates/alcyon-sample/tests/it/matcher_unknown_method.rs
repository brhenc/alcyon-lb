// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A matching method that does not exist is refused with HAProxy's words
//! (`acl a path -m nosuch /x`, measured on 3.5-dev8-885761-29: "unknown matching method
//! 'nosuch' when parsing ACL expression").

use alcyon_sample::Matcher;

#[test]
fn an_unknown_method_is_refused_in_haproxys_words() {
    let err = Matcher::compile("nosuch", "/x").err().expect("refused");
    assert_eq!(err, "unknown matching method 'nosuch' when parsing ACL expression");
}
