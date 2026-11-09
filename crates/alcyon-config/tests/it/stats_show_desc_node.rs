// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `stats show-desc <text...>` keeps every word after the keyword, joined by one space;
//! `stats show-node <name>` keeps the name. Nothing reads them yet (T151 item 1), so this
//! pins only what the parser stores.

use alcyon_config::parse_str;

#[test]
fn show_desc_joins_its_words_and_show_node_keeps_its_name() {
    let cfg = parse_str(
        "listen l\n  bind 127.0.0.1:1\n  stats enable\n  stats show-desc primary  load balancer\n  stats show-node lb1\n",
    )
    .expect("parse");
    let stats = &cfg.listens[0].stats;
    assert_eq!(stats.show_desc.as_deref(), Some("primary load balancer"));
    assert_eq!(stats.show_node.as_deref(), Some("lb1"));
}
