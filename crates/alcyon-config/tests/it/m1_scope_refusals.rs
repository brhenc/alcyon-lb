// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T164: what Milestone 1 leaves out is refused by name, never accepted and dropped
//! (AGENTS.md section 5). Each refusal says `'<keyword>' is not supported by Alcyon (out of
//! scope, see docs/differences.md)`.

use alcyon_config::parse_config;

const FE: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend f\n  bind 127.0.0.1:8080\n";
const BE: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nbackend b\n  server s 127.0.0.1:1\n";

fn refused(cfg: &str, keyword: &str) {
    let err = match parse_config(cfg) {
        Ok(_) => panic!("{keyword}: accepted:\n{cfg}"),
        Err(e) => e.to_string(),
    };
    let want = format!("'{keyword}' is not supported by Alcyon (out of scope, see docs/differences.md)");
    assert!(err.contains(&want), "{keyword}: got {err:?}");
}

#[test]
fn lua_is_refused() {
    refused(&format!("global\n  lua-load /tmp/x.lua\n{FE}"), "lua-load");
    refused(&format!("global\n  lua-load-per-thread /tmp/x.lua\n{FE}"), "lua-load-per-thread");
    refused(&format!("global\n  lua-prepend-path /tmp/?.lua\n{FE}"), "lua-prepend-path");
    refused(&format!("global\n  tune.lua.maxmem 10\n{FE}"), "tune.lua.maxmem");
    refused(&format!("{FE}  http-request lua.foo\n"), "lua.foo");
    refused(&format!("{FE}  http-response lua.foo\n"), "lua.foo");
    refused(&format!("{FE}  use-service lua.foo\n"), "use-service");
    refused(&format!("{FE}  http-request set-header X %[lua.foo]\n"), "lua.foo");
    refused(&format!("{FE}  http-request set-header X %[src,lua.foo]\n"), "lua.foo");
}

#[test]
fn spoe_compression_and_filters_are_refused() {
    refused(&format!("{FE}  filter spoe engine e config /tmp/s.conf\n"), "filter");
    refused(&format!("{FE}  filter compression\n"), "filter");
    refused(&format!("{FE}  compression algo gzip\n"), "compression");
    refused(&format!("{BE}  compression type text/html\n"), "compression");
    refused("defaults\n  compression offload\n", "compression");
}

#[test]
fn peers_cache_fcgi_are_refused() {
    refused(&format!("peers p\n  peer a 127.0.0.1:1234\n{FE}"), "peers");
    refused(&format!("cache c\n  total-max-size 4\n{FE}"), "cache");
    refused(&format!("fcgi-app fa\n  docroot /tmp\n{FE}"), "fcgi-app");
    refused(&format!("{BE}  use-fcgi-app fa\n"), "use-fcgi-app");
    refused(&format!("{BE}  stick-table type ip size 1k peers p\n"), "stick-table ... peers");
    refused(&format!("{FE}  http-request cache-use c\n"), "cache-use");
    refused(&format!("{FE}  http-response cache-store c\n"), "cache-store");
}

#[test]
fn openssl_only_keywords_are_refused() {
    for k in ["ssl-engine rdrand", "ssl-mode-async", "ssl-propquery foo", "ssl-provider default", "ssl-provider-path /tmp", "tune.ssl.async 1"] {
        let name = k.split(' ').next().unwrap();
        refused(&format!("global\n  {k}\n{FE}"), name);
    }
}
