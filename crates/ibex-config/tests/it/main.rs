// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

#![allow(clippy::disallowed_macros)] // tests print with eprintln!; see /clippy.toml

//! ibex-config's integration tests, one binary (T260). Each former `tests/<name>.rs` is the
//! module `<name>` here, unchanged: run one file's tests with
//! `cargo test -p ibex-config --test it <name>::`.
//!
//! A new test file is a module listed below, not a new binary, unless it needs its own
//! process (a `#[global_allocator]`, allocation/RSS counting, rlimits, signal handlers, cwd,
//! or environment changes that C code could race); then it gets its own `[[test]]` in
//! Cargo.toml and says why in its header.
//!
//! `address_forms` calls `std::env::set_var` and stays here: the variable it sets is read by
//! no other test, every environment read in ibex-config goes through `std::env` (which
//! serialises with `set_var` under std's lock, as does `Command::spawn`), and nothing in this
//! binary calls C code that reads the environment (no `getaddrinfo`, no OpenSSL).

mod acl_condition_syntax;
mod acl_must_exist;
mod address_forms;
mod balance_options;
mod bind_keywords;
mod check_rules_parse;
mod cond_enabled;
mod cond_expected_message;
mod connection_limits;
mod cookie_config;
mod crypto_provider;
mod differential;
mod env_expansion;
mod global_identity;
mod h2_max_concurrent_streams;
mod global_sections;
mod gpc_array_actions;
mod http_codes;
mod http_reject_silent_drop;
mod rst_ttl;
mod rule_trailing_words;
mod http_rule_keywords;
mod if_conditions;
mod if_error_position;
mod monitor_fail;
mod monitor_in_backend;
mod lexer_hex_escape;
mod log_format_config;
mod log_tag_sample;
mod m1_scope_refusals;
mod no_memory_trimming;
mod zero_buffers;
mod zero_on_free;
mod ssl_zero_buffers;
mod zero_spares;
mod fail_alloc_keywords;
mod hot_size;
mod normalize_uri_experimental;
mod node_description;
mod pause_rule;
mod preproc;
mod proxy_ids;
mod proxy_options;
mod quic_bind;
mod redispatch_option;
mod response_deny;
mod response_redirect;
mod retry_on;
mod ring_sections;
mod sc_set_gpt0_default;
mod sc_value_missing;
mod server_keywords;
mod server_tls;
mod set_dst_port_retries;
mod set_timeout_rule;
mod use_service_prometheus;
mod ssl_capture_size;
mod ssl_server_verify;
mod stats_show_desc_node;
mod stats_show_node_validation;
mod stats_unknown_words;
mod stick_table_keywords;
mod tcp_response_content;
mod timeout_keywords;
mod timer_overflow;
mod tls_versions;
mod tune_maxaccept;
mod userlist_hashes;
mod wait_for_body;
