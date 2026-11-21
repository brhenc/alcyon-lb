// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Prints field offsets, sizes, and padding for per-connection, per-stream, per-request,
//! and per-proxy/per-server structs (`docs/research/size-map-2026-11-19.md`).
//!
//! Run by hand:
//!   cargo test -p alcyon-rt --test it size_map:: -- --ignored --nocapture

use std::mem::{align_of, offset_of, size_of};

struct FieldInfo {
    name: &'static str,
    ty: &'static str,
    size: usize,
    offset: usize,
}

fn field_size<S, F>(_: fn(&S) -> &F) -> (usize, &'static str) {
    (size_of::<F>(), std::any::type_name::<F>())
}

macro_rules! field {
    ($struct_ty:ty, $field:ident) => {{
        let (size, ty) = field_size(|s: &$struct_ty| &s.$field);
        FieldInfo {
            name: stringify!($field),
            ty,
            size,
            offset: offset_of!($struct_ty, $field),
        }
    }};
}

fn print_struct(name: &str, total_size: usize, align: usize, mut fields: Vec<FieldInfo>) {
    fields.sort_by_key(|f| f.offset);
    eprintln!("\n=== {name} (size={total_size}, align={align}) ===");
    eprintln!(
        "{:<28} {:<56} {:>6} {:>7} {:>7}",
        "field", "type", "size", "offset", "pad_after"
    );
    let mut sum_fields = 0usize;
    let mut sum_pad = 0usize;
    for i in 0..fields.len() {
        let f = &fields[i];
        let end = f.offset + f.size;
        let next_off = if i + 1 < fields.len() {
            fields[i + 1].offset
        } else {
            total_size
        };
        let pad = next_off.saturating_sub(end);
        sum_fields += f.size;
        sum_pad += pad;
        eprintln!(
            "{:<28} {:<56} {:>6} {:>7} {:>7}",
            f.name, f.ty, f.size, f.offset, pad
        );
    }
    let unaccounted = total_size.saturating_sub(sum_fields + sum_pad);
    eprintln!(
        "--- summary: pub_fields={sum_fields}, gaps_after_pub={sum_pad}, leading_or_unaccounted={unaccounted}, total={total_size}"
    );
}

#[test]
#[ignore = "prints a report; run by hand"]
fn print_size_map() {
    use alcyon_proto::mux_h2::{H2MuxContext, H2StreamCtx, StreamEntry, StreamMap};
    use alcyon_rt::buf::Buf;
    use alcyon_rt::engine::{Proxy, ProxyIdInfo, RateCtr, SessionEntry};
    use alcyon_rt::proxy::{H2Child, ReqText, TcpSession};
    use alcyon_rt::srv_rt::{ServerAddrs, ServerMaxconns, ServerNames, ServerWeights};
    use alcyon_rt::srv_set::{ServerArrays, ServerIdArrays};
    use alcyon_rt::stream::Stream;
    use alcyon_rt::txn::{HttpTxn, LenHdrs, MsgState};
    use alcyon_rt::txnlog::StreamLog;

    print_struct(
        "alcyon_rt::engine::SessionEntry",
        size_of::<SessionEntry>(),
        align_of::<SessionEntry>(),
        vec![
            field!(SessionEntry, sess),
            field!(SessionEntry, task),
            field!(SessionEntry, proxy_idx),
            field!(SessionEntry, backend_idx),
            field!(SessionEntry, srv_backend_idx),
            field!(SessionEntry, target_server_idx),
            field!(SessionEntry, cli_raw_fd),
            field!(SessionEntry, srv_raw_fd),
            field!(SessionEntry, cli_interest),
            field!(SessionEntry, srv_interest),
            field!(SessionEntry, actconn_reclaimed),
            field!(SessionEntry, stats_done),
            field!(SessionEntry, be_counted),
            field!(SessionEntry, connect_log_due),
            field!(SessionEntry, rate_max_due),
            field!(SessionEntry, srv_served),
            field!(SessionEntry, log_line),
            field!(SessionEntry, log_err),
            field!(SessionEntry, log_sd),
            field!(SessionEntry, buf_wait),
            field!(SessionEntry, parked),
        ],
    );

    print_struct(
        "alcyon_rt::proxy::TcpSession (pub fields; private: cli: ClientSide)",
        size_of::<TcpSession>(),
        align_of::<TcpSession>(),
        vec![
            field!(TcpSession, parser_kind),
            field!(TcpSession, cli_xprt),
            field!(TcpSession, srv),
            field!(TcpSession, srv_xprt),
            field!(TcpSession, mode),
            field!(TcpSession, client_addr),
            field!(TcpSession, so_name),
            field!(TcpSession, so_id),
            field!(TcpSession, proxy_hdr_err),
            field!(TcpSession, cliexp),
            field!(TcpSession, srvexp),
            field!(TcpSession, req_uri),
            field!(TcpSession, req_method),
            field!(TcpSession, req_body_htx),
            field!(TcpSession, req_headers),
            field!(TcpSession, htx_buf),
            field!(TcpSession, htx_tail),
            field!(TcpSession, htx_blocks),
            field!(TcpSession, htx_head),
            field!(TcpSession, req_head_deferred),
            field!(TcpSession, req_ws),
            field!(TcpSession, cli_state),
            field!(TcpSession, srv_state),
            field!(TcpSession, req),
            field!(TcpSession, rep),
            field!(TcpSession, timeouts),
            field!(TcpSession, be_tunnel_ms),
            field!(TcpSession, be_queue_ms),
            field!(TcpSession, queue),
            field!(TcpSession, conn_retries),
            field!(TcpSession, max_retries),
            field!(TcpSession, cli_exp),
            field!(TcpSession, http_request_ms),
            field!(TcpSession, keep_alive_ms),
            field!(TcpSession, req_exp),
            field!(TcpSession, srv_exp),
            field!(TcpSession, conn_exp),
            field!(TcpSession, retry_after),
            field!(TcpSession, srv_park_exp),
            field!(TcpSession, target_addr),
            field!(TcpSession, bc_src),
            field!(TcpSession, bc_err),
            field!(TcpSession, bytes_in),
            field!(TcpSession, bytes_out),
            field!(TcpSession, stick_acct_in),
            field!(TcpSession, glitches_credited),
            field!(TcpSession, stick_out_pending),
            field!(TcpSession, ending),
            field!(TcpSession, accept_proxy),
            field!(TcpSession, client_proto),
            field!(TcpSession, flags),
            field!(TcpSession, has_htx),
            field!(TcpSession, htx_modified),
            field!(TcpSession, req_head_pending),
            field!(TcpSession, cli_cant_recv),
            field!(TcpSession, srv_cant_recv),
            field!(TcpSession, passes_ran_out),
            field!(TcpSession, is_first_req),
            field!(TcpSession, req_idle),
            field!(TcpSession, accept_unsafe_request),
            field!(TcpSession, drop_req_trailers),
            field!(TcpSession, bc_idle),
            field!(TcpSession, proxy_info),
            field!(TcpSession, server_addr),
            field!(TcpSession, send_proxy_header),
            field!(TcpSession, created_at),
            field!(TcpSession, pending_resp),
            field!(TcpSession, fc_src),
            field!(TcpSession, fc_dst),
            field!(TcpSession, sess_addr),
            field!(TcpSession, inspect_exp),
            field!(TcpSession, dr_wait),
            field!(TcpSession, res_inspect),
            field!(TcpSession, strm),
            field!(TcpSession, tracked_sc),
            field!(TcpSession, bufsize),
            field!(TcpSession, maxrewrite),
            field!(TcpSession, h2_ctx),
            field!(TcpSession, h2_idle_start),
            field!(TcpSession, h2_role),
            field!(TcpSession, h2_flood_config),
        ],
    );

    print_struct(
        "alcyon_rt::stream::Stream",
        size_of::<Stream>(),
        align_of::<Stream>(),
        vec![
            field!(Stream, txn),
            field!(Stream, log),
            field!(Stream, vars),
            field!(Stream, stick_stores),
            field!(Stream, timeouts_set),
        ],
    );

    print_struct(
        "alcyon_rt::txnlog::StreamLog (pub fields; private: date_cache: Cell<(i64, u32)>)",
        size_of::<StreamLog>(),
        align_of::<StreamLog>(),
        vec![
            field!(StreamLog, start),
            field!(StreamLog, first_byte),
            field!(StreamLog, request),
            field!(StreamLog, queue),
            field!(StreamLog, server),
            field!(StreamLog, connect),
            field!(StreamLog, data),
            field!(StreamLog, bytes_in_at_start),
            field!(StreamLog, bytes_out_at_start),
            field!(StreamLog, bytes_from_server),
            field!(StreamLog, checkcache_blocked),
            field!(StreamLog, request_line),
            field!(StreamLog, req_captures),
            field!(StreamLog, res_captures),
            field!(StreamLog, unique_id),
            field!(StreamLog, last_rule),
            field!(StreamLog, prio_class),
            field!(StreamLog, prio_offset),
            field!(StreamLog, uniq_id),
            field!(StreamLog, term),
            field!(StreamLog, status),
            field!(StreamLog, redispatched),
            field!(StreamLog, applet),
            field!(StreamLog, be_queue),
            field!(StreamLog, asap_done),
            field!(StreamLog, srv_status),
        ],
    );

    print_struct(
        "alcyon_rt::proxy::H2Child",
        size_of::<H2Child>(),
        align_of::<H2Child>(),
        vec![
            field!(H2Child, owner),
            field!(H2Child, stream),
            field!(H2Child, late_trailers),
            field!(H2Child, rsp_head),
            field!(H2Child, reset),
            field!(H2Child, finished),
            field!(H2Child, conn_end),
            field!(H2Child, owner_tx_pending),
            field!(H2Child, rst),
            field!(H2Child, goaway),
            field!(H2Child, tls),
            field!(H2Child, quic_ack),
            field!(H2Child, req_abs),
            field!(H2Child, sess_vars_at_start),
        ],
    );

    print_struct(
        "alcyon_proto::mux_h2::H2StreamCtx",
        size_of::<H2StreamCtx>(),
        align_of::<H2StreamCtx>(),
        vec![
            field!(H2StreamCtx, id),
            field!(H2StreamCtx, state),
            field!(H2StreamCtx, rx_htx),
            field!(H2StreamCtx, send_window),
            field!(H2StreamCtx, recv_window),
            field!(H2StreamCtx, reset_reason),
            field!(H2StreamCtx, is_shut),
            field!(H2StreamCtx, dispatched),
            field!(H2StreamCtx, rx_buffered),
            field!(H2StreamCtx, rx_fill),
            field!(H2StreamCtx, rx_limit),
            field!(H2StreamCtx, bad_request),
            field!(H2StreamCtx, text_head),
            field!(H2StreamCtx, req_content_length),
            field!(H2StreamCtx, ext_connect),
            field!(H2StreamCtx, rx_head),
            field!(H2StreamCtx, head_facts),
            field!(H2StreamCtx, abs_len),
            field!(H2StreamCtx, no_memory),
        ],
    );

    print_struct(
        "alcyon_proto::mux_h2::H2MuxContext (pub fields; private: lower_name, decoded, block_scratch, head_wait)",
        size_of::<H2MuxContext>(),
        align_of::<H2MuxContext>(),
        vec![
            field!(H2MuxContext, conn),
            field!(H2MuxContext, is_server),
            field!(H2MuxContext, conn_state),
            field!(H2MuxContext, rx_buf),
            field!(H2MuxContext, tx_buf),
            field!(H2MuxContext, tx_consumed),
            field!(H2MuxContext, streams),
            field!(H2MuxContext, conn_send_window),
            field!(H2MuxContext, conn_recv_window),
            field!(H2MuxContext, rx_window_opened),
            field!(H2MuxContext, remote_initial_window),
            field!(H2MuxContext, local_initial_window),
            field!(H2MuxContext, max_concurrent_streams),
            field!(H2MuxContext, max_frame_size),
            field!(H2MuxContext, last_client_stream_id),
            field!(H2MuxContext, last_server_stream_id),
            field!(H2MuxContext, settings_ack_received),
            field!(H2MuxContext, goaway_sent),
            field!(H2MuxContext, goaway_received),
            field!(H2MuxContext, decoder),
            field!(H2MuxContext, encoder),
            field!(H2MuxContext, is_shut),
            field!(H2MuxContext, reset_count),
            field!(H2MuxContext, continuation_stream),
            field!(H2MuxContext, continuation_flags),
            field!(H2MuxContext, continuation_buf),
            field!(H2MuxContext, continuation_count),
            field!(H2MuxContext, rx_frame_len),
            field!(H2MuxContext, flood_config),
            field!(H2MuxContext, relaxed_path),
            field!(H2MuxContext, total_streams),
            field!(H2MuxContext, glitch_count),
            field!(H2MuxContext, graceful_goaway_sent),
            field!(H2MuxContext, highest_opened),
            field!(H2MuxContext, body_scratch),
            field!(H2MuxContext, spare_htx),
            field!(H2MuxContext, take_rx_head),
            field!(H2MuxContext, ws_key),
        ],
    );

    print_struct(
        "alcyon_rt::txn::HttpTxn",
        size_of::<HttpTxn>(),
        align_of::<HttpTxn>(),
        vec![
            field!(HttpTxn, req),
            field!(HttpTxn, rsp),
            field!(HttpTxn, rsp_interim),
            field!(HttpTxn, status),
            field!(HttpTxn, req_rules_done),
            field!(HttpTxn, body_wait),
            field!(HttpTxn, req_body),
            field!(HttpTxn, rsp_wait),
            field!(HttpTxn, local),
            field!(HttpTxn, keeps_srv),
            field!(HttpTxn, close_after),
            field!(HttpTxn, req_version),
            field!(HttpTxn, req_http11),
            field!(HttpTxn, srv_reusable),
            field!(HttpTxn, client_head),
            field!(HttpTxn, srv_reused),
            field!(HttpTxn, keepalive_lost),
            field!(HttpTxn, error),
            field!(HttpTxn, quiet),
            field!(HttpTxn, aborted),
            field!(HttpTxn, ck),
            field!(HttpTxn, req_htx),
            field!(HttpTxn, rsp_htx),
            field!(HttpTxn, req_len_hdrs),
            field!(HttpTxn, rsp_len_hdrs),
            field!(HttpTxn, req_body_dropped),
            field!(HttpTxn, close_opt),
            field!(HttpTxn, srv_kal_rule),
            field!(HttpTxn, req_len_long),
            field!(HttpTxn, rsp_dechunk),
            field!(HttpTxn, wait_client_gone),
            field!(HttpTxn, l7),
        ],
    );

    print_struct(
        "alcyon_rt::engine::Proxy",
        size_of::<Proxy>(),
        align_of::<Proxy>(),
        vec![
            field!(Proxy, srv),
            field!(Proxy, id),
            field!(Proxy, unpublished),
            field!(Proxy, ids),
            field!(Proxy, name),
            field!(Proxy, has_frontend),
            field!(Proxy, has_backend),
            field!(Proxy, addr),
            field!(Proxy, mode),
            field!(Proxy, balance),
            field!(Proxy, balance_set),
            field!(Proxy, timeouts),
            field!(Proxy, retries),
            field!(Proxy, redisp),
            field!(Proxy, redisp_after),
            field!(Proxy, maxconn),
            field!(Proxy, dispatch),
            field!(Proxy, cookie),
            field!(Proxy, cliexp),
            field!(Proxy, srvexp),
            field!(Proxy, next_server_idx),
            field!(Proxy, stats),
            field!(Proxy, stats_config),
            field!(Proxy, desc),
            field!(Proxy, default_backend),
            field!(Proxy, use_backends),
            field!(Proxy, use_servers),
            field!(Proxy, force_be_switch),
            field!(Proxy, disabled_backends),
            field!(Proxy, routes),
            field!(Proxy, monitor),
            field!(Proxy, acls),
            field!(Proxy, stick_table),
            field!(Proxy, stick_rules),
            field!(Proxy, tcp_req_conn_rules),
            field!(Proxy, tcp_req_session_rules),
            field!(Proxy, tcp_req_content_rules),
            field!(Proxy, tcp_req_inspect_delay),
            field!(Proxy, tcp_res_content_rules),
            field!(Proxy, tcp_res_inspect_delay),
            field!(Proxy, http_req_rules),
            field!(Proxy, http_res_rules),
            field!(Proxy, http_after_res_rules),
            field!(Proxy, rules),
            field!(Proxy, log_target_idx),
            field!(Proxy, log_health_checks),
            field!(Proxy, http_reuse),
            field!(Proxy, abortonclose),
            field!(Proxy, h1_adjust),
            field!(Proxy, h1_case),
            field!(Proxy, h1_lower),
            field!(Proxy, error_files),
            field!(Proxy, error_replies),
            field!(Proxy, log_tag),
            field!(Proxy, log_format),
            field!(Proxy, extra_log),
            field!(Proxy, dont_log_null),
            field!(Proxy, ignore_probes),
            field!(Proxy, log_opts),
            field!(Proxy, unique_id_format),
            field!(Proxy, unique_id_header),
            field!(Proxy, req_capture_slots),
            field!(Proxy, res_capture_slots),
            field!(Proxy, log_count),
            field!(Proxy, log_cursors),
            field!(Proxy, hash_type),
            field!(Proxy, hash_preserve_affinity),
            field!(Proxy, chash),
            field!(Proxy, fwrr),
        ],
    );

    eprintln!("\n=== Auxiliary & Private-Field Sizes ===");
    eprintln!("StreamMap<(u32, H2StreamCtx)>: size={}, align={}", size_of::<StreamMap>(), align_of::<StreamMap>());
    eprintln!("StreamEntry<'_, H2StreamCtx, u32>: size={}, align={}", size_of::<StreamEntry<'_>>(), align_of::<StreamEntry<'_>>());
    eprintln!("(u32, H2StreamCtx): size={}, align={}", size_of::<(u32, H2StreamCtx)>(), align_of::<(u32, H2StreamCtx)>());
    eprintln!("alcyon_rt::proxy::ClientSide: size={}, align={}", size_of::<alcyon_rt::proxy::ClientSide>(), align_of::<alcyon_rt::proxy::ClientSide>());
    eprintln!("alcyon_proto::hpack::DecodedFields: size={}, align={}", size_of::<alcyon_proto::hpack::DecodedFields>(), align_of::<alcyon_proto::hpack::DecodedFields>());
    eprintln!("alcyon_rt::srv_set::ServerArrays: size={}, align={}", size_of::<ServerArrays>(), align_of::<ServerArrays>());
    eprintln!("alcyon_rt::srv_set::ServerIdArrays: size={}, align={}", size_of::<ServerIdArrays>(), align_of::<ServerIdArrays>());
    eprintln!("alcyon_rt::engine::RateCtr: size={}, align={}", size_of::<RateCtr>(), align_of::<RateCtr>());
    eprintln!("alcyon_rt::srv_rt::ServerAddrs: size={}, align={}", size_of::<ServerAddrs>(), align_of::<ServerAddrs>());
    eprintln!("alcyon_rt::srv_rt::ServerNames: size={}, align={}", size_of::<ServerNames>(), align_of::<ServerNames>());
    eprintln!("alcyon_rt::srv_rt::ServerWeights: size={}, align={}", size_of::<ServerWeights>(), align_of::<ServerWeights>());
    eprintln!("alcyon_rt::srv_rt::ServerMaxconns: size={}, align={}", size_of::<ServerMaxconns>(), align_of::<ServerMaxconns>());
    eprintln!("alcyon_rt::txnlog::StreamLog: size={}, align={}", size_of::<StreamLog>(), align_of::<StreamLog>());
    eprintln!("alcyon_sample::VarStore: size={}, align={}", size_of::<alcyon_sample::VarStore>(), align_of::<alcyon_sample::VarStore>());
    eprintln!("alcyon_rt::proxy::Timeouts: size={}, align={}", size_of::<alcyon_rt::proxy::Timeouts>(), align_of::<alcyon_rt::proxy::Timeouts>());
    eprintln!("alcyon_rt::buf::Buf: size={}, align={}", size_of::<Buf>(), align_of::<Buf>());
    eprintln!("alcyon_rt::proxy::ReqText: size={}, align={}", size_of::<ReqText>(), align_of::<ReqText>());
    eprintln!("alcyon_rt::txn::MsgState: size={}, align={}", size_of::<MsgState>(), align_of::<MsgState>());
    eprintln!("alcyon_rt::txn::LenHdrs: size={}, align={}", size_of::<LenHdrs>(), align_of::<LenHdrs>());
    eprintln!("alcyon_rt::cookie::CookieTxn: size={}, align={}", size_of::<alcyon_rt::cookie::CookieTxn>(), align_of::<alcyon_rt::cookie::CookieTxn>());
    eprintln!("alcyon_sample::Acls: size={}, align={}", size_of::<alcyon_sample::Acls>(), align_of::<alcyon_sample::Acls>());
    eprintln!("alcyon_config::StatsConfig: size={}, align={}", size_of::<alcyon_config::StatsConfig>(), align_of::<alcyon_config::StatsConfig>());
    eprintln!("ProxyIdInfo: size={}, align={}", size_of::<ProxyIdInfo>(), align_of::<ProxyIdInfo>());
}
