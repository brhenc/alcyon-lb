// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Tag and type tables for `show stat typed|json` and `show info typed|json`,
//! measured on HAProxy 3.5-dev8-885761-29 (see tasks/T245-progress.md).
//!
//! Where it is called: `applet.rs` `handle_show_stat` / `handle_show_info` pick a
//! [`StatFormat`]; `stats.rs` hands every row to [`emit_stat_row`] and the `show info`
//! pairs to [`render_info`].

use crate::stats::STAT_FIELDS;

/// The three renderings of `show stat`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatFormat {
    Csv,
    Typed,
    Json,
}

/// `(name, tags, type)` per `show stat` field: origin, nature, scope and persistence
/// letters as `typed` prints them. Backends differ for three fields (see `stat_tags`).
pub(crate) static STAT_TAGS: &[(&str, &str, &str)] = &[
    ("pxname", "KNSV", "str"),
    ("svname", "KNSV", "str"),
    ("scur", "MGPV", "u32"),
    ("smax", "MMPV", "u32"),
    ("slim", "CLPV", "u32"),
    ("stot", "MCPP", "u64"),
    ("bin", "MCPP", "u64"),
    ("bout", "MCPP", "u64"),
    ("dreq", "MCPP", "u64"),
    ("dresp", "MCPP", "u64"),
    ("ereq", "MCPP", "u64"),
    ("status", "SGPV", "str"),
    ("pid", "KGPV", "u32"),
    ("iid", "KGSV", "u32"),
    ("sid", "KGSV", "u32"),
    ("type", "CGSV", "u32"),
    ("rate", "MRPP", "u32"),
    ("rate_lim", "CLPV", "u32"),
    ("rate_max", "MMPV", "u32"),
    ("hrsp_1xx", "MCPP", "u64"),
    ("hrsp_2xx", "MCPP", "u64"),
    ("hrsp_3xx", "MCPP", "u64"),
    ("hrsp_4xx", "MCPP", "u64"),
    ("hrsp_5xx", "MCPP", "u64"),
    ("hrsp_other", "MCPP", "u64"),
    ("req_rate", "MRPP", "u32"),
    ("req_rate_max", "MMPV", "u32"),
    ("req_tot", "MCPP", "u64"),
    ("comp_in", "MCPP", "u64"),
    ("comp_out", "MCPP", "u64"),
    ("comp_byp", "MCPP", "u64"),
    ("comp_rsp", "MCPP", "u64"),
    ("mode", "CGSV", "str"),
    ("conn_rate", "MRPP", "u32"),
    ("conn_rate_max", "MMPV", "u32"),
    ("conn_tot", "MCPP", "u64"),
    ("intercepted", "MCPP", "u64"),
    ("dcon", "MCPP", "u64"),
    ("dses", "MCPP", "u64"),
    ("wrew", "MCPP", "u64"),
    ("cache_lookups", "MCPP", "u64"),
    ("cache_hits", "MCPP", "u64"),
    ("eint", "MCPP", "u64"),
    ("sess_other", "MCPV", "u64"),
    ("h1sess", "MCPP", "u64"),
    ("h2sess", "MCPP", "u64"),
    ("h3sess", "MCPP", "u64"),
    ("req_other", "MCPP", "u64"),
    ("h1req", "MCPP", "u64"),
    ("h2req", "MCPP", "u64"),
    ("h3req", "MCPP", "u64"),
    ("reqbin", "MCPP", "u64"),
    ("reqbout", "MCPP", "u64"),
    ("resbin", "MCPP", "u64"),
    ("resbout", "MCPP", "u64"),
    ("cache_hint_hits", "MCPP", "u64"),
    ("h2_headers_rcvd", "MCPV", "u64"),
    ("h2_data_rcvd", "MCPV", "u64"),
    ("h2_settings_rcvd", "MCPV", "u64"),
    ("h2_rst_stream_rcvd", "MCPV", "u64"),
    ("h2_goaway_rcvd", "MCPV", "u64"),
    ("h2_detected_conn_protocol_errors", "MCPV", "u64"),
    ("h2_detected_strm_protocol_errors", "MCPV", "u64"),
    ("h2_rst_stream_resp", "MCPV", "u64"),
    ("h2_goaway_resp", "MCPV", "u64"),
    ("h2_open_connections", "MGPV", "u64"),
    ("h2_backend_open_streams", "MGPV", "u64"),
    ("h2_total_connections", "MCPV", "u64"),
    ("h2_backend_total_streams", "MCPV", "u64"),
    ("ssl_sess", "MCPV", "u64"),
    ("ssl_reused_sess", "MCPV", "u64"),
    ("ssl_failed_handshake", "MCPV", "u64"),
    ("ssl_ocsp_staple", "MCPV", "u64"),
    ("ssl_failed_ocsp_staple", "MCPV", "u64"),
    ("h1_open_connections", "MGPV", "u64"),
    ("h1_open_streams", "MGPV", "u64"),
    ("h1_total_connections", "MCPV", "u64"),
    ("h1_total_streams", "MCPV", "u64"),
    ("h1_bytes_in", "MCPV", "u64"),
    ("h1_bytes_out", "MCPV", "u64"),
    ("h1_spliced_bytes_in", "MCPV", "u64"),
    ("h1_spliced_bytes_out", "MCPV", "u64"),
    ("addr", "CGSV", "str"),
    ("proto", "SGPV", "str"),
    ("qcur", "MGPV", "u32"),
    ("qmax", "MMPV", "u32"),
    ("econ", "MCPP", "u64"),
    ("eresp", "MCPP", "u64"),
    ("wretr", "MCPP", "u64"),
    ("wredis", "MCPP", "u64"),
    ("weight", "MaPV", "u32"),
    ("act", "SGPV", "u32"),
    ("bck", "SGPV", "u32"),
    ("chkfail", "MCPP", "u64"),
    ("chkdown", "MCPP", "u64"),
    ("lastchg", "MAPP", "u32"),
    ("downtime", "MCPV", "u32"),
    ("qlimit", "CGSV", "u32"),
    ("lbtot", "MCPP", "u64"),
    ("check_status", "MOPV", "str"),
    ("check_duration", "MDPV", "u64"),
    ("cli_abrt", "MCPP", "u64"),
    ("srv_abrt", "MCPP", "u64"),
    ("lastsess", "MAPP", "s32"),
    ("last_chk", "MOPV", "str"),
    ("qtime", "MaPV", "u32"),
    ("ctime", "MaPV", "u32"),
    ("rtime", "MaPV", "u32"),
    ("ttime", "MaPV", "u32"),
    ("check_desc", "MOPV", "str"),
    ("check_rise", "CGSV", "u32"),
    ("check_fall", "CGSV", "u32"),
    ("check_health", "CGSV", "u32"),
    ("cookie", "CNSV", "str"),
    ("connect", "MCPP", "u64"),
    ("reuse", "MCPP", "u64"),
    ("srv_icur", "MGPV", "u32"),
    ("qtime_max", "MMPV", "u32"),
    ("ctime_max", "MMPV", "u32"),
    ("rtime_max", "MMPV", "u32"),
    ("ttime_max", "MMPV", "u32"),
    ("idle_conn_cur", "MGPV", "u32"),
    ("safe_conn_cur", "MGPV", "u32"),
    ("used_conn_cur", "MGPV", "u32"),
    ("need_conn_est", "MGPV", "u32"),
    ("uweight", "MaPV", "u32"),
    ("srid", "MCPV", "u32"),
    ("priv_idle_cur", "MGPV", "u32"),
    ("check_code", "MOPV", "u32"),
    ("tracked", "CNSV", "str"),
    ("algo", "CGSV", "str"),
    ("agg_server_status", "MGPV", "u32"),
    ("agg_server_check_status", "MGPV", "u32"),
    ("agg_check_status", "MGPV", "u32"),
];

/// `(pos, name, tags, type)` per `show info` field.
pub(crate) static INFO_TAGS: &[(u32, &str, &str, &str)] = &[
    (0, "Name", "POSV", "str"),
    (1, "Version", "POSV", "str"),
    (2, "Release_date", "POSV", "str"),
    (3, "Nbthread", "CGSV", "u32"),
    (4, "Nbproc", "CGSV", "u32"),
    (5, "Process_num", "KGPV", "u32"),
    (6, "Pid", "SGPV", "u32"),
    (7, "Uptime", "MDPV", "str"),
    (8, "Uptime_sec", "MDPV", "u32"),
    (9, "Memmax_MB", "CLPV", "u32"),
    (10, "PoolAlloc_MB", "MGPV", "u32"),
    (11, "PoolUsed_MB", "MGPV", "u32"),
    (12, "PoolFailed", "MCPV", "u32"),
    (13, "Ulimit-n", "CLPV", "u32"),
    (14, "Maxsock", "CLPV", "u32"),
    (15, "Maxconn", "CLPV", "u32"),
    (16, "Hard_maxconn", "CLPV", "u32"),
    (17, "CurrConns", "MGPV", "u32"),
    (18, "CumConns", "MCPV", "u32"),
    (19, "CumReq", "MCPV", "u32"),
    (20, "MaxSslConns", "MMPV", "u32"),
    (21, "CurrSslConns", "MGPV", "u32"),
    (22, "CumSslConns", "MCPV", "u32"),
    (23, "Maxpipes", "CLPV", "u32"),
    (24, "PipesUsed", "MGPV", "u32"),
    (25, "PipesFree", "MGPV", "u32"),
    (26, "ConnRate", "MRPV", "u32"),
    (27, "ConnRateLimit", "CLPV", "u32"),
    (28, "MaxConnRate", "MMPV", "u32"),
    (29, "SessRate", "MRPV", "u32"),
    (30, "SessRateLimit", "CLPV", "u32"),
    (31, "MaxSessRate", "MRPV", "u32"),
    (32, "SslRate", "MRPV", "u32"),
    (33, "SslRateLimit", "CLPV", "u32"),
    (34, "MaxSslRate", "MMPV", "u32"),
    (35, "SslFrontendKeyRate", "MGPV", "u32"),
    (36, "SslFrontendMaxKeyRate", "MMPV", "u32"),
    (37, "SslFrontendSessionReuse_pct", "MGPV", "u32"),
    (38, "SslBackendKeyRate", "MRPV", "u32"),
    (39, "SslBackendMaxKeyRate", "MMPV", "u32"),
    (40, "SslCacheLookups", "MCPV", "u32"),
    (41, "SslCacheMisses", "MCPV", "u32"),
    (42, "CompressBpsIn", "MRPV", "u32"),
    (43, "CompressBpsOut", "MRPV", "u32"),
    (44, "CompressBpsRateLim", "CLPV", "u32"),
    (45, "ZlibMemUsage", "MGPV", "u32"),
    (46, "MaxZlibMemUsage", "CLPV", "u32"),
    (47, "Tasks", "MGPV", "u32"),
    (48, "Run_queue", "MGPV", "u32"),
    (49, "Idle_pct", "MaPV", "u32"),
    (50, "node", "COSV", "str"),
    (51, "description", "COSV", "str"),
    (52, "Stopping", "MGPV", "u32"),
    (53, "Jobs", "MGPV", "u32"),
    (54, "Unstoppable Jobs", "MGPV", "u32"),
    (55, "Listeners", "MGPV", "u32"),
    (56, "ActivePeers", "MGPV", "u32"),
    (57, "ConnectedPeers", "MGPV", "u32"),
    (58, "DroppedLogs", "MGPV", "u32"),
    (59, "BusyPolling", "MGPV", "u32"),
    (60, "FailedResolutions", "MGPV", "u32"),
    (61, "TotalBytesOut", "MGPV", "u64"),
    (62, "TotalSplicedBytesOut", "MGPV", "u64"),
    (63, "BytesOutRate", "MRPV", "u64"),
    (64, "DebugCommandsIssued", "MGPV", "u32"),
    (65, "CumRecvLogs", "MCPV", "u32"),
    (66, "Build info", "POSV", "str"),
    (67, "Memmax_bytes", "CLPV", "u32"),
    (68, "PoolAlloc_bytes", "MGPV", "u64"),
    (69, "PoolUsed_bytes", "MGPV", "u64"),
    (70, "Start_time_sec", "MDPV", "u32"),
    (71, "Tainted", "SGPV", "str"),
    (72, "TotalWarnings", "MCPV", "u32"),
    (73, "MaxconnReached", "MCPV", "u32"),
    (74, "BootTime_ms", "MDPV", "u32"),
    (75, "Niced_tasks", "MGPV", "u32"),
    (76, "CurrStreams", "MGPV", "u64"),
    (77, "CumStreams", "MGPV", "u64"),
    (78, "BlockedTrafficWarnings", "MGPV", "u32"),
    (79, "PatternsAdded", "MGPV", "u64"),
    (80, "PatternsFreed", "MGPV", "u64"),
    (81, "NbThreadGroups", "CGSV", "u32"),
    (82, "Master_id", "COSV", "str"),
    (83, "Worker_id", "COSV", "str"),
];

/// Tags and type of a `show stat` field of an object (`F`, `B`, `S`). HAProxy tags three
/// fields differently on a backend.
fn stat_tags(obj: char, name: &str) -> Option<(String, &'static str)> {
    let (_, tags, ty) = STAT_TAGS.iter().find(|(n, _, _)| *n == name)?;
    let mut tags = (*tags).to_string();
    if obj == 'B' && matches!(name, "rate_max" | "act" | "bck") {
        tags = format!("MG{}", &tags[2..]);
    }
    Some((tags, ty))
}

fn origin_name(c: u8) -> &'static str {
    match c {
        b'M' => "Metric",
        b'S' => "Status",
        b'K' => "Key",
        b'C' => "Config",
        _ => "Product",
    }
}

fn nature_name(c: u8) -> &'static str {
    match c {
        b'G' => "Gauge",
        b'L' => "Limit",
        b'M' => "Max",
        b'R' => "Rate",
        b'C' => "Counter",
        b'D' => "Duration",
        b'A' => "Age",
        b'N' => "Name",
        b'O' => "Output",
        _ => "Avg",
    }
}

fn scope_name(c: u8) -> &'static str {
    match c {
        // Every tag in `STAT_TAGS` / `INFO_TAGS` is Process or Service
        // (`every_tag_letter_is_named`).
        b'P' => "Process",
        _ => "Service",
    }
}

fn json_escape(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `"tags":{...},"value":{...}` of one field.
fn json_tags_value(out: &mut String, tags: &str, ty: &str, value: &str) {
    let t = tags.as_bytes();
    out.push_str(&format!(
        "\"tags\":{{\"origin\":\"{}\",\"nature\":\"{}\",\"scope\":\"{}\"}},\"value\":{{\"type\":\"{ty}\",\"value\":",
        origin_name(t[0]),
        nature_name(t[1]),
        scope_name(t[2])
    ));
    if ty == "str" {
        json_escape(out, value);
    } else {
        out.push_str(value);
    }
    out.push_str("}}");
}

/// Appends one `show stat` row as `typed` lines or as one JSON array. `fields` is the CSV
/// row in `STAT_FIELDS` order; an empty column is left out, as HAProxy leaves out a field
/// that does not apply to the object.
pub(crate) fn emit_stat_row(out: &mut String, fields: &[String], fmt: StatFormat) {
    let col = |name: &str| STAT_FIELDS.iter().position(|f| *f == name).and_then(|i| fields.get(i)).map_or("", String::as_str);
    // `stats.rs` writes frontend (0), backend (1) and server (2) rows; Alcyon has no
    // listener rows (`option socket-stats`, type 3).
    let (obj, obj_name) = match col("type") {
        "0" => ('F', "Frontend"),
        "2" => ('S', "Server"),
        _ => ('B', "Backend"),
    };
    let (iid, sid) = (col("iid"), col("sid"));
    let mut first = true;
    if fmt == StatFormat::Json {
        if !out.is_empty() {
            out.push(',');
        }
        out.push('[');
    }
    for (i, name) in STAT_FIELDS.iter().enumerate() {
        let value = fields.get(i).map_or("", String::as_str);
        if value.is_empty() || *name == "-" {
            continue;
        }
        let Some((tags, ty)) = stat_tags(obj, name) else { continue };
        // The `-` separator after column 118 is not a field: later ones shift down by one.
        let pos = if i > 119 { i - 1 } else { i };
        if fmt == StatFormat::Typed {
            out.push_str(&format!("{obj}.{iid}.{sid}.{pos}.{name}.1:{tags}:{ty}:{value}\n"));
        } else {
            if !first {
                out.push(',');
            }
            first = false;
            out.push_str(&format!(
                "{{\"objType\":\"{obj_name}\",\"proxyId\":{iid},\"id\":{sid},\"field\":{{\"pos\":{pos},\"name\":\"{name}\"}},\"processNum\":1,"
            ));
            json_tags_value(out, &tags, ty, value);
        }
    }
    if fmt == StatFormat::Json {
        out.push(']');
    }
}

/// `show info`, from its `(name, value)` pairs in HAProxy's order.
pub(crate) fn render_info(pairs: &[(&str, String)], fmt: StatFormat) -> String {
    let mut out = String::new();
    if fmt == StatFormat::Json {
        out.push('[');
    }
    let mut first = true;
    for (name, value) in pairs {
        match fmt {
            StatFormat::Csv => out.push_str(&format!("{name}: {value}\n")),
            StatFormat::Typed | StatFormat::Json => {
                let Some((pos, _, tags, ty)) = INFO_TAGS.iter().find(|(_, n, _, _)| n == name) else { continue };
                if fmt == StatFormat::Typed {
                    out.push_str(&format!("{pos}.{name}.1:{tags}:{ty}:{value}\n"));
                } else {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    out.push_str(&format!("{{\"field\":{{\"pos\":{pos},\"name\":\"{name}\"}},\"processNum\":1,"));
                    json_tags_value(&mut out, tags, ty, value);
                }
            }
        }
    }
    if fmt == StatFormat::Json {
        out.push_str("]\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every column `stats.rs` sets by name has tags: a row would otherwise lose it silently.
    #[test]
    fn every_column_stats_rs_sets_has_tags() {
        let src = include_str!("stats.rs");
        for chunk in src.split("r.set(\"").skip(1) {
            let name = chunk.split('"').next().unwrap();
            assert!(STAT_TAGS.iter().any(|(n, _, _)| *n == name), "{name} has no entry in STAT_TAGS");
        }
    }

    /// `nature_name` and `scope_name` name only the letters the tables use; a new letter
    /// must be added to them, not printed as the default.
    #[test]
    fn every_tag_letter_is_named() {
        let tags = STAT_TAGS.iter().map(|(_, t, _)| *t).chain(INFO_TAGS.iter().map(|(_, _, t, _)| *t));
        for t in tags {
            let b = t.as_bytes();
            assert!(b"GLMRCDANOa".contains(&b[1]), "nature of {t}");
            assert!(b"PS".contains(&b[2]), "scope of {t}");
        }
    }

    /// No field Alcyon prints can hold these characters today (proxy and server names are
    /// checked at load); a string value is still escaped as JSON (RFC 8259) would have it.
    #[test]
    fn a_json_string_value_is_escaped() {
        let mut out = String::new();
        json_escape(&mut out, "q\"b\\c\nd\re\tf\u{1}g");
        assert_eq!(out, r#""q\"b\\c\nd\re\tf\u0001g""#);
    }

    #[test]
    fn backend_tags_differ_for_three_fields() {
        assert_eq!(stat_tags('B', "act").unwrap().0, "MGPV");
        assert_eq!(stat_tags('S', "act").unwrap().0, "SGPV");
    }
}
