// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Modern Single-Page Web Stats Dashboard & Web Admin UI for Ibex.

#![allow(clippy::too_many_lines, clippy::format_push_string)]

use crate::check::{ServerCheckState, ServerStatus};
use crate::engine::Proxy;
use std::fmt::Write;

/// Formats a byte count into a human-readable string (B, KB, MB, GB).
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        let whole = bytes / GB;
        let frac = ((bytes % GB) * 100) / GB;
        format!("{whole}.{frac:02} GB")
    } else if bytes >= MB {
        let whole = bytes / MB;
        let frac = ((bytes % MB) * 100) / MB;
        format!("{whole}.{frac:02} MB")
    } else if bytes >= KB {
        let whole = bytes / KB;
        let frac = ((bytes % KB) * 100) / KB;
        format!("{whole}.{frac:02} KB")
    } else {
        format!("{bytes} B")
    }
}

/// Renders the complete, modern single-page HTML stats and administration dashboard.
#[must_use]
pub fn render_stats_html(proxies: &[Proxy], checks: &[ServerCheckState], pid: u32) -> String {
    render_stats_html_for(proxies, checks, pid, &ibex_config::StatsConfig::default())
}

/// A proxy's `description` for the page, unescaped as HAProxy prints it (`px->desc`).
fn proxy_desc(proxy: &Proxy) -> String {
    proxy.desc.as_deref().map_or(String::new(), |d| format!(r#"<div class="desc">{d}</div>"#))
}

/// [`render_stats_html`] for the page served by the proxy whose `stats` section is
/// `serving`: its `show-node` and `show-desc` go in the title and the report heading
/// ("Statistics Report for pid N on <node>: <desc>", the description unescaped, as
/// HAProxy prints it).
#[must_use]
pub fn render_stats_html_for(
    proxies: &[Proxy],
    checks: &[ServerCheckState],
    pid: u32,
    serving: &ibex_config::StatsConfig,
) -> String {
    let node = serving
        .show_node
        .as_deref()
        .map(|n| if n.is_empty() { crate::stats::node_name() } else { n.to_string() })
        .filter(|n| !n.is_empty());
    let on_node = node.as_deref().map_or(String::new(), |n| format!(" on {n}"));
    // `stats show-desc` without text shows `global description` (`uri->desc ? uri->desc : global.desc`).
    let desc = serving
        .show_desc
        .as_deref()
        .map(|d| if d.is_empty() { crate::stats::description().unwrap_or_default() } else { d.to_string() })
        .map_or(String::new(), |d| format!(": {d}"));
    // `stats show-version` names the build next to the title; the default hides it.
    let version = if serving.show_version() { format!(" version {}", crate::version::VERSION) } else { String::new() };
    let heading = format!("Statistics Report for pid {pid}{on_node}{desc}");
    let mut out = String::with_capacity(32768);

    // Calculate aggregated metrics
    let total_act_conn: u32 = proxies.iter().map(|p| p.stats.iter().map(|s| s.act_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u32>()).sum();
    let total_cum_conn: u64 = proxies.iter().map(|p| p.stats.iter().map(|s| s.cum_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()).sum();
    let total_bytes_in: u64 = proxies.iter().map(|p| p.stats.iter().map(|s| s.bytes_in.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()).sum();
    let total_bytes_out: u64 = proxies.iter().map(|p| p.stats.iter().map(|s| s.bytes_out.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()).sum();

    let mut total_servers = 0;
    let mut total_up = 0;
    let mut total_down = 0;
    let mut total_drain = 0;
    let mut total_maint = 0;

    for proxy in proxies {
        for status_atomic in proxy.server_statuses.iter() { let status = ServerStatus::from(status_atomic.load(std::sync::atomic::Ordering::Relaxed));
            total_servers += 1;
            match status {
                ServerStatus::Up => total_up += 1,
                ServerStatus::Down => total_down += 1,
                ServerStatus::Drain => total_drain += 1,
                ServerStatus::Maint => total_maint += 1,
            }
        }
    }

    let _ = write!(
        out,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ibex Runtime - Stats &amp; Web Admin{on_node}</title>
<style>
:root {{
  --bg-page: #0b0f19;
  --bg-card: #131b2e;
  --bg-card-alt: #17223b;
  --bg-table-header: #1b2640;
  --border-color: #24324f;
  --text-primary: #f8fafc;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  --emerald-bg: rgba(16, 185, 129, 0.15);
  --emerald-text: #34d399;
  --emerald-border: #059669;
  --red-bg: rgba(239, 68, 68, 0.15);
  --red-text: #f87171;
  --red-border: #dc2626;
  --orange-bg: rgba(249, 115, 22, 0.15);
  --orange-text: #fb923c;
  --orange-border: #ea580c;
  --purple-bg: rgba(168, 85, 247, 0.15);
  --purple-text: #c084fc;
  --purple-border: #9333ea;
  --blue-bg: rgba(59, 130, 246, 0.15);
  --blue-text: #60a5fa;
  --blue-border: #2563eb;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg-page);
  color: var(--text-primary);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
  padding: 24px;
  line-height: 1.5;
}}
.container {{ max-width: 1520px; margin: 0 auto; }}
header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
  padding-bottom: 20px;
  margin-bottom: 24px;
  border-bottom: 1px solid var(--border-color);
}}
.brand {{ display: flex; align-items: center; gap: 12px; }}
.brand h1 {{ font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }}
.report-title {{ font-size: 13px; font-weight: 400; margin: 0; color: var(--text-muted); }}
.tag {{
  background: #1e293b;
  color: #38bdf8;
  padding: 3px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  border: 1px solid #334155;
}}
.toolbar {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
.toolbar-item {{ display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text-secondary); }}
.select-refresh {{
  background: var(--bg-card);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  padding: 6px 10px;
  border-radius: 6px;
  font-size: 13px;
}}
.btn {{
  background: var(--bg-card);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  transition: all 0.15s ease;
}}
.btn:hover {{ background: var(--bg-card-alt); border-color: #3b82f6; }}
.btn-csv {{ color: #38bdf8; border-color: #0284c7; }}
.btn-csv:hover {{ background: rgba(56, 189, 248, 0.1); }}
.pulse {{
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #10b981;
  box-shadow: 0 0 8px #10b981;
}}
.cards-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 32px;
}}
.card {{
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px 20px;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
}}
.card-label {{ font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 6px; letter-spacing: 0.5px; }}
.card-val {{ font-size: 26px; font-weight: 700; color: var(--text-primary); font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
.card-sub {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}
.section {{ margin-bottom: 36px; }}
.section-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 14px;
}}
.section-title {{ font-size: 17px; font-weight: 600; display: flex; align-items: center; gap: 8px; }}
.table-wrapper {{
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow-x: auto;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
}}
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  text-align: left;
}}
th {{
  background: var(--bg-table-header);
  color: var(--text-secondary);
  font-weight: 600;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-color);
  white-space: nowrap;
}}
td {{
  padding: 10px 14px;
  border-bottom: 1px solid rgba(36, 50, 79, 0.5);
  white-space: nowrap;
}}
tr:last-child td {{ border-bottom: none; }}
tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
.badge {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}}
.badge-up {{ background: var(--emerald-bg); color: var(--emerald-text); border: 1px solid var(--emerald-border); }}
.badge-down {{ background: var(--red-bg); color: var(--red-text); border: 1px solid var(--red-border); }}
.badge-drain {{ background: var(--orange-bg); color: var(--orange-text); border: 1px solid var(--orange-border); }}
.badge-maint {{ background: var(--purple-bg); color: var(--purple-text); border: 1px solid var(--purple-border); }}
.badge-backup {{ background: var(--blue-bg); color: var(--blue-text); border: 1px solid var(--blue-border); }}
.actions-cell {{ display: flex; align-items: center; gap: 6px; }}
.admin-form {{ display: inline-flex; margin: 0; }}
.btn-xs {{
  padding: 3px 8px;
  font-size: 11px;
  border-radius: 4px;
  font-weight: 600;
}}
.btn-ready {{ color: var(--emerald-text); border-color: var(--emerald-border); }}
.btn-ready:hover {{ background: var(--emerald-bg); }}
.btn-drain {{ color: var(--orange-text); border-color: var(--orange-border); }}
.btn-drain:hover {{ background: var(--orange-bg); }}
.btn-maint {{ color: var(--purple-text); border-color: var(--purple-border); }}
.btn-maint:hover {{ background: var(--purple-bg); }}
.btn-kill {{ color: #f87171; border-color: #dc2626; }}
.btn-kill:hover {{ background: rgba(239, 68, 68, 0.2); }}
.btn-pause {{ color: #fb923c; border-color: #ea580c; }}
.btn-pause:hover {{ background: rgba(249, 115, 22, 0.2); }}
.btn-resume {{ color: #34d399; border-color: #059669; }}
.btn-resume:hover {{ background: rgba(16, 185, 129, 0.2); }}
.weight-form {{ display: inline-flex; align-items: center; gap: 4px; }}
.weight-input {{
  width: 54px;
  background: var(--bg-page);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  padding: 3px 6px;
  border-radius: 4px;
  font-size: 12px;
  font-family: ui-monospace, monospace;
}}
.maxconn-input {{
  width: 58px;
  background: var(--bg-page);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  padding: 3px 6px;
  border-radius: 4px;
  font-size: 12px;
  font-family: ui-monospace, monospace;
}}
.toast {{
  position: fixed;
  bottom: 24px;
  right: 24px;
  background: #1e293b;
  color: #f8fafc;
  padding: 12px 20px;
  border-radius: 6px;
  border: 1px solid #3b82f6;
  box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
  font-size: 14px;
  display: none;
  z-index: 1000;
}}
.empty-card {{
  padding: 24px;
  text-align: center;
  color: var(--text-muted);
  font-size: 14px;
}}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <h1>IBEX{version}</h1>
      <span class="tag">Load Balancer &amp; Runtime</span>
      <span class="tag mono">PID: {pid}</span>
    </div>
    <h2 class="report-title">{heading}</h2>
    <div class="toolbar">
      <div class="toolbar-item">
        <span class="pulse" id="live-indicator"></span>
        <span id="refresh-status">Auto-refresh: 2s</span>
      </div>
      <div class="toolbar-item">
        <label for="refresh-select">Interval:</label>
        <select id="refresh-select" class="select-refresh">
          <option value="1000">1s</option>
          <option value="2000" selected>2s</option>
          <option value="5000">5s</option>
          <option value="10000">10s</option>
          <option value="0">Off</option>
        </select>
      </div>
      <button class="btn" id="btn-manual-refresh">Refresh Now</button>
      <form class="admin-form" method="POST" action="" style="display:inline;" onsubmit="return confirm('Clear all traffic and error statistics counters?');">
        <input type="hidden" name="action" value="clear_counters">
        <button type="submit" class="btn btn-kill" id="btn-clear-counters" title="Clear accumulated traffic &amp; error counters">Clear Counters</button>
      </form>
      <a href=";csv" class="btn btn-csv" id="btn-csv-link">Export CSV</a>
    </div>
  </header>

  <!-- Live Metrics Summary Cards -->
  <div class="cards-grid">
    <div class="card">
      <div class="card-label">Active Connections</div>
      <div class="card-val" id="metric-act-conn">{total_act_conn}</div>
      <div class="card-sub">Current concurrent connections</div>
    </div>
    <div class="card">
      <div class="card-label">Total Connections</div>
      <div class="card-val" id="metric-cum-conn">{total_cum_conn}</div>
      <div class="card-sub">Cumulative accepted sessions</div>
    </div>
    <div class="card">
      <div class="card-label">Traffic In / Out</div>
      <div class="card-val" style="font-size: 18px;" id="metric-traffic">
        <span id="metric-bytes-in">{}</span> &darr; / <span id="metric-bytes-out">{}</span> &uarr;
      </div>
      <div class="card-sub">Total throughput handled</div>
    </div>
    <div class="card">
      <div class="card-label">Backend Health</div>
      <div class="card-val" style="font-size: 20px;" id="metric-health">
        <span style="color: #34d399;" id="count-up">{total_up} UP</span> &bull; 
        <span style="color: #f87171;" id="count-down">{total_down} DOWN</span>
      </div>
      <div class="card-sub"><span id="count-drain">{total_drain} DRAIN</span> &bull; <span id="count-maint">{total_maint} MAINT</span> &bull; Total: {total_servers}</div>
    </div>
  </div>
"#,
        format_bytes(total_bytes_in),
        format_bytes(total_bytes_out)
    );

    // 1. Group: Frontends
    out.push_str(
        r#"  <!-- Frontend Section -->
  <div class="section">
    <div class="section-header">
      <h2 class="section-title">Frontends</h2>
    </div>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Mode</th>
            <th>Bind Address</th>
            <th>Status</th>
            <th>Active Conns</th>
            <th>Max Conns</th>
            <th>Total Conns</th>
            <th>Bytes In</th>
            <th>Bytes Out</th>
          </tr>
        </thead>
        <tbody id="frontend-tbody">
"#,
    );

    let mut frontend_count = 0;
    for proxy in proxies {
        if proxy.addr.port() > 0
            || proxy.default_backend.is_some()
            || !proxy.use_backends.is_empty()
        {
            frontend_count += 1;
            let _ = write!(
                out,
                r#"          <tr id="fe-row-{name}">
            <td><strong>{name}</strong>{desc}</td>
            <td><span class="tag">{mode:?}</span></td>
            <td class="mono">{addr}</td>
            <td><span class="badge badge-up">OPEN</span></td>
            <td class="mono fe-act-conn">{act_conn}</td>
            <td>
              <form class="admin-form maxconn-form" method="POST" action="" style="display:inline-flex; align-items:center; gap:4px;">
                <input type="hidden" name="action" value="maxconn">
                <input type="hidden" name="backend" value="{name}">
                <input type="number" name="maxconn" min="0" max="1000000" value="{maxconn}" class="maxconn-input" id="maxconn-fe-{name}">
                <button type="submit" class="btn btn-xs">Set</button>
              </form>
            </td>
            <td class="mono fe-cum-conn">{cum_conn}</td>
            <td class="mono fe-bytes-in">{bytes_in}</td>
            <td class="mono fe-bytes-out">{bytes_out}</td>
          </tr>
"#,
                name = proxy.name,
                desc = proxy_desc(proxy),
                mode = proxy.mode,
                addr = proxy.addr,
                act_conn = proxy.stats.iter().map(|s| s.act_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u32>(),
                maxconn = proxy.maxconn,
                cum_conn = proxy.stats.iter().map(|s| s.cum_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>(),
                bytes_in = format_bytes(proxy.stats.iter().map(|s| s.bytes_in.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()),
                bytes_out = format_bytes(proxy.stats.iter().map(|s| s.bytes_out.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()),
            );
        }
    }

    if frontend_count == 0 {
        out.push_str(r#"          <tr><td colspan="9" class="empty-card">No frontends configured.</td></tr>"#);
    }

    out.push_str(
        r"        </tbody>
      </table>
    </div>
  </div>
",
    );

    // 2. Group: Backends
    out.push_str(
        r#"  <!-- Backend Section -->
  <div class="section">
    <div class="section-header">
      <h2 class="section-title">Backends &amp; Servers</h2>
    </div>
"#,
    );

    let mut backend_count = 0;
    for (p_idx, proxy) in proxies.iter().enumerate() {
        if proxy.servers.is_empty() {
            continue;
        }
        backend_count += 1;
        let _ = write!(
            out,
            r#"    <div class="table-wrapper" style="margin-bottom: 20px;">
      <div style="padding: 12px 16px; background: var(--bg-table-header); border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="font-weight: 700; font-size: 15px;">Backend: {name}</span>
          <span class="tag">{mode:?}</span>
          <span class="tag">{algo:?}</span>{desc}
          <form class="admin-form kill-form" method="POST" action="" style="display:inline;" onsubmit="return confirm('Terminate all active sessions on backend {name}?');">
            <input type="hidden" name="action" value="shutdown_sessions">
            <input type="hidden" name="backend" value="{name}">
            <button type="submit" class="btn btn-xs btn-kill" title="Terminate all active sessions on this backend">Kill Sessions</button>
          </form>
        </div>
        <div style="font-size: 12px; color: var(--text-secondary);" class="mono">
          Active: <span id="be-act-{name}">{act_conn}</span> &bull; 
          Total: <span id="be-cum-{name}">{cum_conn}</span> &bull; 
          In: <span id="be-bin-{name}">{bytes_in}</span> &bull; 
          Out: <span id="be-bout-{name}">{bytes_out}</span>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Server</th>
            <th>Address</th>
            <th>Role</th>
            <th>Status</th>
            <th>Weight</th>
            <th>Maxconn</th>
            <th>Active Conns</th>
            <th>Health Check</th>
            <th>Administration Actions</th>
          </tr>
        </thead>
        <tbody>
"#,
            name = proxy.name,
            desc = proxy_desc(proxy),
            mode = proxy.mode,
            algo = proxy.balance,
            act_conn = proxy.stats.iter().map(|s| s.act_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u32>(),
            cum_conn = proxy.stats.iter().map(|s| s.cum_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>(),
            bytes_in = format_bytes(proxy.stats.iter().map(|s| s.bytes_in.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()),
            bytes_out = format_bytes(proxy.stats.iter().map(|s| s.bytes_out.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()),
        );

        for (s_idx, srv_addr) in proxy.servers.iter().enumerate() {
            let srv_id = proxy.server_ids.get(s_idx).map_or("srv", String::as_str);
            let srv_status = proxy
                .server_statuses.get(s_idx).map(|s| ServerStatus::from(s.load(std::sync::atomic::Ordering::Relaxed))).unwrap_or(ServerStatus::Up);
            let is_backup = proxy.server_backups.get(s_idx).copied().unwrap_or(false);
            let weight = proxy.server_weights.get(s_idx).unwrap_or(1);
            let srv_maxconn = proxy.server_maxconn.get(s_idx).unwrap_or(0);
            let actconn = proxy.server_actconn.get(s_idx).map(|a| a.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(0);

            let check_state = checks
                .iter()
                .find(|c| c.proxy() == p_idx && c.server() == s_idx);

            let (check_info, health_toggle) = if let Some(c) = check_state {
                let info = if !c.enabled {
                    "PAUSED".to_string()
                } else if c.status == ServerStatus::Up {
                    format!("{}ms (pass {})", c.check_duration_ms, c.rise_count)
                } else {
                    format!("FAIL (fails {})", c.fall_count)
                };
                let toggle = if c.enabled {
                    format!(
                        r#"<form class="admin-form" method="POST" action="" style="display:inline; margin-left: 6px;">
                          <input type="hidden" name="action" value="disable_health">
                          <input type="hidden" name="backend" value="{px}">
                          <input type="hidden" name="server" value="{sv}">
                          <button type="submit" class="btn btn-xs btn-pause" title="Pause active health check">Pause</button>
                        </form>"#,
                        px = proxy.name,
                        sv = srv_id,
                    )
                } else {
                    format!(
                        r#"<form class="admin-form" method="POST" action="" style="display:inline; margin-left: 6px;">
                          <input type="hidden" name="action" value="enable_health">
                          <input type="hidden" name="backend" value="{px}">
                          <input type="hidden" name="server" value="{sv}">
                          <button type="submit" class="btn btn-xs btn-resume" title="Resume active health check">Resume</button>
                        </form>"#,
                        px = proxy.name,
                        sv = srv_id,
                    )
                };
                (info, toggle)
            } else {
                ("no check".to_string(), String::new())
            };

            let badge_class = match srv_status {
                ServerStatus::Up => "badge-up",
                ServerStatus::Down => "badge-down",
                ServerStatus::Drain => "badge-drain",
                ServerStatus::Maint => "badge-maint",
            };

            let _ = write!(
                out,
                r#"          <tr id="srv-row-{px}-{sv}">
            <td><strong>{sv}</strong></td>
            <td class="mono">{addr}</td>
            <td>{role}</td>
            <td><span class="badge {badge_class}" id="badge-{px}-{sv}">{status_str}</span></td>
            <td>
              <form class="admin-form weight-form" method="POST" action="">
                <input type="hidden" name="action" value="weight">
                <input type="hidden" name="backend" value="{px}">
                <input type="hidden" name="server" value="{sv}">
                <input type="number" name="weight" min="0" max="256" value="{weight}" class="weight-input" id="weight-input-{px}-{sv}">
                <button type="submit" class="btn btn-xs">Set</button>
              </form>
            </td>
            <td>
              <form class="admin-form maxconn-form" method="POST" action="">
                <input type="hidden" name="action" value="maxconn">
                <input type="hidden" name="backend" value="{px}">
                <input type="hidden" name="server" value="{sv}">
                <input type="number" name="maxconn" min="0" max="1000000" value="{srv_maxconn}" class="maxconn-input" id="maxconn-input-{px}-{sv}">
                <button type="submit" class="btn btn-xs">Set</button>
              </form>
            </td>
            <td class="mono" id="srv-actconn-{px}-{sv}">{actconn}</td>
            <td class="mono" id="srv-check-{px}-{sv}">
              <span>{check_info}</span>
              {health_toggle}
            </td>
            <td>
              <div class="actions-cell">
                <form class="admin-form" method="POST" action="">
                  <input type="hidden" name="action" value="ready">
                  <input type="hidden" name="backend" value="{px}">
                  <input type="hidden" name="server" value="{sv}">
                  <button type="submit" class="btn btn-xs btn-ready">READY</button>
                </form>
                <form class="admin-form" method="POST" action="">
                  <input type="hidden" name="action" value="drain">
                  <input type="hidden" name="backend" value="{px}">
                  <input type="hidden" name="server" value="{sv}">
                  <button type="submit" class="btn btn-xs btn-drain">DRAIN</button>
                </form>
                <form class="admin-form" method="POST" action="">
                  <input type="hidden" name="action" value="maint">
                  <input type="hidden" name="backend" value="{px}">
                  <input type="hidden" name="server" value="{sv}">
                  <button type="submit" class="btn btn-xs btn-maint">MAINT</button>
                </form>
                <form class="admin-form kill-form" method="POST" action="" onsubmit="return confirm('Terminate all active sessions on server {sv}?');">
                  <input type="hidden" name="action" value="kill_sessions">
                  <input type="hidden" name="backend" value="{px}">
                  <input type="hidden" name="server" value="{sv}">
                  <button type="submit" class="btn btn-xs btn-kill" title="Kill all active sessions on this server">KILL</button>
                </form>
              </div>
            </td>
          </tr>
"#,
                px = proxy.name,
                sv = srv_id,
                addr = srv_addr,
                role = if is_backup {
                    r#"<span class="badge badge-backup">BACKUP</span>"#
                } else {
                    "Active"
                },
                badge_class = badge_class,
                status_str = srv_status.as_str(),
                weight = weight,
                srv_maxconn = srv_maxconn,
                actconn = actconn,
                check_info = check_info,
                health_toggle = health_toggle,
            );
        }

        out.push_str(
            r"        </tbody>
      </table>
    </div>
",
        );
    }

    if backend_count == 0 {
        out.push_str(
            r#"    <div class="table-wrapper empty-card">No backends or servers configured.</div>"#,
        );
    }
    out.push_str("  </div>\n");

    // 3. Group: Stick Tables
    out.push_str(
        r#"  <!-- Stick Tables Section -->
  <div class="section">
    <div class="section-header">
      <h2 class="section-title">Stick Tables</h2>
    </div>
"#,
    );

    let mut stick_table_count = 0;
    for proxy in proxies {
        if let Some(ref tbl) = proxy.stick_table {
            stick_table_count += 1;
            let cfg = tbl.config();
            let entries_count = tbl.len();

            let _ = write!(
                out,
                r#"    <div class="table-wrapper" style="margin-bottom: 20px;">
      <div style="padding: 12px 16px; background: var(--bg-table-header); border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between;">
        <span style="font-weight: 700; font-size: 15px;">Table: {name}</span>
        <span class="mono" style="font-size: 12px; color: var(--text-secondary);">Type: {key_type:?} &bull; Size: {size} &bull; Current Entries: {entries}</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Key</th>
            <th>Conn Rate</th>
            <th>HTTP Req Rate</th>
            <th>HTTP Req Total</th>
          </tr>
        </thead>
        <tbody>
"#,
                name = cfg.name,
                key_type = cfg.key_type,
                size = cfg.max_size,
                entries = entries_count,
            );

            if let Ok(entries) = tbl.dump_entries() {
                if entries.is_empty() {
                    out.push_str(r#"          <tr><td colspan="4" class="empty-card">Table has no stored entries.</td></tr>"#);
                } else {
                    for (k, d) in entries {
                        let conn_rate = d.conn_rate.map_or(0, |r| r.rate());
                        let http_rate = d.http_req_rate.map_or(0, |r| r.rate());
                        let _ = write!(
                            out,
                            r#"          <tr>
            <td class="mono">{k:?}</td>
            <td class="mono">{conn_rate}</td>
            <td class="mono">{http_rate}</td>
            <td class="mono">{req_cnt}</td>
          </tr>
"#,
                            req_cnt = d.http_req_cnt,
                        );
                    }
                }
            } else {
                out.push_str(r#"          <tr><td colspan="4" class="empty-card">Unable to dump table entries.</td></tr>"#);
            }

            out.push_str(
                r"        </tbody>
      </table>
    </div>
",
            );
        }
    }

    if stick_table_count == 0 {
        out.push_str(
            r#"    <div class="table-wrapper empty-card">No stick tables configured in runtime.</div>"#,
        );
    }
    out.push_str("  </div>\n");

    // Toast notification element
    out.push_str(r#"  <div id="toast" class="toast">Action applied successfully</div>"#);

    // Inlined, zero-CDN JavaScript
    out.push_str(
        r"
</div>
<script>
(function() {
  var refreshTimer = null;
  var intervalMs = 2000;
  var selectRefresh = document.getElementById('refresh-select');
  var btnManual = document.getElementById('btn-manual-refresh');
  var statusText = document.getElementById('refresh-status');
  var toastEl = document.getElementById('toast');

  function showToast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.style.display = 'block';
    setTimeout(function() { toastEl.style.display = 'none'; }, 2800);
  }

  function getBaseUrl() {
    var path = window.location.pathname;
    if (window.location.search.indexOf('stats') !== -1) {
      return path + window.location.search;
    }
    return path;
  }

  function getApiUrl() {
    var base = window.location.pathname;
    if (base.endsWith('/')) {
      return base + 'api/data';
    }
    return base + '/api/data';
  }

  function formatBytes(bytes) {
    var b = parseInt(bytes, 10);
    if (isNaN(b)) return '0 B';
    if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
    if (b >= 1048576) return (b / 1048576).toFixed(2) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(2) + ' KB';
    return b + ' B';
  }

  function updateMetrics(data) {
    if (!data) return;
    if (data.totals) {
      var actEl = document.getElementById('metric-act-conn');
      if (actEl) actEl.textContent = data.totals.act_conn;
      var cumEl = document.getElementById('metric-cum-conn');
      if (cumEl) cumEl.textContent = data.totals.cum_conn;
      var binEl = document.getElementById('metric-bytes-in');
      if (binEl) binEl.textContent = formatBytes(data.totals.bytes_in);
      var boutEl = document.getElementById('metric-bytes-out');
      if (boutEl) boutEl.textContent = formatBytes(data.totals.bytes_out);
    }
    if (data.counts) {
      var upEl = document.getElementById('count-up');
      if (upEl) upEl.textContent = data.counts.up + ' UP';
      var downEl = document.getElementById('count-down');
      if (downEl) downEl.textContent = data.counts.down + ' DOWN';
      var drainEl = document.getElementById('count-drain');
      if (drainEl) drainEl.textContent = data.counts.drain + ' DRAIN';
      var maintEl = document.getElementById('count-maint');
      if (maintEl) maintEl.textContent = data.counts.maint + ' MAINT';
    }
    if (data.proxies) {
      data.proxies.forEach(function(px) {
        if (px.servers) {
          px.servers.forEach(function(sv) {
            var badge = document.getElementById('badge-' + px.name + '-' + sv.name);
            if (badge) {
              badge.textContent = sv.status;
              badge.className = 'badge badge-' + sv.status.toLowerCase();
            }
            var actconnEl = document.getElementById('srv-actconn-' + px.name + '-' + sv.name);
            if (actconnEl && sv.act_conn !== undefined) actconnEl.textContent = sv.act_conn;
            var wInput = document.getElementById('weight-input-' + px.name + '-' + sv.name);
            if (wInput && sv.weight !== undefined && document.activeElement !== wInput) {
              wInput.value = sv.weight;
            }
            var mcInput = document.getElementById('maxconn-input-' + px.name + '-' + sv.name);
            if (mcInput && sv.maxconn !== undefined && document.activeElement !== mcInput) {
              mcInput.value = sv.maxconn;
            }
            var chkEl = document.getElementById('srv-check-' + px.name + '-' + sv.name);
            if (chkEl && sv.check_info) {
              var span = chkEl.querySelector('span');
              if (span) {
                span.textContent = sv.check_info;
              } else {
                chkEl.textContent = sv.check_info;
              }
            }
          });
        }
      });
    }
  }

  function fetchStats() {
    var pulse = document.getElementById('live-indicator');
    if (pulse) pulse.style.opacity = '0.3';
    fetch(getApiUrl(), { headers: { 'Accept': 'application/json' } })
      .then(function(res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      })
      .then(function(data) {
        updateMetrics(data);
        if (pulse) pulse.style.opacity = '1';
      })
      .catch(function(err) {
        if (pulse) pulse.style.opacity = '0.2';
      });
  }

  function startTimer() {
    if (refreshTimer) clearInterval(refreshTimer);
    if (intervalMs > 0) {
      refreshTimer = setInterval(fetchStats, intervalMs);
      if (statusText) statusText.textContent = 'Auto-refresh: ' + (intervalMs / 1000) + 's';
    } else {
      refreshTimer = null;
      if (statusText) statusText.textContent = 'Auto-refresh: Off';
    }
  }

  if (selectRefresh) {
    selectRefresh.addEventListener('change', function(e) {
      intervalMs = parseInt(e.target.value, 10);
      startTimer();
    });
  }

  if (btnManual) {
    btnManual.addEventListener('click', function() {
      fetchStats();
      showToast('Dashboard metrics refreshed');
    });
  }

  // Intercept all admin forms for seamless AJAX action
  document.addEventListener('submit', function(e) {
    if (e.target && e.target.classList.contains('admin-form')) {
      e.preventDefault();
      var form = e.target;
      var formData = new FormData(form);
      var params = new URLSearchParams(formData);
      var postUrl = getBaseUrl();

      fetch(postUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json'
        },
        body: params.toString()
      })
      .then(function(res) {
        var action = formData.get('action');
        var srv = formData.get('server');
        var be = formData.get('backend');
        var weight = formData.get('weight');
        var maxconn = formData.get('maxconn');
        if (action === 'ready') {
          showToast('Server ' + srv + ' set to READY (UP)');
          var badge = document.getElementById('badge-' + be + '-' + srv);
          if (badge) { badge.textContent = 'UP'; badge.className = 'badge badge-up'; }
        } else if (action === 'drain') {
          showToast('Server ' + srv + ' set to DRAIN');
          var badge = document.getElementById('badge-' + be + '-' + srv);
          if (badge) { badge.textContent = 'DRAIN'; badge.className = 'badge badge-drain'; }
        } else if (action === 'maint') {
          showToast('Server ' + srv + ' set to MAINT');
          var badge = document.getElementById('badge-' + be + '-' + srv);
          if (badge) { badge.textContent = 'MAINT'; badge.className = 'badge badge-maint'; }
        } else if (action === 'weight') {
          showToast('Server ' + srv + ' weight updated to ' + weight);
        } else if (action === 'kill_sessions' || action === 'shutdown_sessions') {
          if (srv) {
            showToast('Active sessions terminated for server ' + srv);
          } else if (be) {
            showToast('Active sessions terminated for backend ' + be);
          } else {
            showToast('Active sessions terminated');
          }
        } else if (action === 'clear_counters') {
          showToast('Statistics counters cleared');
        } else if (action === 'enable_health') {
          showToast('Health checking enabled for ' + srv);
        } else if (action === 'disable_health') {
          showToast('Health checking paused for ' + srv);
        } else if (action === 'maxconn' || action === 'set_maxconn') {
          if (srv) {
            showToast('Server ' + srv + ' maxconn updated to ' + maxconn);
          } else if (be) {
            showToast('Proxy ' + be + ' maxconn updated to ' + maxconn);
          }
        }
        setTimeout(fetchStats, 100);
      })
      .catch(function(err) {
        showToast('Error applying server action');
      });
    }
  });

  // Ensure export link points to ;csv
  var csvLink = document.getElementById('btn-csv-link');
  if (csvLink) {
    var cur = window.location.pathname;
    csvLink.href = cur.replace(/\/+$/, '') + ';csv';
  }

  startTimer();
})();
</script>
</body>
</html>
",
    );

    out
}

/// Renders JSON telemetry data matching the dashboard layout for live `fetch` auto-refresh.
#[must_use]
pub fn render_stats_json(proxies: &[Proxy], checks: &[ServerCheckState], pid: u32) -> String {
    let mut out = String::with_capacity(8192);

    let total_act_conn: u32 = proxies.iter().map(|p| p.stats.iter().map(|s| s.act_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u32>()).sum();
    let total_cum_conn: u64 = proxies.iter().map(|p| p.stats.iter().map(|s| s.cum_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()).sum();
    let total_bytes_in: u64 = proxies.iter().map(|p| p.stats.iter().map(|s| s.bytes_in.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()).sum();
    let total_bytes_out: u64 = proxies.iter().map(|p| p.stats.iter().map(|s| s.bytes_out.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()).sum();

    let mut count_up = 0;
    let mut count_down = 0;
    let mut count_drain = 0;
    let mut count_maint = 0;

    for proxy in proxies {
        for status_atomic in proxy.server_statuses.iter() { let status = ServerStatus::from(status_atomic.load(std::sync::atomic::Ordering::Relaxed));
            match status {
                ServerStatus::Up => count_up += 1,
                ServerStatus::Down => count_down += 1,
                ServerStatus::Drain => count_drain += 1,
                ServerStatus::Maint => count_maint += 1,
            }
        }
    }

    let _ = write!(
        out,
        r#"{{"pid":{pid},"totals":{{"act_conn":{total_act_conn},"cum_conn":{total_cum_conn},"bytes_in":{total_bytes_in},"bytes_out":{total_bytes_out}}},"counts":{{"up":{count_up},"down":{count_down},"drain":{count_drain},"maint":{count_maint}}},"proxies":["#
    );

    for (p_idx, proxy) in proxies.iter().enumerate() {
        if p_idx > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            r#"{{"name":"{}","maxconn":{},"act_conn":{},"cum_conn":{},"bytes_in":{},"bytes_out":{},"servers":["#,
            proxy.name,
            proxy.maxconn,
            proxy.stats.iter().map(|s| s.act_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u32>(),
            proxy.stats.iter().map(|s| s.cum_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>(),
            proxy.stats.iter().map(|s| s.bytes_in.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>(),
            proxy.stats.iter().map(|s| s.bytes_out.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>(),
        );

        for (s_idx, _) in proxy.servers.iter().enumerate() {
            if s_idx > 0 {
                out.push(',');
            }
            let srv_id = proxy.server_ids.get(s_idx).map_or("srv", String::as_str);
            let srv_status = proxy
                .server_statuses.get(s_idx).map(|s| ServerStatus::from(s.load(std::sync::atomic::Ordering::Relaxed))).unwrap_or(ServerStatus::Up);
            let weight = proxy.server_weights.get(s_idx).unwrap_or(1);
            let srv_maxconn = proxy.server_maxconn.get(s_idx).unwrap_or(0);
            let actconn = proxy.server_actconn.get(s_idx).map(|a| a.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(0);

            let check_state = checks
                .iter()
                .find(|c| c.proxy() == p_idx && c.server() == s_idx);

            let check_info = if let Some(c) = check_state {
                if !c.enabled {
                    "PAUSED".to_string()
                } else if c.status == ServerStatus::Up {
                    format!("{}ms (pass {})", c.check_duration_ms, c.rise_count)
                } else {
                    format!("FAIL (fails {})", c.fall_count)
                }
            } else {
                "no check".to_string()
            };

            let check_enabled = check_state.is_some_and(|c| c.enabled);

            let _ = write!(
                out,
                r#"{{"name":"{}","status":"{}","weight":{},"maxconn":{},"act_conn":{},"check_info":"{}","check_enabled":{}}}"#,
                srv_id,
                srv_status.as_str(),
                weight,
                srv_maxconn,
                actconn,
                check_info,
                check_enabled,
            );
        }

        out.push_str("]}");
    }

    out.push_str("]}");
    out
}

/// Parsed command for admin server state/weight/maxconn mutations and session/health actions.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AdminAction {
    pub action: String,
    pub backend: Option<String>,
    pub server: Option<String>,
    pub weight: Option<u32>,
    pub maxconn: Option<u32>,
}

/// Parses admin action parameters from URL query string or URL-encoded/JSON body.
#[must_use]
pub fn parse_admin_action(query: &str, body: &str) -> Option<AdminAction> {
    let mut action = None;
    let mut backend = None;
    let mut server = None;
    let mut weight = None;
    let mut maxconn = None;

    // Helper closure to examine key-value pairs
    let mut examine_pair = |k: &str, v: &str| {
        let key_clean = k.trim().trim_start_matches('?');
        let val_clean = v.trim();
        match key_clean {
            "action" | "act" | "state" | "status" => action = Some(val_clean.to_ascii_lowercase()),
            "backend" | "b" | "px" | "proxy" => backend = Some(val_clean.to_string()),
            "server" | "s" | "sv" | "srv" => server = Some(val_clean.to_string()),
            "weight" | "w" => weight = val_clean.parse::<u32>().ok(),
            "maxconn" | "mc" => maxconn = val_clean.parse::<u32>().ok(),
            _ => {}
        }
    };

    // 1. Parse from query
    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            examine_pair(k, v);
        }
    }

    // 2. Parse from body (form-urlencoded or basic JSON)
    let body_trimmed = body.trim();
    if body_trimmed.starts_with('{') && body_trimmed.ends_with('}') {
        // Simple JSON extractor without extra dependencies
        let inner = &body_trimmed[1..body_trimmed.len() - 1];
        for pair in inner.split(',') {
            if let Some((k, v)) = pair.split_once(':') {
                let k = k.trim().trim_matches('"').trim_matches('\'');
                let v = v.trim().trim_matches('"').trim_matches('\'');
                examine_pair(k, v);
            }
        }
    } else {
        // Form urlencoded
        for part in body_trimmed.split('&') {
            if let Some((k, v)) = part.split_once('=') {
                examine_pair(k, v);
            }
        }
    }

    if action.is_none() {
        if maxconn.is_some() {
            action = Some("maxconn".to_string());
        } else if weight.is_some() {
            action = Some("weight".to_string());
        }
    }

    action.map(|act| AdminAction {
        action: act,
        backend,
        server,
        weight,
        maxconn,
    })
}
