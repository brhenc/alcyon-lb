// SPDX-License-Identifier: GPL-2.0-or-later
use crate::check::{ServerCheckState, ServerStatus};
use crate::engine::Proxy;
use std::fmt::Write;
use std::time::Instant;

pub struct StatsSnapshot<'a> {
    pub proxies: &'a [Proxy],
    pub checks: &'a [ServerCheckState],
    pub start_time: Instant,
    pub pid: u32,
    pub total_tasks: usize,
    pub run_queue_len: usize,
    pub active_conns: u32,
    pub max_conns: u32,
}

pub fn render(stats: &StatsSnapshot, out: &mut String) {
    out.push_str("# HELP haproxy_process_relative_process_id Relative worker process number (1)\n");
    out.push_str("# TYPE haproxy_process_relative_process_id gauge\n");
    let _ = writeln!(out, "haproxy_process_relative_process_id {}", stats.pid);

    out.push_str("# HELP haproxy_process_uptime_seconds How long ago this worker process was started (seconds)\n");
    out.push_str("# TYPE haproxy_process_uptime_seconds gauge\n");
    let _ = writeln!(
        out,
        "haproxy_process_uptime_seconds {}",
        stats.start_time.elapsed().as_secs()
    );

    out.push_str("# HELP haproxy_process_max_connections Hard limit on the number of per-process connections (configured or imposed by Ulimit-n)\n");
    out.push_str("# TYPE haproxy_process_max_connections gauge\n");
    let _ = writeln!(out, "haproxy_process_max_connections {}", stats.max_conns);

    out.push_str("# HELP haproxy_process_hard_max_connections Hard limit on the number of per-process connections (imposed by Memmax_MB or Ulimit-n)\n");
    out.push_str("# TYPE haproxy_process_hard_max_connections gauge\n");
    let _ = writeln!(
        out,
        "haproxy_process_hard_max_connections {}",
        stats.max_conns
    );

    out.push_str("# HELP haproxy_process_current_connections Current number of connections on this worker process\n");
    out.push_str("# TYPE haproxy_process_current_connections gauge\n");
    let _ = writeln!(
        out,
        "haproxy_process_current_connections {}",
        stats.active_conns
    );

    out.push_str("# HELP haproxy_process_current_tasks Total number of tasks in the current worker process (active + sleeping)\n");
    out.push_str("# TYPE haproxy_process_current_tasks gauge\n");
    let _ = writeln!(out, "haproxy_process_current_tasks {}", stats.total_tasks);

    out.push_str("# HELP haproxy_process_current_run_queue Total number of active tasks+tasklets in the current worker process\n");
    out.push_str("# TYPE haproxy_process_current_run_queue gauge\n");
    let _ = writeln!(
        out,
        "haproxy_process_current_run_queue {}",
        stats.run_queue_len
    );

    out.push_str("# HELP haproxy_frontend_current_sessions Number of current sessions on the frontend, backend or server\n");
    out.push_str("# TYPE haproxy_frontend_current_sessions gauge\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_frontend_current_sessions{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.act_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u32>()
        );
    }

    out.push_str("# HELP haproxy_frontend_max_sessions Highest value of current sessions encountered since process started\n");
    out.push_str("# TYPE haproxy_frontend_max_sessions gauge\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_frontend_max_sessions{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.max_conn.load(std::sync::atomic::Ordering::Relaxed)).max().unwrap_or(0)
        );
    }

    out.push_str(
        "# HELP haproxy_frontend_sessions_total Total number of sessions since process started\n",
    );
    out.push_str("# TYPE haproxy_frontend_sessions_total counter\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_frontend_sessions_total{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.cum_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()
        );
    }

    out.push_str("# HELP haproxy_frontend_bytes_in_total Total number of request bytes since process started\n");
    out.push_str("# TYPE haproxy_frontend_bytes_in_total counter\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_frontend_bytes_in_total{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.bytes_in.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()
        );
    }

    out.push_str("# HELP haproxy_frontend_bytes_out_total Total number of response bytes since process started\n");
    out.push_str("# TYPE haproxy_frontend_bytes_out_total counter\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_frontend_bytes_out_total{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.bytes_out.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()
        );
    }

    out.push_str("# HELP haproxy_frontend_requests_denied_total Total number of denied requests since process started\n");
    out.push_str("# TYPE haproxy_frontend_requests_denied_total counter\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_frontend_requests_denied_total{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.denied_req.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()
        );
    }

    out.push_str("# HELP haproxy_frontend_responses_denied_total Total number of denied responses since process started\n");
    out.push_str("# TYPE haproxy_frontend_responses_denied_total counter\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_frontend_responses_denied_total{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.denied_resp.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()
        );
    }

    out.push_str("# HELP haproxy_frontend_denied_connections_total Total number of incoming connections blocked on a listener/frontend by a tcp-request connection rule since the worker process started\n");
    out.push_str("# TYPE haproxy_frontend_denied_connections_total counter\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_frontend_denied_connections_total{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.denied_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()
        );
    }

    out.push_str("# HELP haproxy_frontend_limit_sessions Frontend/listener/server's maxconn, backend's fullconn\n");
    out.push_str("# TYPE haproxy_frontend_limit_sessions gauge\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_frontend_limit_sessions{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.maxconn
        );
    }

    out.push_str(
        "# HELP haproxy_frontend_status Current status of the service, per state label value.\n",
    );
    out.push_str("# TYPE haproxy_frontend_status gauge\n");
    for proxy in stats.proxies {
        let _ = write!(out, "haproxy_frontend_status{{{{proxy=\"{0}\",state=\"DOWN\"}}}} 0\nhaproxy_frontend_status{{{{proxy=\"{0}\",state=\"UP\"}}}} 1\n", proxy.name);
    }

    out.push_str("# HELP haproxy_backend_current_sessions Number of current sessions on the frontend, backend or server\n");
    out.push_str("# TYPE haproxy_backend_current_sessions gauge\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_backend_current_sessions{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.act_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u32>()
        );
    }

    out.push_str("# HELP haproxy_backend_max_sessions Highest value of current sessions encountered since process started\n");
    out.push_str("# TYPE haproxy_backend_max_sessions gauge\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_backend_max_sessions{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.max_conn.load(std::sync::atomic::Ordering::Relaxed)).max().unwrap_or(0)
        );
    }

    out.push_str(
        "# HELP haproxy_backend_sessions_total Total number of sessions since process started\n",
    );
    out.push_str("# TYPE haproxy_backend_sessions_total counter\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_backend_sessions_total{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.cum_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()
        );
    }

    out.push_str("# HELP haproxy_backend_bytes_in_total Total number of request bytes since process started\n");
    out.push_str("# TYPE haproxy_backend_bytes_in_total counter\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_backend_bytes_in_total{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.bytes_in.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()
        );
    }

    out.push_str("# HELP haproxy_backend_bytes_out_total Total number of response bytes since process started\n");
    out.push_str("# TYPE haproxy_backend_bytes_out_total counter\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_backend_bytes_out_total{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.bytes_out.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()
        );
    }

    out.push_str("# HELP haproxy_backend_requests_denied_total Total number of denied requests since process started\n");
    out.push_str("# TYPE haproxy_backend_requests_denied_total counter\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_backend_requests_denied_total{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.denied_req.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()
        );
    }

    out.push_str("# HELP haproxy_backend_responses_denied_total Total number of denied responses since process started\n");
    out.push_str("# TYPE haproxy_backend_responses_denied_total counter\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_backend_responses_denied_total{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.stats.iter().map(|s| s.denied_resp.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>()
        );
    }

    out.push_str("# HELP haproxy_backend_active_servers Total number of active UP servers with a non-zero weight\n");
    out.push_str("# TYPE haproxy_backend_active_servers gauge\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_backend_active_servers{{proxy=\"{0}\"}} {1}",
            proxy.name, 1
        );
    }

    out.push_str("# HELP haproxy_backend_backup_servers Total number of backup UP servers with a non-zero weight\n");
    out.push_str("# TYPE haproxy_backend_backup_servers gauge\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_backend_backup_servers{{proxy=\"{0}\"}} {1}",
            proxy.name, 0
        );
    }

    out.push_str("# HELP haproxy_backend_weight Server's effective weight, or sum of active servers' effective weights for a backend\n");
    out.push_str("# TYPE haproxy_backend_weight gauge\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_backend_weight{{proxy=\"{0}\"}} {1}",
            proxy.name, 1
        );
    }

    out.push_str("# HELP haproxy_backend_limit_sessions Frontend/listener/server's maxconn, backend's fullconn\n");
    out.push_str("# TYPE haproxy_backend_limit_sessions gauge\n");
    for proxy in stats.proxies {
        let _ = writeln!(
            out,
            "haproxy_backend_limit_sessions{{proxy=\"{0}\"}} {1}",
            proxy.name, proxy.maxconn
        );
    }

    out.push_str(
        "# HELP haproxy_backend_status Current status of the service, per state label value.\n",
    );
    out.push_str("# TYPE haproxy_backend_status gauge\n");
    for proxy in stats.proxies {
        let _ = write!(out, "haproxy_backend_status{{{{proxy=\"{0}\",state=\"DOWN\"}}}} 0\nhaproxy_backend_status{{{{proxy=\"{0}\",state=\"UP\"}}}} 1\n", proxy.name);
    }

    out.push_str("# HELP haproxy_server_current_sessions Number of current sessions on the frontend, backend or server\n");
    out.push_str("# TYPE haproxy_server_current_sessions gauge\n");
    for (p_idx, proxy) in stats.proxies.iter().enumerate() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            let _check_state = stats
                .checks
                .iter()
                .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
            let _ = writeln!(
                out,
                "haproxy_server_current_sessions{{proxy=\"{0}\",server=\"{1}\"}} {2}",
                proxy.name,
                srv_name,
                proxy.server_actconn.get(s_idx).map(|a| a.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(0)
            );
        }
    }

    out.push_str("# HELP haproxy_server_max_sessions Highest value of current sessions encountered since process started\n");
    out.push_str("# TYPE haproxy_server_max_sessions gauge\n");
    for (p_idx, proxy) in stats.proxies.iter().enumerate() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            let _check_state = stats
                .checks
                .iter()
                .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
            let _ = writeln!(
                out,
                "haproxy_server_max_sessions{{proxy=\"{0}\",server=\"{1}\"}} {2}",
                proxy.name, srv_name, 0
            );
        }
    }

    out.push_str(
        "# HELP haproxy_server_sessions_total Total number of sessions since process started\n",
    );
    out.push_str("# TYPE haproxy_server_sessions_total counter\n");
    for (p_idx, proxy) in stats.proxies.iter().enumerate() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            let _check_state = stats
                .checks
                .iter()
                .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
            let _ = writeln!(
                out,
                "haproxy_server_sessions_total{{proxy=\"{0}\",server=\"{1}\"}} {2}",
                proxy.name, srv_name, 0
            );
        }
    }

    out.push_str("# HELP haproxy_server_bytes_in_total Total number of request bytes since process started\n");
    out.push_str("# TYPE haproxy_server_bytes_in_total counter\n");
    for (p_idx, proxy) in stats.proxies.iter().enumerate() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            let _check_state = stats
                .checks
                .iter()
                .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
            let _ = writeln!(
                out,
                "haproxy_server_bytes_in_total{{proxy=\"{0}\",server=\"{1}\"}} {2}",
                proxy.name, srv_name, 0
            );
        }
    }

    out.push_str("# HELP haproxy_server_bytes_out_total Total number of response bytes since process started\n");
    out.push_str("# TYPE haproxy_server_bytes_out_total counter\n");
    for (p_idx, proxy) in stats.proxies.iter().enumerate() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            let _check_state = stats
                .checks
                .iter()
                .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
            let _ = writeln!(
                out,
                "haproxy_server_bytes_out_total{{proxy=\"{0}\",server=\"{1}\"}} {2}",
                proxy.name, srv_name, 0
            );
        }
    }

    out.push_str("# HELP haproxy_server_responses_denied_total Total number of denied responses since process started\n");
    out.push_str("# TYPE haproxy_server_responses_denied_total counter\n");
    for (p_idx, proxy) in stats.proxies.iter().enumerate() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            let _check_state = stats
                .checks
                .iter()
                .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
            let _ = writeln!(
                out,
                "haproxy_server_responses_denied_total{{proxy=\"{0}\",server=\"{1}\"}} {2}",
                proxy.name, srv_name, 0
            );
        }
    }

    out.push_str("# HELP haproxy_server_weight Server's effective weight, or sum of active servers' effective weights for a backend\n");
    out.push_str("# TYPE haproxy_server_weight gauge\n");
    for (p_idx, proxy) in stats.proxies.iter().enumerate() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            let _check_state = stats
                .checks
                .iter()
                .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
            let _ = writeln!(
                out,
                "haproxy_server_weight{{proxy=\"{0}\",server=\"{1}\"}} {2}",
                proxy.name,
                srv_name,
                proxy.server_weights.get(s_idx).copied().unwrap_or(1)
            );
        }
    }

    out.push_str(
        "# HELP haproxy_server_active Total number of active UP servers with a non-zero weight\n",
    );
    out.push_str("# TYPE haproxy_server_active gauge\n");
    for (p_idx, proxy) in stats.proxies.iter().enumerate() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            let _check_state = stats
                .checks
                .iter()
                .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
            let _ = writeln!(
                out,
                "haproxy_server_active{{proxy=\"{0}\",server=\"{1}\"}} {2}",
                proxy.name,
                srv_name,
                i32::from(!proxy.server_backups.get(s_idx).copied().unwrap_or(false))
            );
        }
    }

    out.push_str(
        "# HELP haproxy_server_backup Total number of backup UP servers with a non-zero weight\n",
    );
    out.push_str("# TYPE haproxy_server_backup gauge\n");
    for (p_idx, proxy) in stats.proxies.iter().enumerate() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            let _check_state = stats
                .checks
                .iter()
                .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
            let _ = writeln!(
                out,
                "haproxy_server_backup{{proxy=\"{0}\",server=\"{1}\"}} {2}",
                proxy.name,
                srv_name,
                i32::from(proxy.server_backups.get(s_idx).copied().unwrap_or(false))
            );
        }
    }

    out.push_str("# HELP haproxy_server_check_failures_total Total number of failed individual health checks per server/backend, since the worker process started\n");
    out.push_str("# TYPE haproxy_server_check_failures_total counter\n");
    for (p_idx, proxy) in stats.proxies.iter().enumerate() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            let _check_state = stats
                .checks
                .iter()
                .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
            let _ = writeln!(
                out,
                "haproxy_server_check_failures_total{{proxy=\"{0}\",server=\"{1}\"}} {2}",
                proxy.name,
                srv_name,
                if let Some(c) = _check_state {
                    c.failed_checks
                } else {
                    0
                }
            );
        }
    }

    out.push_str("# HELP haproxy_server_check_up_down_total Total number of failed checks causing UP to DOWN server transitions, per server/backend, since the worker process started\n");
    out.push_str("# TYPE haproxy_server_check_up_down_total counter\n");
    for (p_idx, proxy) in stats.proxies.iter().enumerate() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            let _check_state = stats
                .checks
                .iter()
                .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
            let _ = writeln!(
                out,
                "haproxy_server_check_up_down_total{{proxy=\"{0}\",server=\"{1}\"}} {2}",
                proxy.name,
                srv_name,
                if let Some(c) = _check_state {
                    c.down_transitions
                } else {
                    0
                }
            );
        }
    }

    out.push_str("# HELP haproxy_server_limit_sessions Frontend/listener/server's maxconn, backend's fullconn\n");
    out.push_str("# TYPE haproxy_server_limit_sessions gauge\n");
    for proxy in stats.proxies.iter() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            if let Some(m) = proxy.server_maxconn.get(s_idx).copied().flatten() {
                let _ = writeln!(
                    out,
                    "haproxy_server_limit_sessions{{proxy=\"{0}\",server=\"{1}\"}} {2}",
                    proxy.name, srv_name, m
                );
            } else {
                let _ = writeln!(
                    out,
                    "haproxy_server_limit_sessions{{proxy=\"{0}\",server=\"{1}\"}} NaN",
                    proxy.name, srv_name
                );
            }
        }
    }

    out.push_str(
        "# HELP haproxy_server_status Current status of the service, per state label value.\n",
    );
    out.push_str("# TYPE haproxy_server_status gauge\n");
    for (p_idx, proxy) in stats.proxies.iter().enumerate() {
        for s_idx in 0..proxy.servers.len() {
            let srv_name = if s_idx < proxy.server_ids.len() {
                &proxy.server_ids[s_idx]
            } else {
                "srv"
            };
            let _check_state = stats
                .checks
                .iter()
                .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
            let is_up = if let Some(c) = _check_state {
                c.status == ServerStatus::Up
            } else {
                proxy
                    .server_statuses.get(s_idx).map(|s| ServerStatus::from(s.load(std::sync::atomic::Ordering::Relaxed))).unwrap_or(ServerStatus::Up)
                    == ServerStatus::Up
            };
            let is_down = if let Some(c) = _check_state {
                c.status == ServerStatus::Down
            } else {
                proxy
                    .server_statuses.get(s_idx).map(|s| ServerStatus::from(s.load(std::sync::atomic::Ordering::Relaxed))).unwrap_or(ServerStatus::Up)
                    == ServerStatus::Down
            };
            let _ = writeln!(
                out,
                "haproxy_server_status{{{{proxy=\"{0}\",server=\"{1}\",state=\"DOWN\"}}}} {2}",
                proxy.name,
                srv_name,
                i32::from(is_down)
            );
            let _ = writeln!(
                out,
                "haproxy_server_status{{{{proxy=\"{0}\",server=\"{1}\",state=\"UP\"}}}} {2}",
                proxy.name,
                srv_name,
                i32::from(is_up)
            );
            let _ = writeln!(
                out,
                "haproxy_server_status{{{{proxy=\"{0}\",server=\"{1}\",state=\"MAINT\"}}}} 0",
                proxy.name, srv_name
            );
            let _ = writeln!(
                out,
                "haproxy_server_status{{{{proxy=\"{0}\",server=\"{1}\",state=\"DRAIN\"}}}} 0",
                proxy.name, srv_name
            );
            let _ = writeln!(
                out,
                "haproxy_server_status{{{{proxy=\"{0}\",server=\"{1}\",state=\"NOLB\"}}}} 0",
                proxy.name, srv_name
            );
        }
    }
}
