// SPDX-License-Identifier: GPL-2.0-or-later

//! Process-level CPU measurement.

use std::fs::File;
use std::io::Read;
use std::time::{Duration, Instant};

/// Monitors process-level CPU utilization.
pub struct CpuMonitor {
    last_sample_time: Option<Instant>,
    last_user_ticks: u64,
    last_system_ticks: u64,
    cpu_usage_pct: u8,
    sample_window: Duration,
    buf: [u8; 1024],
}

impl CpuMonitor {
    /// Creates a new CPU monitor with the given sampling window.
    #[must_use]
    pub fn new(sample_window: Duration) -> Self {
        let mut monitor = Self {
            last_sample_time: None,
            last_user_ticks: 0,
            last_system_ticks: 0,
            cpu_usage_pct: 0,
            sample_window,
            buf: [0; 1024],
        };
        monitor.sample();
        monitor
    }

    /// Returns the current CPU utilization as a percentage (0-100).
    pub fn usage_pct(&mut self) -> u8 {
        let should_sample = match self.last_sample_time {
            Some(time) => time.elapsed() >= self.sample_window,
            None => true,
        };
        if should_sample {
            self.sample();
        }
        self.cpu_usage_pct
    }

    /// Returns the idle percentage (100 - usage_pct).
    pub fn idle_pct(&mut self) -> u8 {
        100u8.saturating_sub(self.usage_pct())
    }

    fn sample(&mut self) {
        let mut file = match File::open("/proc/self/stat") {
            Ok(f) => f,
            Err(_) => return,
        };
        
        let n = match file.read(&mut self.buf) {
            Ok(n) => n,
            Err(_) => return,
        };
        
        let s = match std::str::from_utf8(&self.buf[..n]) {
            Ok(s) => s,
            Err(_) => return,
        };
        
        let rparen = match s.rfind(')') {
            Some(i) => i,
            None => return,
        };
        
        let after_paren = &s[rparen + 1..];
        let mut fields = after_paren.split_whitespace();
        
        // 11th and 12th fields after the ')' are utime and stime
        let utime: u64 = match fields.nth(11).and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => return,
        };
        
        let stime: u64 = match fields.next().and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => return,
        };
        
        let now = Instant::now();
        if let Some(last_time) = self.last_sample_time {
            let elapsed = now.duration_since(last_time);
            let user_diff = utime.saturating_sub(self.last_user_ticks);
            let system_diff = stime.saturating_sub(self.last_system_ticks);
            let total_ticks = user_diff + system_diff;
            
            let elapsed_secs = elapsed.as_secs_f64();
            if elapsed_secs > 0.0 {
                // Assuming USER_HZ = 100 on Linux (1 tick = 10ms).
                // cpu_usage = (total_ticks / 100) / elapsed_secs * 100 = total_ticks / elapsed_secs
                let usage = ((total_ticks as f64) / elapsed_secs).round() as u64;
                self.cpu_usage_pct = usage.min(100) as u8;
            }
        }
        
        self.last_user_ticks = utime;
        self.last_system_ticks = stime;
        self.last_sample_time = Some(now);
    }
}

use std::sync::{Mutex, OnceLock};

static GLOBAL_MONITOR: OnceLock<Mutex<CpuMonitor>> = OnceLock::new();

/// Returns the process-wide idle percentage using a global monitor.
pub fn get_idle_pct() -> u8 {
    let mut monitor = GLOBAL_MONITOR
        .get_or_init(|| Mutex::new(CpuMonitor::new(Duration::from_millis(500))))
        .lock()
        .unwrap();
    monitor.idle_pct()
}

/// Returns the process-wide usage percentage using a global monitor.
pub fn get_usage_pct() -> u8 {
    let mut monitor = GLOBAL_MONITOR
        .get_or_init(|| Mutex::new(CpuMonitor::new(Duration::from_millis(500))))
        .lock()
        .unwrap();
    monitor.usage_pct()
}
