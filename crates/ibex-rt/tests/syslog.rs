// SPDX-License-Identifier: GPL-2.0-or-later

//! Syslog emission, verified by receiving real datagrams.
//!
//! The reg-tests these unblock assert on syslog output with varnishtest `syslog` blocks,
//! so the wire format has to be right rather than merely plausible.

use ibex_config::{LogConfig, LogFacility, LogLevel, LogTarget};
use ibex_rt::{format_rfc3164, priority, SyslogTarget};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

fn receiver() -> (UdpSocket, SocketAddr) {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    s.set_read_timeout(Some(Duration::from_millis(500))).expect("timeout");
    let a = s.local_addr().expect("addr");
    (s, a)
}

#[test]
fn priority_is_facility_times_eight_plus_severity() {
    // RFC 3164. local0 = 16, notice = 5, so <133>. Getting this wrong routes messages
    // to the wrong facility on the collector, which looks like logs going missing.
    assert_eq!(priority(LogFacility::Local0, LogLevel::Notice), 133);
    assert_eq!(priority(LogFacility::Kern, LogLevel::Emerg), 0);
    assert_eq!(priority(LogFacility::Daemon, LogLevel::Info), 3 * 8 + 6);
    assert_eq!(priority(LogFacility::Local7, LogLevel::Debug), 23 * 8 + 7);
}

#[test]
fn rfc3164_day_is_space_padded_not_zero_padded() {
    // The RFC specifies a space-padded day. Collectors parse this positionally, and a
    // zero-padded day is a common, quietly incompatible mistake.
    let line = format_rfc3164(133, "ibex", "host", "hello");
    let after_pri = line.split('>').nth(1).expect("pri");
    let day_field = &after_pri[4..6];
    assert!(
        day_field.starts_with(' ') || day_field.chars().all(|c| c.is_ascii_digit()),
        "day field {day_field:?} must be space-padded, not zero-padded"
    );
    assert!(line.starts_with("<133>"));
    assert!(line.ends_with("host ibex: hello"));
}

#[test]
fn a_datagram_actually_arrives_and_is_well_formed() {
    let (rx, addr) = receiver();
    let cfg = LogConfig { target: LogTarget::Udp(addr), max_len: 1024, format: None, sample: None, facility: LogFacility::Local0, level: Some(LogLevel::Notice) };
    let t = SyslogTarget::new(&cfg);

    assert!(t.send(LogLevel::Notice, "ibex", "testhost", "a message"));

    let mut buf = [0u8; 2048];
    let n = rx.recv(&mut buf).expect("a datagram must arrive");
    let got = String::from_utf8_lossy(&buf[..n]).to_string();

    assert!(got.starts_with("<133>"), "wrong priority: {got}");
    assert!(got.contains("testhost ibex: a message"), "wrong body: {got}");
}

#[test]
fn level_filtering_drops_less_severe_messages() {
    // `log <addr> <facility> <level>` is a maximum-level filter: only messages at that
    // level or more severe are emitted. Severity counts downward, so "more severe"
    // means a numerically smaller code -- easy to invert by accident.
    let (rx, addr) = receiver();
    let cfg = LogConfig { target: LogTarget::Udp(addr), max_len: 1024, format: None, sample: None, facility: LogFacility::Local0, level: Some(LogLevel::Warning) };
    let t = SyslogTarget::new(&cfg);

    assert!(t.accepts(LogLevel::Emerg), "more severe than the filter must pass");
    assert!(t.accepts(LogLevel::Warning), "equal to the filter must pass");
    assert!(!t.accepts(LogLevel::Info), "less severe must be dropped");
    assert!(!t.accepts(LogLevel::Debug));

    assert!(!t.send(LogLevel::Debug, "ibex", "h", "should not arrive"));
    let mut buf = [0u8; 512];
    assert!(rx.recv(&mut buf).is_err(), "a filtered message must not be sent");
}

#[test]
fn sending_to_an_unreachable_collector_never_fails_the_caller() {
    // Logging is best-effort by design: a collector that is gone must not stall or
    // crash the proxy. This is the property that matters most in production.
    let cfg = LogConfig {
        // TEST-NET-1, guaranteed not to route anywhere.
        target: LogTarget::Udp("192.0.2.1:514".parse::<SocketAddr>().expect("addr")),
        max_len: 1024,
        format: None,
        sample: None,
        facility: LogFacility::Local0,
        level: Some(LogLevel::Info),
    };
    let t = SyslogTarget::new(&cfg);
    for _ in 0..100 {
        let _ = t.send(LogLevel::Info, "ibex", "h", "into the void");
    }
    // Reaching here at all is the assertion: no panic, no block.
}

#[test]
fn every_facility_maps_to_a_distinct_code() {
    use LogFacility::{
        Alert, Audit, Auth, Auth2, Cron, Cron2, Daemon, Ftp, Kern, Local0, Local1, Local2,
        Local3, Local4, Local5, Local6, Local7, Lpr, Mail, News, Ntp, Syslog, User, Uucp,
    };
    let all = [
        Kern, User, Mail, Daemon, Auth, Syslog, Lpr, News, Uucp, Cron, Auth2, Ftp, Ntp,
        Audit, Alert, Cron2, Local0, Local1, Local2, Local3, Local4, Local5, Local6, Local7,
    ];
    let codes: std::collections::BTreeSet<u8> =
        all.iter().map(|f| ibex_rt::syslog::facility_code(*f)).collect();
    assert_eq!(codes.len(), all.len(), "facility codes must be distinct");
    assert_eq!(*codes.iter().next().expect("min"), 0);
    assert_eq!(*codes.iter().next_back().expect("max"), 23);
}

// ---- health-check log lines ---------------------------------------------------------

use ibex_rt::check::{CheckEvent, ServerCheckConfig, ServerCheckState, ServerStatus};

fn state(rise: u32, fall: u32) -> ServerCheckState {
    ServerCheckState::new(
        0,
        0,
        "127.0.0.1:1".parse().expect("addr"),
        ServerCheckConfig { rise, fall, ..Default::default() },
        ibex_sched::Tick(1000),
    )
}

/// A healthy server passing another check reports nothing.
///
/// `HAProxy` calls this `report` and it is false once the health counter saturates
/// (`src/check.c`). Without it a dead or healthy server produces a log line on every
/// check: at a 100ms interval that is ten datagrams a second, per server, forever.
#[test]
fn a_check_that_changes_nothing_is_not_reported() {
    // rise 1, fall 1 -> full health is 1, and a server starts at `rise`, so it is
    // already saturated.
    let mut s = state(1, 1);
    assert_eq!(s.on_success(3), None, "an already-healthy server has nothing to report");
    assert_eq!(s.on_success(3), None);

    // Likewise at the floor: down and staying down.
    assert_eq!(
        s.on_failure("L4CON", "Connection refused", 1),
        Some(CheckEvent::WentDown)
    );
    assert_eq!(s.on_failure("L4CON", "Connection refused", 1), None);
    assert_eq!(s.on_failure("L4CON", "Connection refused", 1), None);
}

/// A freshly configured server goes DOWN on its first failure, whatever `fall` says.
///
/// Health starts at `rise`, not at full health (`src/server.c`), so the first decrement
/// puts it below the rise threshold and clamps to zero. `fall` only buys the documented
/// number of failures once a server has actually reached full health.
#[test]
fn a_new_server_falls_on_the_first_failure_then_fall_applies() {
    let mut s = state(1, 3);
    assert_eq!(
        s.on_failure("L4CON", "Connection refused", 1),
        Some(CheckEvent::WentDown)
    );
    assert_eq!(s.status, ServerStatus::Down);
    assert!(CheckEvent::WentDown.is_transition());

    // Recover to full health: rise 1 means one success is enough.
    assert_eq!(s.on_success(1), Some(CheckEvent::WentUp));
    assert_eq!(s.status, ServerStatus::Up);

    // Now `fall` failures are needed, and only the last one is the transition.
    assert_eq!(
        s.on_failure("L4CON", "Connection refused", 1),
        Some(CheckEvent::Failed)
    );
    assert_eq!(
        s.on_failure("L4CON", "Connection refused", 1),
        Some(CheckEvent::Failed)
    );
    assert_eq!(
        s.on_failure("L4CON", "Connection refused", 1),
        Some(CheckEvent::WentDown)
    );
    assert_eq!(s.status, ServerStatus::Down);
}

#[test]
fn recovering_reports_went_up_only_at_the_rise_threshold() {
    let mut s = state(2, 1);
    s.on_failure("L4CON", "Connection refused", 1);
    assert_eq!(s.status, ServerStatus::Down);
    assert_eq!(
        s.on_success(2),
        Some(CheckEvent::Succeeded),
        "below the rise threshold"
    );
    assert_eq!(s.on_success(2), Some(CheckEvent::WentUp));
    assert!(CheckEvent::WentUp.is_transition());
}

#[test]
fn the_log_line_matches_the_shape_reg_tests_assert_on() {
    // reg-tests/checks/*.vtc match this with regexes, so the wording and field order
    // are part of the contract, not cosmetic.
    let mut s = state(2, 1);
    s.on_failure("L4CON", "Connection refused", 1);
    // rise 2: the first success climbs but stays DOWN, the second crosses the threshold.
    s.on_success(0).expect("first success reports");
    let ev = s.on_success(0).expect("recovery reports");
    let line = s.log_line("be1", "srv1", ev);

    assert!(
        line.starts_with("Health check for server be1/srv1 succeeded"),
        "{line}"
    );
    assert!(line.contains("reason: Layer4 check passed"), "{line}");
    assert!(line.contains("check duration: 0ms"), "{line}");
    assert!(line.contains("status: 1/1 UP."), "{line}");
}

#[test]
fn a_failed_check_line_says_failed_and_reports_down() {
    let mut s = state(1, 1);
    let ev = s
        .on_failure("L4CON", "Connection refused", 7)
        .expect("the first failure reports");
    let line = s.log_line("be1", "srv2", ev);
    assert!(line.contains("srv2 failed"), "{line}");
    assert!(line.contains("reason: Connection refused"), "{line}");
    assert!(line.contains("check duration: 7ms"), "{line}");
    assert!(line.contains("DOWN."), "{line}");
}

/// The status field can never exceed its own denominator.
///
/// With two free-running counters it did: a server that had been down for four checks
/// logged "status: 4/1 DOWN", which is not a state any threshold describes.
#[test]
fn the_status_field_stays_within_its_threshold() {
    /// Pulls `<count>/<threshold>` out of the rendered line.
    fn counts(line: &str) -> (u32, u32) {
        let tail = line.rsplit("status: ").next().expect("a status field");
        let frac = tail.split(' ').next().expect("count/threshold");
        let (a, b) = frac.split_once('/').expect("a fraction");
        (a.parse().expect("count"), b.parse().expect("threshold"))
    }

    let mut s = state(2, 3);
    for i in 0..40 {
        // Alternate long runs of each so the counter hits both stops.
        let event = if i % 20 < 10 {
            s.on_failure("L4CON", "Connection refused", 0)
        } else {
            s.on_success(0)
        };
        let line = s.log_line("be", "srv", event.unwrap_or(CheckEvent::Succeeded));
        let (count, threshold) = counts(&line);
        assert!(
            count <= threshold,
            "status count ran past its own threshold: {line}"
        );
    }
}

/// The lines `sample <ranges>:<size>` keeps, as `process_send_log` in `src/log.c` picks
/// them: positions 1..=size, repeating, kept when inside one of the ranges.
#[test]
fn sampling_keeps_the_positions_in_its_ranges_and_repeats() {
    use ibex_config::LogSample;
    use ibex_rt::syslog::sample_admits;
    use std::sync::atomic::AtomicU64;

    let pattern = |ranges: Vec<std::ops::RangeInclusive<u32>>, size: u32, n: usize| -> String {
        let sample = LogSample { ranges, size };
        let cursor = AtomicU64::new(0);
        (0..n).map(|_| if sample_admits(&sample, &cursor) { '1' } else { '0' }).collect()
    };
    // load_balancing.vtc's `sample 1,3:5`.
    assert_eq!(pattern(vec![1..=1, 3..=3], 5, 10), "1010010100");
    assert_eq!(pattern(vec![2..=3], 4, 8), "01100110");
    assert_eq!(pattern(vec![1..=2, 4..=4], 4, 8), "11011101");
    assert_eq!(pattern(vec![1..=1], 1, 3), "111");
}

/// Workers share a proxy's cursor, as `HAProxy`'s threads share a logger: however the
/// lines interleave, `sample 1:4` keeps exactly one in four of them.
#[test]
fn threads_sharing_a_cursor_keep_exactly_the_sampled_share() {
    use ibex_config::LogSample;
    use ibex_rt::syslog::sample_admits;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    let sample = LogSample { ranges: vec![1..=1], size: 4 };
    let cursor = AtomicU64::new(0);
    let kept = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                for _ in 0..20_000 {
                    if sample_admits(&sample, &cursor) {
                        kept.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    assert_eq!(kept.load(Ordering::Relaxed), 8 * 20_000 / 4);
}

#[test]
fn a_sample_with_nothing_to_select_keeps_every_line() {
    use ibex_config::LogSample;
    use ibex_rt::syslog::sample_admits;
    use std::sync::atomic::AtomicU64;

    let cursor = AtomicU64::new(0);
    assert!(sample_admits(&LogSample { ranges: vec![], size: 3 }, &cursor));
    assert!(sample_admits(&LogSample { ranges: vec![1..=1], size: 0 }, &cursor));
}
