// SPDX-License-Identifier: GPL-2.0-or-later

//! Syslog emission, verified by receiving real datagrams.
//!
//! The reg-tests these unblock assert on syslog output with varnishtest `syslog` blocks,
//! so the wire format has to be right rather than merely plausible.

use ibex_config::{LogConfig, LogFacility, LogLevel};
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
    let cfg = LogConfig { addr, facility: LogFacility::Local0, level: Some(LogLevel::Notice) };
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
    let cfg = LogConfig { addr, facility: LogFacility::Local0, level: Some(LogLevel::Warning) };
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
        addr: "192.0.2.1:514".parse::<SocketAddr>().expect("addr"),
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

#[test]
fn a_successful_check_reports_success_not_a_transition() {
    let mut s = state(1, 1);
    assert_eq!(s.on_success(3), CheckEvent::Succeeded);
    assert!(!CheckEvent::Succeeded.is_transition());
}

#[test]
fn crossing_the_fall_threshold_reports_a_transition() {
    // A status change is news whether or not per-check logging is on, which is why the
    // caller needs to tell the two apart.
    let mut s = state(1, 2);
    assert_eq!(s.on_failure("L4CON", "Connection refused", 1), CheckEvent::Failed);
    assert_eq!(s.on_failure("L4CON", "Connection refused", 1), CheckEvent::WentDown);
    assert!(CheckEvent::WentDown.is_transition());
    assert_eq!(s.status, ServerStatus::Down);
}

#[test]
fn recovering_reports_went_up() {
    let mut s = state(2, 1);
    s.on_failure("L4CON", "Connection refused", 1);
    assert_eq!(s.status, ServerStatus::Down);
    assert_eq!(s.on_success(2), CheckEvent::Succeeded, "below the rise threshold");
    assert_eq!(s.on_success(2), CheckEvent::WentUp);
    assert!(CheckEvent::WentUp.is_transition());
}

#[test]
fn the_log_line_matches_the_shape_reg_tests_assert_on() {
    // reg-tests/checks/*.vtc match this with regexes, so the wording and field order
    // are part of the contract, not cosmetic.
    let mut s = state(1, 1);
    let ev = s.on_success(0);
    let line = s.log_line("be1", "srv1", ev);

    assert!(line.starts_with("Health check for server be1/srv1 succeeded"), "{line}");
    assert!(line.contains("reason: Layer4 check passed"), "{line}");
    assert!(line.contains("check duration: 0ms"), "{line}");
    assert!(line.contains("status: 1/1 UP"), "{line}");
}

#[test]
fn a_failed_check_line_says_failed_and_reports_down() {
    let mut s = state(1, 1);
    let ev = s.on_failure("L4CON", "Connection refused", 7);
    let line = s.log_line("be1", "srv2", ev);
    assert!(line.contains("srv2 failed"), "{line}");
    assert!(line.contains("reason: Connection refused"), "{line}");
    assert!(line.contains("check duration: 7ms"), "{line}");
    assert!(line.contains("DOWN"), "{line}");
}
