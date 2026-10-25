// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Hostnames on `server` lines (resolved by libc while the configuration loads),
//! `init-addr`, the `resolvers` section and the server's `resolve-*` keywords (T483). The
//! messages are the reference `HAProxy`'s (3.5-dev8-885761-29, 2026-10-25), measured with
//! `haproxy -c`; the rows are in `docs/design/dns-2026-10-25.md`, appendix A (A.t0, t1a-t1f,
//! t15d, t483-*).

use ibex_config::parse_str;

const HEAD: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nbackend l\n";

fn backend(lines: &str) -> String {
    format!("{HEAD}{lines}\n")
}

fn with_resolvers(section: &str) -> String {
    format!("resolvers r\n  nameserver ns1 127.0.0.1:53\n{section}\n{HEAD}  server s1 127.0.0.1:80\n")
}

fn refused(cfg: &str) -> String {
    parse_str(cfg).expect_err("refused").message
}

fn alerts(cfg: &str) -> Vec<String> {
    parse_str(cfg).expect_err("refused").alerts.into_iter().map(|(_, t)| t).collect()
}

/// The first address libc gives for `name`, as `getaddrinfo` orders them (`HAProxy` takes the
/// first, `str2ip2`): `::1` for `localhost` on a host whose `/etc/hosts` lists it first (A.t1f).
fn libc_first(name: &str) -> std::net::IpAddr {
    use std::net::ToSocketAddrs;
    (name, 0).to_socket_addrs().expect("resolves").next().expect("one address").ip()
}

// --- A.t0, A.t1d: a name nothing resolves is fatal, with HAProxy's two alerts ---

#[test]
fn an_unresolvable_name_is_fatal_with_two_alerts() {
    assert_eq!(
        alerts(&backend("  server s1 nosuch.invalid:80")),
        ["{at} : 'server l/s1' : could not resolve address 'nosuch.invalid'.", "Failed to initialize server(s) addr."]
    );
    // `init-addr libc` alone: the same (A.t1d).
    assert_eq!(
        alerts(&backend("  server s1 nosuch.invalid:80 init-addr libc")),
        ["{at} : 'server l/s1' : could not resolve address 'nosuch.invalid'.", "Failed to initialize server(s) addr."]
    );
    // A name libc is never asked about (`resolv_hostname_validation`) fails the same way.
    assert_eq!(
        alerts(&backend("  server s1 bad!name:80")),
        ["{at} : 'server l/s1' : could not resolve address 'bad!name'.", "Failed to initialize server(s) addr."]
    );
}

#[test]
fn every_failing_server_has_its_alert_then_one_summary() {
    // d6: both servers, then the summary once; d5: a server with `none` is not one of them.
    assert_eq!(
        alerts(&backend("  server s1 nosuch.invalid:80\n  server s2 other.invalid:80")),
        [
            "{at} : 'server l/s1' : could not resolve address 'nosuch.invalid'.",
            "{at} : 'server l/s2' : could not resolve address 'other.invalid'.",
            "Failed to initialize server(s) addr.",
        ]
    );
    assert_eq!(
        alerts(&backend("  server s1 nosuch.invalid:80 init-addr none\n  server s2 other.invalid:80")),
        ["{at} : 'server l/s2' : could not resolve address 'other.invalid'.", "Failed to initialize server(s) addr."]
    );
}

#[test]
fn a_name_that_is_not_a_dns_name_is_refused_while_parsing() {
    // `srv_prepare_for_resolution`: an empty label.
    assert_eq!(refused(&backend("  server s1 a..b:80")), "'server s1' : Can't create DNS resolution for server 's1'");
    assert_eq!(refused(&backend("  server s1 .a:80 init-addr none")), "'server s1' : Can't create DNS resolution for server 's1'");
}

// --- init-addr: the order of the methods (A.t1b-t1e) ---

#[test]
fn init_addr_none_starts_the_server_without_an_address() {
    let cfg = parse_str(&backend("  server s1 nosuch.invalid:80 init-addr none")).expect("parses");
    assert!(cfg.backends[0].servers[0].addr.ip().is_unspecified());
    assert_eq!(cfg.backends[0].servers[0].addr.port(), 80);
}

#[test]
fn init_addr_ip_is_the_fallback() {
    let cfg = parse_str(&backend("  server s1 nosuch.invalid:80 init-addr 10.9.9.9")).expect("parses");
    assert_eq!(cfg.backends[0].servers[0].addr, "10.9.9.9:80".parse().unwrap());
    // a12: the address first is used at once.
    let cfg = parse_str(&backend("  server s1 nosuch.invalid:80 init-addr 10.9.9.9,none")).expect("parses");
    assert_eq!(cfg.backends[0].servers[0].addr, "10.9.9.9:80".parse().unwrap());
}

#[test]
fn init_addr_refusals_are_haproxys() {
    assert_eq!(
        refused(&backend("  server s1 nosuch.invalid:80 init-addr libc,foo")),
        "'server s1' : 'init-addr' : unknown init-addr method 'foo', supported methods are 'libc', 'last', 'none'.."
    );
    assert_eq!(
        refused(&backend("  server s1 nosuch.invalid:80 init-addr 1.1.1.1,2.2.2.2")),
        "'server s1' : 'init-addr' : initial address already specified, cannot add '2.2.2.2'.."
    );
    assert_eq!(
        refused(&backend("  server s1 nosuch.invalid:80 init-addr libc,libc,libc,libc,libc,libc,libc,libc,libc,libc,libc")),
        "'server s1' : 'init-addr' : too many init-addr methods when trying to add 'libc'."
    );
    // The user's decision (2026-10-25): `last` needs the server-state file (T490).
    let last = refused(&backend("  server s1 nosuch.invalid:80 init-addr last,libc"));
    assert!(last.contains("'init-addr' : method 'last' is not supported"), "{last}");
    assert!(refused(&backend("  default-server init-addr last\n  server s1 nosuch.invalid:80")).contains("method 'last'"));
}

#[test]
fn init_addr_without_its_argument_is_the_default() {
    // a9: `init-addr` and nothing: no method, so `last,libc`.
    assert_eq!(
        alerts(&backend("  server s1 nosuch.invalid:80 init-addr")),
        ["{at} : 'server l/s1' : could not resolve address 'nosuch.invalid'.", "Failed to initialize server(s) addr."]
    );
}

#[test]
fn init_addr_is_inherited_from_default_server() {
    // a10.
    let cfg = parse_str(&backend("  default-server init-addr none\n  server s1 nosuch.invalid:80")).expect("parses");
    assert!(cfg.backends[0].servers[0].addr.ip().is_unspecified());
}

#[test]
fn init_addr_on_an_ip_address_does_nothing() {
    // a14: only a server with a name is resolved.
    let cfg = parse_str(&backend("  server s1 127.0.0.1:80 init-addr none")).expect("parses");
    assert_eq!(cfg.backends[0].servers[0].addr, "127.0.0.1:80".parse().unwrap());
}

#[test]
fn localhost_is_what_libc_says_first() {
    // A.t1f: HAProxy gives `::1` here; the first `getaddrinfo` answer, not 127.0.0.1.
    let cfg = parse_str(&backend("  server s1 localhost:80\n  server s2 localhost")).expect("parses");
    assert_eq!(cfg.backends[0].servers[0].addr, std::net::SocketAddr::new(libc_first("localhost"), 80));
    assert_eq!(cfg.backends[0].servers[1].addr, std::net::SocketAddr::new(libc_first("localhost"), 0));
}

#[test]
fn srv_record_names_are_refused_until_t487() {
    let m = refused(&backend("  server s1 _http._tcp.x:80"));
    assert!(m.contains("SRV"), "{m}");
}

// --- server resolve-* keywords: HAProxy's argument checks (d7-d13) ---

#[test]
fn resolve_keywords_check_their_arguments() {
    let s = |kw: &str| refused(&backend(&format!("  server s1 127.0.0.1:80 {kw}")));
    assert_eq!(s("resolve-prefer ipv5"), "'server s1' : 'resolve-prefer' expects either ipv4 or ipv6 as argument..");
    assert_eq!(s("resolve-prefer"), "'server s1' : 'resolve-prefer' expects either ipv4 or ipv6 as argument..");
    assert_eq!(s("resolve-net 10.0.0.0/8,foo"), "'server s1' : 'resolve-net' invalid network 'foo'..");
    assert_eq!(s("resolve-net"), "'server s1' : 'resolve-net' expects a list of networks..");
    assert_eq!(s("resolve-net 1.0.0.0/8,2.0.0.0/8,3.0.0.0/8,4.0.0.0/8,5.0.0.0/8,6.0.0.0/8"), "'server s1' : 'resolve-net' exceed 5 networks..");
    assert_eq!(
        s("resolve-opts allow-dup-ip,bar"),
        "'server s1' : 'resolve-opts' : unknown resolve-opts option 'bar', supported methods are 'allow-dup-ip', 'ignore-weight', and 'prevent-dup-ip'.."
    );
    // Accepted alone, as HAProxy does (they only act with `resolvers`, T484).
    for kw in ["resolve-prefer ipv4", "resolve-prefer ipv6", "resolve-net 10.0.0.0/8,2001:db8::/32,10.1.2.3", "resolve-opts", "resolve-opts allow-dup-ip,prevent-dup-ip,ignore-weight"] {
        parse_str(&backend(&format!("  server s1 127.0.0.1:80 {kw}"))).unwrap_or_else(|e| panic!("{kw}: {}", e.message));
        parse_str(&backend(&format!("  default-server {kw}\n  server s1 127.0.0.1:80"))).unwrap_or_else(|e| panic!("{kw}: {}", e.message));
    }
    assert_eq!(
        refused(&backend("  default-server resolve-prefer ipv5\n  server s1 127.0.0.1:80")),
        "'resolve-prefer' expects either ipv4 or ipv6 as argument.."
    );
}

#[test]
fn a_servers_resolvers_and_resolve_options_are_kept() {
    let cfg = parse_str(
        &with_resolvers("")
            .replace("server s1 127.0.0.1:80", "default-server resolvers r resolve-opts allow-dup-ip
  server s1 a1.test:80 resolve-prefer ipv4 resolve-net 10.0.0.0/255.255.0.0,2001:db8::/32
  server s2 a2.test:80 resolve-opts prevent-dup-ip
  server s3 127.0.0.1:80 resolvers r"),
    )
    .unwrap_or_else(|e| panic!("{}", e.message));
    let ex = &cfg.backends[0].server_extras;
    let (s1, s2) = (&ex.names[0], &ex.names[1]);
    assert_eq!((s1.resolvers.as_deref(), s1.resolve.prefer_ipv4, s1.resolve.allow_dup_ip), (Some("r"), true, true));
    assert_eq!(s1.resolve.nets, vec![("10.0.0.0".parse().unwrap(), 16), ("2001:db8::".parse().unwrap(), 32)]);
    assert_eq!((s2.resolvers.as_deref(), s2.resolve.prefer_ipv4, s2.resolve.allow_dup_ip), (Some("r"), false, false));
    // `none` comes with `resolvers` (`srv_iterate_initaddr`): the names did not resolve.
    assert!(s1.unresolved && s2.unresolved);
    // Every server's section is checked, an address's too.
    assert_eq!(ex.resolvers_refs.iter().map(|r| r.0).collect::<Vec<_>>(), vec![0, 1, 2]);
    let e = parse_str(&with_resolvers("").replace("server s1 127.0.0.1:80", "server s1 127.0.0.1:80 resolvers nosuch")).expect_err("refused");
    assert_eq!(e.message, "backend 'l', server 's1': unable to find required resolvers 'nosuch'");
    assert_eq!(refused(&backend("  server s1 127.0.0.1:80 resolvers")), "'server s1' : 'resolvers' expects <resolvers_id> as argument.");
    assert_eq!(refused(&backend("  default-server resolvers")), "'resolvers' expects <resolvers_id> as argument.");
    assert_eq!(refused(&backend("  server s1 127.0.0.1:80 resolve-net 10.0.0.0/33")), "'server s1' : 'resolve-net' invalid network '10.0.0.0/33'..");
    assert_eq!(refused(&backend("  server s1 127.0.0.1:80 resolve-net ::/129")), "'server s1' : 'resolve-net' invalid network '::/129'..");
}

// --- the resolvers section (A.t15d and the t483 rows) ---

#[test]
fn resolvers_section_refusals_are_haproxys() {
    assert_eq!(refused(&with_resolvers("  hold nx foo")), "unexpected character 'f' in argument to <hold>.");
    assert_eq!(
        refused(&with_resolvers("  hold nx")),
        "'hold' expects an <event> and a <time> as arguments.\n<event> can be either 'valid', 'nx', 'refused', 'timeout', or 'other'"
    );
    assert_eq!(
        refused(&with_resolvers("  hold bogus 1s")),
        "'hold' unknown <event>: 'bogus', expects either 'nx', 'timeout', 'valid', 'obsolete' or 'other'."
    );
    assert_eq!(
        refused(&with_resolvers("  hold nx 30d")),
        "timer overflow in argument <nx> to <hold>, maximum value is 2147483647 ms (~24.8 days)."
    );
    assert_eq!(refused(&with_resolvers("  timeout")), "'timeout' expects 'retry' or 'resolve' and <time> as arguments.");
    assert_eq!(refused(&with_resolvers("  timeout resolve")), "'timeout resolve' expects <time> as argument.");
    assert_eq!(
        refused(&with_resolvers("  timeout foo 1s")),
        "'timeout' expects 'retry' or 'resolve' and <time> as arguments got 'foo'."
    );
    assert_eq!(refused(&with_resolvers("  timeout retry 1x")), "unexpected character 'x' in argument to <timeout retry>.");
    assert_eq!(
        refused(&with_resolvers("  timeout resolve 30d")),
        "timer overflow in argument <30d> to <timeout resolve>, maximum value is 2147483647 ms (~24.8 days)."
    );
    assert_eq!(refused(&with_resolvers("  accepted_payload_size")), "'accepted_payload_size' expects <nb> as argument.");
    for bad in ["11", "65536", "abc"] {
        assert_eq!(
            refused(&with_resolvers(&format!("  accepted_payload_size {bad}"))),
            format!("'accepted_payload_size' must be between 12 and 65535 inclusive (was {bad}).")
        );
    }
    assert_eq!(refused(&with_resolvers("  resolve_retries")), "'resolve_retries' expects <nb> as argument.");
    assert_eq!(
        refused(&with_resolvers("  resolution_pool_size 4")),
        "'resolution_pool_size' directive is not supported anymore (it never appeared in a stable release)."
    );
    assert_eq!(refused(&with_resolvers("  foo bar")), "unknown keyword 'foo' in 'resolvers' section");
    // Refused until built: `parse-resolv-conf` (T489), `tcp@` / `udp@` (T488).
    assert!(refused(&with_resolvers("  parse-resolv-conf")).contains("'parse-resolv-conf' is not supported"));
    assert!(refused(&with_resolvers("  nameserver ns2 tcp@127.0.0.1:53")).contains("'tcp@'"));
    assert!(refused(&with_resolvers("  nameserver ns2 udp@127.0.0.1:53")).contains("'udp@'"));
}

#[test]
fn resolvers_section_names_and_nameservers_are_checked() {
    let sec = |s: &str| format!("{s}\n{HEAD}  server s1 127.0.0.1:80\n");
    assert_eq!(refused(&sec("resolvers")), "missing name for resolvers section.");
    assert_eq!(refused(&sec("resolvers r!x")), "character '!' is not permitted in 'resolvers' name 'r!x'.");
    assert_eq!(
        refused(&sec("resolvers r\n  nameserver ns1 127.0.0.1:53\nresolvers r\n  nameserver ns1 127.0.0.1:53")),
        "resolvers 'r' has same name as another resolvers (declared at line 1)."
    );
    let ns = |line: &str| refused(&sec(&format!("resolvers r\n  nameserver ns1 127.0.0.1:53\n  {line}")));
    assert_eq!(ns("nameserver ns1 127.0.0.2:53"), "nameserver 'ns1' has same name as another nameserver (declared at line 2).");
    assert_eq!(ns("nameserver ns2"), "'nameserver' expects <name> and <addr>[:<port>] as arguments.");
    assert_eq!(ns("nameserver n!s 127.0.0.1:53"), "character '!' is not permitted in server name 'n!s'.");
    assert_eq!(ns("nameserver ns2 127.0.0.1"), "'nameserver ns2' : missing port specification in '127.0.0.1'");
    assert_eq!(ns("nameserver ns2 127.0.0.1:0"), "'nameserver ns2' : invalid port '0'");
    assert_eq!(ns("nameserver ns2 127.0.0.1:99999"), "'nameserver ns2' : invalid port '99999'");
    assert_eq!(ns("nameserver ns2 127.0.0.1:53-54"), "'nameserver ns2' : port range not permitted here in '127.0.0.1:53-54'");
    assert_eq!(ns("nameserver ns2 127.0.0.1:+1"), "'nameserver ns2' : port offset not permitted here in '127.0.0.1:+1'");
    // n1, n2, n4.
    assert_eq!(ns("nameserver ns2 127.0.0.1:5x"), "'nameserver ns2' : invalid character 'x' in port number '5x' in '127.0.0.1:5x'");
    assert_eq!(ns("nameserver ns2 [::1"), "'nameserver ns2' : invalid address: '[:' in '[::1'");
    assert_eq!(ns("nameserver ns2 [::1]"), "'nameserver ns2' : missing port specification in '[::1]'");
    // n3: HAProxy takes `ipv4@`; Ibex refuses every prefix but none.
    assert_eq!(ns("nameserver ns2 ipv4@127.0.0.1:53"), "'nameserver ns2' : address prefix 'ipv4@' is not implemented");
    assert_eq!(
        ns("nameserver ns2 nosuch.invalid:53"),
        "'nameserver ns2' : invalid address: 'nosuch.invalid' in 'nosuch.invalid:53'"
    );
}

// --- what reaches the AST ---

#[test]
fn a_resolvers_section_has_haproxys_defaults() {
    // `resolvers_new`, resolvers.c:3787-3793.
    let cfg = parse_str(&with_resolvers("")).expect("parses");
    let r = &cfg.resolvers[0];
    assert_eq!((r.name.as_str(), r.line), ("r", 1));
    assert_eq!(r.nameservers.len(), 1);
    assert_eq!((r.nameservers[0].name.as_str(), r.nameservers[0].addr), ("ns1", "127.0.0.1:53".parse().unwrap()));
    assert_eq!((r.resolve_retries, r.accepted_payload_size), (3, 512));
    assert_eq!((r.timeout_resolve.as_millis(), r.timeout_retry.as_millis()), (1000, 1000));
    let h = r.hold;
    assert_eq!(
        [h.valid, h.nx, h.other, h.refused, h.timeout, h.obsolete].map(|d| d.as_millis()),
        [10_000, 30_000, 30_000, 30_000, 30_000, 0]
    );
}

#[test]
fn every_resolvers_keyword_reaches_the_section() {
    let cfg = parse_str(&with_resolvers(
        "  nameserver ns2 [::1]:5353\n  nameserver ns3 localhost:53\n  resolve_retries 5\n  timeout resolve 2s\n  timeout retry 500ms\n  \
         hold valid 1s\n  hold nx 2s\n  hold other 3s\n  hold refused 4s\n  hold timeout 5s\n  hold obsolete 6s\n  accepted_payload_size 4096",
    ))
    .expect("parses");
    let r = &cfg.resolvers[0];
    assert_eq!(r.nameservers[1].addr, "[::1]:5353".parse().unwrap());
    // A name resolves by libc, as `str2sa_range(.., PA_O_RESOLVE)` (r9).
    assert_eq!(r.nameservers[2].addr, std::net::SocketAddr::new(libc_first("localhost"), 53));
    assert_eq!((r.resolve_retries, r.accepted_payload_size), (5, 4096));
    assert_eq!((r.timeout_resolve.as_millis(), r.timeout_retry.as_millis()), (2000, 500));
    let h = r.hold;
    assert_eq!(
        [h.valid, h.nx, h.other, h.refused, h.timeout, h.obsolete].map(|d| d.as_millis()),
        [1000, 2000, 3000, 4000, 5000, 6000]
    );
    // `atoi`: p6 `512abc` is 512, q2 `abc` is 0, q3 -1 stays.
    let n = |kw: &str| parse_str(&with_resolvers(kw)).expect("parses").resolvers[0].clone();
    assert_eq!(n("  accepted_payload_size 512abc").accepted_payload_size, 512);
    assert_eq!(n("  resolve_retries abc").resolve_retries, 0);
    assert_eq!(n("  resolve_retries -1").resolve_retries, -1);
    // h5, t6: zero is accepted.
    assert!(n("  hold nx 0").hold.nx.is_zero());
}

#[test]
fn a_small_unitless_hold_or_timeout_draws_haproxys_alert_and_loads() {
    // h4, t5: an alert that does not stop the load.
    for (kw, text) in [
        ("  hold nx 50", "'hold nx 50' looks suspiciously small for a value in milliseconds. Please use an explicit unit ('50ms') if that was the intent."),
        ("  timeout resolve 50", "'timeout resolve 50' looks suspiciously small for a value in milliseconds. Please use an explicit unit ('50ms') if that was the intent."),
    ] {
        let cfg = parse_str(&with_resolvers(kw)).expect("loads");
        assert!(cfg.proxy_warnings.iter().any(|w| w.alert && w.text == text && w.line == 3), "{:?}", cfg.proxy_warnings);
    }
}

#[test]
fn a_section_without_nameservers_draws_haproxys_warning() {
    // r2.
    let cfg = parse_str(&format!("resolvers r\n{HEAD}  server s1 127.0.0.1:80\n")).expect("loads");
    assert!(
        cfg.proxy_warnings.iter().any(|w| !w.alert && w.text == "resolvers 'r' {at} has no nameservers configured!" && w.line == 1),
        "{:?}",
        cfg.proxy_warnings
    );
}

#[test]
fn a_server_keeps_its_name_and_whether_it_has_an_address() {
    let cfg = parse_str(&backend("  server s1 localhost:80\n  server s2 nosuch.invalid:80 init-addr libc,none\n  server s3 127.0.0.1:80"))
        .expect("parses");
    let x = &cfg.backends[0].server_extras;
    assert_eq!((x.fqdn(0), x.unresolved(0)), (Some("localhost"), false));
    assert_eq!((x.fqdn(1), x.unresolved(1)), (Some("nosuch.invalid"), true));
    assert_eq!((x.fqdn(2), x.unresolved(2)), (None, false));
    // A17 / a15: the notice HAProxy prints when `none` follows a failure.
    assert!(cfg.proxy_warnings.iter().any(|w| w.text
        == "{at} : 'server l/s2' : could not resolve address 'nosuch.invalid', disabling server."
        && w.style == ibex_config::ast::global::WarnStyle::Notice));
    // a1: `none` first: no attempt, no notice.
    let cfg = parse_str(&backend("  server s1 nosuch.invalid:80 init-addr none")).expect("parses");
    assert!(cfg.proxy_warnings.is_empty(), "{:?}", cfg.proxy_warnings);
    assert!(cfg.backends[0].server_extras.unresolved(0));
    // a13: the address after a failure, with its notice.
    let cfg = parse_str(&backend("  server s1 nosuch.invalid:80 init-addr libc,10.9.9.9")).expect("parses");
    assert!(!cfg.backends[0].server_extras.unresolved(0));
    assert_eq!(
        cfg.proxy_warnings[0].text,
        "{at} : 'server l/s1' : could not resolve address 'nosuch.invalid', falling back to configured address."
    );
}

#[test]
fn a_disabled_backend_is_not_resolved() {
    // `srv_init_addr` skips `PR_FL_DISABLED` proxies.
    parse_str(&backend("  disabled\n  server s1 nosuch.invalid:80")).expect("parses");
}

#[test]
fn dash_dr_starts_an_unresolvable_server_in_maintenance() {
    // `-dr` (`GTUNE_RESOLVE_DONTFAIL`) appends `none`.
    ibex_config::set_resolve_dontfail(true);
    let got = parse_str(&backend("  server s1 nosuch.invalid:80"));
    ibex_config::set_resolve_dontfail(false);
    let cfg = got.expect("parses");
    assert!(cfg.backends[0].server_extras.unresolved(0));
}
