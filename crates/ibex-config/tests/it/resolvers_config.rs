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
}

/// `last` is the server-state file's address (T490); with no file it gives nothing and the
/// next method is tried (`HAProxy`, measured: "no method found" when it is the only one).
#[test]
fn init_addr_last_without_a_state_file_gives_nothing() {
    assert_eq!(
        alerts(&backend("  server s1 nosuch.invalid:80 init-addr last,libc")),
        ["{at} : 'server l/s1' : could not resolve address 'nosuch.invalid'.", "Failed to initialize server(s) addr."]
    );
    assert_eq!(
        alerts(&backend("  default-server init-addr last\n  server s1 nosuch.invalid:80")),
        ["{at} : 'server l/s1' : no method found to resolve address 'nosuch.invalid'.", "Failed to initialize server(s) addr."]
    );
    let cfg = parse_str(&backend("  server s1 nosuch.invalid:80 init-addr last,libc,none")).expect("parses");
    assert!(cfg.backends[0].server_extras.unresolved(0));
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

/// T487, measured on `HAProxy` (`haproxy -c`, 2026-10-31): an SRV name (`_...`) is accepted
/// with `resolvers`, with or without a port, and with `init-addr none`; libc is no method for
/// it, so without `resolvers` (default `init-addr last,libc`) or with `init-addr libc` there is
/// no method left.
#[test]
fn srv_record_names_need_a_resolvers_section() {
    let rs = "resolvers r\n  nameserver ns1 127.0.0.1:53\n";
    let no_method = ["{at} : 'server l/s1' : no method found to resolve address '_http._tcp.x'.", "Failed to initialize server(s) addr."];
    assert_eq!(alerts(&backend("  server s1 _http._tcp.x:80")), no_method);
    assert_eq!(alerts(&format!("{rs}{}", backend("  server s1 _http._tcp.x resolvers r init-addr libc"))), no_method);
    for line in ["  server s1 _http._tcp.x:80 resolvers r", "  server s1 _http._tcp.x resolvers r", "  server s1 _http._tcp.x resolvers r init-addr none"] {
        parse_str(&format!("{rs}{}", backend(line))).unwrap_or_else(|e| panic!("{line}: {}", e.message));
    }
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
    for kw in ["resolve-prefer ipv4", "resolve-prefer ipv6", "resolve-net 10.0.0.0/8,2001:db8::/32,10.1.2.3,2001:db8::1", "resolve-opts", "resolve-opts allow-dup-ip,prevent-dup-ip,ignore-weight"] {
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
}

/// T488, measured with `haproxy -c`: the address prefixes of `nameserver` choose the transport
/// (`tcp@`, `tcp4@`, `tcp6@`, `stream+`: TCP; `udp@`, `udp4@`, `udp6@`, `dgram+`: UDP, no
/// fallback; `ip@`, `ipv4@`, `ipv6@` and none: UDP with the fallback); a `4`/`6` form refuses
/// the other family; any other prefix is refused here (`mptcp@`, `unix@`...: not implemented).
#[test]
fn nameserver_prefixes_choose_the_transport() {
    use ibex_config::ast::NsTransport::{Default, Tcp, Udp};
    let transport = |addr: &str| {
        let cfg = parse_str(&with_resolvers(&format!("  nameserver ns2 {addr}"))).expect("accepted");
        let ns = cfg.resolvers[0].nameservers[1].clone();
        (ns.transport, ns.addr.to_string())
    };
    for (addr, want, shown) in [
        ("tcp@127.0.0.1:53", Tcp, "127.0.0.1:53"),
        ("tcp4@127.0.0.1:54", Tcp, "127.0.0.1:54"),
        ("tcp6@[::1]:53", Tcp, "[::1]:53"),
        ("stream+127.0.0.1:53", Tcp, "127.0.0.1:53"),
        ("udp@127.0.0.1:53", Udp, "127.0.0.1:53"),
        ("udp4@127.0.0.1:53", Udp, "127.0.0.1:53"),
        ("udp6@[::1]:53", Udp, "[::1]:53"),
        ("dgram+127.0.0.1:53", Udp, "127.0.0.1:53"),
        ("ip@127.0.0.1:53", Default, "127.0.0.1:53"),
        ("ipv4@127.0.0.1:53", Default, "127.0.0.1:53"),
        ("ipv6@[::1]:53", Default, "[::1]:53"),
        ("127.0.0.1:53", Default, "127.0.0.1:53"),
    ] {
        assert_eq!(transport(addr), (want, shown.to_string()), "{addr}");
    }
    for (addr, host) in [
        ("tcp4@[::1]:53", "[::1]"),
        ("udp4@[::1]:53", "[::1]"),
        ("ipv4@[::1]:53", "[::1]"),
        ("ipv6@127.0.0.1:53", "127.0.0.1"),
        ("tcp6@127.0.0.1:53", "127.0.0.1"),
        ("udp6@127.0.0.1:53", "127.0.0.1"),
    ] {
        assert_eq!(refused(&with_resolvers(&format!("  nameserver ns2 {addr}"))), format!("'nameserver ns2' : invalid address: '{host}' in '{addr}'"), "{addr}");
    }
    assert_eq!(refused(&with_resolvers("  nameserver ns2 tcp@127.0.0.1")), "'nameserver ns2' : missing port specification in 'tcp@127.0.0.1'");
    assert_eq!(refused(&with_resolvers("  nameserver ns2 tcp@53")), "'nameserver ns2' : missing port specification in 'tcp@53'");
    assert!(refused(&with_resolvers("  nameserver ns2 mptcp@127.0.0.1:53")).contains("'mptcp@' is not implemented"));
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
    assert_eq!(ns("nameserver ns2 mptcp@127.0.0.1:53"), "'nameserver ns2' : address prefix 'mptcp@' is not implemented");
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

// --- server-template (T486, A.t12): `parse_server` once per slot, `SRV_PARSE_TEMPLATE` ---

#[test]
fn server_template_expands_to_numbered_servers_sharing_one_name_and_its_parameters() {
    let cfg = parse_str(&with_resolvers("").replace(
        "server s1 127.0.0.1:80",
        "server-template srv 3 multi.test:80 resolvers r check inter 5s weight 7 resolve-opts allow-dup-ip\n  server-template web 2-4 a1.test resolvers r backup",
    ))
    .unwrap_or_else(|e| panic!("{}", e.message));
    let be = &cfg.backends[0];
    let ids: Vec<&str> = be.servers.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, ["srv1", "srv2", "srv3", "web2", "web3", "web4"]);
    for s in &be.servers[..3] {
        assert!(s.check && s.weight == Some(7) && !s.backup, "{s:?}");
        assert_eq!(s.addr.port(), 80);
        assert_eq!(s.inter, Some(std::time::Duration::from_secs(5)));
    }
    assert!(be.servers[3..].iter().all(|s| s.backup && s.addr.port() == 0 && !s.check));
    let names = &be.server_extras.names;
    assert_eq!(names.iter().map(|n| n.index).collect::<Vec<_>>(), [0, 1, 2, 3, 4, 5]);
    assert!(names[..3].iter().all(|n| &*n.fqdn == "multi.test" && n.resolvers.as_deref() == Some("r") && n.resolve.allow_dup_ip));
    assert!(names[3..].iter().all(|n| &*n.fqdn == "a1.test" && !n.resolve.allow_dup_ip));
    assert_eq!(be.server_extras.resolvers_refs.len(), 6);
}

#[test]
fn server_template_inherits_default_server_and_from_none_drops_it() {
    let cfg = parse_str(&backend(
        "  default-server check weight 3\n  server-template a 2 localhost:80\n  server-template b 1 localhost:80 from none\n  server-template c 1 127.0.0.1:81",
    ))
    .unwrap_or_else(|e| panic!("{}", e.message));
    let s = &cfg.backends[0].servers;
    assert_eq!(s.iter().map(|s| (s.id.as_str(), s.check, s.weight)).collect::<Vec<_>>(), [("a1", true, Some(3)), ("a2", true, Some(3)), ("b1", false, None), ("c1", true, Some(3))]);
    // A template on an address is not a name: the slot keeps it, no resolution.
    assert_eq!(s[3].addr, "127.0.0.1:81".parse().unwrap());
    assert_eq!(cfg.backends[0].server_extras.names.len(), 3);
}

#[test]
fn server_template_works_in_a_listen_section_and_without_resolvers() {
    let cfg = parse_str(&format!("{HEAD}  server-template s 2 localhost:80\n").replace("backend l", "listen l\n  bind 127.0.0.1:0"))
        .unwrap_or_else(|e| panic!("{}", e.message));
    let l = &cfg.listens[0];
    assert_eq!(l.servers.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), ["s1", "s2"]);
    // Both slots took libc's answer (A.t12 without `resolvers`).
    assert_eq!(l.servers[0].addr.ip(), libc_first("localhost"));
    assert_eq!(l.servers[1].addr.ip(), libc_first("localhost"));
}

#[test]
fn server_template_refusals_are_haproxys() {
    let t = |args: &str| refused(&backend(&format!("  server-template {args}")));
    assert_eq!(t("s 0 a.test:80"), "Wrong server-template number or range arg '0'.");
    assert_eq!(t("s 3-1 a.test:80"), "Wrong server-template number or range arg '3-1'.");
    assert_eq!(t("s x a.test:80"), "Wrong server-template number or range arg 'x'.");
    assert_eq!(t("s -3 a.test:80"), "Wrong server-template number or range arg '-3'.");
    assert_eq!(t("s 2"), "'server-template' expects <prefix> <nb | range> <addr>[:<port>] as arguments.");
    assert_eq!(t(""), "'server-template' expects <prefix> <nb | range> <addr>[:<port>] as arguments.");
    assert_eq!(t("s 2 a.test:80 from"), "'server-template l/s' : from: missing value.");
    assert_eq!(t("s 2 a.test:80 from bogus"), "'server-template l/s' : invalid 'bogus' value for 'from' keyword.");
    assert!(t("s 2 a.test:80 from be:l").contains("from"), "refused: Ibex has no server defaults to copy from another backend");
    assert!(t("s 2 a.test:80 from srv:s1").contains("from"));
    // An SRV name is accepted (T487, `srv_record_names_need_a_resolvers_section`).
    parse_str(&format!("resolvers r\n  nameserver ns1 127.0.0.1:53\n{}", backend("  server-template s 2 _http._tcp.x resolvers r"))).expect("accepted");
    // A slot that clashes with a server already there.
    let m = refused(&backend("  server s1 127.0.0.1:80\n  server-template s 2 a.test:80"));
    assert_eq!(m, "'server-template l/s' : another server named 's1' was already defined at line 7, please use a distinct name.");
    let m = refused(&backend("  server-template s 2 a.test:80\n  server-template s 2-3 a.test:80"));
    assert_eq!(m, "'server-template l/s' : another server named 's2' was already defined at line 7, please use a distinct name.");
}

/// Two `server` lines with one name (T513): `HAProxy` refuses at the second
/// (`[f:9] : 'server l/s1' : another server named 's1' was already defined at line 7, ...`).
#[test]
fn a_server_name_used_twice_is_refused_as_haproxy() {
    let e = parse_str(&backend("  server s1 127.0.0.1:80\n  server s2 127.0.0.1:80\n  server s1 127.0.0.1:81")).expect_err("refused");
    assert_eq!(e.message, "'server l/s1' : another server named 's1' was already defined at line 7, please use a distinct name.");
    assert_eq!(e.line, 9);
    // A slot of a template first, then a `server` line with its name.
    let m = refused(&backend("  server-template s 2 127.0.0.1:80\n  server s2 127.0.0.1:81"));
    assert_eq!(m, "'server l/s2' : another server named 's2' was already defined at line 7, please use a distinct name.");
    // The same name in two backends is fine.
    let two = format!("{}backend m\n  server s1 127.0.0.1:81\n", backend("  server s1 127.0.0.1:80"));
    assert!(parse_str(&two).is_ok());
}

#[test]
fn server_template_is_not_a_defaults_or_frontend_keyword() {
    let e = parse_str("defaults\n  server-template s 2 a.test:80\n").expect_err("refused");
    assert!(e.message.contains("server-template"), "{}", e.message);
}

#[test]
fn server_template_alerts_name_the_template_for_its_first_slot() {
    // Measured: `server-template b/s` for the first slot, `server b/s2` for the others.
    assert_eq!(
        alerts(&backend("  server-template s 2 nosuch.invalid:80")),
        [
            "{at} : 'server-template l/s' : could not resolve address 'nosuch.invalid'.",
            "{at} : 'server l/s2' : could not resolve address 'nosuch.invalid'.",
            "Failed to initialize server(s) addr.",
        ]
    );
}

/// T489, `dns-accept-family` (`cfg_parse_dns_accept_family`), measured with `haproxy -c` on
/// 3.5-dev8 (cases `tools/battery/repro/vv-dns/t489/famerr*.json`): `HAProxy` cuts the argument
/// at each comma in place, so the refusal names the list's first item whichever is wrong; a
/// trailing comma ends the list; `auto` anywhere wins.
#[test]
fn dns_accept_family_is_parsed_as_haproxy() {
    use ibex_config::ast::DnsAcceptFamily;
    let family = |arg: &str| parse_str(&format!("global\n  dns-accept-family {arg}\n{HEAD}")).map(|c| c.global.unwrap_or_default().dns_accept_family).map_err(|e| e.message);
    let f = |ipv4, ipv6, auto| Ok(DnsAcceptFamily { ipv4, ipv6, auto });
    assert_eq!(parse_str(&backend("")).expect("accepted").global.unwrap_or_default().dns_accept_family, DnsAcceptFamily { ipv4: false, ipv6: false, auto: true });
    assert_eq!(family("ipv4"), f(true, false, false));
    assert_eq!(family("ipv6"), f(false, true, false));
    assert_eq!(family("ipv4,ipv6"), f(true, true, false));
    assert_eq!(family("ipv4,"), f(true, false, false));
    assert_eq!(family("auto,ipv6"), f(false, true, true));
    let usage = |got: &str| Err(format!("'dns-accept-family' expects a comma-delimited list of 'ipv4' and 'ipv6' but got '{got}'."));
    assert_eq!(family("foo"), usage("foo"));
    assert_eq!(family("IPV4"), usage("IPV4"));
    assert_eq!(family("ipv4,,ipv6"), usage("ipv4"));
    assert_eq!(family("ipv4,foo"), usage("ipv4"));
    assert_eq!(family(",ipv4"), usage(""));
    assert_eq!(family(""), usage(""));
    assert_eq!(family("ipv4 ipv6"), Err("'dns-accept-family' cannot handle unexpected argument 'ipv6'.".to_string()));
}

/// T489, `parse-resolv-conf` on a file (`parse_resolve_conf`, `resolvers.c:3598`), measured on
/// 3.5-dev8 with this file bind-mounted on `/etc/resolv.conf` (`unshare -rm`): only lines that
/// start with `nameserver` and a blank count; no address is a warning, so is an address that
/// is not one (`1.2.3.4#53`) and a name already taken (the address is the name); a name libc
/// resolves is a nameserver; port 53; the last line needs no newline. A file that cannot be
/// read: `failed to open /etc/resolv.conf.`
#[test]
fn parse_resolv_conf_reads_nameserver_lines_as_haproxy() {
    let text = "search x\nnameserver 10.0.0.1\nnameserver\nnameserver   \nnameserverX 1.2.3.4\n  nameserver 1.1.1.1\n\
                nameserver\t10.0.0.2 extra\nnameserver 1.2.3.4#53\nnameserver ::1\nnameserver 10.0.0.1\n\
                nameserver localhost\n#nameserver 9.9.9.9\nnameserver ns1\nnameserver 10.0.0.3";
    let path = std::env::temp_dir().join(format!("ibex_t489_resolv_{}.conf", std::process::id()));
    std::fs::write(&path, text).expect("write");
    let mut r = ibex_config::ast::ResolversSection::new("r".into(), 1);
    r.nameservers.push(parse_str(&with_resolvers("")).expect("ok").resolvers[0].nameservers[0].clone());
    let warnings = ibex_config::parse_resolv_conf(&mut r, path.to_str().expect("path")).expect("read");
    let _ = std::fs::remove_file(&path);
    let names: Vec<String> = r.nameservers.iter().map(|n| format!("{} {}", n.name, n.addr)).collect();
    let lh = std::net::SocketAddr::new(libc_first("localhost"), 53);
    assert_eq!(names, ["ns1 127.0.0.1:53".to_string(), "10.0.0.1 10.0.0.1:53".into(), "10.0.0.2 10.0.0.2:53".into(), "::1 [::1]:53".into(), format!("localhost {lh}"), "10.0.0.3 10.0.0.3:53".into()]);
    assert!(r.nameservers[1..].iter().all(|n| n.from_resolv_conf && n.transport == ibex_config::ast::NsTransport::Default));
    assert_eq!(r.nameservers[1].line, 2);
    assert_eq!(
        warnings,
        [
            "parsing [/etc/resolv.conf:3] : nameserver line is missing address.",
            "parsing [/etc/resolv.conf:4] : nameserver line is missing address.",
            "parsing [/etc/resolv.conf:8] : address '1.2.3.4#53' could not be recognized, nameserver will be excluded.",
            "Parsing [/etc/resolv.conf:10] : generated name for /etc/resolv.conf nameserver '10.0.0.1' conflicts with another nameserver (declared at /etc/resolv.conf:2), it appears to be a duplicate and will be excluded.",
            "Parsing [/etc/resolv.conf:13] : generated name for /etc/resolv.conf nameserver 'ns1' conflicts with another nameserver (declared at {file}:2), it appears to be a duplicate and will be excluded.",
        ]
    );
    assert_eq!(ibex_config::parse_resolv_conf(&mut r, "/nonexistent/resolv.conf"), Err("failed to open /etc/resolv.conf.".to_string()));
}

/// A.t15b: `parse-resolv-conf` inserts the system's nameservers where it stands (here before
/// `ns1`, after `ns0`), from `/etc/resolv.conf` itself.
#[test]
fn parse_resolv_conf_inserts_the_systems_nameservers_in_place() {
    let Ok(text) = std::fs::read_to_string(ibex_config::RESOLV_CONF) else { return };
    let mut want = vec!["ns0".to_string()];
    let mut sys = ibex_config::ast::ResolversSection::new("r".into(), 1);
    let _ = ibex_config::parse_resolv_conf(&mut sys, ibex_config::RESOLV_CONF);
    want.extend(sys.nameservers.iter().filter(|n| n.name != "ns0" && n.name != "ns1").map(|n| n.name.clone()));
    want.push("ns1".into());
    let cfg = parse_str(&format!("resolvers r\n  nameserver ns0 127.0.0.1:5300\n  parse-resolv-conf\n  nameserver ns1 127.0.0.1:5301\n{HEAD}  server s1 127.0.0.1:80\n")).expect("accepted");
    let got: Vec<String> = cfg.resolvers[0].nameservers.iter().map(|n| n.name.clone()).collect();
    assert_eq!(got, want, "{text}");
}
