// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T330: mqtt converters

use crate::common;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Alcyon(Child, std::path::PathBuf);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts alcyon on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Alcyon, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let alcyon = Alcyon(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "alcyon did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (alcyon, sock)
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// One request on a new connection; the whole raw answer.
fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";

fn http_cfg(global: &str, body: &str) -> String {
    format!(
        "global\n  stats socket {{sock}} level admin\n{global}\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{body}"
    )
}

/// The body of the answer to `req` (what follows the first empty line).
fn body(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    s.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {s:?}"), |(_, b)| b.to_string())
}

#[test]
fn mqtt_converters() {
    let a = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {{sock}} level admin\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"%[bin(101000044d5154540402003c000474657374),mqtt_is_valid]|%[bin(101000044d),mqtt_is_valid]|%[bin(101000044d5154540402003c000474657374),mqtt_field_value(connect,protocol_name)]|%[bin(101000044d5154540402003c000474657374),mqtt_field_value(connect,client_identifier)]|%[bin(101000044d5154540402003c000474657374),mqtt_field_value(connect,protocol_version)]|%[bin(101000044d5154540402003c000474657374),mqtt_field_value(connect,flags)]\"",
    );
    let (_alcyon, _sock) = start("mqtt", &cfg, &[a]);
    let b = body(a, GET);
    assert_eq!(b, "1||MQTT|test|4|2");
}

/// One packet and the answers measured on `HAProxy` 3.5-dev8: `(packet type, field, value)`;
/// an empty value is a field that is not found.
type Field = (&'static str, &'static str, &'static str);
type Case = (&'static str, &'static str, &'static [Field]);

const CASES: &[Case] = &[
    // CONNECT 5.0 with properties
    (
        "103300044d5154540502003c22110000012c210014270001000022000519011700150005534352414d160003646174000474657374",
        "1",
        &[
            ("connect", "flags", "2"),
            ("connect", "protocol_version", "5"),
            ("connect", "client_identifier", "test"),
            ("connect", "17", "300"),
            ("connect", "21", "SCRAM"),
            ("connect", "22", "dat"),
            ("connect", "23", "0"),
            ("connect", "25", "1"),
            ("connect", "33", "20"),
            ("connect", "34", "5"),
            ("connect", "39", "65536"),
            ("connect", "Protocol_NAME", "MQTT"),
            ("connect", "will_topic", ""),
            ("connect", "1", ""),
            ("connack", "flags", ""),
        ],
    ),
    // CONNECT 5.0 with a will, will properties, a user name and a password
    (
        "103100044d51545405c6003c0511000000070004746573740c0300026374260001610001620002777400027770000175000170",
        "1",
        &[
            ("connect", "flags", "198"),
            ("connect", "will_topic", "wt"),
            ("connect", "will_payload", "wp"),
            ("connect", "username", "u"),
            ("connect", "password", "p"),
            ("connect", "3", "ct"),
            ("connect", "17", "7"),
            ("connect", "24", "0"),
        ],
    ),
    // CONNACK 5.0 with properties
    (
        "204300004011000000642100092401250027000010001200056369642d312200031f0003776879280129002a0113001e1a0004696e666f1c00037372761500016d16000164",
        "1",
        &[
            ("connack", "reason_code", "0"),
            ("connack", "protocol_version", "5"),
            ("connack", "17", "100"),
            ("connack", "18", "cid-1"),
            ("connack", "19", "30"),
            ("connack", "26", "info"),
            ("connack", "28", "srv"),
            ("connack", "31", "why"),
            ("connack", "36", "1"),
            ("connack", "37", "0"),
            ("connack", "39", "4096"),
            ("connack", "42", "1"),
            ("connect", "flags", ""),
        ],
    ),
    // CONNACK 3.1.1: the version comes from the length, the properties are not there
    ("20020105", "1", &[("connack", "flags", "1"), ("connack", "reason_code", "5"), ("connack", "protocol_version", "4"), ("connack", "17", "")]),
    // invalid: both will QoS bits set without the will flag
    ("101000044d5154540403003c000474657374", "0", &[("connect", "flags", ""), ("connect", "protocol_name", "")]),
    // incomplete: shorter than its remaining length, so more data is awaited (no sample)
    ("101000044d", "", &[("connect", "keepalive", "")]),
    // invalid: a byte left over after the payload
    ("101100044d5154540402003c00047465737400", "0", &[("connect", "keepalive", "")]),
    // a packet type the converters do not parse
    ("c000", "0", &[("disconnect", "17", "")]),
    // Parser refusals (gate covercheck after the 2026-10-17 integration), all measured on
    // HAProxy 3.5-dev8: multi-byte lengths (130-byte client id, 130-byte property block), a
    // fourth varint continuation byte, a repeated property, an unknown property, a property of
    // the wrong packet, a will delay interval, a bad protocol name / version / flag set, short
    (
        "108e0100044d5154540402003c008278787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
        "1",
        &[("connect", "client_identifier", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")],
    ),
    (
        "10910100044d5154540502003c820115007f79797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979000163",
        "1",
        &[("connect", "21", "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"), ("connect", "client_identifier", "c")],
    ),
    (
        "10ffffffff01",
        "0",
        &[("connect", "flags", "")],
    ),
    (
        "101800044d5154540502003c0a11000000011100000002000163",
        "0",
        &[("connect", "17", "")],
    ),
    (
        "101100044d5154540502003c03990000000163",
        "0",
        &[("connect", "17", "")],
    ),
    (
        "101000044d5154540502003c022401000163",
        "0",
        &[("connect", "17", "")],
    ),
    (
        "101a00044d5154540506003c00000163051800000005000174000170",
        "1",
        &[("connect", "24", "5"), ("connect", "will_topic", "t")],
    ),
    (
        "100d0004585858580402003c000163",
        "0",
        &[("connect", "protocol_name", "")],
    ),
    (
        "100d00044d5154540902003c000163",
        "0",
        &[("connect", "protocol_version", "")],
    ),
    (
        "100d00044d5154540403003c000163",
        "0",
        &[("connect", "flags", "")],
    ),
    (
        "2000",
        "0",
        &[("connack", "flags", "")],
    ),
    (
        "200100",
        "0",
        &[("connack", "flags", "")],
    ),
    (
        "10",
        "",
        &[("connect", "flags", "")],
    ),
    (
        "0000",
        "0",
        &[("connect", "flags", "")],
    ),
    (
        "6000",
        "0",
        &[("connect", "flags", "")],
    ),
    (
        "6200",
        "0",
        &[("connect", "flags", "")],
    ),
    (
        "3000",
        "0",
        &[("connect", "flags", "")],
    ),
    (
        "101200044d5154540502003c0416000164000163",
        "0",
        &[("connect", "22", "")],
    ),
    (
        "100d00044d5154540401003c000163",
        "0",
        &[("connect", "flags", "")],
    ),
    (
        "100d00044d5154540418003c000163",
        "0",
        &[("connect", "flags", "")],
    ),
    (
        "20020205",
        "0",
        &[("connack", "flags", "")],
    ),
    (
        "102600044d5154540506003c00000163110101020000000708000272740900026364000174000170",
        "1",
        &[("connect", "1", "1"), ("connect", "2", "7"), ("connect", "8", "rt"), ("connect", "9", "cd"), ("connect", "will_payload", "p")],
    ),
];

fn expected_line(valid: &str, fields: &[Field]) -> String {
    let mut parts = vec![valid.to_string()];
    parts.extend(fields.iter().map(|(_, _, v)| (*v).to_string()));
    parts.join("|")
}

/// T330: the packets above, one rule each, every field of the table against `HAProxy`'s answer.
#[test]
fn mqtt_packets_and_fields_match_haproxy() {
    let a = common::reserve_addr();
    let mut rules = String::new();
    for (i, (hex, _, fields)) in CASES.iter().enumerate() {
        let mut e = vec![format!("%[bin({hex}),mqtt_is_valid]")];
        e.extend(fields.iter().map(|(t, f, _)| format!("%[bin({hex}),mqtt_field_value({t},{f})]")));
        let _ = writeln!(
            rules,
            "  http-request return status 200 content-type text/plain lf-string \"{}\" if {{ path /{i} }}",
            e.join("|")
        );
    }
    let cfg = http_cfg("  nbthread 1\n", &format!("frontend fe\n  bind {a}\n{rules}"));
    let (_alcyon, _sock) = start("mqtt-cases", &cfg, &[a]);
    for (i, (hex, valid, fields)) in CASES.iter().enumerate() {
        let req = format!("GET /{i} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        assert_eq!(body(a, req.as_bytes()), expected_line(valid, fields), "packet {hex}");
    }
}

/// T330: the load-time refusals, with `HAProxy`'s messages (`haproxy -c` on the same lines).
#[test]
fn mqtt_converters_refuse_bad_arguments() {
    let dir = std::env::temp_dir().join(format!("qh-mqtt-bad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let bad: &[(&str, &str)] = &[
        ("mqtt_field_value(foo,flags)", "invalid args in converter 'mqtt_field_value' : Unknown MQTT type 'foo'."),
        ("mqtt_field_value(connect,foo)", "invalid args in converter 'mqtt_field_value' : Unknown MQTT field name 'foo' for packet type 'connect'."),
        ("mqtt_field_value(connect,reason_code)", "Unknown MQTT field name 'reason_code' for packet type 'connect'."),
        ("mqtt_field_value(connect)", "invalid arg 2 in converter 'mqtt_field_value' : missing arguments (got 1/2), type 'string' expected."),
        ("mqtt_field_value(connect,flags,x)", "invalid arg 2 in converter 'mqtt_field_value' : expected ')' before ',x)"),
        ("mqtt_is_valid(1)", "invalid arg 1 in converter 'mqtt_is_valid' : expected ')' before '1)"),
    ];
    for (expr, want) in bad {
        let path = dir.join("c.cfg");
        let cfg = http_cfg(
            "",
            &format!("frontend fe\n  bind 127.0.0.1:48401\n  http-request return status 200 content-type text/plain lf-string \"%[str(a),{expr}]\"\n"),
        );
        std::fs::write(&path, cfg.replace("{sock}", &dir.join("s").display().to_string())).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{expr} was accepted");
        assert!(text.contains(want), "{expr}: wanted {want:?} in {text:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// T330 review: `sample_conv_mqtt_field_value()` never sets the sample type, so the value stays
/// binary (the converter's input type) even for the numeric fields: it casts to a string but not to
/// an integer, and `-m int` never matches. Measured on the `HAProxy` oracle.
#[test]
fn mqtt_field_value_is_binary() {
    let a = common::reserve_addr();
    const H: &str = "101000044d5154540402003c000474657374";
    let line = format!(
        "a%[bin({H}),mqtt_field_value(connect,keepalive),add(1)]|b%[bin({H}),mqtt_field_value(connect,protocol_version),mul(2)]|c%[bin({H}),mqtt_field_value(connect,protocol_name),lower]|d%[bin({H}),mqtt_field_value(connect,keepalive)]|e%[bin({H}),mqtt_field_value(connect,keepalive),length]"
    );
    let cfg = http_cfg(
        "  nbthread 1\n",
        &format!(
            "frontend fe\n  bind {a}\n  acl ka60 bin({H}),mqtt_field_value(connect,keepalive) -m int 60\n  acl kas bin({H}),mqtt_field_value(connect,keepalive) -m str 60\n  http-request return status 200 content-type text/plain lf-string \"{line}|int\" if ka60\n  http-request return status 200 content-type text/plain lf-string \"{line}|str\" if kas\n"
        ),
    );
    let (_alcyon, _sock) = start("mqtt_bin", &cfg, &[a]);
    assert_eq!(body(a, GET), "a|b|cmqtt|d60|e2|str");
}

/// Which `(packet type, field)` pairs load, for the packet types the converters do not parse
/// (`mqtt_check_type_fieldname`): `None` is accepted, `Some(msg)` the message `haproxy -c` gives.
/// Types by name and by number. Measured on `HAProxy` 3.5-dev8 (gate covercheck after the
/// 2026-10-17 integration).
#[test]
fn mqtt_type_and_field_pairs_load_as_in_haproxy() {
    let dir = std::env::temp_dir().join(format!("qh-mqtt-pairs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pairs: &[(&str, &str, Option<&str>)] = &[
        ("publish", "1", None),
        ("publish", "reason_code", Some("Unknown MQTT field name 'reason_code' for packet type 'publish'.")),
        ("puback", "reason_code", None),
        ("pubrel", "31", None),
        ("pubcomp", "38", None),
        ("subscribe", "11", None),
        ("subscribe", "31", Some("Unknown MQTT field name '31' for packet type 'subscribe'.")),
        ("suback", "31", None),
        ("unsuback", "38", None),
        ("unsubscribe", "38", None),
        ("unsubscribe", "31", Some("Unknown MQTT field name '31' for packet type 'unsubscribe'.")),
        ("auth", "21", None),
        ("auth", "reason_code", Some("Unknown MQTT field name 'reason_code' for packet type 'auth'.")),
        ("pingreq", "38", Some("Unknown MQTT field name '38' for packet type 'pingreq'.")),
        ("3", "1", None),
        ("14", "28", None),
        ("0", "flags", Some("Unknown MQTT type '0'.")),
        ("16", "flags", Some("Unknown MQTT type '16'.")),
    ];
    for (ty, field, want) in pairs {
        let path = dir.join("c.cfg");
        let cfg = http_cfg(
            "",
            &format!("frontend fe\n  bind 127.0.0.1:48402\n  http-request return status 200 content-type text/plain lf-string \"%[str(a),mqtt_field_value({ty},{field})]\"\n"),
        );
        std::fs::write(&path, cfg.replace("{sock}", &dir.join("s").display().to_string())).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
        match want {
            None => assert!(out.status.success(), "({ty},{field}) was refused: {text:?}"),
            Some(msg) => {
                assert!(!out.status.success(), "({ty},{field}) was accepted");
                assert!(text.contains(msg), "({ty},{field}): wanted {msg:?} in {text:?}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
