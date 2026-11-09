// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T330: protobuf/ungrpc

use crate::common;

use std::collections::HashMap;
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

fn info(sock: &str) -> HashMap<String, String> {
    cli(sock, "show info").lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn num(i: &HashMap<String, String>, k: &str) -> u64 {
    i.get(k).unwrap_or_else(|| panic!("show info has no {k}")).parse().unwrap_or_else(|_| panic!("{k} is not a number: {:?}", i[k]))
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

/// A server on a free port that reads each request head, answers `resp` and closes the connection.
fn backend(resp: &'static [u8]) -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let (mut head, mut b) = (Vec::new(), [0u8; 4096]);
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&b[..n]),
                }
            }
            let _ = c.write_all(resp);
        }
    });
    addr
}

/// The body of the answer to `req` (what follows the first empty line).
fn body(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    s.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_else(|| panic!("no answer: {s:?}"))
}

/// The value of the `x-out` header in the answer to `req`.
fn xout(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    let head = s.split("\r\n\r\n").next().unwrap_or("");
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("x-out")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("no x-out header in the answer: {s:?}"))
}

#[test]
fn test() {
    let a = common::reserve_addr();
    const CFG: &str = r#"global
  stats socket {sock} level admin
  nbthread 1
defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend fe
  bind {A}
  http-request return status 200 content-type text/plain lf-string "%[bin(08960112036162631a03080102),protobuf(1,uint32)]|%[bin(08960112036162631a03080102),protobuf(2),hex]|%[bin(08960112036162631a03080102),protobuf(3.1,int32)]|%[bin(08960112036162631a03080102),protobuf(9),hex]|%[bin(000000000d08960112036162631a03080102),ungrpc(1,uint32)]|%[bin(000000000d08960112036162631a03080102),ungrpc(2),hex]"
"#;
    let cfg = CFG.replace("{A}", &a.to_string());
    let (_alcyon, _sock) = start("protobuf_ungrpc", &cfg, &[a]);
    let b = body(a, GET);
    assert_eq!(b, "150|616263|1||150|616263");
}

/// T330: every answer below was measured on the `HAProxy` oracle (3.5-dev8): the hex of a message,
/// the converter chain applied to it and the text it gives (nothing when there is no sample).
const ORACLE: &[(&str, &str, &str)] = &[
    ("08960112036162631a03080102", "protobuf(1,uint32)", "150"),
    ("08960112036162631a03080102", "protobuf(1,int32)", "150"),
    ("08960112036162631a03080102", "protobuf(1,sint32)", "75"),
    ("08960112036162631a03080102", "protobuf(1,fixed32)", ""),
    ("08960112036162631a03080102", "protobuf(1),hex", "9601"),
    ("08960112036162631a03080102", "protobuf(1,bool)", "150"),
    ("08960112036162631a03080102", "protobuf(2)", "abc"),
    ("08960112036162631a03080102", "protobuf(2,int32)", ""),
    ("08960112036162631a03080102", "protobuf(2,fixed64)", ""),
    ("08960112036162631a03080102", "protobuf(3),hex", "080102"),
    ("08960112036162631a03080102", "protobuf(3.1,int32)", "1"),
    ("08960112036162631a03080102", "protobuf(3.2,uint64)", ""),
    ("08960112036162631a03080102", "protobuf(3.3)", ""),
    ("08960112036162631a03080102", "protobuf(3.1.1)", ""),
    ("08960112036162631a03080102", "protobuf(3.1.1,int32)", ""),
    ("08960112036162631a03080102", "protobuf(2.1)", ""),
    ("08960112036162631a03080102", "protobuf(9)", ""),
    ("08960112036162631a03080102", "protobuf(.1)", ""),
    ("08960112036162631a03080102", "protobuf(0)", ""),
    ("08960112036162631a03080102", "protobuf(1),hex", "9601"),
    ("0803", "protobuf(1,sint32)", "-2"),
    ("0804", "protobuf(1,sint64)", "2"),
    ("08ffffffffffffffffff01", "protobuf(1,int32)", "-1"),
    ("08ffffffffffffffffff01", "protobuf(1,uint64)", "-1"),
    ("08ffffffffffffffffff01", "protobuf(1,sint64)", "-9223372036854775808"),
    ("08ffffffffffffffffff01", "protobuf(1),hex", "FFFFFFFFFFFFFFFFFF01"),
    ("08ffffffffffffffffffff01", "protobuf(1,int64)", ""),
    ("08ffffffffffffffffffff01", "protobuf(1)", ""),
    ("08ffffffffffffffff7f", "protobuf(1,uint64)", "9223372036854775807"),
    ("0896", "protobuf(1,uint32)", ""),
    ("0896", "protobuf(1)", ""),
    ("08", "protobuf(1,uint32)", "0"),
    ("08", "protobuf(1)", ""),
    ("0801", "protobuf(1,bool)", "1"),
    ("0802", "protobuf(1,enum)", "2"),
    ("0d78563412", "protobuf(1,fixed32)", "305419896"),
    ("0d78563412", "protobuf(1,sfixed32)", "305419896"),
    ("0d78563412", "protobuf(1,float)", "0"),
    ("0d78563412", "protobuf(1),hex", "78563412"),
    ("0d78563412", "protobuf(1,uint32)", ""),
    ("0d78563412", "protobuf(1,fixed64)", ""),
    ("0dffffffff", "protobuf(1,fixed32)", "4294967295"),
    ("0dffffffff", "protobuf(1,sfixed32)", "-1"),
    ("0dffffffff", "protobuf(1,float)", "0"),
    ("0d785634", "protobuf(1,fixed32)", ""),
    ("0d785634", "protobuf(1)", ""),
    ("09efcdab8967452301", "protobuf(1,fixed64)", "81985529216486895"),
    ("09efcdab8967452301", "protobuf(1,sfixed64)", "81985529216486895"),
    ("09efcdab8967452301", "protobuf(1,double)", "0"),
    ("09efcdab8967452301", "protobuf(1),hex", "EFCDAB8967452301"),
    ("09efcdab8967452301", "protobuf(1,fixed32)", ""),
    ("09ffffffffffffffff", "protobuf(1,sfixed64)", "-1"),
    ("09ffffffffffffffff", "protobuf(1,double)", "-9223372036854775808"),
    ("09efcdab89674523", "protobuf(1,fixed64)", ""),
    ("09efcdab8967452301", "protobuf(2)", ""),
    ("0801080208", "protobuf(1,uint32)", "1"),
    ("0801080208", "protobuf(2,uint32)", ""),
    ("0801100208ff", "protobuf(2,uint32)", "2"),
    ("0b0801", "protobuf(1)", ""),
    ("0b0801", "protobuf(2)", ""),
    ("0e0801", "protobuf(1)", ""),
    ("0f", "protobuf(1)", ""),
    ("0e", "protobuf(1)", ""),
    ("12056162", "protobuf(2)", ""),
    ("12056162", "protobuf(3)", ""),
    ("1200", "protobuf(2)", ""),
    ("1200", "protobuf(2,int32)", ""),
    ("1203616263", "protobuf(2,uint32)", ""),
    ("12ffffffffffffffffff01", "protobuf(2)", ""),
    ("120a0801", "protobuf(2.1)", ""),
    ("1203080112", "protobuf(2.1,uint32)", "1"),
    ("0801120208020a0310", "protobuf(2.1,uint32)", "2"),
    ("120208011a03080102", "protobuf(3.2,uint32)", ""),
    ("1a021201", "protobuf(3.2)", ""),
    ("08960112036162631a03080102", "protobuf(1,uint32)", "150"),
    ("120412020801", "protobuf(2.1.1,uint32)", ""),
    ("120412020801", "protobuf(2.2,uint32)", ""),
    ("1204120208011001", "protobuf(1,uint32)", ""),
    ("120210010802", "protobuf(2.1,uint32)", ""),
    ("120210010802", "protobuf(1,uint32)", "2"),
    ("1202100108020804", "protobuf(1,uint32)", "2"),
    ("000000000d08960112036162631a03080102", "ungrpc(1,uint32)", "150"),
    ("000000000d08960112036162631a03080102", "ungrpc(2)", "abc"),
    ("000000000d08960112036162631a03080102", "ungrpc(2),hex", "616263"),
    ("000000000d08960112036162631a03080102", "ungrpc(3.1,int32)", "1"),
    ("000000000d08960112036162631a03080102", "ungrpc(1),hex", "9601"),
    ("000000000d08960112036162631a03080102", "ungrpc(1,uint32)", "150"),
    ("010000000d08960112036162631a03080102", "ungrpc(2)", "abc"),
    ("000000000d08960112036162631a03080102", "protobuf(1,uint32)", ""),
    ("000000000d08960112036162631a03080102", "protobuf(0)", ""),
    ("000000000d08960112036162631a03080102", "protobuf(2)", ""),
    ("0000000000", "ungrpc(1)", ""),
    ("000000000108", "ungrpc(1)", ""),
    ("000000000108", "ungrpc(1,uint32)", "0"),
    ("0000000002", "ungrpc(1)", ""),
    ("00000000020801", "ungrpc(1,uint32)", "1"),
    ("00000000020801", "ungrpc(1),hex", "01"),
    ("00000000ff0801", "ungrpc(1,uint32)", ""),
    ("00ffffffff0801", "ungrpc(1,uint32)", ""),
    ("0000000002080100000000021002", "ungrpc(2,uint32)", "2"),
    ("0000000002080100000000021002", "ungrpc(1,uint32)", "1"),
    ("0000000002080100000000021002", "ungrpc(3,uint32)", ""),
    ("000000000208010000000002100200000000020801", "ungrpc(2,uint32)", "2"),
    ("0000000004120208ff00000000020801", "ungrpc(1,uint32)", "1"),
    ("0000000004120208ff00000000020801", "ungrpc(2.1,uint32)", ""),
    ("0000000004120208ff00000000021002", "ungrpc(2,uint32)", ""),
    ("0000000004120208ff00000000021002", "ungrpc(2.2,uint32)", ""),
    ("0000000003120000000000020801", "ungrpc(1,uint32)", ""),
    ("000000000312000800000000020801", "ungrpc(1,uint32)", "0"),
    ("00000000041202080100000000020809", "ungrpc(2.1,uint32)", "1"),
    ("00000000041202080100000000020809", "ungrpc(1,uint32)", "9"),
    ("000000000612040802080300000000020809", "ungrpc(1,uint32)", "9"),
    ("00000000041202080100000000020801", "ungrpc(1,uint32)", "1"),
    ("000000000a820307da030408051007", "ungrpc(48.59.1,int32)", "5"),
    ("000000000a820307da030408051007", "ungrpc(48.59.2,int32)", "7"),
    ("000000000a820307da030408051007", "ungrpc(48.59),hex", "08051007"),
    ("000000000a820307da030408051007", "ungrpc(48.59),protobuf(1,int32)", "5"),
    ("000000000a820307da030408051007", "ungrpc(48),protobuf(59.1,int32)", "5"),
    ("000000000a820307da030408051007", "ungrpc(48),protobuf(59),protobuf(1,int32)", "5"),
    ("000000000a820307da030408051007", "ungrpc(49.59.1,int32)", ""),
    ("000000000a820307da030408051007", "ungrpc(48),hex", "DA030408051007"),
    ("000000000a820307da030408051007", "ungrpc(48.59.2,sint32)", "-4"),
    ("000000000a820307da030408051007", "ungrpc(48.59.1,fixed32)", ""),
    ("09000000000000f03f", "protobuf(1,double)", "1"),
    ("09000000000000f8bf", "protobuf(1,double)", "-1"),
    ("09003d9160e458e143", "protobuf(1,double)", "-8446744073709551616"),
    ("0900a138149b39ef43", "protobuf(1,double)", "-446744073709551616"),
    ("09ea8ca039593e2946", "protobuf(1,double)", "0"),
    ("09000000000000f07f", "protobuf(1,double)", "0"),
    ("09000000000000f0ff", "protobuf(1,double)", "-9223372036854775808"),
    ("09000000000000f87f", "protobuf(1,double)", "-9223372036854775808"),
    ("095839b4c8d61cc840", "protobuf(1,double)", "12345"),
    ("09000000000000e03f", "protobuf(1,double)", "0"),
    ("09000000000000e043", "protobuf(1,double)", "-9223372036854775808"),
    ("09000000000000e0c3", "protobuf(1,double)", "-9223372036854775808"),
    ("09ea8ca039593e29c6", "protobuf(1,double)", "-9223372036854775808"),
    ("093333070000000842", "protobuf(1,double)", "12884901888"),
    ("09cdccccccccccecbf", "protobuf(1,double)", "0"),
    ("09000000000000f043", "protobuf(1,double)", "0"),
    ("0980b4c33d847ded43", "protobuf(1,double)", "-1446744073709551616"),
    ("090100000000000000", "protobuf(1,double)", "0"),
    ("0d0000803f", "protobuf(1,float)", "1"),
    ("0d00007040", "protobuf(1,float)", "3"),
    ("0d0000c0bf", "protobuf(1,float)", "4294967295"),
    ("0df9021550", "protobuf(1,float)", "1410065408"),
    ("0dcaf24971", "protobuf(1,float)", "0"),
    ("0d0000807f", "protobuf(1,float)", "0"),
    ("0d000080ff", "protobuf(1,float)", "0"),
    ("0d0000c07f", "protobuf(1,float)", "0"),
    ("0d0000003f", "protobuf(1,float)", "0"),
    ("0d00000050", "protobuf(1,float)", "0"),
    ("0d5ed0324f", "protobuf(1,float)", "3000000000"),
    ("0d5ed032cf", "protobuf(1,float)", "1294967296"),
    ("0df90215d0", "protobuf(1,float)", "2884901888"),
    ("0d0000005f", "protobuf(1,float)", "0"),
    ("0d0000804f", "protobuf(1,float)", "0"),
    ("0d666666bf", "protobuf(1,float)", "0"),
    ("0d286b6e4f", "protobuf(1,float)", "4000000000"),
    ("0d0000805e", "protobuf(1,float)", "0"),
    ("0d000080de", "protobuf(1,float)", "0"),
    ("0d00002050", "protobuf(1,float)", "2147483648"),
    // review: HAProxy keeps a field number in an `unsigned int`, so a key for field 2^32+1
    // matches field 1, and a path number past 2^32 wraps (`read_uint()`).
    ("8a808080800103616263", "protobuf(1),hex", "616263"),
    ("000000000a8a808080800103616263", "ungrpc(1),hex", "616263"),
    ("089601", "protobuf(4294967297,uint32)", "150"),
    ("089601", "protobuf(4294967296,uint32)", ""),
];

#[test]
fn fields_match_the_oracle() {
    let a = common::reserve_addr();
    let exprs: Vec<String> = ORACLE.iter().map(|(h, c, _)| format!("%[bin({h}),{c}]")).collect();
    let cfg = http_cfg(
        "  nbthread 1\n",
        &format!(
            "frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"{}\"\n",
            exprs.join("|")
        ),
    );
    let (_alcyon, _sock) = start("protobuf_ungrpc_oracle", &cfg, &[a]);
    let got = body(a, GET);
    let got: Vec<&str> = got.split('|').collect();
    assert_eq!(got.len(), ORACLE.len(), "answer: {got:?}");
    for ((h, c, want), got) in ORACLE.iter().zip(got) {
        assert_eq!(got, *want, "bin({h}),{c}");
    }
}

/// T330: the arguments `HAProxy` refuses at load time are refused, with its message.
#[test]
fn bad_arguments_are_refused() {
    let dir = std::env::temp_dir().join(format!("qh-pbarg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    for (conv, why) in [
        ("protobuf(1,foo)", "invalid args in converter 'protobuf' : Wrong protocol buffer type 'foo'."),
        ("protobuf(1,string)", "Wrong protocol buffer type 'string'."),
        ("protobuf(1,)", "Wrong protocol buffer type ''."),
        ("ungrpc(1,INT32)", "invalid args in converter 'ungrpc' : Wrong protocol buffer type 'INT32'."),
        ("protobuf(1.)", "failed to parse '1.' as type 'Protocol buffers field number' at position 1."),
        ("protobuf(x)", "failed to parse 'x' as type 'Protocol buffers field number' at position 1."),
        ("protobuf()", "expected type 'Protocol buffers field number' at position 1, but got nothing."),
        ("ungrpc", "expected type 'Protocol buffers field number' at position 1, but got nothing."),
        ("protobuf(1,int32,3)", "invalid arg 2 in converter 'protobuf' : expected ')' before ',3)'."),
    ] {
        let cfg = http_cfg(
            "",
            &format!("frontend fe\n  bind 127.0.0.1:1\n  http-request return status 200 content-type text/plain lf-string \"%[bin(00),{conv}]\"\n"),
        );
        std::fs::write(&path, cfg.replace("{sock}", "/tmp/unused.sock")).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().expect("alcyon -c");
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!out.status.success() && text.contains(why), "{conv}: {text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
