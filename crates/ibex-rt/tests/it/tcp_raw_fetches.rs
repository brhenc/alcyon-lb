// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The raw-buffer fetches of a TCP proxy: `req.ssl_*` (the ClientHello parsers of
//! `src/payload.c`), `req.rdp_cookie[_cnt]` and `req.payload_lv`.
//!
//! Every expected line of [`CASES`] was measured on `HAProxy` 3.5-dev8-885761-29: the same
//! configuration ([`config`]), the payload sent in one write and the write side then shut,
//! the stream's log line read back. The payloads are valid hellos, SSLv2 hellos, RDP
//! cookies, and truncations or mutations of them (the bounds checks).

use ibex_rt::engine::Engine;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::common;

fn config(collector: SocketAddr, fe: SocketAddr, format: &str, rules: &str) -> String {
    format!(
        "defaults\n  mode tcp\n  timeout client 2s\n  timeout connect 1s\n  timeout server 1s\n\
         frontend fe\n  bind {fe}\n  log {collector} local0\n  \
         log-format \"{format}\"\n  tcp-request inspect-delay 300ms\n  {rules}\n"
    )
}

const FORMAT: &str = "t=%[var(txn.t)] v=%[var(txn.v)] e=%[var(txn.e)] s=%[var(txn.s)] n=%[var(txn.n)] a=%[var(txn.a)] c=%[var(txn.c)] g=%[var(txn.g)] x=%[var(txn.x)] k=%[var(txn.k)] r=%[var(txn.r)] rn=%[var(txn.rn)] rm=%[var(txn.rm)] l=%[var(txn.l)] l2=%[var(txn.l2)] l3=%[var(txn.l3)] l4=%[var(txn.l4)] ln=%[var(txn.ln)]";

const SETS: &str = "tcp-request content set-var(txn.t) req.ssl_hello_type\n  tcp-request content set-var(txn.v) req.ssl_ver\n  tcp-request content set-var(txn.e) req.ssl_ec_ext\n  tcp-request content set-var(txn.s) req.ssl_st_ext\n  tcp-request content set-var(txn.n) req.ssl_sni\n  tcp-request content set-var(txn.a) req.ssl_alpn\n  tcp-request content set-var(txn.c) req.ssl_cipherlist,hex\n  tcp-request content set-var(txn.g) req.ssl_supported_groups,hex\n  tcp-request content set-var(txn.x) req.ssl_sigalgs,hex\n  tcp-request content set-var(txn.k) req.ssl_keyshare_groups,hex\n  tcp-request content set-var(txn.r) req.rdp_cookie\n  tcp-request content set-var(txn.rn) req.rdp_cookie_cnt\n  tcp-request content set-var(txn.rm) req.rdp_cookie(mstshash)\n  tcp-request content set-var(txn.l) req.payload_lv(0,2),hex\n  tcp-request content set-var(txn.l2) req.payload_lv(0,1,+1),hex\n  tcp-request content set-var(txn.l3) req.payload_lv(1,1,-1),hex\n  tcp-request content set-var(txn.l4) req.payload_lv(0,1,2),hex\n  tcp-request content set-var(txn.ln) req.len\n  tcp-request content reject";

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex")).collect()
}

/// Sends `chunks` (a pause between them), shuts the write side and returns the log line.
fn log_of(engine: &mut Engine, collector: &UdpSocket, fe: SocketAddr, chunks: Vec<Vec<u8>>) -> String {
    let (tx, rx) = mpsc::channel();
    let c = thread::spawn(move || {
        let mut s = TcpStream::connect(fe).expect("connect");
        for (i, chunk) in chunks.iter().enumerate() {
            if i > 0 {
                thread::sleep(Duration::from_millis(80));
            }
            let _ = s.write_all(chunk);
        }
        thread::sleep(Duration::from_millis(40));
        let _ = s.shutdown(std::net::Shutdown::Write);
        s.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let mut sink = [0u8; 16];
        let _ = s.read(&mut sink);
        let _ = tx.send(());
    });
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut line = String::from("NOLOG");
    while Instant::now() < deadline {
        let _ = engine.run_once();
        if let Ok(n) = collector.recv(&mut buf) {
            line = String::from_utf8_lossy(&buf[..n]).split_once("]: ").map_or(String::new(), |(_, b)| b.trim_end().to_string());
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    let _ = rx.recv_timeout(Duration::from_secs(3));
    let _ = c.join();
    line
}

fn start(rules: &str) -> (Engine, UdpSocket, SocketAddr) {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let fe = common::reserve_addr();
    let cfg = config(collector.local_addr().expect("addr"), fe, FORMAT, rules);
    let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    (engine, collector, fe)
}

const CASES: &[(&str, &str)] = &[
    ("160301007f0100007b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100005000000011000e00000b7777772e746573742e6f72670010000e000c02683208687474702f312e31000a00060004001d0017000d00060004040308040033000b0009001d0001aa0017000000230002aabb",
     "t=1 v=196611 e=1 s=2 n=www.test.or a=h2 c=1302 g=001D0017 x=04030804 k=001D0017 r=- rn=0 rm=- l=- l2=01007F0100007B0303000102030405060708090A0B0C l3=030100 l4=0301007F0100007B0303000102030405060708090A0B ln=132"),
    ("16030100410100003d0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000021302010000120010000e000c02683208687474702f312e31",
     "t=1 v=196611 e=0 s=0 n=- a=h2 c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=0100410100003D0303000102030405060708090A0B0C l3=030100 l4=030100410100003D0303000102030405060708090A0B ln=70"),
    ("1603010044010000400303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100001500000011000e00000b7777772e746573742e6f7267",
     "t=1 v=196611 e=0 s=0 n=www.test.or a=- c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=010044010000400303000102030405060708090A0B0C l3=030100 l4=03010044010000400303000102030405060708090A0B ln=73"),
    ("160301002f0100002b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000002130201000000",
     "t=1 v=196611 e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=- l2=01002F0100002B0303000102030405060708090A0B0C l3=030100 l4=0301002F0100002B0303000102030405060708090A0B ln=52"),
    ("160301002d010000290303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100",
     "t=1 v=196611 e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=- l2=01002D010000290303000102030405060708090A0B0C l3=030100 l4=0301002D010000290303000102030405060708090A0B ln=50"),
    ("1603010064010000600303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f207878787878787878787878787878787878787878787878787878787878787878000213020100001500000011000e00000b7777772e746573742e6f7267",
     "t=1 v=196611 e=0 s=0 n=www.test.or a=- c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=010064010000600303000102030405060708090A0B0C l3=030100 l4=03010064010000600303000102030405060708090A0B ln=105"),
    ("160301003f0100003b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000002130201000010000a00060004001d001700230002aabb",
     "t=1 v=196611 e=1 s=2 n=- a=- c=1302 g=001D0017 x=- k=- r=- rn=0 rm=- l=- l2=01003F0100003B0303000102030405060708090A0B0C l3=030100 l4=0301003F0100003B0303000102030405060708090A0B ln=68"),
    ("16030100330100002f0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100000400230000",
     "t=1 v=196611 e=0 s=1 n=- a=- c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=0100330100002F0303000102030405060708090A0B0C l3=030100 l4=030100330100002F0303000102030405060708090A0B ln=56"),
    ("801c0103000003000000100100801112131415161718191a1b1c1d1e1f20",
     "t=- v=196608 e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=- l2=- l3=1C0103000003000000100100801112131415161718191A1B1C1D1E1F l4=- ln=30"),
    ("002f020103010006000000200100800200801112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30aabb",
     "t=- v=196609 e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=020103010006000000200100800200801112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F l2=- l3=2F020103010006000000200100800200801112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E l4=- ln=52"),
    ("16030300050200000100000000",
     "t=2 v=- e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=- rm=- l=- l2=- l3=030300 l4=- ln=13"),
    ("030000130ee00000000000436f6f6b69653a206d737473686173683d68656c6c6f0d0a0100080003000000",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=hello rn=1 rm=hello l=- l2=00130E l3=- l4=000013 ln=43"),
    ("030000130ee00000000000436f6f6b69653a206d7374733d6162630d0a",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=abc rn=1 rm=- l=- l2=00130E l3=- l4=000013 ln=29"),
    ("030000130ee00000000000636f6f6b69653a2020206d737473686173683d68656c",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=- rm=- l=- l2=00130E l3=- l4=000013 ln=33"),
    ("030000130ee00000000000436f6f6b69653a20666f6f3d6261720d0a",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=bar rn=1 rm=- l=- l2=00130E l3=- l4=000013 ln=28"),
    ("0000000568656c6c6f",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=- rm=- l=- l2=- l3=- l4=- ln=9"),
    ("000568656c6c6f20776f726c64",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=- rm=- l=68656C6C6F l2=- l3=0568656C6C l4=- ln=13"),
    ("020568656c6c6f",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=- rm=- l=- l2=6865 l3=0568656C6C l4=0568 ln=7"),
    ("474554202f20485454502f312e300d0a0d0a",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=- rm=- l=- l2=- l3=- l4=- ln=18"),
    ("160301002d010000290303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000002130201",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=- l2=01002D010000290303000102030405060708090A0B0C l3=030100 l4=0301002D010000290303000102030405060708090A0B ln=49"),
    ("1603010044010000400303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020300001500000011000e00000b7700772e746573742e6f7267",
     "t=1 v=196611 e=0 s=0 n=- a=- c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=010044010000400303000102030405060708090A0B0C l3=030100 l4=03010044010000400303000102030405060708090A0B ln=73"),
    ("160301007f0100d87b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100005000000003000e00000b7777772e746573742e6f72670010000e000c02683208687474702f312e31000a00060004001d0017000d00060004040308040033000b0009001d0001aa0017000003230002aabb",
     "t=- v=196611 e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=- l2=01007F0100D87B0303000102030405060708090A0B0C l3=030100 l4=0301007F0100D87B0303000102030405060708090A0B ln=132"),
    ("160301007f0100007b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100005000000011000e00000b7777772e746573742e6f72670010001e000c02683208687474702f312e31000a00060004001d0017000d000600040403a4040033000b0009001d0001aa0017000000230002aabb",
     "t=1 v=196611 e=- s=- n=www.test.or a=h2 c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=01007F0100007B0303000102030405060708090A0B0C l3=030100 l4=0301007F0100007B0303000102030405060708090A0B ln=132"),
    ("1603010064010000600303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f207878787878787878787878787878787878787878787878787878787878787878000213020100001500000011000e00000b7777772e7465131313742e6f7267",
     "t=1 v=196611 e=0 s=0 n=www.tet. a=- c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=010064010000600303000102030405060708090A0B0C l3=030100 l4=03010064010000600303000102030405060708090A0B ln=107"),
    ("1603010064010000600303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f207878787878787878787802787878787878787878787878787878787878787878000213020100001500000211000e00000b7777772e746573742e6f7267",
     "t=1 v=196611 e=- s=- n=- a=- c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=010064010000600303000102030405060708090A0B0C l3=030100 l4=03010064010000600303000102030405060708090A0B ln=105"),
    ("002f020103020006000000200100800200801112131415161718191a1b1c1d1e1f202122232425262700292a2b2c2d2e2f30aabb",
     "t=- v=196610 e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=020103020006000000200100800200801112131415161718191A1B1C1D1E1F202122232425262700292A2B2C2D2E2F l2=- l3=2F020103020006000000200100800200801112131415161718191A1B1C1D1E1F202122232425262700292A2B2C2D2E l4=- ln=52"),
    ("1603010064010000600303000102030405060708090a0b0c0d0e0f100112131415161718191a1b1c1d1e012078787878787878787878787878787878787878787878787878787878787878780002ff020100001500000011000e00000b7777772e746573742e6f7267",
     "t=1 v=196611 e=0 s=0 n=www.test.or a=- c=FF02 g=- x=- k=- r=- rn=0 rm=- l=- l2=010064010000600303000102030405060708090A0B0C l3=030100 l4=03010064010000600303000102030405060708090A0B ln=105"),
    ("160301007f0100007b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100005000000011000e00000b7777772e746573742e6f72670010000e000c02683208687474702f312e31000a00060004001d001700252500060004040308040033000b0009001d0001aa0017000000230002aabb",
     "t=1 v=196611 e=1 s=- n=www.test.or a=h2 c=1302 g=001D0017 x=- k=- r=- rn=0 rm=- l=- l2=01007F0100007B0303000102030405060708090A0B0C l3=030100 l4=0301007F0100007B0303000102030405060708090A0B ln=133"),
    ("160301002dff0000290303000102030405060708090a0b0c0dff0f101112131415161718191a1b1c1d1e1f00000213020100",
     "t=255 v=196611 e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=- l2=01002DFF0000290303000102030405060708090A0B0C l3=030100 l4=0301002DFF0000290303000102030405060708090A0B ln=50"),
    ("030000130ee00000000000436f6f6b69653a206d7473686173683d68656c6c6f0d0a0100080003000000",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=hello rn=1 rm=- l=- l2=00130E l3=- l4=000013 ln=42"),
    ("160301007f0100007b0303000102030405060708090a0b520d0e0f101112131415161718191a1b1c1d1e1f00000213020100005000010011000e00000b7777772e746573742ecd72670010000e000c02683208687474702f312e31000a00060004001d0017000d00060004040308040033000b0009001d0001aa0017000000230002aabb",
     "t=1 v=196611 e=1 s=2 n=- a=h2 c=1302 g=001D0017 x=04030804 k=001D0017 r=- rn=0 rm=- l=- l2=01007F0100007B0303000102030405060708090A0B52 l3=030100 l4=0301007F0100007B0303000102030405060708090A0B ln=132"),
    ("1603010064010000600303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f207878787878787878787878787878787878017878787878787878780378787878000202020100001500000011000e00000b7777772e746573742e6f7267",
     "t=1 v=196611 e=0 s=0 n=www.test.or a=- c=0202 g=- x=- k=- r=- rn=0 rm=- l=- l2=010064010000600303000102030405060708090A0B0C l3=030100 l4=03010064010000600303000102030405060708090A0B ln=105"),
    ("160301007f0100007b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100005000000011000e00000b7777772e746573742e6f72670010000e000c02683208687474702f312e31000a00060004ff1d0017000d00060004040308040033000b0009001d0001aa0017000000230002aabb",
     "t=1 v=196611 e=1 s=2 n=www.test.or a=h2 c=1302 g=FF1D0017 x=04030804 k=001D0017 r=- rn=0 rm=- l=- l2=01007F0100007B0303000102030405060708090A0B0C l3=030100 l4=0301007F0100007B0303000102030405060708090A0B ln=132"),
    ("160301002d030000290303000102030405060708090a0b0c0d0e0f101112130015161718191a1b1c1d1e1f00000213020100",
     "t=3 v=196611 e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=- l2=01002D030000290303000102030405060708090A0B0C l3=030100 l4=0301002D030000290303000102030405060708090A0B ln=50"),
    ("1603010044010000400303000102030405060708090a0b0c0d0e0f101112131415160218191a031c1d1e1f00000213020100001500000011000e00000b7777772e74a673742e6f7267",
     "t=1 v=196611 e=0 s=0 n=www.t�st.or a=- c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=010044010000400303000102030405060708090A0B0C l3=030100 l4=03010044010000400303000102030405060708090A0B ln=73"),
    ("030000ff0ee00000000000436f6f6b69653a20666f6f3dff61720d0a",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=�ar rn=1 rm=- l=- l2=00FF0E l3=- l4=0000FF ln=28"),
    ("160301002d010000290103000148030405060708090a0b020d0e0f101112131415161718191a1b1c1d1e1f00000213020100",
     "t=1 v=65539 e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=- l2=01002D010000290103000148030405060708090A0B02 l3=030100 l4=0301002D010000290103000148030405060708090A0B ln=50"),
    ("160301003f0100003b7e7e7e03000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000002130201000010000a00060004001d001700230002aabb",
     "t=1 v=8257662 e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=- l2=01003F0100003B7E7E7E03000102030405060708090A l3=030100 l4=0301003F0100003B7E7E7E0300010203040506070809 ln=70"),
    ("160301003f2700003b0303000102030405060708090a0b0c030e0f101112131415161718191a1b1c1d1e1f000002130201000010000a00060004001d001700230002aabb",
     "t=39 v=196611 e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=- l2=01003F2700003B0303000102030405060708090A0B0C l3=030100 l4=0301003F2700003B0303000102030405060708090A0B ln=68"),
    ("16030100410100003d0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000021301010000120010000e000c02683208687474702f312e31",
     "t=1 v=196611 e=0 s=0 n=- a=h2 c=1301 g=- x=- k=- r=- rn=0 rm=- l=- l2=0100410100003D0303000102030405060708090A0B0C l3=030100 l4=030100410100003D0303000102030405060708090A0B ln=70"),
    ("16030100410100003d0379000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000021302010000120010000e000c02683208687474702f312e31",
     "t=1 v=196729 e=0 s=0 n=- a=h2 c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=0100410100003D0379000102030405060708090A0B0C l3=030100 l4=030100410100003D0379000102030405060708090A0B ln=70"),
    ("160301007f0100007b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100005000000011000e0000037777772e746573742e6f72670010000e000c02683208687474702f312e31000a001a0104001d0017000d00060004040308040033000b0009001d0001aa0017000000230002aabb",
     "t=1 v=196611 e=1 s=- n=www a=h2 c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=01007F0100007B0303000102030405060708090A0B0C l3=030100 l4=0301007F0100007B0303000102030405060708090A0B ln=132"),
    ("160301007f0100007b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100005000000011000e00000b7777772e746573742e6f72670010000e000c02683208687474702f312e31000a00060004001d0017000d00060004040308040033000b0009001d0001aa0017000000010002aabb",
     "t=1 v=196611 e=1 s=0 n=www.test.or a=h2 c=1302 g=001D0017 x=04030804 k=001D0017 r=- rn=0 rm=- l=- l2=01007F0100007B0303000102030405060708090A0B0C l3=030100 l4=0301007F0100007B0303000102030405060708090A0B ln=132"),
    ("160301007f0100007b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100005000000011000e00000b7777772e746573742e6f72670010000e000c02683208687474702f312e31000a00060004001d0017000d00060004040308040033000b0009001d0000aa0017000000230002aabb",
     "t=1 v=196611 e=1 s=2 n=www.test.or a=h2 c=1302 g=001D0017 x=04030804 k=001DAA00 r=- rn=0 rm=- l=- l2=01007F0100007B0303000102030405060708090A0B0C l3=030100 l4=0301007F0100007B0303000102030405060708090A0B ln=132"),
    ("160301006401000060030300010203040506ff08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f207803787878787878787878787878787878787878787878787878787878787878000213020100001500000011000e00000b77777711746573742e6f7267",
     "t=1 v=196611 e=0 s=0 n=wwwtest.or a=- c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=01006401000060030300010203040506FF08090A0B0C l3=030100 l4=0301006401000060030300010203040506FF08090A0B ln=105"),
    ("160301007f0100007b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100005000000011000e00000b7777772e746573742e6f72670010000e000c026832086874ff702f312e31000a00060004001d0017000d00060004040308040233000b0009001d0001aa0017000000230002aabb",
     "t=1 v=196611 e=1 s=2 n=www.test.or a=h2 c=1302 g=001D0017 x=04030804 k=- r=- rn=0 rm=- l=- l2=01007F0100007B0303000102030405060708090A0B0C l3=030100 l4=0301007F0100007B0303000102030405060708090A0B ln=132"),
    ("030000130ee0000000ff00436f6f6b69653a20666f6f3d6202720d0a",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=br rn=1 rm=- l=- l2=00130E l3=- l4=000013 ln=28"),
    ("160301003f0100003b0303000102030405060708090a0b0c0d0e0f101112131415161718191aa51c1d1e1f000002130201000010000a00060004001d000200230002aabb",
     "t=1 v=196611 e=1 s=2 n=- a=- c=1302 g=001D0002 x=- k=- r=- rn=0 rm=- l=- l2=01003F0100003B0303000102030405060708090A0B0C l3=030100 l4=0301003F0100003B0303000102030405060708090A0B ln=68"),
    ("16030100440100004003ff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100001500000011000e00000b7777772e746573742e6f7267",
     "t=1 v=196863 e=0 s=0 n=www.test.or a=- c=1302 g=- x=- k=- r=- rn=0 rm=- l=- l2=0100440100004003FF000102030405060708090A0B0C l3=030100 l4=030100440100004003FF000102030405060708090A0B ln=73"),
    ("16030100434343010000400303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213020100001500000011000e00000b7777772e746573742e6f7267",
     "t=- v=64 e=- s=- n=- a=- c=- g=- x=- k=- r=- rn=0 rm=- l=- l2=0100434343010000400303000102030405060708090A l3=030100 l4=03010043434301000040030300010203040506070809 ln=75"),
    ("030000130ee00000000000436f6f6b69653a206d737473686173683d68656cff6f0d0a01000800030000f1",
     "t=- v=- e=- s=- n=- a=- c=- g=- x=- k=- r=hel�o rn=1 rm=hel�o l=- l2=00130E l3=- l4=000013 ln=43"),
];

#[test]
fn raw_fetches_agree_with_haproxy() {
    let (mut engine, collector, fe) = start(SETS);
    let mut bad = Vec::new();
    for (hex, want) in CASES {
        let got = log_of(&mut engine, &collector, fe, vec![unhex(hex)]);
        if got != *want {
            bad.push(format!("{hex}\n   want {want}\n   got  {got}"));
        }
    }
    assert!(bad.is_empty(), "{} of {} differ:\n{}", bad.len(), CASES.len(), bad.join("\n"));
}

/// A hello as a client sends it: SNI `www.test.or`, TLS 1.2.
fn client_hello() -> Vec<u8> {
    let name = b"www.test.or";
    let mut list = vec![0];
    list.extend((name.len() as u16).to_be_bytes());
    list.extend(name);
    let mut ext = vec![0, 0];
    ext.extend(((list.len() + 2) as u16).to_be_bytes());
    ext.extend((list.len() as u16).to_be_bytes());
    ext.extend(&list);
    let mut body = vec![3, 3];
    body.extend(0..32u8);
    body.extend([0, 0, 2, 0x13, 2, 1, 0]);
    body.extend((ext.len() as u16).to_be_bytes());
    body.extend(&ext);
    let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
    hs.extend(body);
    let mut rec = vec![0x16, 3, 1, (hs.len() >> 8) as u8, hs.len() as u8];
    rec.extend(hs);
    rec
}

/// Rules that wait on the hello, and on the end of the inspection (`WAIT_END`). Measured on
/// `HAProxy`: a hello that arrives in pieces is matched once whole, one that never completes
/// leaves the rules that read it unmatched, and `WAIT_END` fires at the end of the delay.
const ACL_RULES: &str = "tcp-request content set-var(txn.a) int(1) if { req.ssl_sni -m str www.test.or }\n  \
     tcp-request content set-var(txn.v) int(1) if { req.ssl_ver 3.3 }\n  \
     tcp-request content set-var(txn.g) int(1) if { req_ssl_ver gt 3.3 }\n  \
     tcp-request content set-var(txn.r) int(1) if RDP_COOKIE\n  \
     tcp-request content set-var(txn.w) int(1) if WAIT_END\n  \
     tcp-request content reject";

#[test]
fn rules_on_a_hello_wait_for_it_and_for_the_end_of_the_inspection() {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let fe = common::reserve_addr();
    let fmt = "a=%[var(txn.a)] v=%[var(txn.v)] g=%[var(txn.g)] r=%[var(txn.r)] w=%[var(txn.w)]";
    let cfg = config(collector.local_addr().expect("addr"), fe, fmt, ACL_RULES);
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let hello = client_hello();
    let cookie = [&[3u8, 0, 0, 0x1a, 0x0e, 0xe0, 0, 0, 0, 0, 0][..], b"Cookie: mstshash=u\r\n"].concat();
    let cases: Vec<(&str, Vec<Vec<u8>>, &str)> = vec![
        ("whole", vec![hello.clone()], "a=1 v=1 g=- r=- w=1"),
        ("two pieces", vec![hello[..20].to_vec(), hello[20..].to_vec()], "a=1 v=1 g=- r=- w=1"),
        ("three pieces", vec![hello[..3].to_vec(), hello[3..30].to_vec(), hello[30..].to_vec()], "a=1 v=1 g=- r=- w=1"),
        ("cut short", vec![hello[..20].to_vec()], "a=- v=- g=- r=- w=1"),
        ("not tls", vec![b"GET / HTTP/1.0\r\n\r\n".to_vec()], "a=- v=- g=- r=- w=1"),
        ("rdp cookie", vec![cookie], "a=- v=- g=- r=1 w=1"),
    ];
    for (name, chunks, want) in cases {
        assert_eq!(log_of(&mut engine, &collector, fe, chunks), want, "{name}");
    }
}

/// `ibex -c` on `rule` in a TCP frontend: the first line mentioning an error, if any.
fn check(i: usize, rule: &str) -> Option<String> {
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout client 1s\n  timeout server 1s\n  timeout connect 1s\n\
         frontend fe\n  bind 127.0.0.1:1\n  {rule}\n  default_backend be\nbackend be\n  server s 127.0.0.1:2\n"
    );
    let p = std::env::temp_dir().join(format!("ibex_rawfetch_{}_{i}.cfg", std::process::id()));
    std::fs::write(&p, cfg).expect("write config");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&p).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&p);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    text.lines().find(|l| l.contains("rror")).map(str::to_string)
}

/// Each of these is refused by `haproxy -c` (3.5-dev8-885761-29) with the quoted text; the
/// control rules are accepted. They were accepted here, and then matched nothing.
#[test]
fn raw_fetch_arguments_are_checked_at_load() {
    let refused: &[(&str, &str)] = &[
        ("tcp-request content set-var(txn.x) req.payload_lv(-1,2)", "invalid args in fetch method 'req.payload_lv' : payload offset1 must be positive"),
        ("tcp-request content set-var(txn.x) req.payload_lv(0,0)", "invalid args in fetch method 'req.payload_lv' : payload length must be > 0"),
        ("tcp-request content set-var(txn.x) req.payload_lv(0,2,zz)", "invalid args in fetch method 'req.payload_lv' : payload offset2 is not a number"),
        ("tcp-request content set-var(txn.x) req.payload_lv(1,1,-3)", "invalid args in fetch method 'req.payload_lv' : payload offset2 too negative"),
        ("tcp-request content set-var(txn.x) req.payload_lv(0)", "fetch method 'req.payload_lv' : missing arguments (got 1/2), type 'integer' expected"),
        ("tcp-request content set-var(txn.x) req.payload_lv", "fetch method 'req.payload_lv' : expected type 'integer' at position 1, but got nothing"),
        ("tcp-request content set-var(txn.x) req.payload_lv(a,2)", "fetch method 'req.payload_lv' : failed to parse 'a' as type 'integer' at position 1"),
        ("tcp-request content set-var(txn.x) req.ssl_sni(foo)", "fetch method 'req.ssl_sni' : expected ')' before 'foo)'"),
        ("tcp-request content set-var(txn.x) req.rdp_cookie(a,b)", "fetch method 'req.rdp_cookie' : expected ')' before ',b)'"),
        ("tcp-request content set-var(txn.x) req_rdp_cookie(a)", "unknown fetch method 'req_rdp_cookie'"),
        ("acl a req.ssl_ver 3.x\n  tcp-request content accept if a", "'3.x' is not a dotted number"),
        ("acl a req.ssl_ver 70000.0\n  tcp-request content accept if a", "'70000.0' is not a dotted number"),
    ];
    for (i, (rule, text)) in refused.iter().enumerate() {
        let got = check(i, rule);
        assert!(got.as_deref().is_some_and(|g| g.contains(text)), "{rule}: wanted {text:?}, got {got:?}");
    }
    let accepted = [
        "tcp-request content set-var(txn.x) req.ssl_hello_type",
        "tcp-request content set-var(txn.x) payload_lv(0,2,+2)",
        "tcp-request content accept if { req.ssl_ver 3.0:3.3 }",
        "tcp-request content accept if { req_ssl_ver ge 3.1 }",
        "tcp-request content accept if { req_rdp_cookie_cnt gt 0 }",
        "tcp-request content accept if RDP_COOKIE",
        "tcp-request content accept if WAIT_END",
        "tcp-request content accept if { req.ssl_alpn h2 }",
    ];
    for (i, rule) in accepted.iter().enumerate() {
        assert_eq!(check(100 + i, rule), None, "{rule}");
    }
}

/// A server that answers with `pieces` (a pause after each but the last), then lingers.
fn serve(pieces: Vec<(Vec<u8>, u64)>) -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind server");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        let Ok((mut c, _)) = l.accept() else { return };
        c.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let mut sink = [0u8; 64];
        let _ = c.read(&mut sink);
        for (bytes, pause) in pieces {
            let _ = c.write_all(&bytes);
            thread::sleep(Duration::from_millis(pause));
        }
        thread::sleep(Duration::from_millis(300));
    });
    addr
}

/// What a client receives through a TCP proxy whose backend holds `tcp-response` rules that
/// read a ServerHello, the server answering with `pieces`. Measured on `HAProxy`: a hello
/// that arrives in two pieces is waited for and accepted (49 bytes reach the client), one
/// that stalls, or an answer that is no hello at all, fails the rule and the next one rejects.
fn through_response_rules(pieces: Vec<(Vec<u8>, u64)>) -> usize {
    let srv = serve(pieces);
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout client 3s\n  timeout connect 1s\n  timeout server 3s\n\
         frontend fe\n  bind {fe}\n  default_backend be\n\
         backend be\n  tcp-response inspect-delay 400ms\n  \
         tcp-response content accept if {{ res.ssl_hello_type 2 }}\n  tcp-response content reject\n  server s {srv}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let (tx, rx) = mpsc::channel();
    let c = thread::spawn(move || {
        let mut s = TcpStream::connect(fe).expect("connect");
        s.write_all(b"x").expect("send");
        s.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let mut got = Vec::new();
        let mut buf = [0u8; 100];
        while let Ok(n) = s.read(&mut buf) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        let _ = tx.send(got.len());
    });
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut n = None;
    while n.is_none() && Instant::now() < deadline {
        let _ = engine.run_once();
        n = rx.try_recv().ok();
        thread::sleep(Duration::from_millis(1));
    }
    let _ = c.join();
    n.expect("the client finished")
}

#[test]
fn response_rules_on_a_server_hello_wait_for_it() {
    let hello = [vec![0x16, 3, 3, 0, 0x2c, 2, 0, 0, 0x28, 3, 3], (0..32u8).collect(), vec![0, 0x13, 2, 0, 0, 0]].concat();
    assert_eq!(hello.len(), 49);
    assert_eq!(through_response_rules(vec![(hello[..7].to_vec(), 150), (hello[7..].to_vec(), 0)]), 49, "in two pieces");
    assert_eq!(through_response_rules(vec![(hello[..7].to_vec(), 1000)]), 0, "stalled");
    assert_eq!(through_response_rules(vec![(b"hello world".to_vec(), 0)]), 0, "not a hello");
}

/// `payload` takes the direction of the rule set that runs it, `res.payload_lv` reads the
/// response, and `wait_end` has no value while the inspection can still wait: the registry
/// side of what `tcp-response content` rules and `req_len`/`payload_lv` ACLs evaluate.
#[test]
fn payload_fetches_follow_the_direction_of_their_rule_set() {
    use ibex_sample::{sample_registry, Expr, Sample, SampleContext};
    let reg = sample_registry();
    let res = b"\x00\x00\x00\x06onionsQQ";
    let ctx = SampleContext { raw_res: Some(res), res_body: Some(res), ..Default::default() };
    let sample = |e: &str, c: &SampleContext| Expr::parse(e).expect("parse").eval_sample(reg, c);
    assert_eq!(sample("payload(4,6)", &ctx), Some(Sample::Bin(b"onions".to_vec())));
    assert_eq!(sample("payload(0,3)", &ctx), Some(Sample::Bin(vec![0, 0, 0])));
    assert_eq!(sample("res.payload_lv(0,4)", &ctx), Some(Sample::Bin(b"onions".to_vec())));
    assert_eq!(sample("payload_lv(0,4)", &ctx), Some(Sample::Bin(b"onions".to_vec())));
    assert_eq!(sample("payload(40,6)", &ctx), None);
    let req = b"\x00\x00\x00\x05hello";
    let ctx = SampleContext { raw_req: Some(req), req_body: Some(req), ..Default::default() };
    assert_eq!(sample("req_len", &ctx), Some(Sample::Sint(9)));
    assert_eq!(sample("payload(4,5)", &ctx), Some(Sample::Bin(b"hello".to_vec())), "a request rule set");
    assert_eq!(sample("payload_lv(0,4)", &ctx), Some(Sample::Bin(b"hello".to_vec())));
    // The ACL forms of `req.ssl_ver`: dotted, ranged, with operators.
    let hello = client_hello();
    let ctx = SampleContext { raw_req: Some(&hello), req_body: Some(&hello), ..Default::default() };
    for (expr, want) in [
        ("req.ssl_ver 3.3", true),
        ("req.ssl_ver 3.0", false),
        ("req.ssl_ver 3.0:3.3", true),
        ("req.ssl_ver 3.4:3.9", false),
        ("req.ssl_ver 3.1-3.3", true),
        ("req.ssl_ver :3.2", false),
        ("req.ssl_ver 3.3:", true),
        ("req.ssl_ver ge 3.3", true),
        ("req_ssl_ver gt 3.3", false),
        ("req_ssl_ver lt 4", true),
        ("req.ssl_ver 3", false),
    ] {
        assert_eq!(Expr::parse(expr).expect(expr).eval(reg, &ctx), want, "{expr}");
    }
    assert!(Expr::parse("req.ssl_ver 3.x").is_err());
    assert!(Expr::parse("req.ssl_ver 3.70000").is_err());
    // A single sample sees the first ALPN name, the descriptor's own function included.
    let mut ext = vec![0, 16, 0, 11, 0, 9, 2];
    ext.extend(b"h2");
    ext.push(5);
    ext.extend(b"h2c--");
    let h = {
        let mut body = vec![3, 3];
        body.extend(0..32u8);
        body.extend([0, 0, 2, 0x13, 2, 1, 0]);
        body.extend((ext.len() as u16).to_be_bytes());
        body.extend(&ext);
        let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend(body);
        let mut rec = vec![0x16, 3, 1, (hs.len() >> 8) as u8, hs.len() as u8];
        rec.extend(hs);
        rec
    };
    let ctx = SampleContext { raw_req: Some(&h), ..Default::default() };
    let single = (reg.get_fetch("req.ssl_alpn").expect("registered").func)(&ctx, &[]);
    assert_eq!(single, Some(Sample::Str("h2".into())));
}
