// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `ssl_f_*` fetches describe the certificate the frontend presented (T398).
//!
//! Ibex refused them at load ("unknown fetch method 'ssl_f_der'"). Expected values were
//! measured on `/home/bhenc/reference/haproxy/haproxy` (3.5-dev8) with the same two
//! certificates (`data/ssl_f_common.pem`: RSA, `data/ssl_f_ecdsa.pem`: ECDSA, listed in that
//! order on one bind), one SNI at a time:
//!
//! * SNI `www.test1.com`, or none, or an unknown name: the RSA certificate (the first one is
//!   the default): `ssl_f_sha1` `DF3B...D3EA`, `ssl_f_sig_alg` `RSA-SHA256`, `ssl_f_key_alg`
//!   `rsaEncryption`, `ssl_f_notafter` `330917162600Z`, `ssl_f_notbefore` `230920162600Z`,
//!   `ssl_f_s_dn` `/C=FR/L=Paris/O=test1/CN=www.test1.com`, `ssl_f_version` 3;
//! * SNI `localhost`: the ECDSA one: `ecdsa-with-SHA256`, `id-ecPublicKey`, `/CN=localhost`;
//! * `ssl_f_s_dn(CN)` `www.test1.com`, `ssl_f_s_dn(O,1)` `test1`, `ssl_f_i_dn(CN,1)` the issuer's CN;
//!   an entry that is not there gives no sample;
//! * `ssl_c_*` (the peer's certificate) are not part of this task.

use crate::common;

use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

fn curl(port: u16, sni: Option<&str>) -> String {
    let mut c = Command::new("curl");
    c.args(["-sk", "--http1.1", "-D-", "-o/dev/null", "--max-time", "5"]);
    let url = match sni {
        Some(n) => {
            c.args(["--resolve", &format!("{n}:{port}:127.0.0.1")]);
            format!("https://{n}:{port}/")
        }
        None => format!("https://127.0.0.1:{port}/"),
    };
    let out = c.arg(url).output().expect("curl");
    String::from_utf8_lossy(&out.stdout).to_lowercase()
}

fn hdr(resp: &str, name: &str) -> String {
    resp.lines()
        .find_map(|l| l.strip_prefix(&format!("{name}:")))
        .map_or_else(|| "<none>".to_string(), |v| v.trim().to_string())
}

struct Ibex(std::process::Child, #[allow(dead_code)] NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(port: std::net::SocketAddr) -> Ibex {
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {port} ssl crt {DATA}/ssl_f_common.pem crt {DATA}/ssl_f_ecdsa.pem\n\
         \x20 http-request return status 200 hdr x-der %[ssl_f_der,hex] hdr x-sha1 %[ssl_f_sha1,hex] \
         hdr x-na %[ssl_f_notafter] hdr x-nb %[ssl_f_notbefore] hdr x-sig %[ssl_f_sig_alg] \
         hdr x-i %[ssl_f_i_dn] hdr x-s %[ssl_f_s_dn] hdr x-ser %[ssl_f_serial,hex] \
         hdr x-key %[ssl_f_key_alg] hdr x-ver %[ssl_f_version] hdr x-cn %[ssl_f_s_dn(CN)] \
         hdr x-o %[ssl_f_s_dn(O,1)] hdr x-nope %[ssl_f_s_dn(OU)] hdr x-i1 %[ssl_f_i_dn(CN,1)]\n"
    );
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(cfg.as_bytes()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex(child, f);
    assert!(common::wait_listening(port), "ibex never listened on {port}");
    ibex
}

#[test]
fn the_frontend_certificate_is_described_by_ssl_f() {
    let addr = common::reserve_addr();
    let _ibex = start(addr);
    for sni in [Some("www.test1.com"), None, Some("example.com")] {
        let r = curl(addr.port(), sni);
        assert!(hdr(&r, "x-der").starts_with("308203c7308202afa003020102021445b6c777"), "{sni:?}: {r}");
        assert_eq!(hdr(&r, "x-sha1"), "df3b6e847a7bf83dfaafcfec65ee9bc36230d3ea", "{r}");
        assert_eq!(hdr(&r, "x-na"), "330917162600z", "{r}");
        assert_eq!(hdr(&r, "x-nb"), "230920162600z", "{r}");
        assert_eq!(hdr(&r, "x-sig"), "rsa-sha256", "{r}");
        assert_eq!(hdr(&r, "x-i"), "/c=fr/l=paris/o=haproxy technologies/cn=haproxy test intermediate ca", "{r}");
        assert_eq!(hdr(&r, "x-s"), "/c=fr/l=paris/o=test1/cn=www.test1.com", "{r}");
        assert_eq!(hdr(&r, "x-ser"), "45b6c777a017159a19126340c1053521b91e123b", "{r}");
        assert_eq!(hdr(&r, "x-key"), "rsaencryption", "{r}");
        assert_eq!(hdr(&r, "x-ver"), "3", "{r}");
        assert_eq!(hdr(&r, "x-cn"), "www.test1.com", "{r}");
        assert_eq!(hdr(&r, "x-o"), "test1", "{r}");
        assert_eq!(hdr(&r, "x-nope"), "<none>", "{r}");
        assert_eq!(hdr(&r, "x-i1"), "haproxy test intermediate ca", "{r}");
    }
}

#[test]
fn the_certificate_chosen_by_sni_is_the_one_described() {
    let addr = common::reserve_addr();
    let _ibex = start(addr);
    let r = curl(addr.port(), Some("localhost"));
    assert!(hdr(&r, "x-der").starts_with("3082017f30820105a003020102021460"), "{r}");
    assert_eq!(hdr(&r, "x-sha1"), "a490d069dbafbee66de434bec34030ade8bccbf1", "{r}");
    assert_eq!(hdr(&r, "x-na"), "200118093112z", "{r}");
    assert_eq!(hdr(&r, "x-nb"), "191219093112z", "{r}");
    assert_eq!(hdr(&r, "x-sig"), "ecdsa-with-sha256", "{r}");
    assert_eq!(hdr(&r, "x-i"), "/cn=localhost", "{r}");
    assert_eq!(hdr(&r, "x-s"), "/cn=localhost", "{r}");
    assert_eq!(hdr(&r, "x-ser"), "6038257b288b25229b496ce55373d3081fcf3d82", "{r}");
    assert_eq!(hdr(&r, "x-key"), "id-ecpublickey", "{r}");
    assert_eq!(hdr(&r, "x-cn"), "localhost", "{r}");
    assert_eq!(hdr(&r, "x-o"), "<none>", "{r}");
}
