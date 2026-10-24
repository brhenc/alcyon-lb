// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/ssl_sock.c (ssl_sock_prepare_srv_ctx, ssl_sock_srv_verifycbk),
// src/server.c (srv_configure_auto_sni) and src/tcpcheck.c (tcpcheck_connect_auto_sni).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! TLS towards a server (T113): what a `server ... ssl` line becomes at load, and how a
//! connection to it is opened.
//!
//! `HAProxy` builds one `SSL_CTX` per server at load (`ssl_sock_prepare_srv_ctx`) and
//! decides the name per connection: the `sni` expression -- in `mode http`, without one,
//! the request's Host header (`srv_configure_auto_sni`: `req.hdr(host),field(1,:)`) -- is
//! sent in SNI and is the name the certificate must carry; without SNI, `verifyhost` is
//! that name; without either the name is not checked (`ssl_sock_srv_verifycbk`). Health
//! checks have their own name: `check-sni`, else the `http-check` Host header
//! (`tcpcheck_connect_auto_sni`), else none; and their own ALPN (`check-alpn`).
//!
//! rustls takes the name as the [`ServerName`] a connection is opened with, so the three
//! cases become: a DNS name on a config that sends SNI; a DNS name on a config that does
//! not (`enable_sni` off); the server's IP address, which rustls never sends and which
//! [`ibex_tls::ServerVerifier`] reads as "no name to check".

use crate::xprt::{self, ServerXprt};
use ibex_config::{Server, ServerSsl, SslVerify};
use ibex_sample::{Expr, Registry, Sample, SampleContext};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use std::io;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

/// The two [`ClientConfig`]s of one server line, which differ only in whether the DNS
/// name they are opened with goes on the wire.
#[derive(Debug)]
struct Configs {
    with_sni: Arc<ClientConfig>,
    without_sni: Arc<ClientConfig>,
    verifyhost: Option<String>,
}

impl Configs {
    fn build(ssl: &ServerSsl, alpn: &[String], who: &str) -> io::Result<Self> {
        ibex_tls::install_default_crypto_provider();
        let opts = ibex_tls::BackendTlsOptions {
            verify_required: ssl.verify != Some(SslVerify::None),
            ca_file: ssl.ca_file.as_deref().map(Into::into),
            crl_file: ssl.crl_file.as_deref().map(Into::into),
            client_crt: ssl.crt.as_deref().map(Into::into),
            alpn: alpn.iter().map(|p| p.as_bytes().to_vec()).collect(),
            min_ver: ssl.min_ver,
            max_ver: ssl.max_ver,
            no_reuse: ssl.no_reuse,
        };
        let with_sni = ibex_tls::build_backend_client_config(&opts)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{who} : {e}")))?;
        let mut without = (*with_sni).clone();
        without.enable_sni = false;
        Ok(Self {
            with_sni,
            without_sni: Arc::new(without),
            verifyhost: ssl.verifyhost.clone(),
        })
    }

    /// Opens the TLS transport over the connected `fd`: `sni` is sent and checked when
    /// given, else `verifyhost` is checked without being sent, else no name is checked.
    fn connect(&self, fd: &impl AsRawFd, sni: Option<&str>, server_ip: IpAddr) -> ServerXprt {
        let dns = |name: &str| ServerName::try_from(name.to_string()).ok().filter(|n| matches!(n, ServerName::DnsName(_)));
        if let Some(name) = sni.filter(|s| !s.is_empty()).and_then(dns) {
            return xprt::connect_tls(fd, Arc::clone(&self.with_sni), name);
        }
        if let Some(name) = self.verifyhost.as_deref().and_then(dns) {
            return xprt::connect_tls(fd, Arc::clone(&self.without_sni), name);
        }
        xprt::connect_tls(fd, Arc::clone(&self.without_sni), ServerName::IpAddress(server_ip.into()))
    }
}

/// A server line's TLS, for the data path.
#[derive(Debug)]
pub struct ServerTls {
    configs: Configs,
    /// The `sni` expression, or the automatic one in `mode http`.
    sni: Option<Expr>,
}

impl ServerTls {
    /// What `server ... ssl` becomes, or `None` without `ssl`.
    ///
    /// # Errors
    /// A `ca-file`, `crl-file` or `crt` that cannot be loaded, a version range with
    /// nothing in it, or an `sni` expression that does not parse; `who` names the server.
    pub fn from_server(server: &Server, mode_http: bool, who: &str) -> io::Result<Option<Self>> {
        let Some(ssl) = server.ssl.as_deref().filter(|s| s.ssl) else {
            return Ok(None);
        };
        let configs = Configs::build(ssl, &ssl.alpn, who)?;
        let sni = match ssl.sni.as_deref() {
            Some(e) => Some(e),
            None if mode_http && !ssl.no_sni_auto => Some("req.hdr(host),field(1,:)"),
            None => None,
        }
        .map(|e| {
            let bad = |err: String| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{who} : error detected while parsing sni or pool-conn-name expressions : {err}."),
                )
            };
            let expr = Expr::parse(e).map_err(bad)?;
            // The registry evaluates this at every connection; a fetch it lacks would
            // give no SNI, silently. `HAProxy`: "unknown fetch method 'bogus'".
            if crate::engine::sample_registry().get_fetch(&expr.fetch_name).is_none() {
                return Err(bad(format!("unknown fetch method '{}'", expr.fetch_name)));
            }
            Ok(expr)
        })
        .transpose()?;
        Ok(Some(Self { configs, sni }))
    }

    /// `f` of the name this connection sends in SNI, from the `sni` expression over the
    /// stream (`None`: no SNI). The name is evaluated for every request, which reads it
    /// only, so a text sample is lent to `f` and its string given back to the sample
    /// engine's spares afterwards: the automatic SNI allocates nothing per request.
    pub fn with_sni<R>(&self, registry: &Registry, ctx: &SampleContext<'_>, f: impl FnOnce(Option<&str>) -> R) -> R {
        let Some(smp) = self.sni.as_ref().and_then(|e| e.eval_sample(registry, ctx)) else {
            return f(None);
        };
        let r = match &smp {
            Sample::Str(s) => f(Some(s.as_str()).filter(|s| !s.is_empty())),
            other => f(Some(crate::engine::sample_to_string(other).as_str()).filter(|s| !s.is_empty())),
        };
        ibex_sample::spare::give_sample(smp);
        r
    }

    /// Opens the TLS transport over the connected `fd`.
    pub fn connect(&self, fd: &impl AsRawFd, sni: Option<&str>, server_ip: IpAddr) -> ServerXprt {
        self.configs.connect(fd, sni, server_ip)
    }
}

/// A server line's TLS, for its health checks.
#[derive(Debug)]
pub struct CheckTls {
    configs: Configs,
    /// `check-sni`.
    sni: Option<String>,
    /// Without `check-sni`, the `http-check` Host header is sent (`check-sni-auto`).
    auto_sni: bool,
}

impl CheckTls {
    /// What the checks of `server` use, or `None` when they are plaintext
    /// (`ServerSsl::check_uses_tls`).
    ///
    /// # Errors
    /// As [`ServerTls::from_server`].
    pub fn from_server(server: &Server, who: &str) -> io::Result<Option<Self>> {
        let Some(ssl) = server.ssl.as_deref().filter(|s| s.check_uses_tls(server.check_port)) else {
            return Ok(None);
        };
        let configs = Configs::build(ssl, &ssl.check_alpn, who)?;
        Ok(Some(Self {
            configs,
            sni: ssl.check_sni.clone(),
            auto_sni: !ssl.no_check_sni_auto,
        }))
    }

    /// Opens the TLS transport of one check over the connected `fd`. `host` is the Host
    /// header the check sends, if any, with its port stripped as `HAProxy` strips it.
    pub fn connect(&self, fd: &impl AsRawFd, host: Option<&str>, server_ip: IpAddr) -> ServerXprt {
        let auto = host.filter(|_| self.auto_sni).map(strip_port);
        let sni = self.sni.as_deref().or(auto);
        self.configs.connect(fd, sni, server_ip)
    }
}

/// `tcpcheck_connect_auto_sni`: everything up to the last `:`, unless a `]` (an IPv6
/// literal's) comes after it.
fn strip_port(host: &str) -> &str {
    match host.rfind([':', ']']) {
        Some(i) if host.as_bytes()[i] == b':' => &host[..i],
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::{strip_port, Configs, ServerTls};
    use ibex_config::{ServerSsl, SslVerify};
    use ibex_sample::{Expr, SampleContext};

    /// The name `sni <expr>` gives over an empty stream.
    fn sni_of(expr: &str) -> Option<String> {
        let tls = ServerTls {
            configs: Configs::build(&ServerSsl { verify: Some(SslVerify::None), ..ServerSsl::default() }, &[], "t").expect("configs"),
            sni: Some(Expr::parse(expr).expect("parse")),
        };
        tls.with_sni(crate::engine::sample_registry(), &SampleContext::default(), |s| s.map(str::to_string))
    }

    /// `sample_fetch_as_type(..., SMP_T_STR)`: a sample of another type is sent as its text;
    /// an empty name, or a request without Host under the automatic SNI, sends none.
    #[test]
    fn the_sni_is_the_text_of_the_sample_and_none_when_empty() {
        assert_eq!(sni_of("int(7)").as_deref(), Some("7"));
        assert_eq!(sni_of("str(a.example)").as_deref(), Some("a.example"));
        assert_eq!(sni_of("str()"), None);
        assert_eq!(sni_of("req.hdr(host),field(1,:)"), None);
    }

    #[test]
    fn the_check_host_loses_its_port_as_haproxy_strips_it() {
        assert_eq!(strip_port("hc.example:8443"), "hc.example");
        assert_eq!(strip_port("hc.example"), "hc.example");
        assert_eq!(strip_port("[::1]:443"), "[::1]");
        assert_eq!(strip_port("[::1]"), "[::1]");
    }
}
