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
//! [`ibex_tls::tcp::ServerVerifier`] reads as "no name to check".

use crate::xprt::{self, ServerXprt};
use ibex_config::{Server, ServerSsl, SslVerify};
use ibex_sample::{Expr, Registry, Sample, SampleContext};
use rustls24::pki_types::ServerName;
use rustls24::ClientConfig;
use std::io;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

/// The two [`ClientConfig`]s of one server line on one provider, which differ only in whether
/// the DNS name they are opened with goes on the wire.
#[derive(Debug)]
struct Built {
    with_sni: Arc<ClientConfig>,
    without_sni: Arc<ClientConfig>,
    /// The crypto provider both run on (T460), counted when a handshake completes.
    provider: ibex_tls::TlsCryptoProvider,
}

impl Built {
    fn build(ssl: &ServerSsl, alpn: &[String], who: &str, provider: ibex_tls::TlsCryptoProvider) -> io::Result<Self> {
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
        let with_sni = ibex_tls::tcp::build_backend_client_config_with(&opts, provider)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{who} : {e}")))?;
        let mut without = (*with_sni).clone();
        without.enable_sni = false;
        Ok(Self { with_sni, without_sni: Arc::new(without), provider })
    }
}

/// A server line's configurations: the build of startup, and the build on the other provider
/// once `set ssl crypto-provider` made one (T460), with what that build is made from.
#[derive(Debug)]
struct Builds {
    home: Built,
    other: std::sync::OnceLock<Built>,
    ssl: ServerSsl,
    alpn: Vec<String>,
    who: String,
}

impl Builds {
    /// The build a connection opened now uses: one atomic load.
    fn current(&self) -> &Built {
        if ibex_tls::provider::active() == self.home.provider {
            return &self.home;
        }
        self.other.get().unwrap_or(&self.home)
    }
}

impl ibex_tls::provider::Rebuild for Builds {
    fn prepare(self: Arc<Self>, p: ibex_tls::TlsCryptoProvider) -> Result<Option<ibex_tls::provider::Publish>, String> {
        if p == self.home.provider || self.other.get().is_some() {
            return Ok(None);
        }
        let built = Built::build(&self.ssl, &self.alpn, &self.who, p).map_err(|e| e.to_string())?;
        Ok(Some(Box::new(move || {
            let _ = self.other.set(built);
        })))
    }
}

/// The configurations of one server line (or of its checks), and its `verifyhost`.
#[derive(Debug)]
struct Configs {
    builds: Arc<Builds>,
    verifyhost: Option<String>,
}

impl Configs {
    fn build(ssl: &ServerSsl, alpn: &[String], who: &str) -> io::Result<Self> {
        let home = Built::build(ssl, alpn, who, ibex_tls::provider::active())?;
        let builds = Arc::new(Builds { home, other: std::sync::OnceLock::new(), ssl: ssl.clone(), alpn: alpn.to_vec(), who: who.to_string() });
        ibex_tls::provider::register(Arc::downgrade(&builds) as std::sync::Weak<dyn ibex_tls::provider::Rebuild>);
        Ok(Self { builds, verifyhost: ssl.verifyhost.clone() })
    }

    /// Opens the TLS transport over the connected `fd`: `sni` is sent and checked when
    /// given, else `verifyhost` is checked without being sent, else no name is checked.
    /// The connection is keyed by `sni` whether or not it could be sent ([`ServerXprt::sni`]).
    fn connect(&self, fd: &impl AsRawFd, sni: Option<&str>, server_ip: IpAddr) -> ServerXprt {
        let mut x = self.connect_named(fd, sni, server_ip);
        x.set_key_name(sni);
        x
    }

    fn connect_named(&self, fd: &impl AsRawFd, sni: Option<&str>, server_ip: IpAddr) -> ServerXprt {
        let b = self.builds.current();
        let dns = |name: &str| ServerName::try_from(name.to_string()).ok().filter(|n| matches!(n, ServerName::DnsName(_)));
        if let Some(name) = sni.filter(|s| !s.is_empty()).and_then(dns) {
            return xprt::connect_tls_on(fd, Arc::clone(&b.with_sni), name, b.provider);
        }
        if let Some(name) = self.verifyhost.as_deref().and_then(dns) {
            return xprt::connect_tls_on(fd, Arc::clone(&b.without_sni), name, b.provider);
        }
        xprt::connect_tls_on(fd, Arc::clone(&b.without_sni), ServerName::IpAddress(server_ip.into()), b.provider)
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
        // Without `check-alpn` the check offers the server's `alpn` (`HAProxy`: `alpn h2`
        // and `check` gives an h2 check, A.3 row 23; `check-alpn http/1.1` overrides it, row 25).
        let alpn = if ssl.check_alpn.is_empty() { &ssl.alpn } else { &ssl.check_alpn };
        let configs = Configs::build(ssl, alpn, who)?;
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
