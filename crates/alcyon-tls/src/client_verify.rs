// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Client certificate verification for `bind ... ssl verify optional|required ca-file <f>`
//! (T655 slice C1a).
//!
//! Validation uses `rustls-webpki` exclusively (no hand-rolled path or signature validator).
//! `TlsCtx::server_next` calls [`BindClientVerifier::verify_detailed`] at rustls 0.24's
//! `VerifyClientIdentity` state so Alcyon keeps the verification outcome as OpenSSL
//! `X509_V_ERR` codes (`ssl_c_verify`, `ssl_c_err`, `ssl_c_ca_err`) while returning the
//! corresponding `rustls24::Error` so rustls emits the matching TLS alert.

use crate::config::Der;
use crate::provider;
use crate::x509;
use crate::TlsCryptoProvider;
use alcyon_config::X509ErrMask;
use alcyon_proto::transport::{VerifyError, VerifyResult};
use rustls24::client::danger::HandshakeSignatureValid;
use rustls24::crypto::{
    verify_tls12_signature, verify_tls13_signature, CryptoProvider, Identity, SignatureScheme,
    VerifiedIdentity, WebPkiSupportedAlgorithms,
};
use rustls24::error::{
    ApiMisuse, CertRevocationListError, CertificateError, Error, ExtendedKeyPurpose, OtherError,
};
use rustls24::pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use rustls24::server::danger::{ClientIdentity, ClientVerifier, SignatureVerificationInput};
use rustls24::{DistinguishedName, RootCertStore};
use std::sync::Arc;
use webpki::{
    CertRevocationList, EndEntityCert, ExpirationPolicy, ExtendedKeyUsage,
    ExtendedKeyUsageValidator, KeyPurposeIdIter, RevocationCheckDepth, RevocationOptions,
    RevocationOptionsBuilder, UnknownStatusPolicy,
};

/// OpenSSL `X509_V_ERR_*` numeric codes (`include/openssl/x509_vfy.h`), matching
/// `HAProxy`'s `ssl_c_verify`, `ssl_c_err`, `ssl_c_ca_err` and `x509_v_err_str`.
pub mod x509_err {
    pub const OK: i32 = 0;
    pub const UNSPECIFIED: i32 = 1;
    pub const UNABLE_TO_GET_CRL: i32 = 3;
    pub const CERT_SIGNATURE_FAILURE: i32 = 7;
    pub const CRL_SIGNATURE_FAILURE: i32 = 8;
    pub const CERT_NOT_YET_VALID: i32 = 9;
    pub const CERT_HAS_EXPIRED: i32 = 10;
    pub const CRL_HAS_EXPIRED: i32 = 12;
    pub const ERROR_IN_CERT_NOT_BEFORE_FIELD: i32 = 13;
    pub const ERROR_IN_CERT_NOT_AFTER_FIELD: i32 = 14;
    pub const DEPTH_ZERO_SELF_SIGNED_CERT: i32 = 18;
    pub const SELF_SIGNED_CERT_IN_CHAIN: i32 = 19;
    pub const UNABLE_TO_GET_ISSUER_CERT_LOCALLY: i32 = 20;
    pub const CERT_CHAIN_TOO_LONG: i32 = 22;
    pub const CERT_REVOKED: i32 = 23;
    pub const PATH_LENGTH_EXCEEDED: i32 = 25;
    pub const INVALID_PURPOSE: i32 = 26;
    pub const UNHANDLED_CRITICAL_EXTENSION: i32 = 34;
    pub const KEYUSAGE_NO_CRL_SIGN: i32 = 35;
    pub const INVALID_EXTENSION: i32 = 41;
    pub const DIFFERENT_CRL_SCOPE: i32 = 44;
    pub const UNSUPPORTED_EXTENSION_FEATURE: i32 = 45;
    pub const PERMITTED_VIOLATION: i32 = 47;
    pub const UNSUPPORTED_CONSTRAINT_SYNTAX: i32 = 52;
    pub const UNSUPPORTED_NAME_SYNTAX: i32 = 53;
    pub const HOSTNAME_MISMATCH: i32 = 62;
    pub const UNSUPPORTED_SIGNATURE_ALGORITHM: i32 = 76;
    pub const SIGNATURE_ALGORITHM_MISMATCH: i32 = 77;
    pub const SIGNATURE_ALGORITHM_INCONSISTENCY: i32 = 78;
    pub const INVALID_CA: i32 = 79;
}

/// Recorded OpenSSL `X509_V_ERR` verification outcomes for a client certificate chain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientVerifyCodes {
    /// `ssl_c_verify`: first verification error (0 = `X509_V_OK`).
    pub verify: i32,
    /// `ssl_c_err`: first verification error on the client leaf certificate (depth 0).
    pub crt_err: i32,
    /// `ssl_c_ca_err`: first verification error in the CA chain above the leaf (depth > 0).
    pub ca_err: i32,
}

impl ClientVerifyCodes {
    /// All zero (`X509_V_OK`).
    pub const OK: Self = Self { verify: 0, crt_err: 0, ca_err: 0 };

    #[must_use]
    pub const fn leaf_err(code: i32) -> Self {
        Self { verify: code, crt_err: code, ca_err: 0 }
    }

    #[must_use]
    pub const fn ca_err(code: i32) -> Self {
        Self { verify: code, crt_err: 0, ca_err: code }
    }

    fn record(&mut self, code: i32, is_leaf: bool) {
        if is_leaf {
            if self.crt_err == 0 {
                self.crt_err = code;
            }
        } else if self.ca_err == 0 {
            self.ca_err = code;
        }
        self.verify = if self.crt_err != 0 { self.crt_err } else { self.ca_err };
    }

    /// Records the untrusted-issuer code (`18`/`19`/`20`) at its depth, superseding any
    /// provisional error recorded at that depth before trust-anchor checking ran, while
    /// preserving a non-zero `verify` code (matching OpenSSL's `SSL_get_verify_result`).
    fn record_untrusted(&mut self, code: i32, is_leaf: bool) {
        if is_leaf {
            self.crt_err = code;
        } else {
            self.ca_err = code;
        }
        if self.verify == 0 {
            self.verify = code;
        }
    }

    /// Provider-neutral summary for [`alcyon_proto::transport::TlsInfo::peer_verify`].
    #[must_use]
    pub const fn to_verify_result(self) -> VerifyResult {
        match self.verify {
            x509_err::OK => VerifyResult::Ok,
            x509_err::CERT_HAS_EXPIRED => VerifyResult::Failed(VerifyError::Expired),
            x509_err::CERT_NOT_YET_VALID => VerifyResult::Failed(VerifyError::NotYetValid),
            x509_err::DEPTH_ZERO_SELF_SIGNED_CERT | x509_err::SELF_SIGNED_CERT_IN_CHAIN => {
                VerifyResult::Failed(VerifyError::SelfSigned)
            }
            x509_err::UNABLE_TO_GET_ISSUER_CERT_LOCALLY => VerifyResult::Failed(VerifyError::UntrustedRoot),
            x509_err::CERT_REVOKED => VerifyResult::Failed(VerifyError::Revoked),
            x509_err::HOSTNAME_MISMATCH => VerifyResult::Failed(VerifyError::HostnameMismatch),
            x509_err::CERT_CHAIN_TOO_LONG | x509_err::PATH_LENGTH_EXCEEDED => {
                VerifyResult::Failed(VerifyError::ChainTooLong)
            }
            _ => VerifyResult::Failed(VerifyError::Other),
        }
    }
}

/// Configuration for [`BindClientVerifier`]: combined trust roots (`ca-file` + `ca-verify-file`),
/// `CertificateRequest` hint subjects (`ca-file` only, empty when `no-ca-names` or `ca-verify-file`
/// alone), parsed v2 CRLs (`crl-file`), mandatory flag, and leaf/CA ignore-error masks.
#[derive(Debug)]
pub struct BindClientVerifyOpts {
    pub roots: Arc<RootCertStore>,
    pub root_hint_subjects: Vec<DistinguishedName>,
    pub crls: Vec<CertRevocationList<'static>>,
    pub mandatory: bool,
    pub crt_ignore_err: X509ErrMask,
    pub ca_ignore_err: X509ErrMask,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RevMode {
    Chain,
    EndEntity,
    None,
}

/// Client certificate verifier for a `bind ... ssl verify optional|required` line.
///
/// Advertises the configured CA hints in the `CertificateRequest`, verifies presented client
/// chains (and optional chain-wide CRLs) with `rustls-webpki`, honors `crt-ignore-err` (depth 0)
/// and `ca-ignore-err` (depth > 0), and maps the outcome into OpenSSL `X509_V_ERR` codes.
#[derive(Debug)]
pub struct BindClientVerifier {
    roots: Arc<RootCertStore>,
    root_hint_subjects: Arc<[DistinguishedName]>,
    crls: Vec<CertRevocationList<'static>>,
    mandatory: bool,
    crt_ignore_err: X509ErrMask,
    ca_ignore_err: X509ErrMask,
    supported_algs: WebPkiSupportedAlgorithms,
    all_algs: &'static [&'static dyn SignatureVerificationAlgorithm],
}

impl BindClientVerifier {
    /// Builds a client verifier from the CA roots of `ca-file`, `mandatory` (`true` for
    /// `verify required`, `false` for `verify optional`), and the bind's crypto provider.
    #[must_use]
    pub fn new(
        roots: Arc<RootCertStore>,
        mandatory: bool,
        kind: TlsCryptoProvider,
        provider: &CryptoProvider,
    ) -> Arc<Self> {
        let root_hint_subjects = roots.subjects();
        Self::from_opts(
            BindClientVerifyOpts {
                roots,
                root_hint_subjects,
                crls: Vec::new(),
                mandatory,
                crt_ignore_err: X509ErrMask::EMPTY,
                ca_ignore_err: X509ErrMask::EMPTY,
            },
            kind,
            provider,
        )
    }

    /// Builds a client verifier with full C1a+C1b options (`ca-verify-file`, `crl-file`,
    /// `crt-ignore-err`, `ca-ignore-err`, `no-ca-names`).
    #[must_use]
    pub fn from_opts(
        opts: BindClientVerifyOpts,
        kind: TlsCryptoProvider,
        provider: &CryptoProvider,
    ) -> Arc<Self> {
        Arc::new(Self {
            roots: opts.roots,
            root_hint_subjects: Arc::from(opts.root_hint_subjects),
            crls: opts.crls,
            mandatory: opts.mandatory,
            crt_ignore_err: opts.crt_ignore_err,
            ca_ignore_err: opts.ca_ignore_err,
            supported_algs: provider.signature_verification_algorithms,
            all_algs: provider::verification_algs(kind),
        })
    }

    /// Verifies `identity` with `rustls-webpki` and returns both the rustls verdict (whose error
    /// drives the wire TLS alert) and the OpenSSL `X509_V_ERR` codes for `ssl_c_verify`,
    /// `ssl_c_err`, and `ssl_c_ca_err`.
    ///
    /// # Errors
    /// The returned `Result` is `Err` whenever a non-ignored verification error occurs.
    pub fn verify_detailed<'a>(
        &self,
        identity: &ClientIdentity<'a, '_>,
    ) -> (Result<VerifiedIdentity<'a>, Error>, ClientVerifyCodes) {
        self.verify_identity_at(identity.identity, identity.now)
    }

    const fn is_ignored(&self, code: i32, is_leaf: bool) -> bool {
        if is_leaf {
            self.crt_ignore_err.contains(code)
        } else {
            self.ca_ignore_err.contains(code)
        }
    }

    /// Verifies `identity` at `now`.
    ///
    /// Security invariant: this function returns `Ok` **only** if:
    ///   (a) `EndEntityCert::verify_for_usage` succeeded (`Ok(path)`) on some pass (meaning
    ///       `rustls-webpki` cryptographically verified a chain from the leaf to a trust anchor
    ///       in `self.roots`), OR
    ///   (b) the untrusted-issuer error that prevented reaching a trust anchor
    ///       (`untrusted_issuer_for`: OpenSSL code 18/20 at depth 0, or 19/20 at depth > 0) is
    ///       itself ignored at that depth (`crt_ignore_err` / `ca_ignore_err`).
    ///
    /// Any ignored error that cannot be relaxed — and any leaf-parse error before path building —
    /// returns `Err(CertificateError::UnknownIssuer)` with the untrusted-issuer code recorded
    /// unless (b) holds.
    fn verify_identity_at<'a>(
        &self,
        identity: &Identity<'a>,
        now: UnixTime,
    ) -> (Result<VerifiedIdentity<'a>, Error>, ClientVerifyCodes) {
        let Identity::X509(certificates) = identity else {
            return (
                Err(ApiMisuse::UnverifiableCertificateType.into()),
                ClientVerifyCodes::leaf_err(x509_err::UNSPECIFIED),
            );
        };

        let leaf_der = &certificates.end_entity;
        let cert = match EndEntityCert::try_from(leaf_der) {
            Ok(cert) => cert,
            Err(err) => {
                let code = webpki_error_to_x509(&err);
                let mut codes = ClientVerifyCodes::leaf_err(code);
                if !self.crt_ignore_err.contains(code) {
                    return (Err(webpki_error_to_rustls(err)), codes);
                }
                // Invariant (b): leaf failed to parse before any trust anchor was verified.
                let (u_code, u_is_leaf) = untrusted_issuer_for(leaf_der.as_ref(), &certificates.intermediates);
                if self.is_ignored(u_code, u_is_leaf) {
                    return (Ok(VerifiedIdentity::assertion(identity.clone())), codes);
                }
                codes.record_untrusted(u_code, u_is_leaf);
                return (Err(CertificateError::UnknownIssuer.into()), codes);
            }
        };

        let crl_refs: Vec<&CertRevocationList<'_>> = self.crls.iter().collect();
        let client_eku = ExtendedKeyUsage::client_auth();
        let mut state = VerifyState {
            check_time: now,
            shifted_time: false,
            allow_any_eku: false,
            rev_mode: if crl_refs.is_empty() { RevMode::None } else { RevMode::Chain },
            exp_policy: ExpirationPolicy::Enforce,
        };
        let mut codes = ClientVerifyCodes::OK;

        loop {
            let eku: &dyn ExtendedKeyUsageValidator = if state.allow_any_eku { &AnyEku } else { &client_eku };
            let rev = build_revocation(&crl_refs, state.rev_mode, state.exp_policy);
            match cert.verify_for_usage(
                self.all_algs,
                &self.roots.roots,
                &certificates.intermediates,
                state.check_time,
                eku,
                rev,
                None,
            ) {
                Ok(path) => {
                    // Invariant (a): webpki verified a chain to a trust anchor in `self.roots`.
                    if state.shifted_time {
                        if let Some(err) = self.check_inter_now_validity(&path, now, &mut codes) {
                            return (Err(err), codes);
                        }
                    }
                    return (Ok(VerifiedIdentity::assertion(identity.clone())), codes);
                }
                Err(err) => {
                    let effective = self.refine_pre_chain_error(
                        &cert,
                        err,
                        leaf_der,
                        &certificates.intermediates,
                        &crl_refs,
                        &state,
                    );
                    let (code, is_leaf) = self.classify_with_depth(
                        &cert,
                        &effective,
                        leaf_der,
                        &certificates.intermediates,
                        state.check_time,
                        eku,
                        &crl_refs,
                        state.rev_mode,
                        state.exp_policy,
                    );
                    if matches!(effective, webpki::Error::UnknownIssuer) {
                        codes.record_untrusted(code, is_leaf);
                    } else {
                        codes.record(code, is_leaf);
                    }
                    if !self.is_ignored(code, is_leaf) {
                        return (Err(webpki_error_to_rustls(effective)), codes);
                    }
                    if state.relax(&effective, is_leaf, leaf_der.as_ref(), &certificates.intermediates) {
                        continue;
                    }
                    // No pass reached a trust anchor and nothing remains to relax: enforce
                    // invariant (b) before accepting.
                    let (u_code, u_is_leaf) = if matches!(effective, webpki::Error::UnknownIssuer) {
                        (code, is_leaf)
                    } else {
                        let pair = untrusted_issuer_for(leaf_der.as_ref(), &certificates.intermediates);
                        codes.record_untrusted(pair.0, pair.1);
                        pair
                    };
                    if self.is_ignored(u_code, u_is_leaf) {
                        return (Ok(VerifiedIdentity::assertion(identity.clone())), codes);
                    }
                    return (Err(CertificateError::UnknownIssuer.into()), codes);
                }
            }
        }
    }

    /// Re-orders webpki's pre-chain checks (`RequiredEkuNotFound`, self-signed
    /// `InvalidCertValidity`) to match OpenSSL's trust-anchor-first error reporting.
    fn refine_pre_chain_error(
        &self,
        cert: &EndEntityCert<'_>,
        err: webpki::Error,
        leaf_der: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        crl_refs: &[&CertRevocationList<'_>],
        state: &VerifyState,
    ) -> webpki::Error {
        // webpki checks EKU before building the chain to a trust anchor; OpenSSL builds the
        // trust chain first. Re-check with a permissive EKU so an untrusted server cert still
        // reports `UnknownIssuer` (alert 48 / code 20) as HAProxy does.
        if !state.allow_any_eku && matches!(err, webpki::Error::RequiredEkuNotFound(_)) {
            let rev2 = build_revocation(crl_refs, state.rev_mode, state.exp_policy);
            return match cert.verify_for_usage(
                self.all_algs,
                &self.roots.roots,
                intermediates,
                state.check_time,
                &AnyEku,
                rev2,
                None,
            ) {
                Ok(_) => err,
                Err(chain_err) => chain_err,
            };
        }
        // OpenSSL reports `DEPTH_ZERO_SELF_SIGNED_CERT` (18, alert 48) before checking
        // `notBefore > notAfter`; webpki reports `InvalidCertValidity` (alert 45). When code 18
        // is not ignored on a self-signed leaf, report `UnknownIssuer` (alert 48) instead.
        if matches!(err, webpki::Error::InvalidCertValidity)
            && !self.crt_ignore_err.contains(x509_err::DEPTH_ZERO_SELF_SIGNED_CERT)
            && x509::Cert::parse(leaf_der.as_ref()).is_some_and(|c| c.subject == c.issuer)
        {
            return webpki::Error::UnknownIssuer;
        }
        err
    }

    /// Attributes `effective` to leaf (depth 0) or CA chain (depth > 0), probing
    /// `RevocationCheckDepth::EndEntity` when a chain-wide CRL check fails.
    #[allow(clippy::too_many_arguments)]
    fn classify_with_depth(
        &self,
        cert: &EndEntityCert<'_>,
        effective: &webpki::Error,
        leaf_der: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        check_time: UnixTime,
        eku: &dyn ExtendedKeyUsageValidator,
        crl_refs: &[&CertRevocationList<'_>],
        rev_mode: RevMode,
        exp_policy: ExpirationPolicy,
    ) -> (i32, bool) {
        if is_revocation_error(effective) {
            let code = webpki_error_to_x509(effective);
            let is_leaf = match rev_mode {
                RevMode::Chain => {
                    let ee_rev = build_revocation(crl_refs, RevMode::EndEntity, exp_policy);
                    matches!(
                        cert.verify_for_usage(
                            self.all_algs,
                            &self.roots.roots,
                            intermediates,
                            check_time,
                            eku,
                            ee_rev,
                            None,
                        ),
                        Err(ref ee_err) if webpki_error_to_x509(ee_err) == code
                    )
                }
                RevMode::EndEntity | RevMode::None => true,
            };
            return (code, is_leaf);
        }
        let c = classify_webpki_error(effective, leaf_der, intermediates, check_time);
        (c.verify, c.crt_err != 0)
    }

    /// After `check_time` was shifted to look past an ignored leaf validity error, re-checks `now`
    /// validity of every intermediate in the verified path so a non-ignored CA expiry is still
    /// enforced.
    fn check_inter_now_validity(
        &self,
        path: &webpki::VerifiedPath<'_>,
        now: UnixTime,
        codes: &mut ClientVerifyCodes,
    ) -> Option<Error> {
        for inter in path.intermediate_certificates() {
            if let Some(code) = cert_validity_err(inter.der().as_ref(), now) {
                codes.record(code, false);
                if !self.ca_ignore_err.contains(code) {
                    return Some(validity_code_to_rustls(code));
                }
            }
        }
        None
    }
}

struct VerifyState {
    check_time: UnixTime,
    shifted_time: bool,
    allow_any_eku: bool,
    rev_mode: RevMode,
    exp_policy: ExpirationPolicy,
}

impl VerifyState {
    /// Relaxes only the specific check that produced an ignored error so the next pass still
    /// enforces every remaining non-ignored check (untrusted issuer, revocation, CA depth, etc.).
    /// Strictly monotonic (at most 5 relaxations), guaranteeing loop termination.
    fn relax(
        &mut self,
        effective: &webpki::Error,
        is_leaf: bool,
        leaf_der: &[u8],
        intermediates: &[CertificateDer<'_>],
    ) -> bool {
        if !self.shifted_time
            && matches!(effective, webpki::Error::CertExpired { .. } | webpki::Error::CertNotValidYet { .. })
        {
            if let Some(t) = common_valid_time(leaf_der, intermediates) {
                self.check_time = t;
                self.shifted_time = true;
                return true;
            }
        }
        if !self.allow_any_eku
            && matches!(effective, webpki::Error::RequiredEkuNotFound(_) | webpki::Error::EmptyEkuExtension)
        {
            self.allow_any_eku = true;
            return true;
        }
        if matches!(effective, webpki::Error::CrlExpired { .. }) && self.exp_policy == ExpirationPolicy::Enforce {
            self.exp_policy = ExpirationPolicy::Ignore;
            return true;
        }
        if is_revocation_error(effective) {
            if !is_leaf && self.rev_mode == RevMode::Chain {
                self.rev_mode = RevMode::EndEntity;
                return true;
            }
            if is_leaf && self.rev_mode != RevMode::None {
                self.rev_mode = RevMode::None;
                return true;
            }
        }
        false
    }
}

fn build_revocation<'a>(
    crl_refs: &'a [&'a CertRevocationList<'a>],
    mode: RevMode,
    exp_policy: ExpirationPolicy,
) -> Option<RevocationOptions<'a>> {
    let depth = match mode {
        RevMode::Chain => RevocationCheckDepth::Chain,
        RevMode::EndEntity => RevocationCheckDepth::EndEntity,
        RevMode::None => return None,
    };
    RevocationOptionsBuilder::new(crl_refs).ok().map(|b| {
        b.with_depth(depth)
            .with_status_policy(UnknownStatusPolicy::Deny)
            .with_expiration_policy(exp_policy)
            .build()
    })
}

const fn is_revocation_error(err: &webpki::Error) -> bool {
    matches!(
        err,
        webpki::Error::CertRevoked
            | webpki::Error::UnknownRevocationStatus
            | webpki::Error::CrlExpired { .. }
            | webpki::Error::InvalidCrlSignatureForPublicKey
            | webpki::Error::IssuerNotCrlSigner
            | webpki::Error::UnsupportedCrlSignatureAlgorithm(_)
            | webpki::Error::UnsupportedCrlSignatureAlgorithmForPublicKey(_)
            | webpki::Error::InvalidCrlNumber
            | webpki::Error::UnsupportedCrlVersion
            | webpki::Error::UnsupportedDeltaCrl
            | webpki::Error::UnsupportedIndirectCrl
            | webpki::Error::UnsupportedRevocationReason
            | webpki::Error::UnsupportedRevocationReasonsPartitioning
            | webpki::Error::UnsupportedCrlIssuingDistributionPoint
    )
}

fn validity_code_to_rustls(code: i32) -> Error {
    if code == x509_err::CERT_NOT_YET_VALID {
        CertificateError::NotValidYet.into()
    } else {
        CertificateError::Expired.into()
    }
}

fn cert_validity_window(der: &[u8]) -> Option<(u64, u64)> {
    let cert = x509::Cert::parse(der)?;
    let nb = parse_asn1_time(cert.not_before)?;
    let na = parse_asn1_time(cert.not_after)?;
    Some((nb, na))
}

fn cert_validity_err(der: &[u8], now: UnixTime) -> Option<i32> {
    let (nb, na) = cert_validity_window(der)?;
    let t = now.as_secs();
    if nb > na {
        Some(x509_err::ERROR_IN_CERT_NOT_AFTER_FIELD)
    } else if t < nb {
        Some(x509_err::CERT_NOT_YET_VALID)
    } else if t > na {
        Some(x509_err::CERT_HAS_EXPIRED)
    } else {
        None
    }
}

fn common_valid_time(leaf_der: &[u8], intermediates: &[CertificateDer<'_>]) -> Option<UnixTime> {
    let (mut lo, mut hi) = cert_validity_window(leaf_der)?;
    if lo > hi {
        return None;
    }
    for inter in intermediates {
        if let Some((nb, na)) = cert_validity_window(inter.as_ref()) {
            let nlo = lo.max(nb);
            let nhi = hi.min(na);
            if nb <= na && nlo <= nhi {
                lo = nlo;
                hi = nhi;
            }
        }
    }
    Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(lo)))
}

impl ClientVerifier for BindClientVerifier {
    fn verify_identity<'a>(&self, identity: &ClientIdentity<'a, '_>) -> Result<VerifiedIdentity<'a>, Error> {
        self.verify_detailed(identity).0
    }

    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(input, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(input, &self.supported_algs)
    }

    fn root_hint_subjects(&self) -> Arc<[DistinguishedName]> {
        Arc::clone(&self.root_hint_subjects)
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Permissive EKU validator used only on the `RequiredEkuNotFound` error path to distinguish an
/// untrusted chain (`UnknownIssuer`, alert 48) from a trusted cert with the wrong EKU (alert 43).
struct AnyEku;

impl ExtendedKeyUsageValidator for AnyEku {
    fn validate(&self, _iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

/// Maps a [`webpki::Error`] to its OpenSSL `X509_V_ERR_*` numeric code.
///
/// The complete mapping (exact twins and coarse choices where webpki has fewer variants than
/// OpenSSL) is documented in `docs/differences.md`.
#[must_use]
pub fn webpki_error_to_x509(err: &webpki::Error) -> i32 {
    use webpki::Error as E;
    match err {
        E::CertNotValidYet { .. } => x509_err::CERT_NOT_YET_VALID,
        E::CertExpired { .. } => x509_err::CERT_HAS_EXPIRED,
        E::InvalidCertValidity => x509_err::ERROR_IN_CERT_NOT_AFTER_FIELD,
        E::CertRevoked => x509_err::CERT_REVOKED,
        E::CrlExpired { .. } => x509_err::CRL_HAS_EXPIRED,
        E::UnknownRevocationStatus => x509_err::UNABLE_TO_GET_CRL,
        E::InvalidCrlSignatureForPublicKey => x509_err::CRL_SIGNATURE_FAILURE,
        E::IssuerNotCrlSigner => x509_err::KEYUSAGE_NO_CRL_SIGN,
        E::InvalidSignatureForPublicKey => x509_err::CERT_SIGNATURE_FAILURE,
        E::UnknownIssuer => x509_err::UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        E::RequiredEkuNotFound(_) | E::EmptyEkuExtension | E::CaUsedAsEndEntity => {
            x509_err::INVALID_PURPOSE
        }
        E::EndEntityUsedAsCa => x509_err::INVALID_CA,
        E::PathLenConstraintViolated => x509_err::PATH_LENGTH_EXCEEDED,
        E::MaximumPathDepthExceeded
        | E::MaximumPathBuildCallsExceeded
        | E::MaximumSignatureChecksExceeded => x509_err::CERT_CHAIN_TOO_LONG,
        E::NameConstraintViolation => x509_err::PERMITTED_VIOLATION,
        E::InvalidNetworkMaskConstraint | E::MalformedNameConstraint => {
            x509_err::UNSUPPORTED_CONSTRAINT_SYNTAX
        }
        E::UnsupportedCriticalExtension => x509_err::UNHANDLED_CRITICAL_EXTENSION,
        E::SignatureAlgorithmMismatch => x509_err::SIGNATURE_ALGORITHM_MISMATCH,
        E::UnsupportedSignatureAlgorithm(_) | E::UnsupportedCrlSignatureAlgorithm(_) => {
            x509_err::UNSUPPORTED_SIGNATURE_ALGORITHM
        }
        E::UnsupportedSignatureAlgorithmForPublicKey(_)
        | E::UnsupportedCrlSignatureAlgorithmForPublicKey(_) => {
            x509_err::SIGNATURE_ALGORITHM_INCONSISTENCY
        }
        E::ExtensionValueInvalid | E::MalformedExtensions => x509_err::INVALID_EXTENSION,
        E::CertNotValidForName(_) => x509_err::HOSTNAME_MISMATCH,
        E::MalformedDnsIdentifier | E::UnsupportedNameType => x509_err::UNSUPPORTED_NAME_SYNTAX,
        E::BadDerTime => x509_err::ERROR_IN_CERT_NOT_BEFORE_FIELD,
        E::UnsupportedDeltaCrl | E::UnsupportedRevocationReason => {
            x509_err::UNSUPPORTED_EXTENSION_FEATURE
        }
        E::UnsupportedIndirectCrl
        | E::UnsupportedRevocationReasonsPartitioning
        | E::UnsupportedCrlIssuingDistributionPoint => x509_err::DIFFERENT_CRL_SCOPE,
        // `BadDer`, `TrailingData`, `UnsupportedCertVersion`, `InvalidSerialNumber`,
        // `InvalidCrlNumber`, `UnsupportedCrlVersion`, `MaximumNameConstraintComparisonsExceeded`,
        // and any future `#[non_exhaustive]` variants.
        _ => x509_err::UNSPECIFIED,
    }
}

/// Converts a [`webpki::Error`] to the corresponding [`rustls24::Error`], mirroring rustls 0.24's
/// internal `pki_error` so rustls emits the matching TLS alert on the wire.
fn webpki_error_to_rustls(error: webpki::Error) -> Error {
    use webpki::Error as E;
    match error {
        E::BadDer | E::BadDerTime | E::TrailingData(_) => CertificateError::BadEncoding.into(),
        E::CertNotValidYet { time, not_before } => {
            CertificateError::NotValidYetContext { time, not_before }.into()
        }
        E::CertExpired { time, not_after } => {
            CertificateError::ExpiredContext { time, not_after }.into()
        }
        E::InvalidCertValidity => CertificateError::Expired.into(),
        E::UnknownIssuer => CertificateError::UnknownIssuer.into(),
        E::CertNotValidForName(webpki::InvalidNameContext { expected, presented }) => {
            CertificateError::NotValidForNameContext { expected, presented }.into()
        }
        E::CertRevoked => CertificateError::Revoked.into(),
        E::UnknownRevocationStatus => CertificateError::UnknownRevocationStatus.into(),
        E::CrlExpired { time, next_update } => {
            CertificateError::ExpiredRevocationListContext { time, next_update }.into()
        }
        E::IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl.into(),
        E::InvalidSignatureForPublicKey => CertificateError::BadSignature.into(),
        E::UnsupportedSignatureAlgorithm(cx) => CertificateError::UnsupportedSignatureAlgorithm {
            signature_algorithm_id: cx.signature_algorithm_id,
            supported_algorithms: cx.supported_algorithms,
        }
        .into(),
        E::UnsupportedSignatureAlgorithmForPublicKey(cx) => {
            CertificateError::UnsupportedSignatureAlgorithmForPublicKey {
                signature_algorithm_id: cx.signature_algorithm_id,
                public_key_algorithm_id: cx.public_key_algorithm_id,
            }
            .into()
        }
        E::InvalidCrlSignatureForPublicKey => CertRevocationListError::BadSignature.into(),
        E::UnsupportedCrlSignatureAlgorithm(cx) => CertRevocationListError::UnsupportedSignatureAlgorithm {
            signature_algorithm_id: cx.signature_algorithm_id,
            supported_algorithms: cx.supported_algorithms,
        }
        .into(),
        E::UnsupportedCrlSignatureAlgorithmForPublicKey(cx) => {
            CertRevocationListError::UnsupportedSignatureAlgorithmForPublicKey {
                signature_algorithm_id: cx.signature_algorithm_id,
                public_key_algorithm_id: cx.public_key_algorithm_id,
            }
            .into()
        }
        E::RequiredEkuNotFound(_) | E::EmptyEkuExtension => {
            CertificateError::InvalidPurposeContext {
                required: ExtendedKeyPurpose::ClientAuth,
                presented: Vec::new(),
            }
            .into()
        }
        E::UnsupportedCriticalExtension => CertificateError::UnhandledCriticalExtension.into(),
        other => CertificateError::Other(OtherError::new(other)).into(),
    }
}

/// Attributes a `webpki::Error` returned by `EndEntityCert::verify_for_usage` to either the
/// client leaf certificate (`ssl_c_err`, depth 0) or a CA certificate in the chain
/// (`ssl_c_ca_err`, depth > 0), and refines `UnknownIssuer` into codes 18 / 19 / 20.
fn classify_webpki_error(
    err: &webpki::Error,
    leaf_der: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
) -> ClientVerifyCodes {
    use webpki::Error as E;
    match err {
        // Inherently CA-chain errors (depth > 0).
        E::EndEntityUsedAsCa
        | E::PathLenConstraintViolated
        | E::MaximumPathDepthExceeded
        | E::MaximumPathBuildCallsExceeded
        | E::MaximumSignatureChecksExceeded
        | E::MaximumNameConstraintComparisonsExceeded
        | E::InvalidNetworkMaskConstraint
        | E::MalformedNameConstraint
        | E::CrlExpired { .. }
        | E::UnknownRevocationStatus
        | E::InvalidCrlSignatureForPublicKey
        | E::IssuerNotCrlSigner
        | E::UnsupportedCrlSignatureAlgorithm(_)
        | E::UnsupportedCrlSignatureAlgorithmForPublicKey(_)
        | E::InvalidCrlNumber
        | E::UnsupportedCrlVersion
        | E::UnsupportedDeltaCrl
        | E::UnsupportedIndirectCrl
        | E::UnsupportedRevocationReason
        | E::UnsupportedRevocationReasonsPartitioning
        | E::UnsupportedCrlIssuingDistributionPoint => {
            ClientVerifyCodes::ca_err(webpki_error_to_x509(err))
        }
        // Parse errors after `EndEntityCert::try_from(leaf_der)` already succeeded came from an
        // intermediate certificate in the chain.
        E::BadDer
        | E::BadDerTime
        | E::TrailingData(_)
        | E::UnsupportedCertVersion
        | E::UnsupportedCriticalExtension
        | E::SignatureAlgorithmMismatch
        | E::ExtensionValueInvalid
        | E::MalformedExtensions
        | E::InvalidSerialNumber => ClientVerifyCodes::ca_err(webpki_error_to_x509(err)),
        // Validity errors: check the leaf's own validity window to separate leaf (depth 0) from
        // an intermediate CA (depth > 0).
        E::CertExpired { .. } | E::CertNotValidYet { .. } | E::InvalidCertValidity => {
            let code = webpki_error_to_x509(err);
            if leaf_has_validity_problem(leaf_der.as_ref(), now) {
                ClientVerifyCodes::leaf_err(code)
            } else {
                ClientVerifyCodes::ca_err(code)
            }
        }
        // UnknownIssuer: distinguish depth-0 self-signed (18), self-signed cert in chain (19),
        // and unable to get local issuer cert (20) on leaf vs intermediate.
        E::UnknownIssuer => classify_unknown_issuer(leaf_der.as_ref(), intermediates),
        // EKU errors: if the leaf itself has an EKU extension that does not allow clientAuth
        // (or is empty), attribute to leaf; otherwise an intermediate constrained EKU.
        E::RequiredEkuNotFound(_) | E::EmptyEkuExtension => {
            let code = x509_err::INVALID_PURPOSE;
            if leaf_disallows_client_auth_eku(leaf_der.as_ref()) {
                ClientVerifyCodes::leaf_err(code)
            } else {
                ClientVerifyCodes::ca_err(code)
            }
        }
        // Leaf-attributed errors (and signature/revocation/constraint errors where webpki does not
        // expose chain depth).
        _ => ClientVerifyCodes::leaf_err(webpki_error_to_x509(err)),
    }
}

/// Returns `(code, is_leaf)` for the OpenSSL untrusted-issuer error (`18`/`19`/`20`) of an
/// unverified chain (`DEPTH_ZERO_SELF_SIGNED_CERT`, `SELF_SIGNED_CERT_IN_CHAIN`, or
/// `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`).
fn untrusted_issuer_for(leaf_der: &[u8], intermediates: &[CertificateDer<'_>]) -> (i32, bool) {
    let c = classify_unknown_issuer(leaf_der, intermediates);
    (c.verify, c.crt_err != 0)
}

/// Refines `webpki::Error::UnknownIssuer` into OpenSSL's 18 / 19 / 20 and leaf vs CA depth.
fn classify_unknown_issuer(leaf_der: &[u8], intermediates: &[CertificateDer<'_>]) -> ClientVerifyCodes {
    let Some(leaf) = x509::Cert::parse(leaf_der) else {
        return ClientVerifyCodes::leaf_err(x509_err::UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    };
    if leaf.subject == leaf.issuer {
        return ClientVerifyCodes::leaf_err(x509_err::DEPTH_ZERO_SELF_SIGNED_CERT);
    }
    // Walk presented intermediates by subject == issuer to see if the leaf found its issuer in
    // the presented chain (in which case the missing anchor is at depth > 0).
    let parsed_inters: Vec<x509::Cert<'_>> =
        intermediates.iter().filter_map(|c| x509::Cert::parse(c.as_ref())).collect();
    let mut issuer = leaf.issuer;
    let mut depth = 0usize;
    let mut top_self_signed = false;
    while depth < parsed_inters.len() {
        let Some(next) = parsed_inters.iter().find(|c| c.subject == issuer) else {
            break;
        };
        depth += 1;
        if next.subject == next.issuer {
            top_self_signed = true;
            break;
        }
        issuer = next.issuer;
    }
    if depth == 0 {
        ClientVerifyCodes::leaf_err(x509_err::UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
    } else if top_self_signed {
        ClientVerifyCodes::ca_err(x509_err::SELF_SIGNED_CERT_IN_CHAIN)
    } else {
        ClientVerifyCodes::ca_err(x509_err::UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
    }
}

/// Returns `true` when the leaf certificate's own `notBefore`/`notAfter` fails at `now`.
fn leaf_has_validity_problem(leaf_der: &[u8], now: UnixTime) -> bool {
    let Some(cert) = x509::Cert::parse(leaf_der) else {
        return true;
    };
    let (Some(nb), Some(na)) = (parse_asn1_time(cert.not_before), parse_asn1_time(cert.not_after)) else {
        return true;
    };
    let t = now.as_secs();
    nb > na || t < nb || t > na
}

/// Parses an ASN.1 `UTCTime` (0x17) or `GeneralizedTime` (0x18) into Unix seconds (UTC).
fn parse_asn1_time((tag, bytes): (u8, &[u8])) -> Option<u64> {
    let digits = |s: &[u8]| -> Option<u32> {
        let mut v = 0u32;
        for &b in s {
            if !b.is_ascii_digit() {
                return None;
            }
            v = v * 10 + u32::from(b - b'0');
        }
        Some(v)
    };
    let (year, rest) = match tag {
        0x17 if bytes.len() == 13 && bytes[12] == b'Z' => {
            let yy = digits(&bytes[0..2])?;
            let y = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (y, &bytes[2..12])
        }
        0x18 if bytes.len() == 15 && bytes[14] == b'Z' => (digits(&bytes[0..4])?, &bytes[4..14]),
        _ => return None,
    };
    let month = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    let hour = digits(&rest[4..6])?;
    let min = digits(&rest[6..8])?;
    let sec = digits(&rest[8..10])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(i64::from(year), month, day)?;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec))?;
    u64::try_from(secs).ok()
}

/// Days since 1970-01-01 (Howard Hinnant's civil-date algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = u64::try_from(y - era * 400).ok()?;
    let m = u64::from(month);
    let d = u64::from(day);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + i64::try_from(doe).ok()? - 719_468)
}

/// id-ce-extKeyUsage (2.5.29.37), id-kp-clientAuth (1.3.6.1.5.5.7.3.2), anyExtendedKeyUsage (2.5.29.37.0).
const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];
const OID_KP_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const OID_ANY_EKU: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

/// Returns `true` if `leaf_der` carries an `ExtendedKeyUsage` extension that does not include
/// `id-kp-clientAuth` or `anyExtendedKeyUsage` (including an empty EKU sequence).
fn leaf_disallows_client_auth_eku(leaf_der: &[u8]) -> bool {
    let Some(mut cert) = Der::new(leaf_der).child() else { return false };
    let Some(mut tbs) = cert.child() else { return false };
    let mut extensions = None;
    while !tbs.is_empty() {
        let Some(el) = tbs.tlv() else { return false };
        if el.tag == 0xA3 {
            extensions = Some(Der::new(el.value));
            break;
        }
    }
    let Some(mut seq) = extensions.and_then(|mut e| e.child()) else { return false };
    while !seq.is_empty() {
        let Some(ext) = seq.tlv() else { break };
        let mut ext = Der::new(ext.value);
        let Some(oid) = ext.tlv() else { continue };
        if oid.tag != 0x06 || oid.value != OID_EKU {
            continue;
        }
        let Some(mut val) = ext.tlv() else { return true };
        if val.tag == 0x01 {
            let Some(after) = ext.tlv() else { return true };
            val = after;
        }
        if val.tag != 0x04 {
            return true;
        }
        let Some(mut kp_seq) = Der::new(val.value).child() else { return true };
        let mut saw_any = false;
        while !kp_seq.is_empty() {
            let Some(kp) = kp_seq.tlv() else { break };
            if kp.tag == 0x06 && (kp.value == OID_KP_CLIENT_AUTH || kp.value == OID_ANY_EKU) {
                saw_any = true;
                break;
            }
        }
        return !saw_any;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider;
    use crate::TlsCryptoProvider;
    use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair};

    struct Ca {
        cert: rcgen::Certificate,
        key: KeyPair,
    }

    fn make_ca(cn: &str) -> Ca {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, cn);
        let key = KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("ca");
        Ca { cert, key }
    }

    fn verifier(ca: &Ca, mandatory: bool) -> Arc<BindClientVerifier> {
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert.der().clone()).expect("add root");
        let prov = provider::of(TlsCryptoProvider::Ring, true, true);
        BindClientVerifier::new(Arc::new(roots), mandatory, TlsCryptoProvider::Ring, &prov)
    }

    fn check(v: &BindClientVerifier, chain: Vec<CertificateDer<'static>>) -> (Result<(), Error>, ClientVerifyCodes) {
        let id = Identity::from_cert_chain(chain).expect("identity");
        let (res, codes) = v.verify_identity_at(&id, UnixTime::now());
        (res.map(|_| ()), codes)
    }

    #[test]
    fn valid_expired_future_untrusted_wrong_eku_and_ca_chain_errors() {
        let ca = make_ca("Test Client CA");
        let other_ca = make_ca("Other Untrusted CA");
        let v = verifier(&ca, true);
        assert!(v.client_auth_mandatory());
        assert_eq!(v.root_hint_subjects().len(), 1);

        // 1. Valid client cert -> 0/0/0
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("p");
        p.distinguished_name.push(DnType::CommonName, "good-client");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let k = KeyPair::generate().expect("k");
        let good = p.signed_by(&k, &ca.cert, &ca.key).expect("sign");
        let (res, codes) = check(&v, vec![good.der().clone()]);
        assert!(res.is_ok(), "valid client must pass: {res:?}");
        assert_eq!(codes, ClientVerifyCodes::OK);

        // 2. Expired leaf -> 10/10/0, ExpiredContext
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("p");
        p.distinguished_name.push(DnType::CommonName, "expired-client");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.not_before = date_time_ymd(2020, 1, 1);
        p.not_after = date_time_ymd(2021, 1, 1);
        let k = KeyPair::generate().expect("k");
        let expired = p.signed_by(&k, &ca.cert, &ca.key).expect("sign");
        let (res, codes) = check(&v, vec![expired.der().clone()]);
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::ExpiredContext { .. }))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 10, crt_err: 10, ca_err: 0 });

        // 3. Not-yet-valid leaf -> 9/9/0, NotValidYetContext
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("p");
        p.distinguished_name.push(DnType::CommonName, "future-client");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.not_before = date_time_ymd(2035, 1, 1);
        p.not_after = date_time_ymd(2036, 1, 1);
        let k = KeyPair::generate().expect("k");
        let future = p.signed_by(&k, &ca.cert, &ca.key).expect("sign");
        let (res, codes) = check(&v, vec![future.der().clone()]);
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::NotValidYetContext { .. }))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 9, crt_err: 9, ca_err: 0 });

        // 4. Self-signed untrusted leaf -> 18/18/0, UnknownIssuer
        let self_signed = rcgen::generate_simple_self_signed(vec!["self.example".to_string()]).expect("ss");
        let (res, codes) = check(&v, vec![self_signed.cert.der().clone()]);
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 18, crt_err: 18, ca_err: 0 });

        // 5. Leaf signed by another CA (even with ServerAuth-only EKU) -> 20/20/0, UnknownIssuer
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("p");
        p.distinguished_name.push(DnType::CommonName, "other-client");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let k = KeyPair::generate().expect("k");
        let other_leaf = p.signed_by(&k, &other_ca.cert, &other_ca.key).expect("sign");
        let (res, codes) = check(&v, vec![other_leaf.der().clone()]);
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 20, crt_err: 20, ca_err: 0 });

        // 6. Trusted CA leaf with ServerAuth-only EKU -> 26/26/0, InvalidPurposeContext
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("p");
        p.distinguished_name.push(DnType::CommonName, "wrong-eku");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let k = KeyPair::generate().expect("k");
        let wrong_eku = p.signed_by(&k, &ca.cert, &ca.key).expect("sign");
        let (res, codes) = check(&v, vec![wrong_eku.der().clone()]);
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::InvalidPurposeContext { .. }))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 26, crt_err: 26, ca_err: 0 });

        // 7. Valid leaf under an expired intermediate CA -> 10/0/10 (CA error at depth > 0!)
        let mut inter_p = CertificateParams::new(Vec::<String>::new()).expect("ip");
        inter_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        inter_p.distinguished_name.push(DnType::CommonName, "Expired Inter");
        inter_p.not_before = date_time_ymd(2020, 1, 1);
        inter_p.not_after = date_time_ymd(2021, 1, 1);
        let inter_k = KeyPair::generate().expect("ik");
        let exp_inter = inter_p.signed_by(&inter_k, &ca.cert, &ca.key).expect("sign inter");
        let mut leaf_p = CertificateParams::new(Vec::<String>::new()).expect("lp");
        leaf_p.distinguished_name.push(DnType::CommonName, "leaf-under-exp-inter");
        leaf_p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_k = KeyPair::generate().expect("lk");
        let leaf_under_exp = leaf_p.signed_by(&leaf_k, &exp_inter, &inter_k).expect("sign leaf");
        let (res, codes) = check(&v, vec![leaf_under_exp.der().clone(), exp_inter.der().clone()]);
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::ExpiredContext { .. }))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 10, crt_err: 0, ca_err: 10 });

        // 8. Valid leaf under a non-CA intermediate -> 79/0/79 (EndEntityUsedAsCa)
        let mut nonca_p = CertificateParams::new(Vec::<String>::new()).expect("np");
        nonca_p.is_ca = IsCa::NoCa;
        nonca_p.distinguished_name.push(DnType::CommonName, "Non-CA Inter");
        let nonca_k = KeyPair::generate().expect("nk");
        let nonca_inter = nonca_p.signed_by(&nonca_k, &ca.cert, &ca.key).expect("sign nonca");
        let mut leaf_p = CertificateParams::new(Vec::<String>::new()).expect("lp");
        leaf_p.distinguished_name.push(DnType::CommonName, "leaf-under-nonca");
        leaf_p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_k = KeyPair::generate().expect("lk");
        let leaf_under_nonca = leaf_p.signed_by(&leaf_k, &nonca_inter, &nonca_k).expect("sign leaf");
        let (res, codes) = check(&v, vec![leaf_under_nonca.der().clone(), nonca_inter.der().clone()]);
        assert!(res.is_err());
        assert_eq!(codes, ClientVerifyCodes { verify: 79, crt_err: 0, ca_err: 79 });
    }

    #[test]
    fn webpki_error_table_maps_exact_twins_and_coarse_codes() {
        let t = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000));
        assert_eq!(webpki_error_to_x509(&webpki::Error::CertNotValidYet { time: t, not_before: t }), 9);
        assert_eq!(webpki_error_to_x509(&webpki::Error::CertExpired { time: t, not_after: t }), 10);
        assert_eq!(webpki_error_to_x509(&webpki::Error::CertRevoked), 23);
        assert_eq!(webpki_error_to_x509(&webpki::Error::CrlExpired { time: t, next_update: t }), 12);
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnknownRevocationStatus), 3);
        assert_eq!(webpki_error_to_x509(&webpki::Error::InvalidCrlSignatureForPublicKey), 8);
        assert_eq!(webpki_error_to_x509(&webpki::Error::IssuerNotCrlSigner), 35);
        assert_eq!(webpki_error_to_x509(&webpki::Error::InvalidSignatureForPublicKey), 7);
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnknownIssuer), 20);
        assert_eq!(webpki_error_to_x509(&webpki::Error::EmptyEkuExtension), 26);
        assert_eq!(webpki_error_to_x509(&webpki::Error::CaUsedAsEndEntity), 26);
        assert_eq!(webpki_error_to_x509(&webpki::Error::EndEntityUsedAsCa), 79);
        assert_eq!(webpki_error_to_x509(&webpki::Error::PathLenConstraintViolated), 25);
        assert_eq!(webpki_error_to_x509(&webpki::Error::MaximumPathDepthExceeded), 22);
        assert_eq!(webpki_error_to_x509(&webpki::Error::NameConstraintViolation), 47);
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnsupportedCriticalExtension), 34);
        assert_eq!(webpki_error_to_x509(&webpki::Error::SignatureAlgorithmMismatch), 77);
        assert_eq!(webpki_error_to_x509(&webpki::Error::ExtensionValueInvalid), 41);
        assert_eq!(webpki_error_to_x509(&webpki::Error::BadDerTime), 13);
        assert_eq!(webpki_error_to_x509(&webpki::Error::InvalidCertValidity), 14);
        assert_eq!(webpki_error_to_x509(&webpki::Error::InvalidNetworkMaskConstraint), 52);
        assert_eq!(webpki_error_to_x509(&webpki::Error::MalformedNameConstraint), 52);
        let usa = webpki::UnsupportedSignatureAlgorithmContext {
            signature_algorithm_id: vec![1],
            supported_algorithms: vec![],
        };
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnsupportedSignatureAlgorithm(usa.clone())), 76);
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnsupportedCrlSignatureAlgorithm(usa.clone())), 76);
        let usapk = webpki::UnsupportedSignatureAlgorithmForPublicKeyContext {
            signature_algorithm_id: vec![1],
            public_key_algorithm_id: vec![2],
        };
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnsupportedSignatureAlgorithmForPublicKey(usapk.clone())), 78);
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnsupportedCrlSignatureAlgorithmForPublicKey(usapk.clone())), 78);
        let inc = webpki::InvalidNameContext {
            expected: rustls24::pki_types::ServerName::try_from("a.example").expect("sn"),
            presented: vec!["b.example".to_string()],
        };
        assert_eq!(webpki_error_to_x509(&webpki::Error::CertNotValidForName(inc.clone())), 62);
        assert_eq!(webpki_error_to_x509(&webpki::Error::MalformedDnsIdentifier), 53);
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnsupportedNameType), 53);
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnsupportedDeltaCrl), 45);
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnsupportedRevocationReason), 45);
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnsupportedIndirectCrl), 44);
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnsupportedRevocationReasonsPartitioning), 44);
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnsupportedCrlIssuingDistributionPoint), 44);
        assert_eq!(webpki_error_to_x509(&webpki::Error::BadDer), 1);
        assert_eq!(webpki_error_to_x509(&webpki::Error::UnsupportedCertVersion), 1);

        // Exercise every arm of `webpki_error_to_rustls`.
        assert!(matches!(webpki_error_to_rustls(webpki::Error::BadDer), Error::InvalidCertificate(CertificateError::BadEncoding)));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::InvalidCertValidity), Error::InvalidCertificate(CertificateError::Expired)));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::CertNotValidForName(inc)), Error::InvalidCertificate(CertificateError::NotValidForNameContext { .. })));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::CertRevoked), Error::InvalidCertificate(CertificateError::Revoked)));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::UnknownRevocationStatus), Error::InvalidCertificate(CertificateError::UnknownRevocationStatus)));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::CrlExpired { time: t, next_update: t }), Error::InvalidCertificate(CertificateError::ExpiredRevocationListContext { .. })));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::IssuerNotCrlSigner), Error::InvalidCertRevocationList(CertRevocationListError::IssuerInvalidForCrl)));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::InvalidSignatureForPublicKey), Error::InvalidCertificate(CertificateError::BadSignature)));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::UnsupportedSignatureAlgorithm(usa.clone())), Error::InvalidCertificate(CertificateError::UnsupportedSignatureAlgorithm { .. })));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey(usapk.clone())), Error::InvalidCertificate(CertificateError::UnsupportedSignatureAlgorithmForPublicKey { .. })));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::InvalidCrlSignatureForPublicKey), Error::InvalidCertRevocationList(CertRevocationListError::BadSignature)));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::UnsupportedCrlSignatureAlgorithm(usa)), Error::InvalidCertRevocationList(CertRevocationListError::UnsupportedSignatureAlgorithm { .. })));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::UnsupportedCrlSignatureAlgorithmForPublicKey(usapk)), Error::InvalidCertRevocationList(CertRevocationListError::UnsupportedSignatureAlgorithmForPublicKey { .. })));
        assert!(matches!(webpki_error_to_rustls(webpki::Error::UnsupportedCriticalExtension), Error::InvalidCertificate(CertificateError::UnhandledCriticalExtension)));

        // Exercise every arm of `ClientVerifyCodes::to_verify_result`.
        assert_eq!(ClientVerifyCodes::OK.to_verify_result(), VerifyResult::Ok);
        assert_eq!(ClientVerifyCodes::leaf_err(x509_err::CERT_HAS_EXPIRED).to_verify_result(), VerifyResult::Failed(VerifyError::Expired));
        assert_eq!(ClientVerifyCodes::leaf_err(x509_err::CERT_NOT_YET_VALID).to_verify_result(), VerifyResult::Failed(VerifyError::NotYetValid));
        assert_eq!(ClientVerifyCodes::leaf_err(x509_err::DEPTH_ZERO_SELF_SIGNED_CERT).to_verify_result(), VerifyResult::Failed(VerifyError::SelfSigned));
        assert_eq!(ClientVerifyCodes::ca_err(x509_err::SELF_SIGNED_CERT_IN_CHAIN).to_verify_result(), VerifyResult::Failed(VerifyError::SelfSigned));
        assert_eq!(ClientVerifyCodes::leaf_err(x509_err::UNABLE_TO_GET_ISSUER_CERT_LOCALLY).to_verify_result(), VerifyResult::Failed(VerifyError::UntrustedRoot));
        assert_eq!(ClientVerifyCodes::leaf_err(x509_err::CERT_REVOKED).to_verify_result(), VerifyResult::Failed(VerifyError::Revoked));
        assert_eq!(ClientVerifyCodes::leaf_err(x509_err::HOSTNAME_MISMATCH).to_verify_result(), VerifyResult::Failed(VerifyError::HostnameMismatch));
        assert_eq!(ClientVerifyCodes::ca_err(x509_err::CERT_CHAIN_TOO_LONG).to_verify_result(), VerifyResult::Failed(VerifyError::ChainTooLong));
        assert_eq!(ClientVerifyCodes::ca_err(x509_err::PATH_LENGTH_EXCEEDED).to_verify_result(), VerifyResult::Failed(VerifyError::ChainTooLong));
        assert_eq!(ClientVerifyCodes::leaf_err(x509_err::UNSPECIFIED).to_verify_result(), VerifyResult::Failed(VerifyError::Other));
    }

    #[test]
    fn classify_and_asn1_helpers_handle_chains_eku_times_and_rpk() {
        let ca = make_ca("Helper CA");
        let other_ca = make_ca("Other Untrusted Root");
        let v = verifier(&ca, true);
        let now = UnixTime::now();

        // RawPublicKey is rejected cleanly.
        let rpk = Identity::RawPublicKey(rustls24::pki_types::SubjectPublicKeyInfoDer::from(vec![0u8]));
        let (res, codes) = v.verify_identity_at(&rpk, now);
        assert!(res.is_err());
        assert_eq!(codes, ClientVerifyCodes::leaf_err(x509_err::UNSPECIFIED));

        // Leaf without EKU, plus intermediate under `other_ca`.
        let mut inter_p = CertificateParams::new(Vec::<String>::new()).expect("ip");
        inter_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        inter_p.distinguished_name.push(DnType::CommonName, "Other Untrusted Inter");
        let inter_k = KeyPair::generate().expect("ik");
        let other_inter = inter_p.signed_by(&inter_k, &other_ca.cert, &other_ca.key).expect("sign inter");

        let mut leaf_p = CertificateParams::new(Vec::<String>::new()).expect("lp");
        leaf_p.distinguished_name.push(DnType::CommonName, "plain-leaf");
        let leaf_k = KeyPair::generate().expect("lk");
        let leaf_under_inter = leaf_p.clone().signed_by(&leaf_k, &other_inter, &inter_k).expect("sign leaf");
        let leaf_under_root = leaf_p.signed_by(&leaf_k, &other_ca.cert, &other_ca.key).expect("sign leaf2");

        // Intermediate parse error (BadDer), intermediate EKU error (leaf has no EKU), and leaf fallback.
        assert_eq!(
            classify_webpki_error(&webpki::Error::BadDer, leaf_under_root.der(), &[], now),
            ClientVerifyCodes::ca_err(x509_err::UNSPECIFIED)
        );
        assert_eq!(
            classify_webpki_error(&webpki::Error::EmptyEkuExtension, leaf_under_root.der(), &[], now),
            ClientVerifyCodes::ca_err(x509_err::INVALID_PURPOSE)
        );
        assert_eq!(
            classify_webpki_error(&webpki::Error::InvalidSignatureForPublicKey, leaf_under_root.der(), &[], now),
            ClientVerifyCodes::leaf_err(x509_err::CERT_SIGNATURE_FAILURE)
        );

        // UnknownIssuer depth/self-signed refinement.
        assert_eq!(
            classify_unknown_issuer(b"not-der", &[]),
            ClientVerifyCodes::leaf_err(x509_err::UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
        );
        assert_eq!(
            classify_unknown_issuer(leaf_under_root.der().as_ref(), &[ca.cert.der().clone()]),
            ClientVerifyCodes::leaf_err(x509_err::UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
        );
        assert_eq!(
            classify_unknown_issuer(leaf_under_root.der().as_ref(), &[other_ca.cert.der().clone()]),
            ClientVerifyCodes::ca_err(x509_err::SELF_SIGNED_CERT_IN_CHAIN)
        );
        assert_eq!(
            classify_unknown_issuer(leaf_under_inter.der().as_ref(), &[other_inter.der().clone()]),
            ClientVerifyCodes::ca_err(x509_err::UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
        );

        // Validity & ASN.1 time parsing edge cases.
        assert!(leaf_has_validity_problem(b"not-der", now));
        assert!(parse_asn1_time((0x17, b"20aa01000000Z")).is_none());
        assert!(parse_asn1_time((0x16, b"200101000000Z")).is_none());
        assert!(parse_asn1_time((0x17, b"201301000000Z")).is_none());
        assert!(parse_asn1_time((0x18, b"20550101000000Z")).is_some());
        // Minimal synthetic cert with unparseable notBefore bytes so Cert::parse succeeds and
        // `leaf_has_validity_problem` hits its `parse_asn1_time` None fallback.
        let der_tlv = |tag: u8, body: &[u8]| -> Vec<u8> {
            let mut v = vec![tag, u8::try_from(body.len()).expect("short")];
            v.extend_from_slice(body);
            v
        };
        let bad_validity = der_tlv(0x30, &[der_tlv(0x17, b"bad"), der_tlv(0x17, b"bad")].concat());
        let alg_id = der_tlv(0x30, &der_tlv(0x06, &[0x01]));
        let bad_tbs = der_tlv(
            0x30,
            &[
                der_tlv(0xA0, &[0x02, 0x01, 0x02]), // v3
                der_tlv(0x02, &[0x01]),             // serial
                alg_id.clone(),                     // sigAlg
                der_tlv(0x30, &[]),                 // issuer
                bad_validity,                       // validity
                der_tlv(0x30, &[]),                 // subject
                der_tlv(0x30, &alg_id),             // spki
            ]
            .concat(),
        );
        let bad_time_cert = der_tlv(0x30, &bad_tbs);
        assert!(x509::Cert::parse(&bad_time_cert).is_some());
        assert!(leaf_has_validity_problem(&bad_time_cert, now));

        // EKU helper: leaf with ClientAuth EKU + SAN -> false; leaf with SAN but NO EKU -> false;
        // critical EKU with non-OCTET-STRING value -> true.
        let mut ok_p = CertificateParams::new(vec!["client.example".to_string()]).expect("okp");
        ok_p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let ok_c = ok_p.signed_by(&leaf_k, &ca.cert, &ca.key).expect("okc");
        assert!(!leaf_disallows_client_auth_eku(ok_c.der().as_ref()));
        let no_eku_p = CertificateParams::new(vec!["no-eku.example".to_string()]).expect("nep");
        let no_eku_c = no_eku_p.signed_by(&leaf_k, &ca.cert, &ca.key).expect("nec");
        assert!(!leaf_disallows_client_auth_eku(no_eku_c.der().as_ref()));

        let crit_bad_eku_ext = der_tlv(
            0x30,
            &[
                der_tlv(0x06, OID_EKU),
                der_tlv(0x01, &[0xFF]), // critical = TRUE
                der_tlv(0x05, &[]),     // NULL instead of OCTET STRING
            ]
            .concat(),
        );
        let eku_tbs = der_tlv(0x30, &der_tlv(0xA3, &der_tlv(0x30, &crit_bad_eku_ext)));
        let crit_bad_eku_cert = der_tlv(0x30, &eku_tbs);
        assert!(leaf_disallows_client_auth_eku(&crit_bad_eku_cert));
    }

    #[test]
    fn v1_client1_against_v3_ca_auth_fails_with_unspecified() {
        let fx = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../alcyon-rt/tests/data/client_auth");
        let roots = crate::config::load_ca_file(&fx.join("ca-auth.crt")).expect("ca-auth.crt is v3");
        let prov = provider::of(TlsCryptoProvider::Ring, true, true);
        let v = BindClientVerifier::new(Arc::new(roots), true, TlsCryptoProvider::Ring, &prov);
        let (chain, _key) = crate::config::load_cert_file(&fx.join("client1.pem")).expect("load client1");
        let (res, codes) = check(&v, chain);
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::Other(_)))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 1, crt_err: 1, ca_err: 0 });
    }

    #[test]
    fn ignore_err_relaxation_covers_eku_untrusted_and_validity() {
        let ca = make_ca("Ignore Test CA");
        let other_ca = make_ca("Other CA");
        let prov = provider::of(TlsCryptoProvider::Ring, true, true);
        let make_v = |crt_ign: X509ErrMask, ca_ign: X509ErrMask| {
            let mut roots = RootCertStore::empty();
            roots.add(ca.cert.der().clone()).expect("root");
            BindClientVerifier::from_opts(
                BindClientVerifyOpts {
                    roots: Arc::new(roots),
                    root_hint_subjects: Vec::new(),
                    crls: Vec::new(),
                    mandatory: true,
                    crt_ignore_err: crt_ign,
                    ca_ignore_err: ca_ign,
                },
                TlsCryptoProvider::Ring,
                &prov,
            )
        };

        // 1. Trusted leaf with ServerAuth-only EKU ignored by crt-ignore-err 26 -> Ok, 26/26/0.
        let mut eku_p = CertificateParams::new(Vec::<String>::new()).expect("p");
        eku_p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let eku_k = KeyPair::generate().expect("k");
        let eku_c = eku_p.signed_by(&eku_k, &ca.cert, &ca.key).expect("sign");
        let mut mask_eku = X509ErrMask::EMPTY;
        mask_eku.insert(26);
        let (res, codes) = check(&make_v(mask_eku, X509ErrMask::EMPTY), vec![eku_c.der().clone()]);
        assert!(res.is_ok(), "ignored EKU must pass: {res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 26, crt_err: 26, ca_err: 0 });

        // 2. Untrusted self-signed leaf ignored by crt-ignore-err 18 -> Ok, 18/18/0.
        let ss = rcgen::generate_simple_self_signed(vec!["ss.example".to_string()]).expect("ss");
        let mut mask_ss = X509ErrMask::EMPTY;
        mask_ss.insert(18);
        let (res, codes) = check(&make_v(mask_ss, X509ErrMask::EMPTY), vec![ss.cert.der().clone()]);
        assert!(res.is_ok(), "ignored self-signed must pass: {res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 18, crt_err: 18, ca_err: 0 });

        // 3. Expired leaf under expired inter with crt-ignore-err 10 ONLY -> check_inter_now_validity
        //    must still reject the expired intermediate (no CA bypass!).
        let mut inter_p = CertificateParams::new(Vec::<String>::new()).expect("ip");
        inter_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        inter_p.not_before = date_time_ymd(2020, 1, 1);
        inter_p.not_after = date_time_ymd(2021, 1, 1);
        let inter_k = KeyPair::generate().expect("ik");
        let exp_inter = inter_p.signed_by(&inter_k, &ca.cert, &ca.key).expect("inter");
        let mut leaf_p = CertificateParams::new(Vec::<String>::new()).expect("lp");
        leaf_p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        leaf_p.not_before = date_time_ymd(2020, 1, 1);
        leaf_p.not_after = date_time_ymd(2021, 1, 1);
        let leaf_k = KeyPair::generate().expect("lk");
        let exp_leaf = leaf_p.signed_by(&leaf_k, &exp_inter, &inter_k).expect("leaf");
        let mut mask_exp = X509ErrMask::EMPTY;
        mask_exp.insert(10);
        let (res, codes) = check(&make_v(mask_exp, X509ErrMask::EMPTY), vec![exp_leaf.der().clone(), exp_inter.der().clone()]);
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::Expired))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 10, crt_err: 10, ca_err: 10 });

        // 4. Not-yet-valid intermediate under future leaf + crt-ignore-err 9 ONLY -> rejects NotValidYet!
        let mut future_ca_params = CertificateParams::new(Vec::<String>::new()).expect("fip");
        future_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        future_ca_params.not_before = date_time_ymd(2035, 1, 1);
        future_ca_params.not_after = date_time_ymd(2036, 1, 1);
        let future_ca_key = KeyPair::generate().expect("fik");
        let fut_inter = future_ca_params.signed_by(&future_ca_key, &ca.cert, &ca.key).expect("fi");
        let mut future_leaf_params = CertificateParams::new(Vec::<String>::new()).expect("flp");
        future_leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        future_leaf_params.not_before = date_time_ymd(2035, 1, 1);
        future_leaf_params.not_after = date_time_ymd(2036, 1, 1);
        let future_leaf_key = KeyPair::generate().expect("flk");
        let fut_leaf = future_leaf_params.signed_by(&future_leaf_key, &fut_inter, &future_ca_key).expect("fl");
        let mut mask_nyv = X509ErrMask::EMPTY;
        mask_nyv.insert(9);
        let (res, codes) = check(&make_v(mask_nyv, X509ErrMask::EMPTY), vec![fut_leaf.der().clone(), fut_inter.der().clone()]);
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::NotValidYet))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 9, crt_err: 9, ca_err: 9 });

        // 5. Inverted validity window (`not_before > not_after`) exercises `cert_validity_err` & `common_valid_time`.
        let mut inv_p = CertificateParams::new(Vec::<String>::new()).expect("inv");
        inv_p.not_before = date_time_ymd(2025, 1, 1);
        inv_p.not_after = date_time_ymd(2020, 1, 1);
        let inv_k = KeyPair::generate().expect("invk");
        let inv_c = inv_p.signed_by(&inv_k, &other_ca.cert, &other_ca.key).expect("invc");
        assert_eq!(cert_validity_err(inv_c.der().as_ref(), UnixTime::now()), Some(x509_err::ERROR_IN_CERT_NOT_AFTER_FIELD));
        assert!(common_valid_time(inv_c.der().as_ref(), &[]).is_none());
    }

    #[test]
    fn ignore_err_relaxation_covers_expired_and_partial_crls() {
        let prov = provider::of(TlsCryptoProvider::Ring, true, true);
        let fx = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../alcyon-rt/tests/data/client_auth");
        let fx_roots = Arc::new(crate::config::load_ca_file(&fx.join("crl-root-ca.crt")).expect("root"));

        // 1. Expired CRL ignored by crt-ignore-err 12: valid leaf passes (12/12/0), while revoked leaf
        //    in that same expired CRL is STILL rejected (Revoked)!
        let exp_crl_ders = crate::config::load_crl_file(&fx.join("crl-root-expired.pem")).expect("exp crl");
        let exp_crls: Vec<CertRevocationList<'static>> = exp_crl_ders
            .into_iter()
            .map(|d| CertRevocationList::Owned(webpki::OwnedCertRevocationList::from_der(d.as_ref()).expect("der")))
            .collect();
        let mut mask_crl_exp = X509ErrMask::EMPTY;
        mask_crl_exp.insert(12);
        let v_exp_crl = BindClientVerifier::from_opts(
            BindClientVerifyOpts {
                roots: Arc::clone(&fx_roots),
                root_hint_subjects: Vec::new(),
                crls: exp_crls,
                mandatory: true,
                crt_ignore_err: mask_crl_exp,
                ca_ignore_err: X509ErrMask::EMPTY,
            },
            TlsCryptoProvider::Ring,
            &prov,
        );
        let (ok_chain, _) = crate::config::load_cert_file(&fx.join("crl-direct-ok.pem")).expect("ok");
        let (res, codes) = check(&v_exp_crl, ok_chain);
        assert!(res.is_ok(), "ignored expired CRL must allow valid leaf: {res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 12, crt_err: 12, ca_err: 0 });
        let (rev_chain, _) = crate::config::load_cert_file(&fx.join("crl-direct-revoked.pem")).expect("rev");
        let (res, codes) = check(&v_exp_crl, rev_chain);
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::Revoked))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 12, crt_err: 12, ca_err: 0 });

        // 2. Missing root CRL (ca_err=3 ignored by ca-ignore-err 3) + revoked leaf (crt_err=23 NOT ignored):
        //    exercises `RevMode::Chain -> EndEntity` then `EndEntity` rejecting leaf!
        let inter1_crl_ders = crate::config::load_crl_file(&fx.join("crl-inter1.pem")).expect("i1 crl");
        let inter1_crls: Vec<CertRevocationList<'static>> = inter1_crl_ders
            .into_iter()
            .map(|d| CertRevocationList::Owned(webpki::OwnedCertRevocationList::from_der(d.as_ref()).expect("der")))
            .collect();
        let mut mask_no_crl = X509ErrMask::EMPTY;
        mask_no_crl.insert(3);
        let v_ca_nocrl = BindClientVerifier::from_opts(
            BindClientVerifyOpts {
                roots: fx_roots,
                root_hint_subjects: Vec::new(),
                crls: inter1_crls,
                mandatory: true,
                crt_ignore_err: X509ErrMask::EMPTY,
                ca_ignore_err: mask_no_crl,
            },
            TlsCryptoProvider::Ring,
            &prov,
        );
        let (mut rev_leaf, _) = crate::config::load_cert_file(&fx.join("crl-leaf-revoked.pem")).expect("lr");
        let inter1_pem = std::fs::read(fx.join("crl-inter1.crt")).expect("i1");
        let mut rdr = std::io::BufReader::new(inter1_pem.as_slice());
        for item in rustls_pemfile::read_all(&mut rdr) {
            if let Ok(rustls_pemfile::Item::X509Certificate(c)) = item {
                rev_leaf.push(c);
            }
        }
        let (res, codes) = check(&v_ca_nocrl, rev_leaf);
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::Revoked))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 23, crt_err: 23, ca_err: 3 });
    }

    #[test]
    fn relax_exhausted_and_leaf_parse_errors_never_bypass_trust_anchor() {
        let prov = provider::of(TlsCryptoProvider::Ring, true, true);
        let fx = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../alcyon-rt/tests/data/client_auth");
        let roots = Arc::new(crate::config::load_ca_file(&fx.join("v3-ca.crt")).expect("v3-ca"));
        let make_v = |crt_ign: X509ErrMask, ca_ign: X509ErrMask| {
            BindClientVerifier::from_opts(
                BindClientVerifyOpts {
                    roots: Arc::clone(&roots),
                    root_hint_subjects: Vec::new(),
                    crls: Vec::new(),
                    mandatory: true,
                    crt_ignore_err: crt_ign,
                    ca_ignore_err: ca_ign,
                },
                TlsCryptoProvider::Ring,
                &prov,
            )
        };

        // Load untrusted disjoint-expired leaf (2024) + untrusted self-signed inter (2010..2011).
        let (mut evil_chain, _) = crate::config::load_cert_file(&fx.join("crl-evil-leaf.pem")).expect("evil leaf");
        let inter_pem = std::fs::read(fx.join("crl-evil-inter.crt")).expect("evil inter");
        for item in rustls_pemfile::read_all(&mut std::io::BufReader::new(inter_pem.as_slice())) {
            if let Ok(rustls_pemfile::Item::X509Certificate(c)) = item {
                evil_chain.push(c);
            }
        }

        // 1. Ignoring expiry at both depths MUST reject (relax exhausted without reaching trust anchor).
        let mut mask_exp = X509ErrMask::EMPTY;
        mask_exp.insert(10);
        let (res, codes) = check(&make_v(mask_exp, mask_exp), evil_chain.clone());
        assert!(
            matches!(res, Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))),
            "relax-exhausted untrusted chain must fail with UnknownIssuer, got {res:?} ({codes:?})"
        );
        assert_eq!(codes.ca_err, x509_err::SELF_SIGNED_CERT_IN_CHAIN);

        // 2. Ignoring 10+19 at the CA depth (or `all` at both depths) accepts with 10/10/19.
        let mut mask_ca19 = mask_exp;
        mask_ca19.insert(19);
        let (res, codes) = check(&make_v(mask_exp, mask_ca19), evil_chain.clone());
        assert!(res.is_ok(), "ignored 10 + ca 19 must pass: {res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 10, crt_err: 10, ca_err: 19 });

        // 3. Leaf parse error (`UnsupportedCertVersion` = 1) with ONLY code 1 ignored (NOT 20)
        //    must reject with UnknownIssuer; with `all` (includes 20) it returns Ok with err=1.
        let (v1_chain, _) = crate::config::load_cert_file(&fx.join("client1.pem")).expect("v1");
        let mut mask_unspec = X509ErrMask::EMPTY;
        mask_unspec.insert(1);
        let (res, codes) = check(&make_v(mask_unspec, X509ErrMask::EMPTY), v1_chain.clone());
        assert!(
            matches!(res, Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))),
            "ignoring only code 1 must not bypass trust anchor: {res:?} ({codes:?})"
        );
        assert_eq!(codes.crt_err, x509_err::UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

        let (res, codes) = check(&make_v(X509ErrMask::ALL, X509ErrMask::EMPTY), v1_chain);
        assert!(res.is_ok(), "crt-ignore-err all includes both 1 and 20: {res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 1, crt_err: 1, ca_err: 0 });

        // 4. Untrusted self-signed cert with notBefore > notAfter under exp_both -> UnknownIssuer (18);
        //    under crt-ignore-err 18 only -> Expired (14); under all -> Ok with crt_err=18.
        let (inv_chain, _) = crate::config::load_cert_file(&fx.join("crl-evil-inverted.pem")).expect("inv");
        let (res, codes) = check(&make_v(mask_exp, mask_exp), inv_chain.clone());
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 18, crt_err: 18, ca_err: 0 });

        let mut mask_ss = X509ErrMask::EMPTY;
        mask_ss.insert(18);
        let (res, codes) = check(&make_v(mask_ss, X509ErrMask::EMPTY), inv_chain.clone());
        assert!(matches!(res, Err(Error::InvalidCertificate(CertificateError::Expired))), "{res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 14, crt_err: 14, ca_err: 0 });

        let (res, codes) = check(&make_v(X509ErrMask::ALL, X509ErrMask::EMPTY), inv_chain);
        assert!(res.is_ok(), "all must accept inverted self-signed: {res:?}");
        assert_eq!(codes, ClientVerifyCodes { verify: 14, crt_err: 18, ca_err: 0 });
    }
}
