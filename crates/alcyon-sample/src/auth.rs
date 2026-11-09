// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/auth.c and src/http_fetch.c (smp_fetch_http_auth,
// smp_fetch_http_auth_grp, smp_fetch_http_auth_user/pass/type).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http_auth(<userlist>)`, `http_auth_group(<userlist>)` and the `http_auth_user`,
//! `http_auth_pass` and `http_auth_type` fetches, over the `userlist` sections of the
//! configuration.

use std::sync::RwLock;

use crate::registry::{Registry, SampleContext};
use crate::sample::{Sample, SampleType};
use crate::FetchDesc;

/// A user of a userlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUser {
    pub name: String,
    /// `insecure-password`; a user with none never authenticates.
    pub password: Option<String>,
    /// `password <hash>`: the verifier of the `crypt(3)` hash, which `password` then holds
    /// as text.
    pub crypt: Option<alcyon_crypt::CryptHash>,
    pub groups: Vec<String>,
}

/// A `userlist` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUserlist {
    pub name: String,
    pub users: Vec<AuthUser>,
}

static USERLISTS: RwLock<Vec<AuthUserlist>> = RwLock::new(Vec::new());

/// Whether a panic unwound through a change of the userlists (T447).
pub(crate) fn poisoned() -> bool {
    USERLISTS.is_poisoned()
}

/// Installs the configuration's userlists, replacing those of a previous load.
pub fn set_userlists(lists: Vec<AuthUserlist>) {
    if let Ok(mut all) = USERLISTS.write() {
        *all = lists;
    }
}

/// What the `Authorization` header carries.
enum Credentials {
    /// `Basic <base64(user:password)>`.
    Basic { user: String, pass: String },
    /// `Bearer <token>`: only its type is read.
    Bearer,
}

impl Credentials {
    fn kind(&self) -> &'static str {
        match self {
            Credentials::Basic { .. } => "Basic",
            Credentials::Bearer => "Bearer",
        }
    }
}

/// The credentials of the request's first `Authorization` header, as `HAProxy` reads them:
/// a scheme, one or more spaces (not a tab), then for `Basic` the base64 of `user:password`.
/// The scheme is compared without regard to case. Anything else is no credentials.
fn credentials(ctx: &SampleContext) -> Option<Credentials> {
    let value = crate::registry::request_header(ctx, "authorization")?;
    let value = value.trim_end_matches(' ');
    let (scheme, rest) = value.split_once(' ')?;
    let rest = rest.trim_start_matches(' ');
    if scheme.eq_ignore_ascii_case("basic") {
        let decoded = crate::registry::base64_decode(rest, false, true)?;
        let decoded = String::from_utf8(decoded).ok()?;
        let (user, pass) = decoded.split_once(':')?;
        Some(Credentials::Basic { user: user.to_string(), pass: pass.to_string() })
    } else if scheme.eq_ignore_ascii_case("bearer") {
        Some(Credentials::Bearer)
    } else {
        None
    }
}

/// Equality without an early exit on the first differing byte: the time depends on the
/// longer length, not on where the two differ.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// The user of `userlist` the request authenticates as: it exists, has a password, and the
/// request carries it.
fn authenticated(ctx: &SampleContext, userlist: &str) -> Option<AuthUser> {
    let Some(Credentials::Basic { user, pass }) = credentials(ctx) else { return None };
    let all = USERLISTS.read().ok()?;
    let list = all.iter().find(|l| l.name == userlist)?;
    let u = list.users.iter().find(|u| u.name == user)?;
    // A hashed password is hashed again on every request that carries one, as HAProxy does
    // (it caches nothing).
    let ok = match &u.crypt {
        Some(hash) => hash.verify(pass.as_bytes()),
        None => u.password.as_deref().is_some_and(|p| ct_eq(p.as_bytes(), pass.as_bytes())),
    };
    ok.then(|| u.clone())
}

pub(crate) fn register(reg: &mut Registry) {
    // T331f: `smp_fetch_http_auth` gives no sample unless the request carries well-formed Basic
    // credentials; with them it gives whether `check_user` accepts them.
    reg.register_fetch(FetchDesc {
        name: "http_auth",
        out_type: SampleType::Bool,
        func: |ctx, args| {
            let list = args.first()?;
            let Credentials::Basic { .. } = credentials(ctx)? else { return None };
            Some(Sample::Bool(authenticated(ctx, list).is_some()))
        },
    });
    // T331f: `smp_fetch_http_auth_grp` gives the user name when the credentials check out, and no
    // sample otherwise.
    reg.register_fetch(FetchDesc {
        name: "http_auth_group",
        out_type: SampleType::Str,
        func: |ctx, args| authenticated(ctx, args.first()?).map(|u| Sample::Str(u.name)),
    });
    // What an ACL on `http_auth_group(<userlist>)` matches (`pat_match_auth`): any group of the
    // user the request authenticates as. `eval_all`, the ACL path, reads this; `eval` reads the
    // plain fetch above.
    reg.register_multi_fetch("http_auth_group", |ctx, args| {
        let Some(list) = args.first() else { return Vec::new() };
        authenticated(ctx, list).map_or_else(Vec::new, |u| u.groups.into_iter().map(Sample::Str).collect())
    });
    reg.register_fetch(FetchDesc {
        name: "http_auth_user",
        out_type: SampleType::Str,
        func: |ctx, _| match credentials(ctx)? {
            Credentials::Basic { user, .. } => Some(Sample::Str(user)),
            Credentials::Bearer => None,
        },
    });
    reg.register_fetch(FetchDesc {
        name: "http_auth_pass",
        out_type: SampleType::Str,
        func: |ctx, _| match credentials(ctx)? {
            Credentials::Basic { pass, .. } => Some(Sample::Str(pass)),
            Credentials::Bearer => None,
        },
    });
    reg.register_fetch(FetchDesc {
        name: "http_auth_type",
        out_type: SampleType::Str,
        func: |ctx, _| credentials(ctx).map(|c| Sample::Str(c.kind().to_string())),
    });
}

#[cfg(test)]
mod ct_tests {
    use super::ct_eq;

    #[test]
    fn compares_whole_values() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"secret", b"secret"));
        assert!(!ct_eq(b"secret", b"secreT"));
        assert!(!ct_eq(b"secret", b"secre"));
        assert!(!ct_eq(b"", b"x"));
        assert!(!ct_eq(b"a\0", b"a"));
    }
}
