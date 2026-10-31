// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A proxy's named ACLs.
//!
//! `HAProxy` looks a name up in the proxy's own ACLs first (`find_acl_by_name`) and then
//! in the predefined ones (`find_acl_default`, `default_acl_list` in src/acl.c), which
//! exist once for the process. Ibex used to compile the 23 predefined ACLs into every
//! proxy, about 20 KB each: 200 MB at 10,000 backends (T175). They are now compiled once
//! and shared, and a proxy holds only the ACLs it declares.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::expr::Expr;

/// `HAProxy`'s predefined ACLs (`default_acl_list`, src/acl.c), by name.
pub const PREDEFINED_ACLS: &[(&str, &str)] = &[
    ("TRUE", "always_true"),
    ("WAIT_END", "wait_end"),
    ("FALSE", "always_false"),
    ("LOCALHOST", "src 127.0.0.1/8 ::1"),
    ("HTTP", "req.proto_http"),
    ("HTTP_1.0", "req.ver 1.0"),
    ("HTTP_1.1", "req.ver 1.1"),
    ("HTTP_2.0", "req.ver 2.0"),
    ("HTTP_3.0", "req.ver 3.0"),
    ("METH_CONNECT", "method CONNECT"),
    ("METH_DELETE", "method DELETE"),
    ("METH_GET", "method GET HEAD"),
    ("METH_HEAD", "method HEAD"),
    ("METH_OPTIONS", "method OPTIONS"),
    ("METH_POST", "method POST"),
    ("METH_PUT", "method PUT"),
    ("METH_TRACE", "method TRACE"),
    ("HTTP_URL_ABS", "url -m reg ^[^/:]*://"),
    ("HTTP_URL_SLASH", "url -m beg /"),
    ("HTTP_URL_STAR", "url *"),
    ("HTTP_CONTENT", "req.hdr_val(content-length) gt 0"),
    ("REQ_CONTENT", "req.len gt 0"),
    ("RDP_COOKIE", "req.rdp_cookie_cnt gt 0"),
];

/// The predefined ACL `name`, compiled on its first use and shared by every proxy and thread.
/// Each is compiled alone: `HTTP_URL_ABS` is a regex, whose compilation allocates tens of KB,
/// and a configuration that never names it (nor any predefined ACL) must not pay that at
/// start-up, where `-m 1` leaves no room for it (T508).
fn predefined(name: &str) -> Option<&'static Expr> {
    static PREDEFINED: [OnceLock<Option<Expr>>; PREDEFINED_ACLS.len()] = [const { OnceLock::new() }; PREDEFINED_ACLS.len()];
    let i = PREDEFINED_ACLS.iter().position(|&(n, _)| n == name)?;
    PREDEFINED[i].get_or_init(|| Expr::parse(PREDEFINED_ACLS[i].1).ok()).as_ref()
}

/// A proxy's ACLs by name: its own, then the predefined ones.
#[derive(Debug, Clone, Default)]
pub struct Acls {
    own: HashMap<String, usize>,
    exprs: Box<[Expr]>,
}

/// An ACL [`Acls::resolve`]d once, when the configuration loads: evaluated through
/// [`Acls::at`] with no lookup by its name (S7).
#[derive(Debug, Clone, Copy)]
pub enum AclRef {
    /// The proxy's own, by its index.
    Own(usize),
    /// A predefined one.
    Predefined(&'static Expr),
}

impl Acls {
    /// The proxy's own ACLs from its `acl <name> <expr>` lines, in order. A name declared
    /// on several lines is one ACL matching if any line does; it replaces a predefined ACL
    /// of that name. A line whose expression does not parse is skipped (the configuration
    /// check refuses it first).
    pub fn compile<'a>(lines: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut own: HashMap<String, usize> = HashMap::new();
        let mut exprs: Vec<Expr> = Vec::new();
        for (name, text) in lines {
            let Ok(expr) = Expr::parse(text) else { continue };
            if let Some(&first) = own.get(name) {
                exprs[first].alternates.push(expr);
            } else {
                own.insert(name.to_string(), exprs.len());
                exprs.push(expr);
            }
        }
        Self { own, exprs: exprs.into_boxed_slice() }
    }

    /// The ACL named `name`: the proxy's own, else the predefined one.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Expr> {
        self.resolve(name).and_then(|r| self.at(r))
    }

    /// The ACL named `name`, to be evaluated later with [`Self::at`].
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<AclRef> {
        match self.own.get(name) {
            Some(&i) => Some(AclRef::Own(i)),
            None => predefined(name).map(AclRef::Predefined),
        }
    }

    /// The ACL `r` is: one [`Self::resolve`] gave for these ACLs (none for another proxy's).
    #[must_use]
    pub fn at(&self, r: AclRef) -> Option<&Expr> {
        match r {
            AclRef::Own(i) => self.exprs.get(i),
            AclRef::Predefined(e) => Some(e),
        }
    }

    /// Whether `name` names an ACL, the proxy's own or a predefined one.
    #[must_use]
    pub fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_acls_replace_predefined_ones_and_alternate() {
        let acls = Acls::compile([("TRUE", "always_false"), ("TRUE", "always_true"), ("x", "src 10.0.0.1")]);
        assert_eq!(acls.get("TRUE").map(|e| e.alternates.len()), Some(1));
        assert!(acls.contains_key("x"));
        assert!(acls.contains_key("METH_GET"));
        assert!(!acls.contains_key("nope"));
        assert!(Acls::default().get("HTTP_1.1").is_some());
    }
}
