// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The lines of a `userlist` section: `group <name> [users <u>,...]` and
//! `user <name> [insecure-password <pw>] [groups <g>,...]`.

use super::{ConfigError, Token, Userlist, UserlistUser};

/// A comma list as `HAProxy` splits it: empty elements are skipped.
fn names(list: &str) -> impl Iterator<Item = &str> {
    list.split(',').filter(|n| !n.is_empty())
}

/// What `HAProxy` does with `password <hash>` at load: `crypt("", hash)` must not fail, and a
/// hash that takes 10 ms or more to verify is warned about.
fn check_hash(hash: &str, user: &str) -> Result<(), String> {
    match ibex_crypt::CryptHash::parse(hash) {
        Ok(h) => {
            let t = std::time::Instant::now();
            let _ = h.verify(b"");
            let ms = t.elapsed().as_millis();
            if ms >= 10 {
                crate::stderr_line!(
                    "[ibex] warning: the hash algorithm used for this password takes {ms} milliseconds to verify, which can have devastating performance and stability impacts. Please hash this password using a lighter algorithm (one that is compatible with web usage)."
                );
            }
            Ok(())
        }
        Err(ibex_crypt::Refusal::Invalid) => Err(format!("the encrypted password used for user '{user}' is not supported by crypt(3).")),
        Err(ibex_crypt::Refusal::Format(f)) => Err(format!(
            "the encrypted password used for user '{user}' is in the {f} format, which Ibex cannot verify \
             (it verifies $1$, $5$, $6$, $2a$, $2b$ and $2y$); rehash it with one of those or use 'insecure-password'."
        )),
    }
}

/// One line of a `userlist` section. The messages are `HAProxy`'s (3.5-dev8-885761-29).
///
/// A `password` is a `crypt(3)` hash, read by `ibex-crypt`: `$1$`, `$5$`, `$6$` and
/// `$2a$`/`$2b$`/`$2y$` load; what glibc itself refuses is refused with its message; DES,
/// yescrypt and the other formats glibc verifies and Ibex cannot are refused naming the
/// format (a user that could never authenticate would turn every request away unexplained).
pub(crate) fn parse_userlist_directive(list: &mut Userlist, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    let err = |t: &Token, m: String| ConfigError::new(t.line, t.col, m);
    match kw.text.as_str() {
        "group" => {
            let Some(name) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
                return Err(err(kw, "'group' expects <name> as arguments.".to_string()));
            };
            if name.text.contains(',') {
                return Err(err(name, format!("character ',' is not permitted in 'group' name '{}'.", name.text)));
            }
            if list.groups.contains(&name.text) {
                // Ignored, as HAProxy ignores it (with a warning).
                return Ok(());
            }
            list.groups.push(name.text.clone());
            let mut i = 2;
            while let Some(arg) = tokens.get(i) {
                match arg.text.as_str() {
                    "users" => {
                        if let Some(users) = tokens.get(i + 1) {
                            list.members.extend(names(&users.text).map(|u| (name.text.clone(), u.to_string(), kw.line)));
                        }
                        i += 2;
                    }
                    _ => return Err(err(kw, "'group' only supports 'users' option.".to_string())),
                }
            }
            Ok(())
        }
        "user" => {
            let Some(name) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
                return Err(err(kw, "'user' expects <name> as arguments.".to_string()));
            };
            let mut password = None;
            let mut is_hash = false;
            let mut groups = Vec::new();
            let mut i = 2;
            while let Some(arg) = tokens.get(i) {
                match arg.text.as_str() {
                    "password" => {
                        let hash = tokens.get(i + 1).map_or("", |t| t.text.as_str());
                        check_hash(hash, &name.text).map_err(|m| err(arg, m))?;
                        password = Some(hash.to_string());
                        is_hash = true;
                        i += 2;
                    }
                    "insecure-password" => {
                        password = tokens.get(i + 1).map(|t| t.text.clone());
                        is_hash = false;
                        i += 2;
                    }
                    "groups" => {
                        if let Some(g) = tokens.get(i + 1) {
                            groups.extend(names(&g.text).map(str::to_string));
                        }
                        i += 2;
                    }
                    _ => return Err(err(kw, "'user' only supports 'password', 'insecure-password' and 'groups' options.".to_string())),
                }
            }
            if list.users.iter().any(|u| u.name == name.text) {
                // Ignored, as HAProxy ignores it (with a warning).
                return Ok(());
            }
            for g in groups {
                list.user_groups.push((name.text.clone(), g, kw.line));
            }
            list.users.push(UserlistUser { name: name.text.clone(), password, password_is_hash: is_hash, groups: Vec::new() });
            Ok(())
        }
        other => Err(err(kw, format!("unknown keyword '{other}' in 'userlist' section"))),
    }
}
