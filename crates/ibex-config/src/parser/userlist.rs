// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The lines of a `userlist` section: `group <name> [users <u>,...]` and
//! `user <name> [insecure-password <pw>] [groups <g>,...]`.

use super::{ConfigError, Token, Userlist, UserlistUser};

/// A comma list as `HAProxy` splits it: empty elements are skipped.
fn names(list: &str) -> impl Iterator<Item = &str> {
    list.split(',').filter(|n| !n.is_empty())
}

/// One line of a `userlist` section. The messages are `HAProxy`'s (3.5-dev8-885761-29).
///
/// A `password` (a `crypt(3)` hash) is refused: Ibex has no `crypt(3)`, and a user it could
/// never authenticate would turn every request away without a word as to why.
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
            let mut groups = Vec::new();
            let mut i = 2;
            while let Some(arg) = tokens.get(i) {
                match arg.text.as_str() {
                    "password" => {
                        return Err(err(
                            arg,
                            format!(
                                "the encrypted 'password' of user '{}' is not supported: Ibex has no crypt(3); \
                                 use 'insecure-password'.",
                                name.text
                            ),
                        ));
                    }
                    "insecure-password" => {
                        password = tokens.get(i + 1).map(|t| t.text.clone());
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
            list.users.push(UserlistUser { name: name.text.clone(), password, groups: Vec::new() });
            Ok(())
        }
        other => Err(err(kw, format!("unknown keyword '{other}' in 'userlist' section"))),
    }
}
