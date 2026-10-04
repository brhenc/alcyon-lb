// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `userlist <name>`: the users and groups `http_auth(<name>)` and `http_auth_group(<name>)`
//! check a request's credentials against.

use std::cell::RefCell;

/// One `user <name> [insecure-password <pw>] [groups <g>,...]` line, with the groups that
/// `group <g> users <name>,...` lines add to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserlistUser {
    pub name: String,
    /// `insecure-password`; `None` for a user declared without one, who never authenticates.
    pub password: Option<String>,
    pub groups: Vec<String>,
}

/// A `userlist` section.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Userlist {
    pub name: String,
    /// The line of its header, where a reference to a missing user or group is reported.
    pub line: usize,
    pub groups: Vec<String>,
    pub users: Vec<UserlistUser>,
    /// `group <g> users <u>,...`, resolved when the section ends: (group, user, line).
    pub(crate) members: Vec<(String, String, usize)>,
    /// `user <u> groups <g>,...`, resolved when the section ends: (user, group, line).
    pub(crate) user_groups: Vec<(String, String, usize)>,
}

impl Userlist {
    fn add_to_group(&mut self, user: &str, group: String) {
        for u in self.users.iter_mut().filter(|u| u.name == user && !u.groups.contains(&group)) {
            u.groups.push(group.clone());
        }
    }

    /// Resolves what the section's lines named: every group of a user must be declared, and
    /// every user of a group must exist (`HAProxy` refuses both at load).
    ///
    /// # Errors
    /// `HAProxy`'s message and the line of the section's header.
    pub fn resolve(&mut self) -> Result<(), (usize, String)> {
        for (user, group, _) in std::mem::take(&mut self.user_groups) {
            if !self.groups.contains(&group) {
                return Err((self.line, format!("userlist '{}': no such group '{group}' specified in user '{user}'", self.name)));
            }
            self.add_to_group(&user, group);
        }
        for (group, user, _) in std::mem::take(&mut self.members) {
            if !self.users.iter().any(|u| u.name == user) {
                return Err((self.line, format!("userlist '{}': no such user '{user}' specified in group '{group}'", self.name)));
            }
            self.add_to_group(&user, group);
        }
        Ok(())
    }
}

thread_local! {
    /// The `userlist` sections of the parse in progress on this thread, in the order read.
    static USERLISTS: RefCell<Vec<Userlist>> = const { RefCell::new(Vec::new()) };
}

/// Forgets this thread's userlists. Called at the start of `parse_str`.
pub fn clear_userlists() {
    USERLISTS.with_borrow_mut(Vec::clear);
}

/// Keeps a parsed section; one whose name is already taken is dropped, as `HAProxy` keeps
/// the first of two with the same name.
pub fn register_userlist(list: Userlist) {
    USERLISTS.with_borrow_mut(|all| {
        if !all.iter().any(|l| l.name == list.name) {
            all.push(list);
        }
    });
}

/// The userlists of the parse, taken out of the thread's registry.
#[must_use]
pub fn take_userlists() -> Vec<Userlist> {
    USERLISTS.with_borrow_mut(std::mem::take)
}
