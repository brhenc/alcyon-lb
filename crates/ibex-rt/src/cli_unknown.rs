// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/cli.c (`cli_gen_usage_msg`) and src/tools.c (word fingerprints).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The answer to an unknown command on the stats socket (T597): `HAProxy` lists the commands
//! that begin with the words typed so far, or else the five whose remaining words are nearest
//! to the ones typed, by the distance between the fingerprints of their letter transitions.
//! The commands are those of `HAProxy` 3.5-dev8 at the `admin` level (`cli_usage.txt`: its `help`
//! output, in the order the commands register, which breaks ties); the text is what is listed,
//! not what Ibex runs, and it is the same at every level.

/// How many words of a command name the keyword table keeps (`CLI_PREFIX_KW_NB`).
const PREFIX_WORDS: usize = 5;
/// How many near matches are kept (`CLI_MAX_MATCHES`).
const MAX_MATCHES: usize = 5;

/// One command: its usage line and the words that name it.
struct Kw {
    usage: &'static str,
    words: Vec<&'static str>,
}

fn table() -> Vec<Kw> {
    include_str!("cli_usage.txt")
        .lines()
        .map(|usage| {
            // The name is the words before the first argument (`[..]`, `<..>`, `{..}`, `(..)`) or the
            // `:` that starts the description.
            let words = usage
                .split_whitespace()
                .take_while(|w| *w != ":" && !w.starts_with(['[', '<', '{', '(', '@']))
                .take(PREFIX_WORDS)
                .collect();
            Kw { usage, words }
        })
        .collect()
}

/// `update_word_fingerprint`: counts the transitions between characters, indexed
/// `32 * from + to` (letters 1..=26, digits 27, anything else, begin and end 28).
fn add_fingerprint(fp: &mut [u8; 1024], word: &str) {
    let mut from = 28usize;
    for c in word.bytes() {
        let c = c.to_ascii_lowercase();
        let to = match c {
            b'a'..=b'z' => usize::from(c - b'a') + 1,
            b'0'..=b'9' => 27,
            _ => 28,
        };
        fp[to] = 1;
        fp[32 * from + to] = fp[32 * from + to].wrapping_add(1);
        from = to;
    }
    fp[32 * from + 28] = fp[32 * from + 28].wrapping_add(1);
}

fn distance(a: &[u8; 1024], b: &[u8; 1024]) -> usize {
    a.iter().zip(b).map(|(&x, &y)| usize::from(x.abs_diff(y))).sum()
}

/// The answer to `args` (the words of the command line, the first being unknown).
#[must_use]
pub fn answer(args: &[String]) -> String {
    let kws = table();
    let arg = |i: usize| args.get(i).map(String::as_str).filter(|a| !a.is_empty());
    // The longest run of words that some command begins with.
    let mut length = 0;
    for kw in &kws {
        for (idx, w) in kw.words.iter().enumerate() {
            if arg(idx).is_none_or(|a| a != *w) {
                break;
            }
            length = length.max(idx + 1);
        }
    }
    let mut out = format!("Unknown command: '{}'", args.first().map_or("", String::as_str));
    if length == 0 && arg(0).is_none() {
        out.push_str(". Please enter one of the following commands only:\n");
    } else {
        out.push_str(", but maybe one of the following ones is a better match:\n");
    }
    // Commands that begin with the first `length` words.
    let begins = |kw: &Kw| kw.words.len() >= length && kw.words[..length].iter().enumerate().all(|(i, w)| arg(i) == Some(*w));
    let mut matches: Vec<(usize, &Kw)> = Vec::new();
    if arg(length).is_some() {
        for kw in kws.iter().filter(|kw| begins(kw)) {
            let (mut word_sig, mut list_sig) = ([0u8; 1024], [0u8; 1024]);
            let mut totlen = 0;
            for i in length..PREFIX_WORDS {
                let Some(a) = arg(i) else { break };
                add_fingerprint(&mut word_sig, a);
                totlen += a.len();
            }
            for w in kw.words.iter().skip(length) {
                add_fingerprint(&mut list_sig, w);
                totlen += w.len();
            }
            let dist = distance(&word_sig, &list_sig);
            let worst = if matches.len() < MAX_MATCHES { usize::MAX } else { matches[MAX_MATCHES - 1].0 };
            if dist < 5 * totlen / 2 && dist < worst {
                // After the ones at the same distance: a nearer one moves up only past strictly farther ones.
                let at = matches.iter().position(|m| m.0 > dist).unwrap_or(matches.len());
                matches.insert(at, (dist, kw));
                matches.truncate(MAX_MATCHES);
            }
        }
    }
    let mut lines: Vec<&str> = Vec::new();
    if let Some(&(best, _)) = matches.first() {
        lines.extend(matches.iter().take_while(|m| m.0 <= 5 * best / 2).map(|m| m.1.usage));
    } else {
        lines.extend(kws.iter().filter(|kw| begins(kw)).map(|kw| kw.usage));
    }
    lines.sort_unstable();
    for l in lines {
        out.push_str("  ");
        out.push_str(l);
        out.push('\n');
    }
    out.push_str(
        "  help [<command>]                        : list matching or all commands\n  \
         prompt [help | n | i | p | timed ]*     : toggle interactive mode with prompt\n  \
         quit                                    : disconnect\n\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::answer;

    /// A command line with no first word matches nothing: HAProxy's `cli_gen_usage_msg` then
    /// lists every command ("Please enter one of the following commands only"), not the nearest.
    #[test]
    fn an_empty_command_lists_the_commands_only() {
        let out = answer(&[String::new()]);
        assert!(out.starts_with("Unknown command: ''. Please enter one of the following commands only:\n"), "{out}");
        assert!(out.lines().count() > 10, "{out}");
    }
}
