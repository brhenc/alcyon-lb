// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The stats page's admin POST, as `stats_process_http_post` and `stats_send_http_redirect`
//! (src/stats-html.c) and `stats_check_same_origin` (src/http_ana.c) have it: the form body
//! (`b=<backend>&s=<server>&s=...&action=<verb>`) is read from its end, the servers are
//! altered, and the answer is a `303` to `<uri>;st=<CODE>` whose GET shows a banner for the code.

/// The result of an admin POST (`enum stat_status`), named by the four letters of `;st=`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StCode {
    Deny,
    Done,
    Errp,
    Excd,
    None,
    Part,
    Unkn,
    Ival,
}

impl StCode {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            StCode::Deny => "DENY",
            StCode::Done => "DONE",
            StCode::Errp => "ERRP",
            StCode::Excd => "EXCD",
            StCode::None => "NONE",
            StCode::Part => "PART",
            StCode::Unkn => "UNKN",
            StCode::Ival => "IVAL",
        }
    }

    /// The code a GET asks to show: the four bytes after `;st=` anywhere in the URI past the
    /// stats prefix. `None` when the URI has no such room (`http_handle_stats` needs four
    /// bytes after `st=`), `Unkn` for four bytes that name nothing.
    #[must_use]
    pub fn from_uri(rest: &str) -> Option<StCode> {
        let at = rest.find(";st=")?;
        let word = rest.as_bytes().get(at + 4..at + 8)?;
        Some(
            [StCode::Deny, StCode::Done, StCode::Errp, StCode::Excd, StCode::None, StCode::Part, StCode::Ival]
                .into_iter()
                .find(|c| c.name().as_bytes() == word)
                .unwrap_or(StCode::Unkn),
        )
    }

    /// The banner the page shows for the code (`stats_dump_html_info`); `href` removes it.
    #[must_use]
    pub fn banner(self, href: &str) -> String {
        let (class, text) = match self {
            StCode::Done => ("active_up", "Action processed successfully."),
            StCode::None => ("active_going_down", "Nothing has changed."),
            StCode::Part => (
                "active_going_down",
                "Action partially processed.<br>Some server names are probably unknown or ambiguous (duplicated names in the backend).",
            ),
            StCode::Errp => (
                "active_down",
                "Action not processed because of invalid parameters.<ul><li>The action is maybe unknown.</li>\
                 <li>Invalid key parameter (empty or too long).</li>\
                 <li>The backend name is probably unknown or ambiguous (duplicated names).</li>\
                 <li>Some server names are probably unknown or ambiguous (duplicated names in the backend).</li></ul>",
            ),
            StCode::Excd => (
                "active_down",
                "<b>Action not processed : the buffer couldn't store all the data.<br>You should retry with less servers at a time.</b>",
            ),
            StCode::Deny => ("active_down", "<b>Action denied.</b>"),
            StCode::Ival => ("active_down", "<b>Invalid requests (unsupported method or chunked encoded request).</b>"),
            StCode::Unkn => ("active_no_check", "Unexpected result."),
        };
        format!(
            "<style>.active_down{{background:#ff9090}}.active_going_down{{background:#ffffa0}}.active_up{{background:#c0ffc0}}\
             .active_no_check{{background:#e0e0e0}}</style>\
             <p><div class={class}><a class=lfsb href=\"{href}\" title=\"Remove this message\">[X]</a> {text}</div>\n"
        )
    }
}

/// What an admin verb does to one server. The verbs HAProxy knows that Alcyon has no state for
/// (`hnolb`, `dagent`, `eagent`, `arunn`, `adown`, `shutdown`) are refused as invalid
/// (`ERRP`) rather than accepted and dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Ready,
    Drain,
    Maint,
    Disable,
    Enable,
    Stop,
    Start,
    Dhlth,
    Ehlth,
    Hrunn,
    Hdown,
}

fn verb(name: &str) -> Result<Verb, ()> {
    Ok(match name {
        "ready" => Verb::Ready,
        "drain" => Verb::Drain,
        "maint" => Verb::Maint,
        "disable" => Verb::Disable,
        "enable" => Verb::Enable,
        "stop" => Verb::Stop,
        "start" => Verb::Start,
        "dhlth" => Verb::Dhlth,
        "ehlth" => Verb::Ehlth,
        "hrunn" => Verb::Hrunn,
        "hdown" => Verb::Hdown,
        _ => return Err(()),
    })
}

/// `url_decode(s, 1)`: `+` is a space, `%XX` a byte; a `%` without two hex digits fails.
fn url_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let h = b.get(i + 1..i + 3)?;
                let v = u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?;
                if !h.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                out.push(v);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// Longest `key=value` segment: `LINESIZE` (2048) counts the `&` that ends it.
const MAX_SEGMENT: usize = 2047;

/// Walks the POST body from its end as `stats_process_http_post` does (only the last value
/// of `b` and `action` counts; a `s` met before both are known waits for them) and calls
/// `apply(backend, verb, server)` for each server name: `None` for a name that is not a
/// server of the backend, `Some(altered)` otherwise (only an altered server counts as one). `backend` maps a `b` value to a backend.
pub fn process_post(
    body: &str,
    backend: &mut dyn FnMut(&str) -> Option<usize>,
    apply: &mut dyn FnMut(usize, Verb, &str) -> Option<bool>,
) -> StCode {
    let segs: Vec<&str> = if body.is_empty() { Vec::new() } else { body.split('&').collect() };
    let mut px: Option<usize> = None;
    let mut act: Option<Verb> = None;
    let (mut total, mut altered) = (0usize, 0usize);
    let mut deferred: Option<usize> = None;
    let mut i = segs.len();
    while i > 0 {
        i -= 1;
        let seg = segs[i];
        if seg.len() > MAX_SEGMENT {
            return StCode::Errp;
        }
        let (k, v) = seg.split_once('=').unwrap_or((seg, ""));
        let (Some(k), Some(v)) = (url_decode(k), url_decode(v)) else { break };
        if px.is_none() && k == "b" {
            match backend(&v) {
                Some(p) => px = Some(p),
                None => return StCode::Errp,
            }
        } else if act.is_none() && k == "action" {
            match verb(&v) {
                Ok(a) => act = Some(a),
                Err(()) => return StCode::Errp,
            }
        } else if k == "s" {
            match (px, act) {
                (Some(p), Some(a)) => match apply(p, a, &v) {
                    // A server name that is not one counts in `total` only.
                    None => total += 1,
                    Some(true) => {
                        total += 1;
                        altered += 1;
                    }
                    // A server the verb leaves as it is counts for nothing.
                    Some(false) => {}
                },
                _ => {
                    if deferred.is_none() {
                        deferred = Some(i);
                    }
                }
            }
        }
        if let (Some(d), Some(_), Some(_)) = (deferred, px, act) {
            deferred = None;
            i = d + 1;
        }
    }
    if total == 0 {
        StCode::None
    } else if altered == 0 {
        StCode::Errp
    } else if altered == total {
        StCode::Done
    } else {
        StCode::Part
    }
}

/// `stats_check_same_origin`: the `Origin` (else `Referer`) of a browser must name the `Host`
/// the request was sent to; a request with neither header is not from a browser.
#[must_use]
pub fn same_origin(headers: &[(&str, &str)]) -> bool {
    let find = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim());
    let Some(source) = find("origin").or_else(|| find("referer")) else { return true };
    // A URL or a bare authority; a path names none.
    let after = source.split_once("://").map_or(source, |(_, a)| a);
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty() && find("host").is_some_and(|h| h.eq_ignore_ascii_case(authority))
}

/// Whether the request, with `body_len` bytes of body and its `nhdr` header lines in
/// `head_len` bytes, fits the buffer the way HAProxy's does (measured: the body of a POST
/// must fit in `tune.bufsize` with the headers; `EXCD` otherwise).
#[must_use]
pub fn fits_buffer(bufsize: usize, head_len: usize, nhdr: usize, body_len: usize) -> bool {
    head_len + 4 * nhdr + body_len + 64 <= bufsize
}

/// Puts the banner at the top of the page.
#[must_use]
pub fn with_banner(html: String, banner: &str) -> String {
    const MARK: &str = "<div class=\"container\">\n";
    match html.find(MARK) {
        Some(at) => {
            let at = at + MARK.len();
            let mut out = String::with_capacity(html.len() + banner.len());
            out.push_str(&html[..at]);
            out.push_str(banner);
            out.push_str(&html[at..]);
            out
        }
        None => html,
    }
}

/// Whether the body names anything only Alcyon's own admin API knows (`backend`, `server`, the
/// `weight` and `maxconn` verbs' values): such a POST is the dashboard's, not HAProxy's form.
#[must_use]
pub fn uses_alcyon_keys(body: &str) -> bool {
    body.split('&').any(|seg| {
        let k = seg.split_once('=').map_or(seg, |(k, _)| k);
        matches!(k, "backend" | "server" | "px" | "proxy" | "sv" | "srv" | "weight" | "w" | "maxconn" | "mc" | "state" | "status" | "act")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_names_round_trip_through_the_uri() {
        for c in [StCode::Deny, StCode::Done, StCode::Errp, StCode::Excd, StCode::None, StCode::Part, StCode::Ival] {
            assert_eq!(StCode::from_uri(&format!(";st={}", c.name())), Some(c));
        }
        assert_eq!(StCode::Unkn.name(), "UNKN");
        assert_eq!(StCode::from_uri(";st=UNKN"), Some(StCode::Unkn));
        assert_eq!(StCode::from_uri(";st=XXXX"), Some(StCode::Unkn));
        assert_eq!(StCode::from_uri(";st=DO"), None);
    }

    #[test]
    fn a_page_without_the_container_is_left_as_it_is() {
        assert_eq!(with_banner("<html></html>".to_string(), "<p>b"), "<html></html>");
        assert_eq!(with_banner("<div class=\"container\">\nx".to_string(), "<p>b"), "<div class=\"container\">\n<p>bx");
    }
}
