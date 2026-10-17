// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The cookie names `req.cook_names` and `res.cook_names` list, found the way
//! `smp_fetch_cookie_names` (`src/http_fetch.c`) finds them with
//! `http_extract_next_cookie_name` (`src/http.c`): a request `Cookie` value is read element
//! by element (split on `,`), each `;`-separated pair gives its name; a response
//! `Set-Cookie` value gives one name, its first pair's. `$` attributes and pairs without
//! `=` are skipped, quoted values are honoured.
//!
//! [`values`] reads the cookie values `req.cook`/`res.cook` give the same way (T337).

fn is_spht(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// The end of a cookie value starting at `s` (`http_find_cookie_value_end`): the next `,`
/// or `;` outside a quoted string, or the end.
fn cookie_value_end(v: &[u8], mut s: usize) -> usize {
    let (mut quoted, mut qdpair) = (false, false);
    while s < v.len() {
        let c = v[s];
        if qdpair {
            qdpair = false;
        } else if quoted {
            if c == b'\\' {
                qdpair = true;
            } else if c == b'"' {
                quoted = false;
            }
        } else if c == b'"' {
            quoted = true;
        } else if c == b',' || c == b';' {
            return s;
        }
        s += 1;
    }
    s
}

/// The end of a header element starting at `s` (`http_find_hdr_value_end`): the next `,`
/// outside a quoted string, or the end.
fn element_end(v: &[u8], mut s: usize) -> usize {
    let (mut quoted, mut qdpair) = (false, false);
    while s < v.len() {
        let c = v[s];
        if qdpair {
            qdpair = false;
        } else if quoted {
            if c == b'\\' {
                qdpair = true;
            } else if c == b'"' {
                quoted = false;
            }
        } else if c == b'"' {
            quoted = true;
        } else if c == b',' {
            return s;
        }
        s += 1;
    }
    s
}

/// The next cookie name in `v` from `from` (`http_extract_next_cookie_name`), as its start
/// and end, and where to search from next.
fn next_name(v: &[u8], from: usize, is_req: bool) -> Option<(usize, usize, usize)> {
    let end = v.len();
    let mut att_beg = from;
    while att_beg + 1 < end {
        while att_beg < end && is_spht(v[att_beg]) {
            att_beg += 1;
        }
        let (mut equal, mut att_end) = (att_beg, att_beg);
        while equal < end {
            let c = v[equal];
            if c == b'=' || c == b';' {
                break;
            }
            equal += 1;
            if !is_spht(c) {
                att_end = equal;
            }
        }
        let next = if equal < end && v[equal] == b'=' {
            let mut val_beg = equal + 1;
            while val_beg < end && is_spht(v[val_beg]) {
                val_beg += 1;
            }
            cookie_value_end(v, val_beg)
        } else {
            equal
        };
        if v.get(att_beg) != Some(&b'$') && equal != next {
            return Some((att_beg, att_end, if is_req { next + 1 } else { end }));
        }
        att_beg = next + 1;
    }
    None
}

/// T337: the values of the cookies named `name` (every cookie when `name` is empty) in one
/// header element, in order, as `smp_fetch_cookie` finds them by calling
/// `http_extract_cookie_value` (`src/http.c`) again from where the last one ended. `list` is
/// the request direction: a `,` also ends a name, and every pair is a cookie; otherwise a
/// search looks only at its first pair that is not a `$` attribute and has a `=` (but the
/// next search starts after a value found, so `a=1; a=2` gives both). Values keep their
/// quotes, end at a `;` or `,` outside them, and are trimmed of blanks.
pub fn values<'a>(elem: &'a str, name: &str, list: bool) -> Vec<&'a str> {
    let (v, name) = (elem.as_bytes(), name.as_bytes());
    let end = v.len();
    let mut out = Vec::new();
    let mut att_beg = 0;
    while att_beg + name.len() + 1 < end {
        while att_beg < end && is_spht(v[att_beg]) {
            att_beg += 1;
        }
        let (mut equal, mut att_end) = (att_beg, att_beg);
        while equal < end {
            let c = v[equal];
            if c == b'=' || c == b';' || (list && c == b',') {
                break;
            }
            equal += 1;
            if !is_spht(c) {
                att_end = equal;
            }
        }
        let (val_beg, val_end, next) = if equal < end && v[equal] == b'=' {
            let mut val_beg = equal + 1;
            while val_beg < end && is_spht(v[val_beg]) {
                val_beg += 1;
            }
            let next = cookie_value_end(v, val_beg);
            let mut val_end = next;
            while val_end > val_beg && is_spht(v[val_end - 1]) {
                val_end -= 1;
            }
            (val_beg, val_end, next)
        } else {
            (equal, equal, equal)
        };
        if v.get(att_beg) != Some(&b'$') && equal != next {
            if name.is_empty() || v.get(att_beg..att_end) == Some(name) {
                // The bounds border ASCII delimiters or the ends: char boundaries.
                out.push(elem.get(val_beg..val_end).unwrap_or(""));
            } else if !list {
                break;
            }
        }
        att_beg = next + 1;
    }
    out
}

/// Appends the names of one `value` to `out` the way `smp_fetch_cookie_names` does: `delim`
/// goes in front of a name only when `out` is not empty, so an empty name vanishes at the
/// start and keeps its slot after that. `is_req` reads a `Cookie` value, else a
/// `Set-Cookie` one.
pub fn append(out: &mut String, value: &str, is_req: bool, delim: char) {
    let mut push = |elem: &str| {
        let v = elem.as_bytes();
        let mut from = 0;
        while let Some((beg, end, next)) = next_name(v, from, is_req) {
            if !out.is_empty() {
                out.push(delim);
            }
            // `beg` and `end` border ASCII bytes or the ends, so they are char boundaries.
            out.push_str(elem.get(beg..end).unwrap_or(""));
            from = next;
        }
    };
    if !is_req {
        push(value.trim_matches([' ', '\t']));
        return;
    }
    let v = value.as_bytes();
    let mut s = 0;
    while s < v.len() {
        let e = element_end(v, s);
        // `s` and `e` border a `,` or the ends.
        push(value.get(s..e).unwrap_or("").trim_matches([' ', '\t']));
        s = e + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(values: &[&str], is_req: bool) -> String {
        let mut out = String::new();
        for v in values {
            append(&mut out, v, is_req, ',');
        }
        out
    }

    #[test]
    fn request_names_measured() {
        // As HAProxy 3.5-dev8 lists them with req.cook_names.
        assert_eq!(names(&["$Version=1; a=1; $Path=/; b=2"], true), "a,b");
        assert_eq!(names(&["a=1, b=2"], true), "a,b");
        assert_eq!(names(&["=1; b=2; c="], true), "b,c");
        assert_eq!(names(&["a=1; =2; b=3"], true), "a,,b");
        assert_eq!(names(&["a=\"x;y\"; b=2"], true), "a,b");
        assert_eq!(names(&["a=\"1,2\", b=3"], true), "a,b");
        assert_eq!(names(&["a=1", "c=3; d"], true), "a,c");
        assert_eq!(names(&["a=1;b", "x"], true), "a");
        assert_eq!(names(&["a b=1", "é=1"], true), "a b,é");
    }

    #[test]
    fn quoted_backslash_pairs_do_not_end_quotes() {
        // As HAProxy 3.5-dev8 lists them with req.cook_names: a backslash inside a quoted
        // string escapes the next byte, in the value (`;`) and in the element (`,`) scans.
        assert_eq!(names(&["a=\"p\\\"q;r=1\"; b=2"], true), "a,b");
        assert_eq!(names(&["a=\"p\\\"q,r=1\", b=2"], true), "a,b");
        assert_eq!(names(&["a=\"p\\\"q,r=1\"; b=2"], true), "a,b");
    }

    #[test]
    fn values_measured() {
        // T337: as HAProxy 3.5-dev8 gives them with res.cook/cook (ACL rows: every value).
        assert_eq!(values("a=1; a=2", "a", false), ["1", "2"]);
        assert_eq!(values("s=1; Path=/", "", false), ["1", "/"]);
        assert_eq!(values(r#"a="x\"y;z"; b=2"#, "a", false), [r#""x\"y;z""#]);
        assert!(values(r#"a="x\"y;z"; b=2"#, "b", false).is_empty());
        assert_eq!(values("$v=1; a=4; b=5", "a", false), ["4"]);
        assert_eq!(values(r#"a="x;y"; b=2"#, "", true), [r#""x;y""#, "2"]);
        assert_eq!(values("a = 7 ; b=1", "a", true), ["7"]);
        assert_eq!(values("$a=9; a=5", "a", true), ["5"]);
    }

    #[test]
    fn response_names_measured() {
        // As HAProxy 3.5-dev8 lists them with res.cook_names.
        assert_eq!(names(&["s=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT", " u = 2", "nov", "$d=1", "w="], false), "s,u,w");
        assert_eq!(names(&["=1", "t=2", "v=\"a;b\""], false), "t,v");
        assert_eq!(names(&["$d=1; x=2", "nov; y=3"], false), "x,y");
        assert_eq!(names(&["=1", "=2"], false), "");
        assert_eq!(names(&["t=2", "=1", "v=3"], false), "t,,v");
        assert_eq!(names(&["="], false), "");
    }
}
