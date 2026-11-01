// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/stats.c and src/stats-html.c (the stats applet's dump loop).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The stats page and `show stat`, produced a buffer at a time (T572).
//!
//! `HAProxy`'s stats applet never builds the page whole: it dumps into the channel until
//! the buffer is full, yields, and resumes from what it saved in its context (`ctx->obj1`,
//! `obj2`, `px_st`) when the client has read. A [`Dump`] is that context here: a cursor of a
//! few integers over the units of the page (a row, a table head, the style sheet), kept
//! between two buffers. [`fill`] writes as many whole units as the room it is given holds,
//! framed as one HTTP chunk or raw; the room is the session's response buffer (`rep`) or the
//! CLI's output, and the unit is formatted in a scratch string of `crate::reuse` (pool
//! `scratch_str`). Memory per dump is one buffer whatever the server count, and the event
//! loop runs the other streams between two buffers.

use crate::check::ServerCheckState;
use crate::engine::Proxy;
use crate::stats::StatCursor;
use crate::stats_html::{HtmlCursor, JsonCursor};

/// What is being dumped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    /// The HTML page; `banner` the `;st=` code of an admin action's result.
    Html(HtmlCursor, Option<crate::stats_post::StCode>),
    /// `show stat` rows: the page's `;csv`, or the CLI's answer.
    Rows(StatCursor),
    /// The dashboard's `/api/data`.
    Json(JsonCursor),
    /// A fixed text sent in one unit (`;json-schema`); `true` once it is out.
    Text(&'static str, bool),
}

/// A dump in progress: the page's cursor, how it is framed, and the unit cut in two when
/// one did not fit an empty buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dump {
    page: Page,
    /// HTTP/1.1 chunks; raw bytes otherwise (HTTP/1.0, the CLI).
    chunked: bool,
    /// The cursor before a unit larger than an empty buffer, and how much of it went.
    split: Option<(Page, u32)>,
    /// No unit is left: the end (the last chunk, for HTTP/1.1) is still to be written.
    units_done: bool,
    /// The last byte is written.
    pub finished: bool,
    /// The proxy whose `stats` section serves the page (its `show-node`, `show-desc`).
    pub serving: u32,
}

/// What [`fill`] reads besides the cursor.
pub struct Ctx<'a> {
    pub proxies: &'a [Proxy],
    pub checks: &'a [ServerCheckState],
    pub pid: u32,
    /// The `stats` section of the proxy that serves the page.
    pub cfg: &'a ibex_config::StatsConfig,
    /// The text of the banner the page shows for a `;st=` code; called only when the unit
    /// that holds it is next.
    pub banner: &'a dyn Fn(crate::stats_post::StCode) -> String,
}

/// Room for `ffffffff\r\n` before a chunk and `\r\n` after it.
const CHUNK_PRE: usize = 10;
const CHUNK_POST: usize = 2;
/// Less room than this is not worth a chunk: the caller comes back when the client has read.
const MIN_ROOM: usize = 64;
const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

impl Dump {
    #[must_use]
    pub const fn new(page: Page, chunked: bool, serving: u32) -> Dump {
        Dump { page, chunked, split: None, units_done: false, finished: false, serving }
    }

    /// The dump is framed as HTTP/1.1 chunks.
    #[must_use]
    pub const fn chunked(&self) -> bool {
        self.chunked
    }
}

/// The body of `page` built whole, unframed: what the streamed page must add up to. Nothing
/// sends a page built whole since HTTP/2 streams too (T580).
#[cfg(test)]
#[must_use]
pub fn render_all(page: Page, ctx: &Ctx<'_>) -> String {
    let mut page = page;
    let mut out = String::new();
    while next_unit(&mut page, ctx, &mut out) {}
    out
}

/// Writes the next unit of `page` to `out`; `false` once there is none.
fn next_unit(page: &mut Page, ctx: &Ctx<'_>, out: &mut String) -> bool {
    match page {
        Page::Html(cur, code) => {
            let banner = code.filter(|_| cur.at_banner()).map(|c| (ctx.banner)(c));
            cur.next_unit(ctx.proxies, ctx.checks, ctx.pid, ctx.cfg, banner.as_deref(), out)
        }
        Page::Rows(cur) => cur.next_unit(ctx.proxies, ctx.checks, ctx.pid, out),
        Page::Json(cur) => cur.next_unit(ctx.proxies, ctx.checks, ctx.pid, out),
        Page::Text(text, sent) => {
            if *sent {
                return false;
            }
            *sent = true;
            out.push_str(text);
            true
        }
    }
}

/// The whole units that fit in `room`, written at its start (a cut one when even the first
/// does not fit); how many bytes. `unit` is the scratch string each is made in.
fn fill_units(d: &mut Dump, ctx: &Ctx<'_>, unit: &mut String, room: &mut [u8]) -> usize {
    let mut w = 0usize;
    loop {
        let (base, skip) = match d.split.take() {
            Some((p, off)) => (p, off as usize),
            None => (d.page, 0),
        };
        d.page = base;
        unit.clear();
        if !next_unit(&mut d.page, ctx, unit) {
            d.units_done = true;
            return w;
        }
        let data = unit.as_bytes().get(skip..).unwrap_or_default();
        if w + data.len() <= room.len() {
            room[w..w + data.len()].copy_from_slice(data);
            w += data.len();
            continue;
        }
        if w == 0 {
            // Larger than the whole room: the part that fits now, the rest next time.
            let n = room.len();
            room.copy_from_slice(&data[..n]);
            d.split = Some((base, u32::try_from(skip + n).unwrap_or(u32::MAX)));
            return n;
        }
        // For the next buffer, from where it started. (Never the rest of a cut unit: that
        // comes first, into an empty room.)
        d.page = base;
        return w;
    }
}

/// Fills `dst` with the next part of the dump -- whole units, as many as fit, as one chunk
/// when the dump is chunked, followed by the last chunk once the units are over and it
/// fits -- and returns how many bytes it wrote. 0 when `dst` is too small to be worth it or
/// the dump is finished.
///
/// A unit that does not fit an empty `dst` is cut: what fits goes, and the next call makes
/// the unit again from the cursor it started at and sends the rest. Only the fixed parts of
/// the page (the style sheet, the script, ~8 kB) come near a default buffer.
pub fn fill(d: &mut Dump, ctx: &Ctx<'_>, dst: &mut [u8]) -> usize {
    if d.finished || dst.len() < MIN_ROOM {
        return 0;
    }
    let (pre, post) = if d.chunked { (CHUNK_PRE, CHUNK_POST) } else { (0, 0) };
    let room = dst.len() - pre - post;
    let w = if d.units_done { 0 } else { crate::reuse::with_string(|unit| fill_units(d, ctx, unit, &mut dst[pre..pre + room])) };
    let mut n = 0;
    if w > 0 {
        if d.chunked {
            use std::io::Write as _;
            let mut head = [0u8; CHUNK_PRE];
            let mut cur = &mut head[..];
            let _ = write!(cur, "{w:x}\r\n");
            let hl = CHUNK_PRE - cur.len();
            dst.copy_within(pre..pre + w, hl);
            dst[..hl].copy_from_slice(&head[..hl]);
            dst[hl + w..hl + w + 2].copy_from_slice(b"\r\n");
            n = hl + w + 2;
        } else {
            n = w;
        }
    }
    if d.units_done {
        if !d.chunked {
            d.finished = true;
        } else if dst.len() - n >= LAST_CHUNK.len() {
            dst[n..n + LAST_CHUNK.len()].copy_from_slice(LAST_CHUNK);
            n += LAST_CHUNK.len();
            d.finished = true;
        }
    }
    n
}

/// The whole of a dump at once, as [`fill`] would send it into buffers of `size` bytes, the
/// chunk framing taken off: for the tests, which compare it with the one-shot renderers.
#[cfg(test)]
fn stream_all(mut d: Dump, ctx: &Ctx<'_>, size: usize) -> (Vec<u8>, usize) {
    let mut buf = vec![0u8; size];
    let (mut out, mut calls) = (Vec::new(), 0);
    while !d.finished {
        let n = fill(&mut d, ctx, &mut buf);
        calls += 1;
        assert!(n > 0 && calls < 10_000_000, "no progress");
        out.extend_from_slice(&buf[..n]);
    }
    (out, calls)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frontend and `nb` backends of `per` servers, as the engine builds them.
    fn proxies(nb: usize, per: usize) -> crate::engine::Proxies {
        let mut c = String::from("defaults\n    mode http\nfrontend fe\n    bind 127.0.0.1:8080\n    stats enable\n    stats uri /s\n");
        // Two stick tables: one with entries enough for several units, one empty.
        c.push_str("backend t1\n    stick-table type integer size 100 store http_req_cnt\nbackend t2\n    stick-table type ip size 10\n");
        for b in 0..nb {
            c.push_str(&format!("backend b{b}\n"));
            for s in 0..per {
                c.push_str(&format!("    server s{s} 127.0.0.{}:{}\n", 1 + s % 250, 1000 + b));
            }
        }
        let config = ibex_config::parse_str(&c).expect("config");
        let proxies = crate::engine::Engine::build_shared_state(&config).expect("proxies");
        let t1 = proxies.iter().find_map(|p| p.stick_table.as_ref().filter(|_| p.name == "t1")).expect("t1");
        for k in 0..40 {
            t1.update_entry(&ibex_stick_table::entry::StickKey::Integer(k), |d| d.http_req_cnt = k as u64 * 3).expect("entry");
        }
        proxies
    }

    fn dechunk(mut b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let eol = b.windows(2).position(|w| w == b"\r\n").expect("size line");
            let n = usize::from_str_radix(std::str::from_utf8(&b[..eol]).expect("hex"), 16).expect("size");
            if n == 0 {
                assert_eq!(&b[eol..], b"\r\n\r\n", "nothing after the last chunk");
                return out;
            }
            out.extend_from_slice(&b[eol + 2..eol + 2 + n]);
            assert_eq!(&b[eol + 2 + n..eol + 4 + n], b"\r\n");
            b = &b[eol + 4 + n..];
        }
    }

    /// Every page, streamed into buffers from far too small to larger than the page, chunked
    /// or not, is the page the one-shot renderer makes.
    #[test]
    fn a_streamed_page_is_the_one_shot_page_at_any_buffer_size() {
        let proxies = proxies(12, 37);
        let checks: Vec<ServerCheckState> = Vec::new();
        let cfg = ibex_config::StatsConfig::default();
        let banner = |c: crate::stats_post::StCode| c.banner("/s");
        let ctx = Ctx { proxies: &proxies, checks: &checks, pid: 7, cfg: &cfg, banner: &banner };
        let done = crate::stats_post::StCode::Done;
        type Make<'a> = Box<dyn Fn() -> (Page, String) + 'a>;
        let pages: [Make<'_>; 5] = [
            Box::new(|| (Page::Html(HtmlCursor::new(), None), crate::stats_html::render_stats_html_for(&proxies, &checks, 7, &cfg))),
            Box::new(|| {
                let html = crate::stats_html::render_stats_html_for(&proxies, &checks, 7, &cfg);
                (Page::Html(HtmlCursor::new(), Some(done)), crate::stats_post::with_banner(html, &done.banner("/s")))
            }),
            Box::new(|| (Page::Rows(StatCursor::csv()), crate::stats::format_show_stat(&proxies, &checks, 7))),
            Box::new(|| {
                let json = crate::stats::format_show_stat_as(&proxies, &checks, 7, None, None, None, crate::stats::StatFormat::Json);
                (Page::Rows(StatCursor::new(crate::stats::StatFormat::Json, None, None, None)), json)
            }),
            Box::new(|| (Page::Json(JsonCursor::new()), crate::stats_html::render_stats_json(&proxies, &checks, 7))),
        ];
        let (_, html) = pages[0]();
        let (_, csv) = pages[2]();
        assert!(html.len() > 100_000 && csv.len() > 20_000, "the pages need many buffers");
        assert!(html.contains("Table has no stored entries.") && html.matches("<td class=\"mono\">117</td>").count() == 1, "both tables shown");
        for make in &pages {
            let big = make().1.len() > 1 << 20;
            // A page of MBs (the JSON rows) in 64-byte buffers would take seconds.
            for size in [MIN_ROOM, 100, 1000, 4096, 16384, 1 << 24].into_iter().filter(|&n| !big || n >= 4096) {
                for chunked in [true, false] {
                    // `lastchg` counts seconds: a page that took one to stream is made again.
                    let attempt = || {
                        let (page, want) = make();
                        let (got, calls) = stream_all(Dump::new(page, chunked, 0), &ctx, size);
                        (if chunked { dechunk(&got) } else { got }, want, calls, page)
                    };
                    let mut r = attempt();
                    for _ in 0..2 {
                        if r.0 != r.1.as_bytes() { r = attempt(); }
                    }
                    let (got, want, calls, page) = r;
                    let at = got.iter().zip(want.as_bytes()).position(|(a, b)| a != b).unwrap_or(got.len().min(want.len()));
                    assert!(got == want.as_bytes(), "{page:?} in buffers of {size}, chunked {chunked}: {} bytes, want {}; from {at}: {:?}", got.len(), want.len(), &want[at.saturating_sub(80)..(at + 40).min(want.len())]);
                    assert!(size > 16384 || calls >= want.len() / size, "{calls} buffers of {size} for {} bytes", want.len());
                }
            }
        }
    }

    /// A dump that is over, or a room too small for a chunk, gets nothing written.
    #[test]
    fn nothing_is_written_when_over_or_without_room() {
        let proxies = proxies(1, 2);
        let banner = |c: crate::stats_post::StCode| c.banner("/s");
        let cfg = ibex_config::StatsConfig::default();
        let ctx = Ctx { proxies: &proxies, checks: &[], pid: 1, cfg: &cfg, banner: &banner };
        let mut d = Dump::new(Page::Rows(StatCursor::csv()), true, 0);
        assert_eq!(fill(&mut d, &ctx, &mut [0u8; MIN_ROOM - 1]), 0);
        let mut buf = vec![0u8; 1 << 16];
        let n = fill(&mut d, &ctx, &mut buf);
        assert!(d.finished && buf[..n].ends_with(LAST_CHUNK), "one fill holds it all");
        assert_eq!(fill(&mut d, &ctx, &mut buf), 0);
    }

    /// `show stat <iid> 4 <sid>`: the one server row asked for, as the one-shot answer has it.
    #[test]
    fn a_server_filter_keeps_one_row() {
        let proxies = proxies(2, 5);
        let b1 = proxies.iter().find(|p| p.name == "b1").expect("b1");
        let iid = i32::try_from(b1.ids.iid).expect("iid");
        let one = crate::stats::format_show_stat_as(&proxies, &[], 1, Some(iid), Some(4), Some(3), crate::stats::StatFormat::Csv);
        let rows: Vec<&str> = one.lines().skip(1).collect();
        assert_eq!(rows.len(), 1, "{one}");
        assert!(rows[0].starts_with("b1,s2,"), "{one}");
    }

    /// The JSON rows are `[...]` with commas between them, however the buffers fall.
    #[test]
    fn json_rows_with_none_are_an_empty_array() {
        let proxies = proxies(0, 0);
        // Only server rows asked for, and there are none.
        let mut cur = StatCursor::new(crate::stats::StatFormat::Json, None, Some(4), None);
        let mut out = String::new();
        while cur.next_unit(&proxies, &[], 1, &mut out) {}
        assert_eq!(out, "[]\n");
    }
}
