// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! What a log sender controls on a `log-forward` section (T242): a TCP stream split into
//! messages by RFC 6587 framing (octet counting or LF), each message parsed as RFC 5424 /
//! 3164 and its header rebuilt in every output format, as forwarding does. The first byte
//! picks `assume-rfc6587-ntf`; the rest is the stream.
#![no_main]
use ibex_config::RingFormat;
use ibex_rt::{logfwd, loghdr};
use libfuzzer_sys::fuzz_target;

const FORMATS: [RingFormat; 8] = [
    RingFormat::Raw,
    RingFormat::Iso,
    RingFormat::Local,
    RingFormat::Rfc3164,
    RingFormat::Rfc5424,
    RingFormat::Short,
    RingFormat::Priority,
    RingFormat::Timed,
];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, stream)) = data.split_first() else { return };
    let mut r = std::io::Cursor::new(stream);
    let mut buf = Vec::new();
    let mut out = Vec::new();
    while logfwd::read_frame(&mut r, sel & 1 != 0, 16384, &mut buf) {
        let p = loghdr::parse(&buf);
        let fac = u8::try_from(p.facility).unwrap_or(1);
        let lvl = u8::try_from(p.level.max(0)).unwrap_or(0);
        for f in FORMATS {
            out.clear();
            loghdr::build_header(&mut out, Some(f), fac, lvl, &p.meta);
        }
        out.clear();
        loghdr::build_header(&mut out, None, fac, lvl, &p.meta);
    }
});
