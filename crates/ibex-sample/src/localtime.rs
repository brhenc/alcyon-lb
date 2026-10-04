// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Local civil time without `unsafe`: the UTC offset in force at an instant, read from
//! the system's TZif zone file, and the calendar fields log lines print.
//!
//! `HAProxy` prints local time (`localtime_r`, after `tzset()` at startup) in syslog
//! headers and in `%t`, `%tr`, `%Tl` and `%trl`. libc's `localtime_r` would need
//! `unsafe` here, so the zone file (`$TZ` if it names a file, else `/etc/localtime`) is
//! parsed once instead. Its explicit transitions cover every instant this proxy will log
//! (the tz database writes them out to 2037); past the last one the last offset holds.
//! No zone file means UTC.

use std::sync::OnceLock;

/// The offsets of one zone: `(transition time, offset in seconds east of UTC)` in time
/// order, and the offset before the first transition.
#[derive(Debug, Default)]
pub struct Zone {
    transitions: Vec<(i64, i32)>,
    initial: i32,
    /// The abbreviation of each transition's type (`CEST`), and of the initial one.
    abbrs: Vec<String>,
    initial_abbr: String,
}

impl Zone {
    /// The UTC offset, in seconds east, in force at `unix` seconds.
    #[must_use]
    pub fn offset_at(&self, unix: i64) -> i32 {
        match self.transitions.partition_point(|&(t, _)| t <= unix) {
            0 => self.initial,
            n => self.transitions[n - 1].1,
        }
    }

    /// The zone's abbreviation (`CEST`) at `unix` seconds; `UTC` for no zone file.
    #[must_use]
    pub fn abbr_at(&self, unix: i64) -> &str {
        let abbr = match self.transitions.partition_point(|&(t, _)| t <= unix) {
            0 => &self.initial_abbr,
            n => &self.abbrs[n - 1],
        };
        if abbr.is_empty() { "UTC" } else { abbr }
    }

    /// Parses a TZif file (RFC 8536), version 1 or later. Uses the 64-bit section when
    /// there is one.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Zone> {
        let header = |at: usize| -> Option<[usize; 6]> {
            if data.get(at..at + 4)? != b"TZif" {
                return None;
            }
            let mut c = [0usize; 6];
            for (i, v) in c.iter_mut().enumerate() {
                let o = at + 20 + i * 4;
                *v = u32::from_be_bytes(data.get(o..o + 4)?.try_into().ok()?) as usize;
            }
            Some(c)
        };
        // isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt
        let [isut, isstd, leap, time, typ, chars] = header(0)?;
        let v1_len = time * 5 + typ * 6 + chars + leap * 8 + isstd + isut;
        let (at, width) = if data.get(4).copied().unwrap_or(0) >= b'2' {
            (44 + v1_len, 8)
        } else {
            (0, 4)
        };
        let [_, _, _, time, typ, nchars] = header(at)?;
        let mut o = at + 44;
        let mut times = Vec::with_capacity(time);
        for _ in 0..time {
            let b = data.get(o..o + width)?;
            times.push(if width == 8 {
                i64::from_be_bytes(b.try_into().ok()?)
            } else {
                i64::from(i32::from_be_bytes(b.try_into().ok()?))
            });
            o += width;
        }
        let idx = data.get(o..o + time)?.to_vec();
        o += time;
        let mut offsets = Vec::with_capacity(typ);
        let mut abbr_idx = Vec::with_capacity(typ);
        for _ in 0..typ {
            offsets.push(i32::from_be_bytes(data.get(o..o + 4)?.try_into().ok()?));
            abbr_idx.push(usize::from(*data.get(o + 5)?));
            o += 6;
        }
        let chars = data.get(o..o + nchars)?;
        let abbr_of = |t: usize| -> String {
            let from = abbr_idx.get(t).copied().unwrap_or(0).min(chars.len());
            let end = chars[from..].iter().position(|&c| c == 0).map_or(chars.len(), |e| from + e);
            String::from_utf8_lossy(&chars[from..end]).into_owned()
        };
        let abbrs = idx.iter().map(|&i| abbr_of(usize::from(i))).collect();
        let transitions = times
            .into_iter()
            .zip(idx)
            .map(|(t, i)| Some((t, *offsets.get(usize::from(i))?)))
            .collect::<Option<Vec<_>>>()?;
        Some(Zone { transitions, initial: offsets.first().copied().unwrap_or(0), abbrs, initial_abbr: abbr_of(0) })
    }
}

/// The process's zone, loaded on first use.
pub fn zone() -> &'static Zone {
    static ZONE: OnceLock<Zone> = OnceLock::new();
    ZONE.get_or_init(|| {
        let path = std::env::var("TZ")
            .ok()
            .and_then(|tz| tz.strip_prefix(':').map(str::to_string).or(Some(tz)))
            .map(|tz| if tz.starts_with('/') { tz } else { format!("/usr/share/zoneinfo/{tz}") })
            .unwrap_or_else(|| "/etc/localtime".to_string());
        std::fs::read(path).ok().and_then(|d| Zone::parse(&d)).unwrap_or_default()
    })
}

/// Calendar fields of an instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    /// 1-12.
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    /// The UTC offset these fields are in, seconds east.
    pub offset: i32,
}

pub const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

impl Civil {
    /// The fields of `unix` seconds shifted by `offset`.
    #[must_use]
    pub fn at(unix: i64, offset: i32) -> Civil {
        let t = unix + i64::from(offset);
        let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
        // Civil-from-days (Howard Hinnant), on a March-based year.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        let field = |v: i64| u32::try_from(v).unwrap_or(0);
        Civil {
            year,
            month: field(month),
            day: field(day),
            hour: field(secs / 3600),
            minute: field(secs % 3600 / 60),
            second: field(secs % 60),
            offset,
        }
    }

    /// Local time at `unix` seconds.
    #[must_use]
    pub fn local(unix: i64) -> Civil {
        Civil::at(unix, zone().offset_at(unix))
    }

    /// The month's three-letter name.
    #[must_use]
    pub fn month_name(&self) -> &'static str {
        MONTHS[(self.month as usize).saturating_sub(1).min(11)]
    }

    /// `+0200`, as `strftime("%z")` writes the offset.
    #[must_use]
    pub fn offset_hhmm(&self) -> String {
        let sign = if self.offset < 0 { '-' } else { '+' };
        let m = self.offset.unsigned_abs() / 60;
        format!("{sign}{:02}{:02}", m / 60, m % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zone_file_gives_the_offset_in_force() {
        let Ok(data) = std::fs::read("/usr/share/zoneinfo/Europe/Zagreb") else { return };
        let z = Zone::parse(&data).expect("TZif");
        // 2026-10-03 14:48:18 UTC is summer time (+2h); 2026-01-15 12:00 UTC is not.
        assert_eq!(z.offset_at(1_791_038_898), 7200);
        assert_eq!(z.offset_at(1_768_478_400), 3600);
        // Across the change: 2026-10-25 01:00 UTC is when CEST ends.
        assert_eq!(z.offset_at(1_792_890_000 - 1), 7200);
        assert_eq!(z.offset_at(1_792_890_000), 3600);
        let utc = std::fs::read("/usr/share/zoneinfo/UTC").ok().and_then(|d| Zone::parse(&d)).expect("UTC");
        assert_eq!(utc.offset_at(1_791_038_898), 0);
    }

    /// A version-1 file (no 64-bit section): 32-bit transition times.
    #[test]
    fn a_version_1_zone_file() {
        let mut d = b"TZif\0".to_vec();
        d.extend_from_slice(&[0; 15]);
        for n in [0u32, 0, 0, 1, 2, 4] {
            d.extend_from_slice(&n.to_be_bytes());
        }
        d.extend_from_slice(&1000i32.to_be_bytes());
        d.push(1);
        for off in [0i32, 3600] {
            d.extend_from_slice(&off.to_be_bytes());
            d.extend_from_slice(&[0, 0]);
        }
        d.extend_from_slice(b"UTC\0");
        let z = Zone::parse(&d).expect("v1 TZif");
        assert_eq!(z.offset_at(2000), 3600);
    }

    #[test]
    fn calendar_fields() {
        // HAProxy printed `03/Oct/2026:16:48:18 +0200` for this instant.
        let c = Civil::at(1_791_038_898, 7200);
        assert_eq!((c.year, c.month, c.day, c.hour, c.minute, c.second), (2026, 10, 3, 16, 48, 18));
        assert_eq!((c.month_name(), c.offset_hhmm()), ("Oct", "+0200".to_string()));
        assert_eq!(Civil::at(0, -9000).offset_hhmm(), "-0230");
        assert_eq!(Civil::at(951_782_400, 0).day, 29, "2000-02-29");
        assert!(Zone::parse(b"not a zone").is_none());
        assert_eq!(Zone::default().offset_at(5), 0);
    }
}
