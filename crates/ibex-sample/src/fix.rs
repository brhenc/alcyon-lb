// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/fix.c, include/haproxy/fix.h and fix-t.h.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The Financial Information eXchange (FIX) protocol: message validation and tag
//! lookup, for the `fix_is_valid` and `fix_tag_value` converters.

/// The field delimiter, SOH.
pub const DELIMITER: u8 = 0x01;
/// The shortest message that can be complete.
const MSG_MINSIZE: usize = 26;

pub const TAG_BEGIN_STRING: u32 = 8;
pub const TAG_BODY_LENGTH: u32 = 9;
pub const TAG_CHECKSUM: u32 = 10;
pub const TAG_MSG_TYPE: u32 = 35;
pub const TAG_SENDER_COMP_ID: u32 = 49;
pub const TAG_TARGET_COMP_ID: u32 = 56;

/// The outcome of [`validate_message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    Invalid,
    NeedMoreData,
    Valid,
}

/// The outcome of [`tag_value`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagValue<'a> {
    Found(&'a [u8]),
    /// The message ends before the tag, or before its value's delimiter.
    NeedMoreData,
    /// Not in the message, or the message is malformed before it.
    NotFound,
}

/// `read_uint`: the leading decimal digits, and how many bytes they took.
fn read_uint(s: &[u8]) -> (u32, usize) {
    let mut n: u32 = 0;
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        n = n.wrapping_mul(10).wrapping_add(u32::from(s[i] - b'0'));
        i += 1;
    }
    (n, i)
}

/// The versions `fix_version` knows, with the highest tag id each defines
/// (`fix_check_id`; 5.0 SP1 and SP2 share 5.0's version string, so its widest range).
fn version_max_tag(s: &[u8]) -> Option<u32> {
    [(b"FIX.4.0" as &[u8], 140), (b"FIX.4.1", 211), (b"FIX.4.2", 446), (b"FIX.4.3", 659), (b"FIX.4.4", 956), (b"FIXT.1.1", 1621)]
        .into_iter()
        .find(|(v, _)| *v == s)
        .map(|(_, max)| max)
}

/// `fix_check_id`: a tag id, all digits and not 0, at most `max` if a version gave one
/// (10000-19999 are user-defined and always allowed); 0 if not valid.
fn check_id(tag: &[u8], max: Option<u32>) -> u32 {
    let (id, used) = read_uint(tag);
    if used != tag.len() || id == 0 {
        return 0;
    }
    match max {
        Some(max) if id > max && !(10000..=19999).contains(&id) => 0,
        _ => id,
    }
}

/// `fix_tagid`: a tag given by number or by one of the names `HAProxy` knows.
#[must_use]
pub fn tag_id(tag: &str) -> Option<u32> {
    let id = check_id(tag.as_bytes(), None);
    if id != 0 {
        return Some(id);
    }
    [
        ("MsgType", TAG_MSG_TYPE),
        ("CheckSum", TAG_CHECKSUM),
        ("BodyLength", TAG_BODY_LENGTH),
        ("TargetCompID", TAG_TARGET_COMP_ID),
        ("BeginString", TAG_BEGIN_STRING),
        ("SenderCompID", TAG_SENDER_COMP_ID),
    ]
    .into_iter()
    .find(|(name, _)| name.eq_ignore_ascii_case(tag))
    .map(|(_, id)| id)
}

/// One `<tag>=<value><SOH>` at the start of a message.
enum Field<'a> {
    /// Its delimiter has not arrived.
    Incomplete,
    /// The tag or the value is empty.
    Empty,
    Complete(&'a [u8], &'a [u8]),
}

fn next_field(parser: &[u8]) -> Field<'_> {
    // `iststop(istfind(parser, '='), DELIMITER)`: from the first '=' up to the next SOH.
    let eq = parser.iter().position(|&b| b == b'=').unwrap_or(parser.len());
    let rest = &parser[eq..];
    match rest.iter().position(|&b| b == DELIMITER) {
        None => Field::Incomplete,
        Some(stop) if eq == 0 || stop == 0 => Field::Empty,
        Some(stop) => Field::Complete(&parser[..eq], &rest[1..stop]),
    }
}

/// `fix_validate_message`: the first three tags are `BeginString` (a known version),
/// `BodyLength` (matching the body) and `MsgType`; every tag is numeric and in range; the
/// last is `CheckSum`, three digits, matching the sum of the bytes before it.
#[must_use]
pub fn validate_message(msg: &[u8]) -> Validity {
    if msg.len() < MSG_MINSIZE {
        return Validity::NeedMoreData;
    }
    let mut parser = msg;
    let mut version_seen: Option<u32> = None;
    let mut checksum: u8 = 0;
    let mut tagnum = 0;
    let mut bodylen: usize = 0;
    let mut body_start: Option<usize> = None;
    while !parser.is_empty() {
        let (tag, value) = match next_field(parser) {
            Field::Incomplete => return Validity::NeedMoreData,
            Field::Empty => return Validity::Invalid,
            Field::Complete(t, v) => (t, v),
        };
        let tagid = check_id(tag, version_seen);
        if tagid == 0 {
            return Validity::Invalid;
        }
        tagnum += 1;
        let at = msg.len() - parser.len();
        if tagnum == 1 {
            if tagid != TAG_BEGIN_STRING {
                return Validity::Invalid;
            }
            version_seen = version_max_tag(value);
            if version_seen.is_none() {
                return Validity::Invalid;
            }
        } else if tagnum == 2 {
            if tagid != TAG_BODY_LENGTH {
                return Validity::Invalid;
            }
            let (n, used) = read_uint(value);
            if used != value.len() || n == 0 {
                return Validity::Invalid;
            }
            bodylen = n as usize;
            body_start = Some(at + tag.len() + 1 + value.len() + 1);
        } else if tagnum == 3 {
            if tagid != TAG_MSG_TYPE {
                return Validity::Invalid;
            }
        } else if tagid == TAG_CHECKSUM {
            if Some(at) != body_start.map(|b| b + bodylen) {
                return Validity::Invalid;
            }
            let (sum, used) = read_uint(value);
            if value.len() != 3 || used != 3 || u32::from(checksum) != sum {
                return Validity::Invalid;
            }
            return Validity::Valid;
        }
        for &b in tag.iter().chain(b"=").chain(value).chain(&[DELIMITER]) {
            checksum = checksum.wrapping_add(b);
        }
        parser = &parser[tag.len() + value.len() + 2..];
    }
    // Every field so far was complete and none was CheckSum. (`HAProxy` answers "invalid"
    // if BodyLength was not reached either, but a message long enough to get here always
    // has: its first field is at most `8=FIXT.1.1<SOH>`, 11 bytes.)
    Validity::NeedMoreData
}

/// `fix_tag_value`: the value of tag `id`, scanning up to `CheckSum`.
#[must_use]
pub fn tag_value(msg: &[u8], id: u32) -> TagValue<'_> {
    let mut parser = msg;
    while !parser.is_empty() {
        let (tag, value) = match next_field(parser) {
            Field::Incomplete => return TagValue::NeedMoreData,
            Field::Empty => return TagValue::NotFound,
            Field::Complete(t, v) => (t, v),
        };
        let tagid = check_id(tag, None);
        if tagid == 0 {
            return TagValue::NotFound;
        }
        if tagid == id {
            return TagValue::Found(value);
        }
        if tagid == TAG_CHECKSUM {
            return TagValue::NotFound;
        }
        parser = &parser[tag.len() + value.len() + 2..];
    }
    TagValue::NeedMoreData
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `|` for SOH, as the reg-test's comments write the messages.
    fn msg(s: &str) -> Vec<u8> {
        s.bytes().map(|b| if b == b'|' { DELIMITER } else { b }).collect()
    }

    // converter/fix.vtc, which the reference HAProxy passes.
    const LOGON_44: &str = "8=FIX.4.4|9=102|35=A|49=CLIENT1|56=EXECUTOR|34=1|52=20201029-13:02:44.528|98=0|108=30|141=Y|553=Username|554=Password|10=252|";
    const LOGON_50: &str = "8=FIXT.1.1|9=116|35=A|49=CLIENT1|56=EXECUTOR|34=1|52=20201029-13:13:22.624|1128=7|98=0|108=30|141=Y|553=Username|554=Password|1137=7|10=204|";

    #[test]
    fn the_reg_test_logons_are_valid() {
        assert_eq!(validate_message(&msg(LOGON_44)), Validity::Valid);
        assert_eq!(validate_message(&msg(LOGON_50)), Validity::Valid);
    }

    #[test]
    fn the_reg_test_malformed_messages_are_invalid() {
        for bad in [
            "8=FIX.4.4|9=100|35=A|49=CLIENT1|56=EXECUTOR|34=1|52=20201029-13:02:44.528|=0|108=30|141=Y|553=Username|554=Password|10=252|",
            "8=FIX.4.4|9=101|35=A|49=CLIENT1|56=EXECUTOR|34=1|52=20201029-13:02:44.528|98=|108=30|141=Y|553=Username|554=Password|10=252|",
            "9=102|8=FIX.4.4|35=A|49=CLIENT1|56=EXECUTOR|34=1|52=20201029-13:02:44.528|98=0|108=30|141=Y|553=Username|554=Password|10=252|",
            "8=FIX.4.4|35=A|9=102|49=CLIENT1|56=EXECUTOR|34=1|52=20201029-13:02:44.528|98=0|108=30|141=Y|553=Username|554=Password|10=252|",
            "8=FIX.4.4|9=102|49=CLIENT1|35=A|56=EXECUTOR|34=1|52=20201029-13:02:44.528|98=0|108=30|141=Y|553=Username|554=Password|10=252|",
            "8=FIX.4.4|9=100|35=A|49=CLIENT1|56=EXECUTOR|34=1|52=20201029-13:02:44.528|98=0|108=30|141=Y|553=Username|554=Password|10=252|",
            "8=FIX.4.4|9=102|35=A|49=CLIENT1|56=EXECUTOR|34=1|52=20201029-13:02:44.528|98=0|108=30|141=Y|553=Username|554=Password|10=253|",
        ] {
            assert_eq!(validate_message(&msg(bad)), Validity::Invalid, "{bad}");
        }
    }

    #[test]
    fn a_message_cut_short_needs_more_data() {
        let full = msg(LOGON_44);
        for cut in [10, 30, 60, full.len() - 1] {
            assert_eq!(validate_message(&full[..cut]), Validity::NeedMoreData, "cut at {cut}");
        }
        assert_eq!(tag_value(&full[..30], TAG_TARGET_COMP_ID), TagValue::NeedMoreData);
    }

    #[test]
    fn tag_ids_are_checked_against_the_version_s_range() {
        // `fix_check_id`: 4.0 tops out at 140, 4.4 at 956, 5.0 (FIXT.1.1) at 1621;
        // 10000-19999 are user-defined anywhere.
        assert_eq!(check_id(b"140", version_max_tag(b"FIX.4.0")), 140);
        assert_eq!(check_id(b"141", version_max_tag(b"FIX.4.0")), 0);
        assert_eq!(check_id(b"211", version_max_tag(b"FIX.4.1")), 211);
        assert_eq!(check_id(b"446", version_max_tag(b"FIX.4.2")), 446);
        assert_eq!(check_id(b"660", version_max_tag(b"FIX.4.3")), 0);
        assert_eq!(check_id(b"957", version_max_tag(b"FIX.4.4")), 0);
        assert_eq!(check_id(b"1621", version_max_tag(b"FIXT.1.1")), 1621);
        assert_eq!(check_id(b"15000", version_max_tag(b"FIX.4.0")), 15000);
        assert_eq!(check_id(b"0", None), 0);
        assert_eq!(check_id(b"12x", None), 0);
        // A tag out of range for the message's version makes it invalid.
        let m = msg("8=FIX.4.0|9=10|35=A|141=Y|10=000|");
        assert_eq!(validate_message(&m), Validity::Invalid);
    }

    #[test]
    fn an_empty_or_unknown_version_or_a_bad_body_length_is_invalid() {
        for bad in [
            "8=FIX.9.9|9=5|35=A|10=000|xxxxxxxxxx",
            "8=FIX.4.4|9=0|35=A|10=000|xxxxxxxxxx",
            "8=FIX.4.4|9=1x|35=A|10=000|xxxxxxxxx",
            "8=FIX.4.4|9=10|35=A|10=00|xxxxxxxxxx",
        ] {
            assert_eq!(validate_message(&msg(bad)), Validity::Invalid, "{bad}");
        }
        assert_eq!(version_max_tag(b"FIX.9.9"), None);
        // Complete fields, no CheckSum yet: more may come.
        assert_eq!(validate_message(&msg("8=FIX.4.4|9=10|35=A|49=CLIENT1|")), Validity::NeedMoreData);
        assert_eq!(tag_value(&msg("8=FIX.4.4|9=10|35=A|"), TAG_SENDER_COMP_ID), TagValue::NeedMoreData);
    }

    #[test]
    fn tag_lookup_stops_at_a_malformed_field_or_the_checksum() {
        assert_eq!(tag_value(&msg("8=FIX.4.4|=1|49=X|"), TAG_SENDER_COMP_ID), TagValue::NotFound);
        assert_eq!(tag_value(&msg("8=FIX.4.4|x=1|49=X|"), TAG_SENDER_COMP_ID), TagValue::NotFound);
        assert_eq!(tag_value(&msg("8=FIX.4.4|10=000|49=X|"), TAG_SENDER_COMP_ID), TagValue::NotFound);
        for name in ["MsgType", "BodyLength", "TargetCompID", "SenderCompID"] {
            assert!(tag_id(name).is_some(), "{name}");
        }
    }

    #[test]
    fn tags_are_found_by_number_or_name() {
        let m = msg(LOGON_44);
        assert_eq!(tag_value(&m, tag_id("BeginString").expect("known")), TagValue::Found(b"FIX.4.4"));
        assert_eq!(tag_value(&m, tag_id("9").expect("numeric")), TagValue::Found(b"102"));
        assert_eq!(tag_value(&m, tag_id("checksum").expect("any case")), TagValue::Found(b"252"));
        assert_eq!(tag_value(&m, 999), TagValue::NotFound);
        assert_eq!(tag_id("NoSuchTag"), None);
    }
}
