// SPDX-License-Identifier: GPL-2.0-or-later

//! The swappable-parser seam, and the differential that compares two of them.

use ibex_proto::htx::{Htx, HtxBlock};
use ibex_proto::parser::{self, Differential, HttpParser, HttpStream, OnMismatch, ParserKind, H1};
use std::io;

const GET: &[u8] = b"GET /x HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n";

/// The built-in parser is reachable through the trait and parses a request.
#[test]
fn the_builtin_parser_works_through_the_seam() {
    let p = parser::build(ParserKind::H1).expect("h1 must be built in");
    assert_eq!(p.name(), "h1");
    let mut s = p.stream(false);
    let mut htx = Htx::new();
    let n = s.parse(GET, &mut htx).expect("parse");
    assert_eq!(n, GET.len());
    assert!(matches!(htx.blocks().first(), Some(HtxBlock::ReqLine(_))));
}

/// Names round-trip, and every name is listed whether or not it is built in.
#[test]
fn every_parser_has_a_name_that_round_trips() {
    for k in ParserKind::all() {
        assert_eq!(ParserKind::parse(k.as_str()), Some(*k), "{}", k.as_str());
    }
    assert_eq!(ParserKind::parse("nonsense"), None);
    assert_eq!(ParserKind::all().len(), 4, "h1, htx-flat, pingora, haproxy-ffi");
}

/// An unbuilt parser fails with a reason, and is not silently swapped for another.
///
/// Falling back to the default would mean an operator who asked for a specific parser --
/// to reproduce a bug, or to A/B a candidate -- gets a different one and is told nothing.
#[test]
fn an_unavailable_parser_says_why() {
    for k in [ParserKind::HtxFlat, ParserKind::Pingora, ParserKind::HaproxyFfi] {
        let Err(err) = parser::build(k) else {
            panic!("{} must not be built in yet", k.as_str())
        };
        assert!(err.contains(k.as_str()), "{err}");
        assert!(
            err.contains("not implemented") || err.contains("not built into"),
            "the reason must distinguish unimplemented from not-compiled-in: {err}"
        );
    }
    assert_eq!(parser::available(), vec!["h1"]);
}

/// Two identical parsers agree on everything, and the result is unchanged.
#[test]
fn a_differential_of_two_identical_parsers_never_disagrees() {
    let d = Differential::new(Box::new(H1), Box::new(H1), OnMismatch::Reject);
    let mut s = d.stream(false);
    let mut htx = Htx::new();
    let n = s.parse(GET, &mut htx).expect("identical parsers cannot disagree");
    assert_eq!(n, GET.len());

    let mut direct = Htx::new();
    let mut plain = H1.stream(false);
    plain.parse(GET, &mut direct).expect("parse");
    assert_eq!(htx, direct, "the differential must not alter the result");
}

/// A parser that lies is caught, and `Reject` fails the message.
///
/// The whole point of the seam: a candidate is correct exactly insofar as it agrees with
/// the one in service, and where they differ the difference is the bug report. Here the
/// candidate under-reports what it consumed, which for HTTP is precisely the shape of a
/// desync -- two intermediaries disagreeing about where a message ends.
#[test]
fn a_disagreement_is_detected_and_can_fail_the_message() {
    /// Consumes two bytes fewer than it should, and produces nothing.
    struct Truncating;
    struct TruncatingStream;

    impl HttpParser for Truncating {
        fn name(&self) -> &'static str {
            "truncating"
        }
        fn stream(&self, _is_response: bool) -> Box<dyn HttpStream> {
            Box::new(TruncatingStream)
        }
    }
    impl HttpStream for TruncatingStream {
        fn parse(&mut self, input: &[u8], _htx: &mut Htx) -> io::Result<usize> {
            Ok(input.len().saturating_sub(2))
        }
        fn reset(&mut self, _is_response: bool) {}
        fn finish(&mut self, _htx: &mut Htx) {}
        fn connection_close(&self) -> bool {
            false
        }
        fn framing_conflict(&self) -> bool {
            false
        }
    }

    // Reject: the message fails.
    let d = Differential::new(Box::new(H1), Box::new(Truncating), OnMismatch::Reject);
    let mut s = d.stream(false);
    let mut htx = Htx::new();
    let err = s
        .parse(GET, &mut htx)
        .expect_err("a disagreement must fail the message under Reject");
    assert!(err.to_string().contains("disagree"), "{err}");

    // Observe: the message survives on the primary's result, and the disagreement is
    // recorded rather than acted on.
    let d = Differential::new(Box::new(H1), Box::new(Truncating), OnMismatch::Observe);
    let mut s = d.stream(false);
    let mut htx = Htx::new();
    let n = s.parse(GET, &mut htx).expect("Observe must not fail the message");
    assert_eq!(n, GET.len(), "the primary's answer is the one used");
    assert!(
        matches!(htx.blocks().first(), Some(HtxBlock::ReqLine(_))),
        "the primary's blocks are the ones kept"
    );
}

/// Neither parser may see the other's output.
///
/// If they shared a buffer the first to run would change what the second parses, and
/// agreement would prove nothing. The candidate here asserts it was handed a buffer
/// holding only what was there before the call.
#[test]
fn the_parsers_do_not_share_an_output_buffer() {
    struct Checking;
    struct CheckingStream;

    impl HttpParser for Checking {
        fn name(&self) -> &'static str {
            "checking"
        }
        fn stream(&self, _r: bool) -> Box<dyn HttpStream> {
            Box::new(CheckingStream)
        }
    }
    impl HttpStream for CheckingStream {
        fn parse(&mut self, input: &[u8], htx: &mut Htx) -> io::Result<usize> {
            assert!(
                htx.blocks().is_empty(),
                "the candidate was shown the primary's output: {:?}",
                htx.blocks()
            );
            let mut inner = H1.stream(false);
            inner.parse(input, htx)
        }
        fn reset(&mut self, _r: bool) {}
        fn finish(&mut self, _h: &mut Htx) {}
        fn connection_close(&self) -> bool {
            false
        }
        fn framing_conflict(&self) -> bool {
            false
        }
    }
    let d = Differential::new(Box::new(H1), Box::new(Checking), OnMismatch::Reject);
    let mut s = d.stream(false);
    let mut htx = Htx::new();
    s.parse(GET, &mut htx).expect("identical output must agree");
}

/// Either parser wanting the connection closed closes it.
///
/// Reuse is an optimisation; keeping a connection one parser believes is finished is how
/// a desync starts, so this rule is deliberately asymmetric.
#[test]
fn connection_close_is_the_union_of_both() {
    struct AlwaysClose;
    struct AlwaysCloseStream;
    impl HttpParser for AlwaysClose {
        fn name(&self) -> &'static str {
            "always-close"
        }
        fn stream(&self, _r: bool) -> Box<dyn HttpStream> {
            Box::new(AlwaysCloseStream)
        }
    }
    impl HttpStream for AlwaysCloseStream {
        fn parse(&mut self, input: &[u8], htx: &mut Htx) -> io::Result<usize> {
            let mut s = H1.stream(false);
            s.parse(input, htx)
        }
        fn reset(&mut self, _r: bool) {}
        fn finish(&mut self, _h: &mut Htx) {}
        fn connection_close(&self) -> bool {
            true
        }
        fn framing_conflict(&self) -> bool {
            false
        }
    }

    let d = Differential::new(Box::new(H1), Box::new(AlwaysClose), OnMismatch::Observe);
    let mut s = d.stream(false);
    let mut htx = Htx::new();
    let _ = s.parse(GET, &mut htx);
    assert!(
        s.connection_close(),
        "one parser asking to close must close the connection"
    );
}

/// The differential survives a keep-alive reset and keeps both sides in step.
#[test]
fn reset_advances_both_parsers() {
    let d = Differential::new(Box::new(H1), Box::new(H1), OnMismatch::Reject);
    let mut s = d.stream(false);
    for _ in 0..3 {
        let mut htx = Htx::new();
        let n = s.parse(GET, &mut htx).expect("parse");
        assert_eq!(n, GET.len());
        s.reset(false);
    }
}
