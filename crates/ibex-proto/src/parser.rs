// SPDX-License-Identifier: GPL-2.0-or-later
// Shaped after HAProxy's mux_ops / mux context split (include/haproxy/connection-t.h).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Swappable HTTP/1 parsers, and the machinery to compare two of them.
//!
//! Ibex is meant to carry more than one HTTP parser and choose between them without a
//! rebuild: the hand-written one here, the flat-buffer HTX rewrite, a third-party parser,
//! and eventually HAProxy's own C parser through FFI. That is worth having for two
//! reasons beyond taste. A parser can be swapped out when it is found wanting without
//! disturbing anything above it, and two of them can be run against the same bytes to see
//! where they disagree -- which, for HTTP framing, *is* the definition of a
//! request-smuggling vulnerability. Two parsers that agree on every input cannot be
//! desynchronised against each other.
//!
//! ## Shape
//!
//! Two traits, mirroring `HAProxy`'s split between `struct mux_ops` and the per-connection
//! mux context:
//!
//! - [`HttpParser`] is the implementation. One per process, immutable, shared by every
//!   connection.
//! - [`HttpStream`] is one message in flight. One per connection, mutable, carrying the
//!   phase and framing state.
//!
//! Both are object-safe on purpose. An associated type or a generic parameter would be
//! marginally faster and would also decide the parser at compile time, which is the one
//! thing this must not do. The cost is a vtable call per `parse`, and `parse` is called
//! once per socket read rather than once per byte -- it sits beside a syscall, not inside
//! a loop.
//!
//! ## What is not here
//!
//! No parser is registered but the built-in one. The others are named in [`ParserKind`]
//! with what each needs, so the seam is defined and the work to fill it is visible,
//! rather than the seam being invented later around whichever one arrives first.

use crate::h1::H1Parser;
use crate::htx::Htx;
use std::io;

/// Which implementation. Names are what a config or the runtime socket accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserKind {
    /// The hand-written incremental parser in `h1.rs`, building `Htx` as `Vec<HtxBlock>`.
    ///
    /// The one in use today, and the reference the others are compared against: it is
    /// what the strict-framing work and the smuggling tests were written for.
    H1,
    /// The same grammar over the flat `HtxBuffer` layout rather than `Vec<HtxBlock>`.
    ///
    /// Not registered yet: `HtxBuffer` is being finished separately. When it lands, this
    /// is the one worth running differentially against [`ParserKind::H1`], because the
    /// change is a representation change and the parse results must be identical.
    HtxFlat,
    /// A third-party parser, behind a feature flag.
    ///
    /// Not registered: it would pull a dependency that has its own idea of what an HTTP
    /// message is, and the adapter is the interesting part.
    Pingora,
    /// HAProxy's own `h1_headers_to_hdr_list` and friends, through FFI.
    ///
    /// Not registered, and the most valuable of the four: it makes the oracle the actual
    /// implementation rather than a reading of it. It needs a C shim and a build that
    /// links against the reference tree, so it stays behind a feature flag and out of the
    /// default build.
    HaproxyFfi,
}

impl ParserKind {
    /// The name this is selected by.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ParserKind::H1 => "h1",
            ParserKind::HtxFlat => "htx-flat",
            ParserKind::Pingora => "pingora",
            ParserKind::HaproxyFfi => "haproxy-ffi",
        }
    }

    /// Parses a name, for config and the runtime socket.
    ///
    /// Not `FromStr`: that returns a `Result` whose error type would have to be invented
    /// for a lookup whose only failure is "no such name".
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "h1" => Some(ParserKind::H1),
            "htx-flat" => Some(ParserKind::HtxFlat),
            "pingora" => Some(ParserKind::Pingora),
            "haproxy-ffi" => Some(ParserKind::HaproxyFfi),
            _ => None,
        }
    }

    /// Every name, whether or not it is built into this binary.
    #[must_use]
    pub const fn all() -> &'static [ParserKind] {
        &[
            ParserKind::H1,
            ParserKind::HtxFlat,
            ParserKind::Pingora,
            ParserKind::HaproxyFfi,
        ]
    }
}

/// One HTTP message being parsed. Per connection.
pub trait HttpStream: Send {
    /// Consumes wire bytes, appending blocks to `htx`. Returns bytes consumed.
    ///
    /// Incremental: a partial message consumes what it can and returns, and the caller
    /// calls again when more arrives. Anything not consumed must be presented again
    /// unchanged.
    ///
    /// # Errors
    /// A framing violation. The caller must treat the message as unparseable rather than
    /// forwarding what was read so far -- a partially parsed request is how a desync
    /// starts.
    fn parse(&mut self, input: &[u8], htx: &mut Htx) -> io::Result<usize>;

    /// Prepares for the next message on a kept-alive connection.
    fn reset(&mut self, is_response: bool);

    /// Called at EOF, for messages delimited by connection close.
    fn finish(&mut self, htx: &mut Htx);

    /// True once the peer must not send another message on this connection.
    fn connection_close(&self) -> bool;

    /// True when the message carried conflicting framing (`Content-Length` and
    /// `Transfer-Encoding` both, and disagreeing).
    ///
    /// Distinct from an error: RFC 9112 says to honour `Transfer-Encoding` and close the
    /// connection, so the message is parseable and the connection is not reusable.
    fn framing_conflict(&self) -> bool;
}

/// A parser implementation. One per process.
pub trait HttpParser: Send + Sync {
    /// The name this was selected by, for `show info` and logs.
    fn name(&self) -> &'static str;

    /// Begins a message. `is_response` picks the response grammar.
    fn stream(&self, is_response: bool) -> Box<dyn HttpStream>;
}

// ---------------------------------------------------------------------------
// The built-in parser
// ---------------------------------------------------------------------------

/// The hand-written parser in `h1.rs`.
#[derive(Debug, Default, Clone, Copy)]
pub struct H1;

impl HttpParser for H1 {
    fn name(&self) -> &'static str {
        ParserKind::H1.as_str()
    }

    fn stream(&self, is_response: bool) -> Box<dyn HttpStream> {
        Box::new(H1Parser::new(is_response))
    }
}

impl HttpStream for H1Parser {
    fn parse(&mut self, input: &[u8], htx: &mut Htx) -> io::Result<usize> {
        H1Parser::parse(self, input, htx)
    }

    fn reset(&mut self, is_response: bool) {
        H1Parser::reset(self, is_response);
    }

    fn finish(&mut self, htx: &mut Htx) {
        H1Parser::finish(self, htx);
    }

    fn connection_close(&self) -> bool {
        self.connection_close
    }

    fn framing_conflict(&self) -> bool {
        self.framing_conflict
    }
}

// ---------------------------------------------------------------------------
// Running two parsers against the same bytes
// ---------------------------------------------------------------------------

/// What to do when two parsers disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnMismatch {
    /// Record it and continue with the primary's result.
    ///
    /// For measuring a candidate parser against the one in service, where the point is to
    /// collect disagreements rather than to act on them.
    Observe,
    /// Fail the message.
    ///
    /// The correct setting for anything carrying real traffic. Two parsers disagreeing
    /// about where a message ends is the precondition for request smuggling: whichever
    /// one is right, an intermediary reading it the other way sees a different request
    /// than this one does. Refusing is the only answer that is safe whichever is wrong.
    Reject,
}

/// A disagreement between two parsers on the same input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    pub primary: &'static str,
    pub candidate: &'static str,
    /// What differed: consumed length, error status, or the blocks themselves.
    pub detail: String,
}

/// Runs two parsers over the same bytes and compares what they made of them.
///
/// This is the A/B mechanism, and it is also a smuggling detector, because for HTTP those
/// are the same measurement. A candidate parser is correct exactly insofar as it agrees
/// with the one in service on every input; where they differ, one of them is wrong and
/// the difference is the bug report.
///
/// Both parsers see identical input and neither sees the other's output.
pub struct Differential {
    primary: Box<dyn HttpParser>,
    candidate: Box<dyn HttpParser>,
    on_mismatch: OnMismatch,
}

impl Differential {
    #[must_use]
    pub fn new(
        primary: Box<dyn HttpParser>,
        candidate: Box<dyn HttpParser>,
        on_mismatch: OnMismatch,
    ) -> Self {
        Self {
            primary,
            candidate,
            on_mismatch,
        }
    }
}

impl HttpParser for Differential {
    fn name(&self) -> &'static str {
        "differential"
    }

    fn stream(&self, is_response: bool) -> Box<dyn HttpStream> {
        Box::new(DifferentialStream {
            primary: self.primary.stream(is_response),
            candidate: self.candidate.stream(is_response),
            primary_name: self.primary.name(),
            candidate_name: self.candidate.name(),
            on_mismatch: self.on_mismatch,
            mismatches: Vec::new(),
        })
    }
}

/// One message, parsed twice.
pub struct DifferentialStream {
    primary: Box<dyn HttpStream>,
    candidate: Box<dyn HttpStream>,
    primary_name: &'static str,
    candidate_name: &'static str,
    on_mismatch: OnMismatch,
    mismatches: Vec<Mismatch>,
}

impl DifferentialStream {
    /// Disagreements seen on this message.
    #[must_use]
    pub fn mismatches(&self) -> &[Mismatch] {
        &self.mismatches
    }

    fn record(&mut self, detail: &str) -> io::Result<()> {
        self.mismatches.push(Mismatch {
            primary: self.primary_name,
            candidate: self.candidate_name,
            detail: detail.to_string(),
        });
        match self.on_mismatch {
            OnMismatch::Observe => Ok(()),
            OnMismatch::Reject => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "parsers disagree ({} vs {}): {detail}",
                    self.primary_name, self.candidate_name
                ),
            )),
        }
    }
}

impl HttpStream for DifferentialStream {
    fn parse(&mut self, input: &[u8], htx: &mut Htx) -> io::Result<usize> {
        // Each parser gets its own output buffer. Handing them the same one would let the
        // first to run change what the second sees, and then agreement would prove
        // nothing.
        let mut primary_htx = std::mem::take(htx);
        let before = primary_htx.blocks().len();
        let primary_res = self.primary.parse(input, &mut primary_htx);

        let mut candidate_htx = Htx::new();
        for blk in &primary_htx.blocks()[..before] {
            candidate_htx.push(blk.clone());
        }
        let candidate_res = self.candidate.parse(input, &mut candidate_htx);

        // Compare before returning, so a disagreement is recorded even when both fail.
        match (&primary_res, &candidate_res) {
            (Ok(a), Ok(b)) if a != b => {
                self.record(&format!("consumed {a} vs {b} bytes"))?;
            }
            (Ok(a), Err(e)) => {
                self.record(&format!("primary consumed {a}, candidate errored: {e}"))?;
            }
            (Err(e), Ok(b)) => {
                self.record(&format!("primary errored: {e}, candidate consumed {b}"))?;
            }
            // Both errored. The messages may differ without the framing differing, and a
            // rejected message is rejected either way, so this is not a disagreement.
            (Err(_), Err(_)) | (Ok(_), Ok(_)) => {}
        }

        if primary_res.is_ok() && candidate_res.is_ok() && primary_htx != candidate_htx {
            self.record(&format!(
                "different blocks: {} produced {:?}, {} produced {:?}",
                self.primary_name,
                primary_htx.blocks(),
                self.candidate_name,
                candidate_htx.blocks()
            ))?;
        }

        *htx = primary_htx;
        primary_res
    }

    fn reset(&mut self, is_response: bool) {
        self.primary.reset(is_response);
        self.candidate.reset(is_response);
        self.mismatches.clear();
    }

    fn finish(&mut self, htx: &mut Htx) {
        self.primary.finish(htx);
        // Deliberately given a throwaway buffer: `finish` appends an end-of-message to
        // whatever it is handed, and running both over one buffer would append it twice.
        let mut scratch = Htx::new();
        self.candidate.finish(&mut scratch);
    }

    fn connection_close(&self) -> bool {
        // Either parser wanting the connection closed closes it. This is the only
        // asymmetric rule here, and it is deliberate: reuse is an optimisation, and
        // keeping a connection the candidate believes is finished is how a desync starts.
        self.primary.connection_close() || self.candidate.connection_close()
    }

    fn framing_conflict(&self) -> bool {
        self.primary.framing_conflict() || self.candidate.framing_conflict()
    }
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// Builds the parser named, or reports why it cannot.
///
/// # Errors
/// The name is unknown, or names an implementation this binary was not built with. The
/// two are different and the message says which: a missing feature flag is a build
/// decision, a bad name is a typo.
pub fn build(kind: ParserKind) -> Result<Box<dyn HttpParser>, String> {
    match kind {
        ParserKind::H1 => Ok(Box::new(H1)),
        ParserKind::HtxFlat => Err(
            "parser 'htx-flat' is not implemented yet: the flat HtxBuffer layout is \
             still being finished"
                .to_string(),
        ),
        ParserKind::Pingora => Err(
            "parser 'pingora' is not built into this binary: it needs the `pingora` \
             feature"
                .to_string(),
        ),
        ParserKind::HaproxyFfi => Err(
            "parser 'haproxy-ffi' is not built into this binary: it needs the \
             `haproxy-ffi` feature and a build linked against the reference tree"
                .to_string(),
        ),
    }
}

/// The names this binary can actually serve.
#[must_use]
pub fn available() -> Vec<&'static str> {
    ParserKind::all()
        .iter()
        .filter(|k| build(**k).is_ok())
        .map(|k| k.as_str())
        .collect()
}
