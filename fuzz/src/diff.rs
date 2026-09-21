// SPDX-License-Identifier: GPL-2.0-or-later
//! Differential Analyzer for HTTP/1 Framing Discrepancies.
//!
//! Evaluates Ibex versus HAProxy 3.5 Oracle results and classifies differences into:
//! - Category 1: Acceptance Disagreement (Accepted vs Rejected)
//! - Category 2: Request Framing Disagreement (Method, URI, Headers, Body Length)
//! - Category 3: Next Request Boundary / Request Smuggling (Desync, Pipelining, CL/TE conflict)
//! - Self-Differential: Ibex Single-Pass vs Incremental Stream Disagreement

#![forbid(unsafe_code)]

use crate::generator::TestCase;
use crate::oracle_haproxy::HaproxyParseResult;
use crate::oracle_ibex::IbexParseResult;

/// Discrepancy category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscrepancyCategory {
    /// Disagreement on whether the request is valid HTTP/1 syntax (Accepted vs Rejected).
    Category1Acceptance,
    /// Disagreement on request framing details (Method, URI, Header count, Body length).
    Category2Framing,
    /// Disagreement on where this request ends and the next request begins (Request Smuggling finding).
    Category3SmugglingBoundary,
    /// Ibex parser disagreeing with itself across single-pass vs incremental byte streams.
    SelfDifferential,
}

impl DiscrepancyCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiscrepancyCategory::Category1Acceptance => "Category 1: Acceptance Disagreement (Accepted vs Rejected)",
            DiscrepancyCategory::Category2Framing => "Category 2: Request Framing Disagreement (Method/Path/Headers/Body)",
            DiscrepancyCategory::Category3SmugglingBoundary => "Category 3: Request Smuggling Boundary Finding (Next Request Desync)",
            DiscrepancyCategory::SelfDifferential => "Self-Differential Disagreement (Ibex Inconsistent Across Streaming Modes)",
        }
    }
}

/// A recorded discrepancy finding between Ibex and HAProxy or Ibex self-differential.
#[derive(Debug, Clone)]
pub struct DiscrepancyFinding {
    pub id: usize,
    pub test_case: TestCase,
    pub category: DiscrepancyCategory,
    pub summary: String,
    pub ibex_result: IbexParseResult,
    pub haproxy_result: HaproxyParseResult,
    pub details: String,
}

/// Compares Ibex and HAProxy results for a given test case.
pub fn compare_results(
    id: usize,
    test_case: &TestCase,
    ibex: &IbexParseResult,
    haproxy: &HaproxyParseResult,
) -> Option<DiscrepancyFinding> {
    // 0. Check Ibex Self-Differential Consistency
    if !ibex.self_consistent {
        return Some(DiscrepancyFinding {
            id,
            test_case: test_case.clone(),
            category: DiscrepancyCategory::SelfDifferential,
            summary: format!("Ibex parser produced inconsistent results between full-buffer and single-byte streaming on '{}'", test_case.name),
            ibex_result: ibex.clone(),
            haproxy_result: haproxy.clone(),
            details: "Full-buffer parse succeeded/failed differently than byte-by-byte incremental stream.".into(),
        });
    }

    // 1. Category 3: smuggling / next-request boundary.
    //
    // This must be DIFFERENTIAL. Firing on `haproxy.next_request_smuggled` alone
    // reported HAProxy's own behaviour as an Ibex finding without ever consulting
    // Ibex, which is not a comparison. It is only interesting when the two disagree
    // about where the message ended.
    // A pipelined case legitimately leaves bytes unconsumed after the first message;
    // that is streaming, not desync. Only a genuine boundary disagreement counts.
    // A rejected input cannot desync anything: nothing was forwarded. Without this,
    // every case both parsers reject was reported as a boundary disagreement, because
    // a rejection consumes 0 bytes and therefore "left trailing data".
    let ibex_left_trailing = ibex.consumed_bytes < test_case.raw_bytes.len();
    let ibex_desynced = ibex.accepted && ibex_left_trailing && !test_case.is_pipelined;
    if haproxy.next_request_smuggled != ibex_desynced {
        return Some(DiscrepancyFinding {
            id,
            test_case: test_case.clone(),
            category: DiscrepancyCategory::Category3SmugglingBoundary,
            summary: format!("Request Smuggling finding: Next request boundary desynchronized on '{}'", test_case.name),
            ibex_result: ibex.clone(),
            haproxy_result: haproxy.clone(),
            details: "HAProxy detected trailing data as part of request body or corrupted the subsequent pipelined request boundary.".into(),
        });
    }

    // Check if CL.TE conflict was handled with Connection: close
    if test_case.class == crate::generator::AmbiguityClass::ClTeConflict {
        if ibex.accepted && haproxy.accepted {
            // HAProxy enforces Connection: close or rejects subsequent pipelined request when CL & TE conflict
            if !ibex.connection_close && !haproxy.saw_sentinel_request {
                return Some(DiscrepancyFinding {
                    id,
                    test_case: test_case.clone(),
                    category: DiscrepancyCategory::Category3SmugglingBoundary,
                    summary: format!("Request Smuggling finding: Ibex kept keep-alive connection open on CL-TE conflict in '{}'", test_case.name),
                    ibex_result: ibex.clone(),
                    haproxy_result: haproxy.clone(),
                    details: "Ibex accepted ambiguous CL+TE without setting Connection: close, risking downstream pipelined request smuggling.".into(),
                });
            }
        }
    }

    // 2. Check Category 1: Acceptance Disagreements (Accepted vs Rejected)
    if ibex.accepted != haproxy.accepted {
        let summary = if ibex.accepted && !haproxy.accepted {
            format!("Acceptance disagreement: Ibex accepted input while HAProxy rejected (HTTP {}) on '{}'", haproxy.status_code.unwrap_or(0), test_case.name)
        } else {
            format!("Acceptance disagreement: HAProxy accepted input while Ibex rejected (parse error) on '{}'", test_case.name)
        };

        return Some(DiscrepancyFinding {
            id,
            test_case: test_case.clone(),
            category: DiscrepancyCategory::Category1Acceptance,
            summary,
            ibex_result: ibex.clone(),
            haproxy_result: haproxy.clone(),
            details: format!(
                "Ibex: accepted={}, phase={:?}, err={:?}. HAProxy: accepted={}, status={:?}, err={:?}",
                ibex.accepted, ibex.phase, ibex.error_message, haproxy.accepted, haproxy.status_code, haproxy.error_message
            ),
        });
    }

    // 3. Check Category 2: Request Framing Disagreements on Accepted Requests
    if ibex.accepted && haproxy.accepted {
        if let Some(ref hp_req) = haproxy.forwarded_req {
            let mut diffs = Vec::new();

            if ibex.method.as_deref() != Some(&hp_req.method) {
                diffs.push(format!("Method mismatch (Ibex: {:?}, HAProxy: {:?})", ibex.method, hp_req.method));
            }

            if ibex.uri.as_deref() != Some(&hp_req.uri) {
                diffs.push(format!("URI mismatch (Ibex: {:?}, HAProxy: {:?})", ibex.uri, hp_req.uri));
            }

            if ibex.body_len != hp_req.body_len {
                diffs.push(format!("Body length mismatch (Ibex: {} bytes, HAProxy: {} bytes)", ibex.body_len, hp_req.body_len));
            }

            if !diffs.is_empty() {
                return Some(DiscrepancyFinding {
                    id,
                    test_case: test_case.clone(),
                    category: DiscrepancyCategory::Category2Framing,
                    summary: format!("Request framing disagreement on '{}': {}", test_case.name, diffs.join("; ")),
                    ibex_result: ibex.clone(),
                    haproxy_result: haproxy.clone(),
                    details: diffs.join("\n"),
                });
            }
        }
    }

    None
}
