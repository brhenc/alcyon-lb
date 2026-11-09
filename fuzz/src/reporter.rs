// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Discrepancy Reporting, Corpus Serialization, and Hex Dump Formatter.
//!
//! Generates `fuzz/corpus/` raw files and formats `fuzz/FINDINGS.md`.

#![forbid(unsafe_code)]

use crate::diff::{DiscrepancyCategory, DiscrepancyFinding};
use std::fs;
use std::path::Path;

/// Formats a byte slice into a standard canonical hex dump with ASCII sidebar.
pub fn format_hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    let chunk_size = 16;

    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        let offset = i * chunk_size;
        out.push_str(&format!("{offset:08x}: "));

        // Hex bytes
        for (j, &byte) in chunk.iter().enumerate() {
            out.push_str(&format!("{byte:02x} "));
            if j == 7 {
                out.push(' ');
            }
        }

        // Padding if last chunk < 16 bytes
        if chunk.len() < chunk_size {
            for j in chunk.len()..chunk_size {
                out.push_str("   ");
                if j == 7 {
                    out.push(' ');
                }
            }
        }

        out.push_str(" |");
        // ASCII representation
        for &byte in chunk {
            if (32..=126).contains(&byte) {
                out.push(byte as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }

    out
}

/// Saves all finding inputs to `corpus_dir` as verbatim binary files.
pub fn save_corpus<P: AsRef<Path>>(corpus_dir: P, findings: &[DiscrepancyFinding]) -> Result<(), String> {
    let dir = corpus_dir.as_ref();
    if dir.exists() {
        let _ = fs::remove_dir_all(dir);
    }
    fs::create_dir_all(dir).map_err(|e| format!("Failed to create corpus dir {}: {e}", dir.display()))?;

    for finding in findings {
        let file_name = format!(
            "finding_{:03}_{}.bin",
            finding.id,
            finding.test_case.name.replace('/', "_").replace(' ', "_")
        );
        let path = dir.join(file_name);
        fs::write(&path, &finding.test_case.raw_bytes)
            .map_err(|e| format!("Failed to write corpus file {}: {e}", path.display()))?;
    }

    Ok(())
}

/// Generates the markdown content for `FINDINGS.md`.
pub fn generate_findings_markdown(
    total_tested: usize,
    accepted_both: usize,
    rejected_both: usize,
    findings: &[DiscrepancyFinding],
    haproxy_version: &str,
    alcyon_sha: &str,
) -> String {
    let mut cat1_count = 0;
    let mut cat2_count = 0;
    let mut cat3_count = 0;
    let mut self_diff_count = 0;

    for f in findings {
        match f.category {
            DiscrepancyCategory::Category1Acceptance => cat1_count += 1,
            DiscrepancyCategory::Category2Framing => cat2_count += 1,
            DiscrepancyCategory::Category3SmugglingBoundary => cat3_count += 1,
            DiscrepancyCategory::SelfDifferential => self_diff_count += 1,
        }
    }

    let mut md = String::new();
    md.push_str("# Differential Fuzzing Findings: Alcyon vs HAProxy\n\n");
    md.push_str("## Executive Summary\n\n");
    md.push_str(&format!(
        "This report documents differential testing between the **Alcyon HTTP/1 parser** (`crates/alcyon-proto`) \
         and the reference **{}** oracle (`$ALCYON_REFERENCE/haproxy/haproxy`); Alcyon at commit `{}`.\n\n\
         - **Total Inputs Evaluated:** {}\n\
         - **Accepted by Both Parsers:** {}\n\
         - **Rejected by Both Parsers:** {}\n\
         - **Total Disagreements Found:** {}\n\
           - **Category 1 (Acceptance Disagreements):** {}\n\
           - **Category 2 (Framing Disagreements):** {}\n\
           - **Category 3 (Smuggling / Boundary Findings):** {}\n\
           - **Self-Differential (Streaming Consistency):** {}\n\n",
        haproxy_version, alcyon_sha, total_tested, accepted_both, rejected_both, findings.len(),
        cat1_count, cat2_count, cat3_count, self_diff_count
    ));

    md.push_str("## Discrepancy Classification Framework\n\n");
    md.push_str("1. **Category 1 (Acceptance):** One parser accepted the input as valid HTTP/1 while the other rejected it (HTTP 400 Bad Request or parse syntax error).\n");
    md.push_str("2. **Category 2 (Framing):** Both parsers accepted the input, but disagreed on parsed method, URI, header count, or body length.\n");
    md.push_str("3. **Category 3 (Smuggling Boundary):** Disagreements on message boundaries (where this request ends and the next begins), keep-alive connection reuse enforcement on ambiguous framing, or request smuggling desynchronization.\n");
    md.push_str("4. **Self-Differential:** Discrepancies within Alcyon itself across single-pass buffer evaluation versus incremental byte-by-byte streaming.\n\n");

    md.push_str("---\n\n");
    md.push_str("## Detailed Findings\n\n");

    if findings.is_empty() {
        md.push_str("*(No discrepancies discovered across tested inputs.)*\n");
        return md;
    }

    for finding in findings {
        md.push_str(&format!("### Finding {:03}: {}\n\n", finding.id, finding.test_case.name));
        md.push_str(&format!("- **Category:** {}\n", finding.category.as_str()));
        md.push_str(&format!("- **Ambiguity Class:** {}\n", finding.test_case.class.as_str()));
        md.push_str(&format!("- **Description:** {}\n\n", finding.test_case.description));

        md.push_str("#### Raw Input Hex Dump\n\n```text\n");
        md.push_str(&format_hexdump(&finding.test_case.raw_bytes));
        md.push_str("```\n\n");

        md.push_str("#### Alcyon Behavior\n\n");
        md.push_str(&format!("- **Accepted:** `{}`\n", finding.alcyon_result.accepted));
        md.push_str(&format!("- **Phase:** `{}`\n", finding.alcyon_result.phase));
        md.push_str(&format!("- **Consumed Bytes:** `{} / {}`\n", finding.alcyon_result.consumed_bytes, finding.test_case.raw_bytes.len()));
        if let Some(ref m) = finding.alcyon_result.method {
            md.push_str(&format!("- **Parsed Method:** `{m}`\n"));
        }
        if let Some(ref u) = finding.alcyon_result.uri {
            md.push_str(&format!("- **Parsed URI:** `{u}`\n"));
        }
        md.push_str(&format!("- **Body Length:** `{} bytes`\n", finding.alcyon_result.body_len));
        md.push_str(&format!("- **Connection Close Set:** `{}`\n", finding.alcyon_result.connection_close));
        if let Some(ref err) = finding.alcyon_result.error_message {
            md.push_str(&format!("- **Error Message:** `{err}`\n"));
        }

        md.push_str("\n#### HAProxy Behavior\n\n");
        md.push_str(&format!("- **Accepted:** `{}`\n", finding.haproxy_result.accepted));
        md.push_str(&format!("- **HTTP Status Code:** `{:?}`\n", finding.haproxy_result.status_code));
        if let Some(ref fwd) = finding.haproxy_result.forwarded_req {
            md.push_str(&format!("- **Forwarded Method:** `{}`\n", fwd.method));
            md.push_str(&format!("- **Forwarded URI:** `{}`\n", fwd.uri));
            md.push_str(&format!("- **Forwarded Body Length:** `{} bytes`\n", fwd.body_len));
        } else {
            md.push_str("- **Forwarded to Backend:** `No (connection dropped or rejected with 400)`\n");
        }
        md.push_str(&format!("- **Saw Sentinel Next Request:** `{}`\n", finding.haproxy_result.saw_sentinel_request));
        md.push_str(&format!("- **Next Request Smuggled / Desynced:** `{}`\n", finding.haproxy_result.next_request_smuggled));

        md.push_str("\n#### Security Analysis & Root Cause\n\n");
        md.push_str(&format!("{}\n\n", finding.details));
        md.push_str("---\n\n");
    }

    md
}
