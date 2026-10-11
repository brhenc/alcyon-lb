// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Ibex HTTP/1 Parser Differential Fuzzing Harness.
//!
//! Compares Ibex's HTTP/1 parser (`crates/ibex-proto`) against HAProxy 3.5 (`/home/bhenc/reference/haproxy/haproxy`)
//! and against itself across equivalent streaming inputs.

#![forbid(unsafe_code)]

mod diff;
mod generator;
mod oracle_haproxy;
mod oracle_ibex;
mod reporter;

use diff::compare_results;
use generator::{generate_mutated_cases, generate_structured_corpus};
use oracle_haproxy::HaproxyOracle;
use oracle_ibex::parse_with_ibex;
use reporter::{generate_findings_markdown, save_corpus};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

struct Config {
    haproxy_bin: PathBuf,
    corpus_dir: PathBuf,
    findings_file: PathBuf,
    mutated_count: usize,
    seed: u64,
    soak: bool,
}

fn parse_args() -> Config {
    let args: Vec<String> = env::args().collect();
    let mut haproxy_bin = PathBuf::from("/home/bhenc/reference/haproxy/haproxy");
    let mut corpus_dir = PathBuf::from("fuzz/corpus");
    let mut findings_file = PathBuf::from("fuzz/FINDINGS.md");
    let mut mutated_count = 250;
    let mut seed = 42;
    let mut soak = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--haproxy" => {
                if i + 1 < args.len() {
                    haproxy_bin = PathBuf::from(&args[i + 1]);
                    i += 1;
                }
            }
            "--corpus-dir" => {
                if i + 1 < args.len() {
                    corpus_dir = PathBuf::from(&args[i + 1]);
                    i += 1;
                }
            }
            "--findings-file" => {
                if i + 1 < args.len() {
                    findings_file = PathBuf::from(&args[i + 1]);
                    i += 1;
                }
            }
            "--iters" => {
                if i + 1 < args.len() {
                    if let Ok(val) = args[i + 1].parse::<usize>() {
                        mutated_count = val;
                    }
                    i += 1;
                }
            }
            "--seed" => {
                if i + 1 < args.len() {
                    if let Ok(val) = args[i + 1].parse::<u64>() {
                        seed = val;
                    }
                    i += 1;
                }
            }
            "--soak" => {
                soak = true;
                mutated_count = 2500;
            }
            "--help" | "-h" => {
                println!("Usage: ibex-fuzz [OPTIONS]");
                println!("Options:");
                println!("  --haproxy <PATH>        Path to HAProxy binary (default: /home/bhenc/reference/haproxy/haproxy)");
                println!("  --corpus-dir <PATH>     Directory to save discrepancy inputs (default: fuzz/corpus)");
                println!("  --findings-file <PATH>  Output markdown report (default: fuzz/FINDINGS.md)");
                println!("  --iters <N>             Number of mutated cases to generate (default: 250)");
                println!("  --seed <U64>            Random seed for deterministic generation (default: 42)");
                println!("  --soak                  Run soak test with 2500+ iterations");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    Config {
        haproxy_bin,
        corpus_dir,
        findings_file,
        mutated_count,
        seed,
        soak,
    }
}

/// Self-test validating that the oracle and harness correctly classify 5 known-good requests.
fn run_self_test(haproxy: &mut HaproxyOracle) -> Result<(), String> {
    let test_vectors: [(&'static str, &'static [u8]); 5] = [
        ("Plain GET", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ("GET with query", b"GET /search?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ("POST with Content-Length", b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"),
        ("POST chunked", b"POST /chunked HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
        ("Pipelined pair", b"GET /p1 HTTP/1.1\r\nHost: example.com\r\n\r\nGET /p2 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    ];

    for (name, raw) in test_vectors {
        let ibex_res = parse_with_ibex(raw);
        let hp_res = haproxy.test_input(raw, false);

        if !ibex_res.accepted {
            return Err(format!(
                "Harness self-test FAILED on '{}': Ibex rejected a baseline valid request (phase={:?}, err={:?})",
                name, ibex_res.phase, ibex_res.error_message
            ));
        }

        if !hp_res.accepted {
            return Err(format!(
                "Harness self-test FAILED on '{}': HAProxy rejected a baseline valid request (status={:?}, err={:?}, raw_response={:?})",
                name, hp_res.status_code, hp_res.error_message, String::from_utf8_lossy(&hp_res.client_response)
            ));
        }
    }

    Ok(())
}

fn main() {
    let start_time = Instant::now();
    let config = parse_args();

    println!("================================================================================");
    println!("  Ibex HTTP/1 Parser Differential Fuzzing Harness");
    println!("================================================================================");
    println!("  Architecture: Hand-rolled Structured & Combinatorial Property Generator");
    println!("  Rationale:    Strict `#![forbid(unsafe_code)]` in Safe Stable Rust");
    println!("  Oracle:       HAProxy 3.5 ({})", config.haproxy_bin.display());
    println!("  Corpus Dir:   {}", config.corpus_dir.display());
    println!("  Findings Doc: {}", config.findings_file.display());
    println!("  Mode:         {}", if config.soak { "SOAK TEST (extended)" } else { "CI DEFAULT (under 2 min)" });
    println!("  Random Seed:  {}", config.seed);
    println!("================================================================================\n");

    // 1. Initialize HAProxy Oracle on dynamic ephemeral ports
    print!("[+] Initializing HAProxy 3.5 Oracle on dynamic ephemeral ports... ");
    let mut haproxy = match HaproxyOracle::new(&config.haproxy_bin) {
        Ok(h) => {
            println!("READY.");
            h
        }
        Err(e) => {
            eprintln!("\n[-] [FATAL] Failed to initialize HAProxy Oracle: {e}");
            std::process::exit(1);
        }
    };

    // 2. Run Self-Test on 5 Known-Good Baseline Requests
    print!("[+] Running harness self-test on 5 baseline valid requests... ");
    if let Err(e) = run_self_test(&mut haproxy) {
        eprintln!("\n[-] [FATAL] {e}");
        eprintln!("[-] The harness cannot correctly classify known-valid HTTP/1 requests. Aborting.");
        std::process::exit(1);
    }
    println!("PASSED (5/5 accepted by both parsers).");

    // 3. Generate Structured Test Cases
    println!("[+] Generating structured test cases targeting framing ambiguity classes...");
    let mut test_cases = generate_structured_corpus();
    let structured_count = test_cases.len();
    println!("    Generated {structured_count} structured CVE-class test cases.");

    // 4. Generate Combinatorial Mutation Cases
    println!("[+] Generating {} combinatorial mutation test cases (seed: {})...", config.mutated_count, config.seed);
    let mutated_cases = generate_mutated_cases(config.seed, config.mutated_count);
    test_cases.extend(mutated_cases);
    let total_count = test_cases.len();
    println!("    Total test cases to evaluate: {total_count}");

    // 5. Run Differential Testing Loop
    println!("\n[+] Running differential comparisons...");
    let mut findings = Vec::new();
    let mut accepted_both = 0;
    let mut rejected_both = 0;
    let mut finding_id_seq = 1;

    for (idx, tc) in test_cases.iter().enumerate() {
        // Evaluate with Ibex
        let ibex_res = parse_with_ibex(&tc.raw_bytes);

        // Evaluate with HAProxy (and sentinel request boundary check)
        let haproxy_res = haproxy.test_input(&tc.raw_bytes, !tc.is_pipelined);

        if ibex_res.accepted && haproxy_res.accepted {
            accepted_both += 1;
        } else if !ibex_res.accepted && !haproxy_res.accepted {
            rejected_both += 1;
        }

        // Compare results
        if let Some(finding) = compare_results(finding_id_seq, tc, &ibex_res, &haproxy_res) {
            println!(
                "  [!] Discrepancy #{:03} found on '{}': {}",
                finding.id, tc.name, finding.category.as_str()
            );
            findings.push(finding);
            finding_id_seq += 1;
        }

        if (idx + 1) % 50 == 0 || idx + 1 == total_count {
            print!("    Processed {} / {} cases...\r", idx + 1, total_count);
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    }
    println!("\n    Completed evaluation of {total_count} test cases in {:.2?}s.", start_time.elapsed());

    // 6. Save Corpus Artifacts
    print!("[+] Saving discrepancy inputs to corpus directory... ");
    if let Err(e) = save_corpus(&config.corpus_dir, &findings) {
        eprintln!("\n[-] Warning: Failed to save corpus: {e}");
    } else {
        println!("SAVED {} files.", findings.len());
    }

    // 7. Generate and Write FINDINGS.md
    print!("[+] Generating and writing {}... ", config.findings_file.display());
    let findings_md = generate_findings_markdown(
        total_count,
        accepted_both,
        rejected_both,
        &findings,
        &command_first_line(&config.haproxy_bin, &["-v"]),
        &command_first_line(std::path::Path::new("git"), &["rev-parse", "--short", "HEAD"]),
    );
    if let Err(e) = fs::write(&config.findings_file, findings_md) {
        eprintln!("\n[-] Warning: Failed to write findings markdown: {e}");
    } else {
        println!("DONE.");
    }

    // 8. Print Final Summary Table
    let mut cat1 = 0;
    let mut cat2 = 0;
    let mut cat3 = 0;
    let mut self_diff = 0;

    for f in &findings {
        match f.category {
            diff::DiscrepancyCategory::Category1Acceptance => cat1 += 1,
            diff::DiscrepancyCategory::Category2Framing => cat2 += 1,
            diff::DiscrepancyCategory::Category3SmugglingBoundary => cat3 += 1,
            diff::DiscrepancyCategory::SelfDifferential => self_diff += 1,
        }
    }

    println!("\n================================================================================");
    println!("  DIFFERENTIAL FUZZING RESULTS SUMMARY");
    println!("================================================================================");
    println!("  Total Cases Evaluated:       {total_count}");
    println!("  Accepted by Both:            {accepted_both}");
    println!("  Rejected by Both:            {rejected_both}");
    println!("  Total Disagreements:         {}", findings.len());
    println!("    - Category 1 (Acceptance): {cat1}");
    println!("    - Category 2 (Framing):    {cat2}");
    println!("    - Category 3 (Smuggling):  {cat3}");
    println!("    - Self-Differential:       {self_diff}");
    println!("  Elapsed Duration:            {:.2?}", start_time.elapsed());
    println!("================================================================================\n");
}

/// First line of a command's stdout, for the report header; "unknown" if it cannot be run.
fn command_first_line(bin: &std::path::Path, args: &[&str]) -> String {
    std::process::Command::new(bin)
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().next().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}
