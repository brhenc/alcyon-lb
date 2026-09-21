// SPDX-License-Identifier: GPL-2.0-or-later
//
// HAProxy 1.0 configuration parser, ported to Rust.
// Derived from HAProxy 1.0.2 (haproxy.c) by Willy Tarreau <willy@meta-x.org>.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const ORACLE_BIN: &str = "/home/bhenc/reference/haproxy-1.0.2/haproxy102";

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    Reject,
}

fn run_oracle(config_path: &Path) -> (Verdict, String) {
    let mut child = match Command::new(ORACLE_BIN)
        .arg("-f")
        .arg(config_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!("Failed to execute oracle binary at {ORACLE_BIN}: {e}"),
    };

    // Wait briefly to check if it exits on config error or stays running
    let wait_duration = Duration::from_millis(150);
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child.wait_with_output().unwrap();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                if status.success() {
                    return (Verdict::Accept, stderr);
                }
                return (Verdict::Reject, stderr);
            }
            Ok(None) => {
                if start.elapsed() >= wait_duration {
                    let _ = child.kill();
                    let output = child.wait_with_output().unwrap();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    return (Verdict::Accept, stderr);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("Error waiting for oracle process: {e}"),
        }
    }
}

#[test]
fn test_corpus_differential() {
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut entries: Vec<_> = fs::read_dir(&corpus_dir)
        .expect("Read corpus dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "cfg"))
        .collect();

    entries.sort();
    assert!(
        entries.len() >= 25,
        "Corpus must have at least 25 test configs, found {}",
        entries.len()
    );

    let known_disagreements = [
        "34_non_numeric_retries.cfg",
        "35_negative_retries.cfg",
        "36_non_numeric_contimeout.cfg",
        "37_out_of_range_port.cfg",
    ];

    let mut agreed_count = 0;
    let mut disagreement_count = 0;

    for path in &entries {
        let filename = path.file_name().unwrap().to_str().unwrap();
        let (oracle_verdict, oracle_msg) = run_oracle(path);
        let ibex_result = ibex_config::parse_file(path);
        let ibex_verdict = if ibex_result.is_ok() {
            Verdict::Accept
        } else {
            Verdict::Reject
        };

        let is_disagreement = known_disagreements.contains(&filename);

        if is_disagreement {
            disagreement_count += 1;
            assert_eq!(
                oracle_verdict,
                Verdict::Accept,
                "Case {filename} expected Oracle to accept due to 2001 C atol/overflow behavior"
            );
            assert_eq!(
                ibex_verdict,
                Verdict::Reject,
                "Case {filename} expected Ibex to reject invalid input"
            );
            println!(
                "[DISAGREEMENT] {filename}: Oracle={oracle_verdict:?}, Ibex={ibex_verdict:?} (Err: {})",
                ibex_result.unwrap_err()
            );
        } else {
            assert_eq!(
                oracle_verdict, ibex_verdict,
                "Mismatch on {filename}!\nOracle verdict: {oracle_verdict:?}\nOracle output: {oracle_msg}\nIbex verdict: {ibex_verdict:?}\nIbex result: {ibex_result:?}"
            );
            agreed_count += 1;
            println!("[AGREE] {filename}: {ibex_verdict:?}");
        }
    }

    println!(
        "\nCorpus verification complete: {} total cases, {} agreed, {} documented disagreements",
        entries.len(),
        agreed_count,
        disagreement_count
    );
}
