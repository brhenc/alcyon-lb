// SPDX-License-Identifier: GPL-2.0-or-later
// Integration tests for Ibex CLI options and HAProxy 3.5 command-line compatibility.

use std::fs;
use std::process::Command;
use tempfile::tempdir;

const IBEX_BIN: &str = env!("CARGO_BIN_EXE_ibex");

const VALID_CONFIG: &str = r"
global
    maxconn 1000

defaults
    mode http
    timeout client 10s
    timeout server 10s
    timeout connect 10s

listen test_proxy
    bind 127.0.0.1:58080
    server s1 127.0.0.1:58081
";

const INVALID_CONFIG: &str = r"
listen broken_proxy
    invalid_syntax_directive_unknown_token
";

#[test]
fn test_version_flags() {
    // -v short version
    let out_v = Command::new(IBEX_BIN)
        .arg("-v")
        .output()
        .expect("Failed to execute ibex -v");
    assert!(out_v.status.success(), "-v should exit with code 0");
    let stdout_v = String::from_utf8_lossy(&out_v.stdout);
    assert!(
        stdout_v.contains("Ibex version"),
        "stdout should contain 'Ibex version'"
    );
    assert!(
        stdout_v.contains("HAProxy 3.5 Compatibility Layer"),
        "stdout should mention HAProxy 3.5 compatibility"
    );

    // -vv extended version and build features
    let out_vv = Command::new(IBEX_BIN)
        .arg("-vv")
        .output()
        .expect("Failed to execute ibex -vv");
    assert!(out_vv.status.success(), "-vv should exit with code 0");
    let stdout_vv = String::from_utf8_lossy(&out_vv.stdout);
    assert!(
        stdout_vv.contains("Build options"),
        "-vv should display build options"
    );
    assert!(
        stdout_vv.contains("Feature list"),
        "-vv should display feature list"
    );
    assert!(
        stdout_vv.contains("+EPOLL"),
        "-vv should display epoll feature"
    );
    assert!(
        stdout_vv.contains("Available polling systems"),
        "-vv should display available polling systems"
    );
    assert!(
        stdout_vv.contains("Memory Safety Guarantee"),
        "-vv should state memory safety guarantee"
    );
}

#[test]
fn test_help_flag() {
    // -h help
    let out_h = Command::new(IBEX_BIN)
        .arg("-h")
        .output()
        .expect("Failed to execute ibex -h");
    assert!(out_h.status.success(), "-h should exit with code 0");
    let stdout_h = String::from_utf8_lossy(&out_h.stdout);
    assert!(
        stdout_h.contains("Usage :"),
        "-h should display usage information"
    );
    assert!(
        stdout_h.contains("-f <cfgfile|cfgdir>"),
        "-h should list -f option"
    );
    assert!(
        stdout_h.contains("-c check mode"),
        "-h should list -c option"
    );

    // --help long flag
    let out_help = Command::new(IBEX_BIN)
        .arg("--help")
        .output()
        .expect("Failed to execute ibex --help");
    assert!(out_help.status.success(), "--help should exit with code 0");
    let stdout_help = String::from_utf8_lossy(&out_help.stdout);
    assert!(
        stdout_help.contains("Usage :"),
        "--help should display usage information"
    );
}

#[test]
fn test_check_mode_valid_and_invalid() {
    let dir = tempdir().expect("create tempdir");
    let valid_path = dir.path().join("valid.cfg");
    fs::write(&valid_path, VALID_CONFIG).expect("write valid config");

    let invalid_path = dir.path().join("invalid.cfg");
    fs::write(&invalid_path, INVALID_CONFIG).expect("write invalid config");

    // Valid configuration check
    let out_valid = Command::new(IBEX_BIN)
        .arg("-c")
        .arg("-f")
        .arg(&valid_path)
        .output()
        .expect("Failed to run check on valid config");
    assert!(
        out_valid.status.success(),
        "-c on valid config must exit 0"
    );
    let stdout_valid = String::from_utf8_lossy(&out_valid.stdout);
    assert!(
        stdout_valid.contains("Configuration file is valid."),
        "stdout should confirm valid config"
    );

    // Valid check in quiet mode (-q)
    let out_quiet = Command::new(IBEX_BIN)
        .arg("-c")
        .arg("-q")
        .arg("-f")
        .arg(&valid_path)
        .output()
        .expect("Failed to run check with -q");
    assert!(out_quiet.status.success(), "-c -q must exit 0");
    assert!(
        out_quiet.stdout.is_empty(),
        "Quiet mode must produce no stdout on success"
    );

    // Invalid configuration check
    let out_invalid = Command::new(IBEX_BIN)
        .arg("-c")
        .arg("-f")
        .arg(&invalid_path)
        .output()
        .expect("Failed to run check on invalid config");
    assert!(
        !out_invalid.status.success(),
        "-c on invalid config must exit with non-zero status"
    );
    assert_eq!(
        out_invalid.status.code(),
        Some(1),
        "Invalid configuration must exit with code 1"
    );
}

#[test]
fn test_multiple_config_files() {
    let dir = tempdir().expect("create tempdir");
    let part1_path = dir.path().join("01_global.cfg");
    let part1_content = r"
global
    maxconn 3000

defaults
    mode http
    timeout client 10s
    timeout server 10s
    timeout connect 10s
";
    fs::write(&part1_path, part1_content).expect("write part 1");

    let part2_path = dir.path().join("02_listen.cfg");
    let part2_content = r"
listen multi_f_proxy
    bind 127.0.0.1:58082
    server s1 127.0.0.1:58083
";
    fs::write(&part2_path, part2_content).expect("write part 2");

    // Run with two -f flags
    let out = Command::new(IBEX_BIN)
        .arg("-c")
        .arg("-f")
        .arg(&part1_path)
        .arg("-f")
        .arg(&part2_path)
        .output()
        .expect("Failed to run multiple -f check");
    assert!(
        out.status.success(),
        "Multiple -f flags should parse cleanly"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Configuration file is valid."));

    // Run with trailing '--' file list
    let out_trailing = Command::new(IBEX_BIN)
        .arg("-c")
        .arg("--")
        .arg(&part1_path)
        .arg(&part2_path)
        .output()
        .expect("Failed to run trailing -- check");
    assert!(
        out_trailing.status.success(),
        "Trailing '--' config list should parse cleanly"
    );
}

#[test]
fn test_directory_config_expansion() {
    let dir = tempdir().expect("create tempdir");
    let conf_d = dir.path().join("conf.d");
    fs::create_dir(&conf_d).expect("create conf.d");

    // 1. Global & defaults section
    fs::write(
        conf_d.join("00-global.cfg"),
        r"
global
    maxconn 4000

defaults
    mode http
    timeout client 10s
    timeout server 10s
    timeout connect 10s
",
    )
    .expect("write 00-global.cfg");

    // 2. Listen section
    fs::write(
        conf_d.join("10-frontend.cfg"),
        r"
listen dir_expanded_proxy
    bind 127.0.0.1:58084
    server s1 127.0.0.1:58085
",
    )
    .expect("write 10-frontend.cfg");

    // 3. Hidden file (must be ignored, containing syntax that would error)
    fs::write(conf_d.join(".hidden.cfg"), "INVALID SYNTAX THAT WOULD CRASH")
        .expect("write .hidden.cfg");

    // 4. Non-.cfg file (must be ignored)
    fs::write(conf_d.join("readme.txt"), "This is a documentation file")
        .expect("write readme.txt");

    // Execute check pointing -f to directory
    let out = Command::new(IBEX_BIN)
        .arg("-c")
        .arg("-V")
        .arg("-f")
        .arg(&conf_d)
        .output()
        .expect("Failed to run directory config check");
    assert!(
        out.status.success(),
        "Directory expansion should load valid .cfg files in lexical order"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Total configuration files loaded: 2"),
        "Should load exactly 2 valid .cfg files, skipping hidden and non-.cfg files"
    );
}

#[test]
fn test_pidfile_creation() {
    let dir = tempdir().expect("create tempdir");
    let cfg_path = dir.path().join("test.cfg");
    fs::write(&cfg_path, VALID_CONFIG).expect("write test.cfg");

    let pid_path = dir.path().join("ibex.pid");

    // Run check mode with -p <pidfile>
    let out = Command::new(IBEX_BIN)
        .arg("-c")
        .arg("-f")
        .arg(&cfg_path)
        .arg("-p")
        .arg(&pid_path)
        .output()
        .expect("Failed to run ibex with -p");
    assert!(out.status.success(), "Execution with -p should succeed");

    assert!(pid_path.exists(), "Pidfile must be created at path");
    let content = fs::read_to_string(&pid_path).expect("read pidfile");
    let trimmed = content.trim();
    let parsed_pid: u32 = trimmed.parse().expect("Pidfile must contain a valid PID integer");
    assert!(parsed_pid > 0, "PID must be greater than 0");
}

#[test]
fn test_maxconn_parameter_override() {
    let dir = tempdir().expect("create tempdir");
    let cfg_path = dir.path().join("test.cfg");
    fs::write(&cfg_path, VALID_CONFIG).expect("write test.cfg");

    // Run check with -n 8888 in verbose mode (-V)
    let out = Command::new(IBEX_BIN)
        .arg("-c")
        .arg("-V")
        .arg("-n")
        .arg("8888")
        .arg("-f")
        .arg(&cfg_path)
        .output()
        .expect("Failed to run ibex with -n override");
    assert!(out.status.success(), "-n override check should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Global maxconn override: 8888"),
        "Verbose output should confirm global maxconn override of 8888"
    );

    // Invalid -n argument
    let out_bad = Command::new(IBEX_BIN)
        .arg("-c")
        .arg("-n")
        .arg("invalid_not_a_number")
        .arg("-f")
        .arg(&cfg_path)
        .output()
        .expect("Failed to run ibex with invalid -n");
    assert_eq!(
        out_bad.status.code(),
        Some(1),
        "Invalid integer for -n must exit with code 1"
    );
}

#[test]
fn test_working_directory_change() {
    let dir = tempdir().expect("create tempdir");
    let sub_dir = dir.path().join("subdir");
    fs::create_dir(&sub_dir).expect("create subdir");

    let rel_cfg = sub_dir.join("relative.cfg");
    fs::write(&rel_cfg, VALID_CONFIG).expect("write relative.cfg");

    // -C sub_dir allows referencing "relative.cfg" relatively
    let out = Command::new(IBEX_BIN)
        .arg("-C")
        .arg(&sub_dir)
        .arg("-f")
        .arg("relative.cfg")
        .arg("-c")
        .output()
        .expect("Failed to run ibex with -C");
    assert!(
        out.status.success(),
        "-C should change working directory before loading relative configs"
    );
}

#[test]
fn test_diagnostic_flags() {
    let dir = tempdir().expect("create tempdir");
    let cfg_path = dir.path().join("test.cfg");
    fs::write(&cfg_path, VALID_CONFIG).expect("write test.cfg");

    let out = Command::new(IBEX_BIN)
        .arg("-c")
        .arg("-dr")
        .arg("-de")
        .arg("-dp")
        .arg("-dM")
        .arg("-dL")
        .arg("-f")
        .arg(&cfg_path)
        .output()
        .expect("Failed to run diagnostic flags");
    assert!(out.status.success(), "Diagnostic flags should exit cleanly");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("[DIAG] Flag -dr"),
        "stderr should log -dr flag"
    );
    assert!(
        stderr.contains("[DIAG] Flag -de"),
        "stderr should log -de flag"
    );
    assert!(
        stderr.contains("[DIAG] Flag -dp"),
        "stderr should log -dp flag"
    );
    assert!(
        stderr.contains("[DIAG] Flag -dM"),
        "stderr should log -dM flag"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(".so"),
        "-dL should list loaded dynamic shared objects"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_unsupported_tcp_request_actions_are_refused() {
    // Valid control configuration should succeed
    let valid_cases = [
        "tcp-request content sc-inc-gpc0",
        "tcp-request content sc-inc-gpc0(0)",
        "tcp-request content sc-inc-gpc0(1)",
        "tcp-request content sc-inc-gpc0(2)",
        "tcp-request content sc-inc-gpc1",
        "tcp-request content sc-inc-gpc1(1)",
        "tcp-request content sc-set-gpt0 42",
        "tcp-request content sc-set-gpt0(1) 99",
        "tcp-request session sc-inc-gpc0",
        "tcp-request session sc-inc-gpc0(1)",
        "tcp-request session sc-inc-gpc1",
        "tcp-request session sc-set-gpt0 10",
        "http-request sc-inc-gpc0",
        "http-request sc-inc-gpc0(2)",
        "http-request sc-inc-gpc1",
        "http-request sc-set-gpt0 55",
    ];
    for valid_line in valid_cases {
        let dir = tempdir().expect("create tempdir");
        let cfg_path = dir.path().join("test.cfg");
        let cfg = format!(
            r"
global
    maxconn 100

defaults
    mode http
    timeout client 10s
    timeout server 10s
    timeout connect 10s

frontend fe
    bind 127.0.0.1:58080
    stick-table type ip size 100 store gpc0,gpc1,gpt0
    tcp-request content track-sc0 src
    {valid_line}
"
        );
        fs::write(&cfg_path, &cfg).expect("write test.cfg");
        let out = Command::new(IBEX_BIN)
            .arg("-f")
            .arg(&cfg_path)
            .arg("-c")
            .output()
            .expect("Failed to execute ibex -c");
        assert!(
            out.status.success(),
            "ibex -c should succeed for valid line '{valid_line}', got stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Invalid / unsupported actions must be refused with descriptive messages naming the action
    let refused_cases = [
        ("tcp-request content lua.handler", "lua actions require Lua support"),
        ("tcp-request content use-service s1", "use-service"),
        ("tcp-request session attach-srv s1", "attach-srv"),
        ("tcp-request content do-log", "do-log"),
        ("tcp-request session do-log", "do-log"),
        ("tcp-request connection do-log", "do-log"),
        ("tcp-request content sc-inc-gpc0(99)", "stick counter index must be 0, 1, or 2"),
        ("tcp-request content sc-inc-gpc0(abc)", "invalid stick counter index"),
        ("tcp-request content sc-inc-gpc0(0", "missing closing parenthesis"),
        ("tcp-request content sc-inc-gpc0foo", "invalid stick table track ID"),
        ("tcp-request session sc-inc-gpc0(99)", "stick counter index must be 0, 1, or 2"),
        ("tcp-request session sc-inc-gpc0foo", "invalid stick table track ID"),
        ("http-request sc-inc-gpc0(99)", "stick counter index must be 0, 1, or 2"),
        ("http-request sc-inc-gpc0foo", "invalid stick table track ID"),
    ];

    for (line, expected_msg) in refused_cases {
        let dir = tempdir().expect("create tempdir");
        let cfg_path = dir.path().join("test.cfg");
        let cfg = format!(
            r"
global
    maxconn 100

defaults
    mode tcp
    timeout client 10s
    timeout server 10s
    timeout connect 10s

frontend fe
    bind 127.0.0.1:58080
    stick-table type ip size 100 store gpc0
    tcp-request content track-sc0 src
    {line}
"
        );
        fs::write(&cfg_path, &cfg).expect("write test.cfg");
        let out = Command::new(IBEX_BIN)
            .arg("-f")
            .arg(&cfg_path)
            .arg("-c")
            .output()
            .expect("Failed to execute ibex -c");
        assert!(
            !out.status.success(),
            "ibex -c should fail for refused/invalid action: {line}"
        );
        let err_output = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            err_output.contains(expected_msg),
            "Expected '{expected_msg}' in error output for '{line}', got:\n{err_output}"
        );
    }
}

#[test]
fn test_extended_version_does_not_advertise_unreachable_h2() {
    let out_vv = Command::new(IBEX_BIN)
        .arg("-vv")
        .output()
        .expect("Failed to execute ibex -vv");
    assert!(out_vv.status.success(), "-vv should exit with code 0");
    let stdout_vv = String::from_utf8_lossy(&out_vv.stdout);
    assert!(
        !stdout_vv.contains("+H2"),
        "-vv must not advertise +H2 while H2 is unreachable from daemon"
    );
    assert!(
        stdout_vv.contains("-H2"),
        "-vv should explicitly state -H2"
    );
    assert!(
        !stdout_vv.contains("mux=H2"),
        "-vv must not list H2 in available multiplexers while unreachable"
    );
}
