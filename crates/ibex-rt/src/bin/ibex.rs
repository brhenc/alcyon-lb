// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Ibex Load Balancer main daemon entrypoint.

//! Ibex main executable binary with `HAProxy` 3.5 command-line interface compatibility.

#![forbid(unsafe_code)]
#![allow(clippy::struct_excessive_bools)]

#[path = "ibex/identity.rs"]
mod identity;
#[path = "ibex/master.rs"]
mod master;

use ibex_rt::Engine;
use rustix::process::{kill_process, Pid, Resource, Rlimit, setrlimit, Signal};
use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

/// `println!` that does not panic when stdout is closed (`ibex -h | head`): the output is
/// best effort, and an EPIPE is the reader's choice, not an error of ours.
macro_rules! println {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($arg)*);
    }};
}

/// Command-line parsed options for Ibex runtime.
#[derive(Debug, Default)]
struct CliOptions {
    config_paths: Vec<PathBuf>,
    stats_socket: Option<PathBuf>,
    /// `-S <path>[,<opts>]`: the master CLI, raw (see `master::parse_socket`).
    master_socket: Option<String>,
    check_only: bool,
    /// `-cc <condition>`: evaluated once the whole command line is read, the last one wins.
    check_condition: Option<String>,
    change_dir: Option<PathBuf>,
    pid_file: Option<PathBuf>,
    quiet: bool,
    verbose: bool,
    daemon_mode: bool,
    debug_mode: bool,
    master_worker: bool,
    systemd_notify: bool,
    maxconn: Option<u32>,
    maxpconn: Option<u32>,
    memory_limit_mb: Option<u64>,
    sf_pids: Vec<u32>,
    /// `-x <socket>`: take the listening sockets over from the process behind this socket.
    old_socket: Option<PathBuf>,
    st_pids: Vec<u32>,
    ignore_resolve_fail: bool,
    disable_epoll: bool,
    disable_poll: bool,
    dump_libs: bool,
    overrides: Vec<String>,
}

fn print_help(program: &str) {
    println!("Ibex 0.1.0 - Memory-Safe Soft-Realtime Load Balancer (HAProxy 3.5 compatibility)");
    println!("Usage : {program} [-f <cfgfile|cfgdir>]* [ -vdVD ] [ -n <maxconn> ] [ -N <maxpconn> ]");
    println!("        [ -p <pidfile> ] [ -m <max megs> ] [ -C <dir> ] [-- <cfgfile>*]");
    println!("        -v displays version ; -vv shows known build options.");
    println!("        -vq/-vqs/-vqb only displays version, short version, branch.");
    println!("        -d enters debug mode ; -db only disables background mode.");
    println!("        -V enters verbose mode (disables quiet mode)");
    println!("        -D goes daemon ; -C changes to <dir> before loading files.");
    println!("        -W reload on SIGUSR2, handing listening sockets to the new process.");
    println!("        -Ws as -W, with systemd notify support (Type=notify).");
    println!("        -x <unix_socket> get listening sockets from a unix socket");
    println!("        -q quiet mode : don't display messages");
    println!("        -c check mode : only check config files and exit");
    println!("        -n sets the maximum total # of connections");
    println!("        -m limits the usable amount of memory (in MB)");
    println!("        -N sets the default, per-proxy maximum # of connections");
    println!("        -p writes pids of all children to this file");
    println!("        -de disables epoll() usage even when available");
    println!("        -dp disables poll() usage even when available");
    println!("        -dr ignores server address resolution failures");
    println!("        -dL dumps loaded object files after config checks");
    println!("        -sf/-st [pid ]* finishes/terminates old pids.");
    println!("        -S <bind>[,<bind options>...] master CLI / stats socket");
    println!("        -e <setting> override configuration directives");
    println!("        -h, --help show this help message");
}

fn print_version() {
    println!("Ibex version 0.1.0 2026/09/21 - https://github.com/project-ibex/ibex");
    println!("HAProxy 3.5 Compatibility Layer (Memory-Safe Soft-Realtime Engine)");
    println!("Running on: Linux x86_64");
}

fn print_plain_version(arg: &str) {
    match arg {
        "-vqs" | "-vqb" => println!("0.1"),
        _ => println!("0.1.0"),
    }
}

fn print_extended_version() {
    println!("Ibex version 0.1.0 2026/09/21 - https://github.com/project-ibex/ibex");
    println!("HAProxy 3.5 Compatibility Layer (Memory-Safe Soft-Realtime Engine)");
    println!("Running on: Linux x86_64");
    println!();
    println!("Build options :");
    println!("  TARGET  = x86_64-unknown-linux-gnu");
    println!("  CC      = rustc (cargo)");
    println!("  OPTIONS = STRICT_FORBID_UNSAFE=1 USE_EPOLL=1 USE_POLL=1 USE_RUSTLS=1 USE_HTX=1");
    println!();
    println!("Feature list : +EPOLL +POLL -KQUEUE -EVPORTS +H1 +H2 +HTX +PROXY_V1 +PROXY_V2 +STICK_TABLES +CRDT +APPLET +CLI +HEALTH_CHECKS +CONTENT_SWITCHING +FORBID_UNSAFE_CODE");
    println!();
    println!("Default settings :");
    println!("  bufsize = 16384, maxconn = 65536, maxpollevents = 200");
    println!();
    println!("Available polling systems :");
    println!("      epoll : pref=300,  test result OK");
    println!("       poll : pref=200,  test result OK");
    println!("Total: 2 (2 usable), will use epoll.");
    println!();
    println!("Available multiplexer protocols :");
    println!("         h2 : mode=HTTP  side=FE|BE  mux=H2    flags=");
    println!("         h1 : mode=HTTP  side=FE|BE  mux=H1    flags=");
    println!("       none : mode=TCP   side=FE|BE  mux=PASS  flags=");
    println!();
    println!("Memory Safety Guarantee :");
    println!("  100% pure safe Rust (#![forbid(unsafe_code)] enforced across all crates).");
}

/// Expands a list of files and directories into a flattened, lexically-ordered file list.
///
/// Follows `HAProxy` 3.5 `cfgfiles_expand_directories()` semantics:
/// - Hidden files (starting with '.') are skipped.
/// - Only regular files ending with `.cfg` are included.
/// - Directory entries are sorted in strict lexical order (`LC_COLLATE=C`).
fn expand_config_paths(inputs: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for path in inputs {
        if !path.exists() {
            return Err(format!(
                "Cannot open configuration file/directory {} : No such file or directory",
                path.display()
            ));
        }
        if path.is_dir() {
            let entries = std::fs::read_dir(path).map_err(|e| {
                format!(
                    "Cannot open configuration directory '{}': {e}",
                    path.display()
                )
            })?;
            let mut dir_files = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|e| format!("Error reading directory entry: {e}"))?;
                let file_name = entry.file_name();
                let name = file_name.to_string_lossy();
                let is_cfg = Path::new(&*name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("cfg"));
                if name.starts_with('.') || !is_cfg {
                    continue;
                }
                let file_type = entry.file_type().map_err(|e| {
                    format!(
                        "Error reading file metadata for '{}': {e}",
                        entry.path().display()
                    )
                })?;
                if file_type.is_file() {
                    dir_files.push(entry.path());
                }
            }
            dir_files.sort();
            files.extend(dir_files);
        } else {
            files.push(path.clone());
        }
    }
    if files.is_empty() {
        return Err("No configuration files found to parse.".to_string());
    }
    Ok(files)
}

/// Safely sends signal `sig` to each PID in `pids`.
fn send_signals_to_pids(pids: &[u32], signal: Signal, quiet: bool) {
    for &pid in pids {
        if let Ok(pid_i32) = i32::try_from(pid) {
            if let Some(target) = Pid::from_raw(pid_i32) {
                if let Err(err) = kill_process(target, signal) {
                    if !quiet && err != rustix::io::Errno::SRCH {
                        ibex_rt::stderr_line!("[WARNING] Failed to send signal {signal:?} to PID {pid}: {err}");
                    }
                }
            }
        }
    }
}

/// Dumps loaded dynamic libraries by safely parsing `/proc/self/maps`.
fn dump_loaded_libraries() {
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        let mut seen = std::collections::BTreeSet::new();
        for line in maps.lines() {
            if let Some(idx) = line.find('/') {
                let path = &line[idx..];
                let is_so = Path::new(path)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))
                    || path.contains(".so.");
                if is_so {
                    seen.insert(path.to_string());
                }
            }
        }
        for lib in seen {
            println!("{lib}");
        }
    }
}

fn parse_arg_u32(val: &str, flag: &str) -> u32 {
    val.parse::<u32>().unwrap_or_else(|_| {
        ibex_rt::stderr_line!("Option {flag}: invalid integer argument '{val}'");
        process::exit(1);
    })
}

fn parse_arg_u64(val: &str, flag: &str) -> u64 {
    val.parse::<u64>().unwrap_or_else(|_| {
        ibex_rt::stderr_line!("Option {flag}: invalid integer argument '{val}'");
        process::exit(1);
    })
}

#[allow(clippy::too_many_lines)]
fn parse_cli_args(args: &[String]) -> (String, CliOptions) {
    let program = args.first().map_or("ibex", String::as_str).to_string();
    let mut opts = CliOptions::default();

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-f" => {
                i += 1;
                if i >= args.len() {
                    ibex_rt::stderr_line!("Option -f expects a configuration file/directory path argument.");
                    process::exit(1);
                }
                opts.config_paths.push(PathBuf::from(&args[i]));
            }
            "--" => {
                // All remaining arguments are treated as configuration paths
                while i + 1 < args.len() {
                    i += 1;
                    opts.config_paths.push(PathBuf::from(&args[i]));
                }
            }
            // `-cc <expr>` evaluates a build condition and exits: 0 for true, 1 for
            // false. The reg-tests gate themselves on it, and a binary that does not
            // implement it fails every gate, so every gated test skips -- which a
            // scoreboard cannot tell apart from "not applicable".
            //
            // Matched before "-c" because a prefix match would swallow it.
            "-cc" => {
                i += 1;
                if i >= args.len() {
                    ibex_rt::stderr_line!("Option -cc expects a condition expression.");
                    process::exit(1);
                }
                opts.check_condition = Some(args[i].clone());
            }
            "-c" => {
                opts.check_only = true;
            }
            "-C" => {
                i += 1;
                if i >= args.len() {
                    ibex_rt::stderr_line!("Option -C expects a directory path argument.");
                    process::exit(1);
                }
                opts.change_dir = Some(PathBuf::from(&args[i]));
            }
            "-q" => {
                opts.quiet = true;
            }
            "-V" => {
                opts.verbose = true;
                opts.quiet = false;
            }
            "-v" | "--version" => {
                print_version();
                process::exit(0);
            }
            "-vv" => {
                print_extended_version();
                process::exit(0);
            }
            "-vq" | "-vqs" | "-vqb" => {
                print_plain_version(arg);
                process::exit(0);
            }
            "-h" | "--help" => {
                print_help(&program);
                process::exit(0);
            }
            "-D" => {
                opts.daemon_mode = true;
            }
            "-db" => {
                opts.debug_mode = false;
                opts.daemon_mode = false;
            }
            "-d" => {
                opts.debug_mode = true;
                opts.daemon_mode = false;
            }
            "-W" => {
                opts.master_worker = true;
            }
            "-Ws" => {
                opts.master_worker = true;
                opts.systemd_notify = true;
                opts.daemon_mode = false;
            }
            "-p" => {
                i += 1;
                if i >= args.len() {
                    ibex_rt::stderr_line!("Option -p expects a pidfile path argument.");
                    process::exit(1);
                }
                opts.pid_file = Some(PathBuf::from(&args[i]));
            }
            "-x" => {
                i += 1;
                if i >= args.len() {
                    ibex_rt::stderr_line!("Option -x requires a unix socket path");
                    process::exit(1);
                }
                opts.old_socket = Some(PathBuf::from(&args[i]));
            }
            "-sf" => {
                while i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 1;
                    opts.sf_pids.push(parse_arg_u32(&args[i], "-sf"));
                }
            }
            "-st" => {
                while i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 1;
                    opts.st_pids.push(parse_arg_u32(&args[i], "-st"));
                }
            }
            "-S" | "-s" | "--stats-socket" => {
                i += 1;
                if i >= args.len() {
                    ibex_rt::stderr_line!("Option -S expects a socket path argument.");
                    process::exit(1);
                }
                // `-S` is the master CLI (see master.rs); `-s` / `--stats-socket` are Ibex's
                // command-line stats socket.
                let raw = &args[i];
                let sock_str = raw.split(',').next().unwrap_or(raw);
                let sock_str = sock_str.strip_prefix("unix@").unwrap_or(sock_str);
                if arg == "-S" {
                    opts.master_socket = Some(raw.clone());
                } else {
                    opts.stats_socket = Some(PathBuf::from(sock_str));
                }
            }
            "-n" => {
                i += 1;
                if i >= args.len() {
                    ibex_rt::stderr_line!("Option -n expects an integer argument (maxconn).");
                    process::exit(1);
                }
                opts.maxconn = Some(parse_arg_u32(&args[i], "-n"));
            }
            "-N" => {
                i += 1;
                if i >= args.len() {
                    ibex_rt::stderr_line!("Option -N expects an integer argument (maxpconn).");
                    process::exit(1);
                }
                opts.maxpconn = Some(parse_arg_u32(&args[i], "-N"));
            }
            "-m" => {
                i += 1;
                if i >= args.len() {
                    ibex_rt::stderr_line!("Option -m expects an integer argument (megabytes).");
                    process::exit(1);
                }
                opts.memory_limit_mb = Some(parse_arg_u64(&args[i], "-m"));
            }
            "-dr" => {
                opts.ignore_resolve_fail = true;
            }
            "-de" => {
                opts.disable_epoll = true;
            }
            "-dp" => {
                opts.disable_poll = true;
            }
            "-dL" => {
                opts.dump_libs = true;
            }
            "-e" => {
                i += 1;
                if i < args.len() {
                    opts.overrides.push(args[i].clone());
                }
            }
            other if other.starts_with("-f") => {
                opts.config_paths.push(PathBuf::from(&other[2..]));
            }
            other if other.starts_with("-C") => {
                opts.change_dir = Some(PathBuf::from(&other[2..]));
            }
            other if other.starts_with("-p") => {
                opts.pid_file = Some(PathBuf::from(&other[2..]));
            }
            other if other.starts_with("-n") => {
                opts.maxconn = Some(parse_arg_u32(&other[2..], "-n"));
            }
            other if other.starts_with("-N") => {
                opts.maxpconn = Some(parse_arg_u32(&other[2..], "-N"));
            }
            other if other.starts_with("-m") => {
                opts.memory_limit_mb = Some(parse_arg_u64(&other[2..], "-m"));
            }
            other if other.starts_with("-dM") => {
                ibex_rt::stderr_line!(
                    "{other}: -dM (memory pool debugging) is not supported: Ibex has no memory pools to poison"
                );
                process::exit(1);
            }
            unknown => {
                ibex_rt::stderr_line!("Unknown option: {unknown}");
                print_help(&program);
                process::exit(1);
            }
        }
        i += 1;
    }

    (program, opts)
}

/// `HAProxy`'s alert line without a subsystem: `[ALERT]    (<pid>) : <text>`.
fn config_alert_plain(text: &str) {
    ibex_rt::stderr_line!("[ALERT]    ({}) : {text}", process::id());
}

/// `HAProxy`'s alert line: `[ALERT]    (<pid>) : config : <text>`.
fn config_alert(text: &str) {
    ibex_rt::stderr_line!("[ALERT]    ({}) : config : {text}", process::id());
}

/// The file a line of the merged configuration text is in, and its line there.
fn locate(starts: &[(u32, String)], line: usize) -> (&str, usize) {
    let line = u32::try_from(line).unwrap_or(u32::MAX);
    starts
        .iter()
        .rev()
        .find(|(first, _)| *first <= line)
        .map_or(("", line as usize), |(first, path)| (path.as_str(), (line - first + 1) as usize))
}

/// Reports a configuration that does not load as `HAProxy` does and exits 1: the alerts, then
/// the file the errors are in.
fn config_failed(starts: &[(u32, String)], at: Option<usize>, msg: &str) -> ! {
    match at.map(|line| locate(starts, line)) {
        Some((file, line)) => {
            config_alert(&format!("parsing [{file}:{line}] : {msg}"));
            config_alert(&format!("Error(s) found in configuration file : {file}"));
        }
        None => {
            config_alert(msg);
            let files: Vec<&str> = starts.iter().map(|(_, f)| f.as_str()).collect();
            config_alert(&format!("Error(s) found in configuration file : {}", files.join(", ")));
        }
    }
    config_alert("Fatal errors found in configuration.");
    process::exit(1);
}

fn load_and_merge_configs(config_files: &[PathBuf]) -> (String, Vec<(u32, String)>) {
    let mut combined = String::new();
    // Where each file starts in the text, for the `file:line` of `last_rule_file`.
    let mut starts = Vec::new();
    for path in config_files {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                starts.push((u32::try_from(combined.matches('\n').count() + 1).unwrap_or(u32::MAX), path.display().to_string()));
                combined.push_str(&content);
                if !combined.ends_with('\n') {
                    combined.push('\n');
                }
            }
            Err(err) => {
                config_alert(&format!("Cannot open configuration file/directory {} : {err}", path.display()));
                process::exit(1);
            }
        }
    }
    ibex_rt::engine::set_config_files(starts.clone());
    (combined, starts)
}

fn report_diagnostics(opts: &CliOptions) {
    if opts.ignore_resolve_fail && !opts.quiet {
        ibex_rt::stderr_line!("[DIAG] Flag -dr: ignoring server address resolution failures.");
    }
    if opts.disable_epoll && !opts.quiet {
        ibex_rt::stderr_line!("[DIAG] Flag -de: disabling epoll poller (falling back to standard poll).");
    }
    if opts.disable_poll && !opts.quiet {
        ibex_rt::stderr_line!("[DIAG] Flag -dp: disabling poll poller.");
    }
    if opts.dump_libs {
        dump_loaded_libraries();
    }
}

fn enforce_memory_limit(megs: u64, quiet: bool) {
    let bytes = megs.saturating_mul(1024 * 1024);
    let rlim = Rlimit {
        current: Some(bytes),
        maximum: Some(bytes),
    };
    if let Err(err) = setrlimit(Resource::As, rlim) {
        if !quiet {
            ibex_rt::stderr_line!("[WARNING] Unable to enforce memory limit (-m {megs} MB): {err}");
        }
    }
}

fn handle_pid_file(pid_path: &Path) {
    let pid = std::process::id();
    if let Err(err) = std::fs::write(pid_path, format!("{pid}\n")) {
        ibex_rt::stderr_line!("Cannot create pidfile '{}': {err}", pid_path.display());
        process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    // A panic anywhere is a bug and takes the whole process down (T238).
    ibex_rt::crash::abort_on_panic();
    let raw_args: Vec<String> = env::args().collect();
    let (program, opts) = parse_cli_args(&raw_args);
    // `HAProxy` evaluates a `-cc` condition before anything else and exits: 0 for true, 1
    // for false, 2 when it does not evaluate.
    if let Some(cond) = &opts.check_condition {
        match ibex_rt::cond::eval_cc(cond) {
            Ok(true) => process::exit(0),
            Ok(false) => process::exit(1),
            Err(msg) => {
                ibex_rt::stderr_line!("[ALERT] : {msg}");
                process::exit(2);
            }
        }
    }
    // `-S` is HAProxy's master CLI: it needs master-worker mode, and an option it does not
    // apply stops the start rather than being dropped.
    let master_sock = opts.master_socket.as_deref().map(|raw| {
        if !opts.master_worker {
            config_alert_plain("a master CLI socket was defined, but master-worker mode (-W) is not enabled.");
            process::exit(1);
        }
        master::parse_socket(raw).unwrap_or_else(|e| {
            config_alert_plain(&e);
            config_alert_plain("Can't create the master's CLI.");
            process::exit(1);
        })
    });
    // Set by the master that started this process as one of its workers.
    let master_dir = std::env::var_os(master::MASTER_DIR_ENV).map(PathBuf::from);
    std::env::remove_var(master::MASTER_DIR_ENV);
    // A reload restarts this binary with these same arguments; relative paths in them are
    // relative to where it was started, not to wherever `-C` moved it.
    let start_dir = std::env::current_dir().ok();
    // Set by the process that started this one to take over from it (see `Reload`).
    let reload_child = std::env::var_os("IBEX_RELOAD_CHILD").is_some();
    std::env::remove_var("IBEX_RELOAD_CHILD");

    // 1. Change working directory if requested via -C <dir>
    if let Some(ref dir) = opts.change_dir {
        if let Err(err) = std::env::set_current_dir(dir) {
            ibex_rt::stderr_line!("Cannot change directory to '{}': {err}", dir.display());
            process::exit(1);
        }
    }

    // 2. Validate that configuration files were provided
    if opts.config_paths.is_empty() {
        ibex_rt::stderr_line!("Error: No configuration file specified. Use -f <path>.");
        print_help(&program);
        process::exit(1);
    }

    // 3. Expand directories and collect config files in lexical order
    let config_files = match expand_config_paths(&opts.config_paths) {
        Ok(files) => files,
        Err(err) => {
            config_alert(&err);
            process::exit(1);
        }
    };

    // 4. Read and concatenate all configuration files
    let (combined_config, config_starts) = load_and_merge_configs(&config_files);

    // 5. Parse unified configuration AST
    let mut config = match ibex_config::parse_str(&combined_config) {
        Ok(cfg) => cfg,
        Err(err) if !err.alerts.is_empty() => {
            // Checks that name their own place print as `HAProxy`'s do: one alert each, its
            // `[file:line]` in the text, and no other line (`src/proxy.c`'s check of the
            // buffer size for HTTP/2).
            for (line, text) in &err.alerts {
                let (file, line) = locate(&config_starts, *line);
                ibex_rt::stderr_line!("[ALERT]    ({}) : {}", process::id(), text.replace("{at}", &format!("[{file}:{line}]")));
            }
            process::exit(1);
        }
        Err(err) => {
            config_failed(&config_starts, Some(err.line), &err.message);
        }
    };

    // 5-bis. `.warning` and `.notice` lines of the configuration, as HAProxy prints them
    //     while it loads (`.alert` has failed the parse).
    for m in &config.directive_messages {
        let file = if config_files.len() == 1 { config_files[0].display().to_string() } else { "<config>".to_string() };
        let (sev, pad) = if m.warning { ("WARNING", " ") } else { ("NOTICE", "  ") };
        ibex_rt::stderr_line!("[{sev}]{pad} ({}) : config : parsing [{file}:{}]: '{}'.", process::id(), m.line, m.text);
    }

    // 5-ter. What the keywords printed while they were parsed and went on (a second `user`,
    //     a `uid` that is not a number, `cookie` in a frontend), in the order of the lines,
    //     each in the frame HAProxy gives it; then what it finds once everything is read
    //     (no `bind`, missing timeouts).
    let mut load_msgs: Vec<&ibex_config::ast::global::LoadWarning> =
        config.global.iter().flat_map(|g| &g.load_warnings).chain(&config.proxy_warnings).collect();
    load_msgs.sort_by_key(|w| w.line);
    let mut warned = config.directive_messages.iter().any(|m| m.warning);
    for w in load_msgs {
        use ibex_config::ast::global::WarnStyle;
        let (file, line) = locate(&config_starts, w.line);
        let sev = if w.alert { "[ALERT]   " } else { "[WARNING] " };
        let pid = process::id();
        match w.style {
            WarnStyle::Spaced => ibex_rt::stderr_line!("{sev} ({pid}) : config : parsing [{file}:{line}] : {}", w.text),
            WarnStyle::SpacedBlank => ibex_rt::stderr_line!("{sev} ({pid}) : config : parsing [{file}:{line}] : {}\n", w.text),
            WarnStyle::Tight => ibex_rt::stderr_line!("{sev} ({pid}) : config : parsing [{file}:{line}]: {}", w.text),
            WarnStyle::At => ibex_rt::stderr_line!("{sev} ({pid}) : config : [{file}:{line}] : {}", w.text),
        }
        warned |= !w.alert;
    }
    for text in config.check_warnings() {
        ibex_rt::stderr_line!("[WARNING]  ({}) : {text}", process::id());
        warned = true;
    }

    // 5a. Every rule action's expression must name fetches and converters that exist.
    //     `HAProxy` refuses the configuration otherwise; checked here so that `-c` reports
    //     it and a start fails before anything is daemonized, signalled or bound.
    if let Err(e) = ibex_rt::rule_exprs::validate_config(&config) {
        config_failed(&config_starts, None, &e);
    }

    // 5a-bis. `default_backend`, `use_backend` and `track-sc` tables that name nothing: what
    //     `HAProxy` checks once everything is read, after the rules' expressions.
    if let Err(err) = config.check_references() {
        for (_, text) in &err.alerts {
            ibex_rt::stderr_line!("[ALERT]    ({}) : {text}", process::id());
        }
        process::exit(1);
    }

    // 5b. TLS is wired now: `Engine::new` builds a rustls config per `bind ... ssl crt`
    // and refuses to start if one cannot be loaded, so the blanket guard that used to
    // live here is gone. What it protected against has not changed -- a listener on :443
    // serving cleartext to clients that believe they negotiated TLS -- it is just
    // enforced where the certificates actually are, in `bind_tls`, and again per
    // connection in the accept path, which drops rather than downgrades.

    // 6. Apply command-line maxconn override (-n <maxconn>)
    if let Some(mc) = opts.maxconn {
        for listen in &mut config.listens {
            if listen.maxconn == 0 || listen.maxconn > mc {
                listen.maxconn = mc;
            }
        }
        for frontend in &mut config.frontends {
            if frontend.maxconn == 0 || frontend.maxconn > mc {
                frontend.maxconn = mc;
            }
        }
    }

    // 7. Diagnostic reporting
    report_diagnostics(&opts);

    // 7.5 Daemon mode
    if opts.daemon_mode && env::var("IBEX_DAEMON_CHILD").is_err() {
        let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from(&program));
        let mut cmd = process::Command::new(exe);
        cmd.args(env::args().skip(1));
        cmd.env("IBEX_DAEMON_CHILD", "1");
        cmd.stdin(process::Stdio::null());
        cmd.stdout(process::Stdio::null());
        cmd.stderr(process::Stdio::null());
        match cmd.spawn() {
            Ok(child) => {
                if let Some(ref pidfile) = opts.pid_file {
                    if let Err(err) = std::fs::write(pidfile, format!("{}\n", child.id())) {
                        ibex_rt::stderr_line!("Cannot create pidfile '{}': {}", pidfile.display(), err);
                        process::exit(1);
                    }
                }
                process::exit(0);
            }
            Err(e) => {
                ibex_rt::stderr_line!("Failed to daemonize: {e}");
                process::exit(1);
            }
        }
    }


    // 8. Write PID file if requested (-p <pidfile>). A process started by a reload waits
    //    until it has taken over: if its configuration fails to load, the pidfile must go
    //    on naming the process that is still serving.
    if let Some(ref pidfile) = opts.pid_file {
        if !reload_child && master_dir.is_none() {
            handle_pid_file(pidfile);
        }
    }

    // 9. Handle check-only syntax validation (-c)
    if opts.check_only {
        // Certificates are loaded here, not just parsed. Reporting a config valid and
        // then failing to start on it moves the discovery from CI to production.
        if let Err(e) = ibex_rt::validate_tls(&config) {
            ibex_rt::stderr_line!("Configuration error: {e}");
            process::exit(1);
        }
        if warned {
            println!("Warnings were found.");
        }
        if !opts.quiet {
            if opts.verbose {
                println!("Configuration file(s) are valid.");
                if let Some(mc) = opts.maxconn {
                    println!("Global maxconn override: {mc}");
                }
                if let Some(ref p) = opts.pid_file {
                    println!("PID file configured: {}", p.display());
                }
                println!("Total configuration files loaded: {}", config_files.len());
            } else {
                println!("Configuration file is valid.");
            }
        }
        process::exit(0);
    }

    // 9a. `-W -S`: this process becomes the master, and the proxy runs in worker processes
    //     it starts (see master.rs).
    //     Plain `-W` is a process of its own that reloads by starting the binary again,
    //     which it could no longer do once it has given up root or entered a chroot: with
    //     `user`/`group`/`chroot` it becomes a master as well, which keeps its privileges
    //     while its workers drop theirs, as `HAProxy`'s does.
    let identity = identity::Identity::from_config(&config);
    if master_dir.is_none() && (master_sock.is_some() || (opts.master_worker && identity.any())) {
        master::run(master_sock.as_ref(), &raw_args[1..], start_dir, opts.systemd_notify) }

    // 9b. The ACL and map files the configuration reads become the objects `show map`,
    //     `add acl` and the other runtime commands work on, numbered in the order written.
    ibex_sample::patref::scan_config(&combined_config, &|line| {
        let (file, l) = locate(&config_starts, line);
        (file.to_string(), l)
    });

    // 10. Enforce memory limits if requested (-m <megabytes>)
    if let Some(megs) = opts.memory_limit_mb {
        enforce_memory_limit(megs, opts.quiet);
    }

    // 11. SIGUSR1 is the soft stop, as in HAProxy. Installed before any listener exists,
    //     so there is no moment where this process is serving and the signal is fatal.
    ibex_rt::systemd::init();
    let lifecycle = ibex_rt::lifecycle::Lifecycle::new();
    // Under -W / -Ws, SIGTERM is a stop that exits 0, as HAProxy's master does.
    let master_worker = opts.master_worker;
    let installed = lifecycle
        .install_signal_handlers()
        .and_then(|()| if master_worker { lifecycle.install_term_handler() } else { Ok(()) });
    if let Err(e) = installed {
        ibex_rt::stderr_line!("Failed to install signal handlers: {e}");
        process::exit(1);
    }

    // 12. Initialize Ibex soft-realtime engine
    
    let capacity = opts.maxconn.unwrap_or(65536) as usize;
    // HAProxy: without `nbthread`, one thread per CPU in the affinity mask, capped at
    // MAX_THREADS_DEFAULT (64); an explicit value is taken as is. `available_parallelism`
    // reads sched_getaffinity on Linux (also cgroup quotas).
    let nbthread = config
        .global
        .as_ref()
        .and_then(|g| g.nbthread)
        .map(|n| n as usize)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()).clamp(1, 64));
    ibex_rt::stats::set_identity(
        config.global.as_ref().and_then(|g| g.node.as_deref()),
        config.global.as_ref().and_then(|g| g.description.as_deref()),
    );
    ibex_rt::stats::NBTHREAD.store(nbthread as u32, std::sync::atomic::Ordering::Relaxed);

    // The soft limit on open files goes up to `maxsock` before any socket is opened;
    // `maxsock` counts `maxconn`, settled first.
    ibex_rt::engine::configure_maxconn(&config);
    let maxsock = ibex_rt::engine::config_maxsock(&config, nbthread);
    // A `maxconn` computed from the hard limit fits it: only a configured one is refused.
    let strict = config.global.as_ref().is_some_and(|g| g.maxconn.is_some() && !g.no_strict_limits);
    match ibex_rt::globalconn::apply_nofile_limit(u64::try_from(maxsock).unwrap_or(u64::MAX), strict) {
        Ok(None) => {}
        Ok(Some(warning)) => ibex_rt::stderr_line!("[WARNING]  ({}) : {warning}", process::id()),
        Err(alert) => {
            config_alert_plain(&alert);
            process::exit(1);
        }
    }

    let cli_socket: Option<ibex_config::StatsAddr> = opts
        .stats_socket
        .as_ref()
        .map(|p| ibex_config::StatsAddr::Unix(p.display().to_string()))
        .or_else(|| config.global.as_ref().and_then(|g| g.stats_socket_addr.clone()));
    
    let mut extra_sockets: Vec<ibex_config::StatsSocket> =
        config.global.as_ref().map(|g| g.extra_stats_sockets.clone()).unwrap_or_default();
    // A master's worker: one more admin socket, which the master forwards `@1 <cmd>` to and
    // the next worker takes the listening sockets from (see master.rs).
    extra_sockets.extend(master_dir.as_ref().map(|d| ibex_config::StatsSocket {
        path: d.join(format!("{}.sock", process::id())).display().to_string(),
        addr: ibex_config::StatsAddr::Unix(d.join(format!("{}.sock", process::id())).display().to_string()),
        mode: None,
        level: Some("admin".into()),
        expose_fd: true,
    }));
    let stats_socket_mode = config.global.as_ref().and_then(|g| g.stats_socket_mode);
    let stats_timeout = config.global.as_ref().and_then(|g| g.stats_timeout);
    let stats_maxconn = config.global.as_ref().and_then(|g| g.stats_maxconn);
    // A `stats socket` without `level` is operator, as in HAProxy (`bind_conf->level |=
    // ACCESS_LVL_OPER`, src/cli.c); the master socket `-S` is admin.
    let default_level = if opts.stats_socket.is_some() {
        ibex_rt::applet::CliLevel::Admin
    } else {
        ibex_rt::applet::CliLevel::Operator
    };
    let stats_socket_level = Some(
        config
            .global
            .as_ref()
            .and_then(|g| g.stats_socket_level.as_deref())
            .and_then(ibex_rt::applet::CliLevel::parse)
            .unwrap_or(default_level),
    );

    // 12b. Hitless reload: take the listening sockets over from the old process rather
    //      than binding new ones, so the connections already queued on them survive it
    //      exiting. See crates/ibex-rt/src/handover.rs.
    if opts.master_worker || config.global.as_ref().is_some_and(|g| g.stats_socket_expose_fd) {
        ibex_rt::handover::enable_expose();
    }
    if let Some(ref old) = opts.old_socket {
        if old != Path::new("/dev/null") {
            match ibex_rt::handover::fetch(old) {
                Ok(socks) => {
                    if !opts.quiet {
                        ibex_rt::stderr_line!("[NOTICE] took over {} listening socket(s) from {}", socks.len(), old.display());
                    }
                    ibex_rt::handover::distribute(socks, nbthread);
                }
                Err(e) => {
                    // HAProxy's behaviour exactly (src/haproxy.c:2069): refuse to start. The
                    // old process has not been signalled yet -- that only happens once this
                    // one is listening -- so it keeps serving and nothing is lost.
                    ibex_rt::stderr_line!("[ALERT] Failed to get the sockets from the old process! ({}: {e})", old.display());
                    process::exit(1);
                }
            }
        }
    }

    // After 12b: `build_shared_state` binds the `log-forward` sockets, which take the ones
    // handed over by `-x` and are exposed for the next reload only once 12b has run.
    let shared_proxies = match Engine::build_shared_state(&config) {
        Ok(p) => p,
        Err(err) => {
            ibex_rt::stderr_line!("Failed to build shared state: {err}");
            process::exit(1);
        }
    };

    // 12c. Every worker's QUIC socket is bound here, before the first worker starts, so the
    //      reuseport group a client's datagrams are hashed over is whole from its first
    //      datagram on (T210). HAProxy binds all its listeners before creating its threads.
    if let Err(err) = ibex_rt::engine::prebind_quic(&config, nbthread) {
        ibex_rt::stderr_line!("[ALERT] {err}");
        ibex_rt::stderr_line!("[ALERT] [haproxy.main()] Some protocols failed to start their listeners! Exiting.");
        process::exit(1);
    }

    // 12d. Every stats socket is bound here too (T220), so the file exists before any worker
    //      accepts a client and an unbindable path stops the start before any port listens
    //      (HAProxy: `protocol_bind_all`). Worker 0 serves them.
    // A TCP or abstract stats socket (T246) is bound here the same way; `mode` applies to
    // socket files only, as on the oracle, which accepts it on the others and ignores it.
    let bind_cli = |addr: &ibex_config::StatsAddr, mode: Option<u32>| -> (ibex_rt::cli_listener::CliListener, String, Option<PathBuf>) {
        use ibex_config::StatsAddr;
        use ibex_rt::cli_listener::CliListener;
        let name = addr.name();
        let old_pids: Vec<u32> = opts.sf_pids.iter().chain(&opts.st_pids).copied().collect();
        let fail = |proto: &str, what: &str, err: std::io::Error, at: &str| -> ! {
            // A process told to let go of its abstract name takes it back.
            send_signals_to_pids(&old_pids, Signal::Ttin, true);
            let why = err.to_string();
            let why = why.split(" (os error").next().unwrap_or(&why).to_string();
            ibex_rt::stderr_line!("[ALERT] Binding for frontend GLOBAL: protocol {proto}: {what} ({why}) [{at}].");
            ibex_rt::stderr_line!("[ALERT] [haproxy.main()] Some protocols failed to start their listeners! Exiting.");
            process::exit(1);
        };
        match addr {
            StatsAddr::Unix(p) => {
                let path = Path::new(p);
                match ibex_rt::engine::bind_unix_listener(path) {
                    Ok((l, path)) => {
                        if let Some(mode) = mode {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
                        }
                        (l.into(), name, Some(path))
                    }
                    Err(err) => fail("unix_stream", "cannot bind UNIX socket", err, p),
                }
            }
            StatsAddr::Abstract { name: n, padded } => {
                // An abstract name cannot be shared, so when a process we replace (`-sf`,
                // `-st`) still holds it, it is told to pause (SIGTTOU: it lets go of its
                // abstract stats sockets) and the bind is retried, as HAProxy does (T354).
                let mut paused = false;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                loop {
                    match CliListener::bind_abstract(n, *padded) {
                        Ok(l) => break (l, name, None),
                        Err(err)
                            if err.kind() == std::io::ErrorKind::AddrInUse
                                && !old_pids.is_empty()
                                && std::time::Instant::now() < deadline =>
                        {
                            if !paused {
                                send_signals_to_pids(&old_pids, Signal::Ttou, true);
                                paused = true;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(20));
                        }
                        Err(err) => fail("abns", "cannot bind UNIX socket", err, &name),
                    }
                }
            }
            StatsAddr::Tcp(a) => match CliListener::bind_tcp(*a) {
                Ok(l) => (l, name, None),
                Err(err) => fail(if a.is_ipv4() { "tcpv4" } else { "tcpv6" }, "cannot bind socket", err, &a.to_string()),
            },
        }
    };
    let mut cli_pre = cli_socket.as_ref().map(|a| bind_cli(a, stats_socket_mode));
    let mut extra_pre: Option<Vec<_>> = Some(
        extra_sockets
            .iter()
            .map(|x| {
                let level = x.level.as_deref().and_then(ibex_rt::applet::CliLevel::parse).unwrap_or(ibex_rt::applet::CliLevel::Operator);
                let (l, name, file) = bind_cli(&x.addr, x.mode);
                (l, name, file, level)
            })
            .collect(),
    );

    // Each worker reports once it is listening. `-sf` and READY=1 wait for all of them.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    // And then waits for `go` before it accepts anything: the process changes root, group
    // and user in between (see identity.rs), and nothing is served before it has.
    let go = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let mut threads = Vec::new();
    // The idle server connections, one slot per worker, taken across workers unless
    // `tune.idle-pool.shared off`.
    let idle_pools = ibex_rt::engine::IdlePools::new(nbthread, &config);
    // One mailbox per worker: the CLI's `show sess` and `shutdown session(s)` ask them all.
    // A failure is reported by each worker as its engine's.
    let mailboxes = ibex_rt::mailbox::Mailboxes::new(nbthread).map_err(|e| e.to_string());
    // One configuration for every worker, as the proxies are (T160): a worker reads it
    // while it starts, and a copy each held it for the life of the process.
    let config = std::sync::Arc::new(config);
    ibex_rt::watchdog::init(nbthread);
    for worker_id in 0..nbthread {
        let config_clone = std::sync::Arc::clone(&config);
        let proxies_clone = shared_proxies.clone();
        let idle_pools = std::sync::Arc::clone(&idle_pools);
        let mailboxes = mailboxes.clone();
        let (cli_pre, extra_pre) = if worker_id == 0 { (cli_pre.take(), extra_pre.take()) } else { (None, None) };
        let lifecycle_clone = lifecycle.clone();
        // Told to pause for our abstract stats socket, they are told to resume if we fail.
        let replaced: Vec<u32> = opts.sf_pids.iter().chain(&opts.st_pids).copied().collect();
        let ready_tx = ready_tx.clone();
        let go = std::sync::Arc::clone(&go);

        let t = std::thread::spawn(move || {
            // Before the ready message, so before the chroot: it opens this thread's
            // /proc/thread-self/schedstat.
            ibex_rt::watchdog::register(worker_id);
            let started = Engine::new_worker(&config_clone, capacity, worker_id, proxies_clone).and_then(|mut eng| {
                let boxes = mailboxes.as_ref().map_err(|m| std::io::Error::other(m.clone()))?;
                eng.share_mailboxes(boxes, worker_id)?;
                Ok(eng)
            });
            let mut engine = match started {
                Ok(eng) => eng,
                Err(err) => {
                    ibex_rt::stderr_line!("Failed to initialize Ibex engine (worker {}): {}", worker_id, err);
                    send_signals_to_pids(&replaced, Signal::Ttin, true);
                    process::exit(1);
                }
            };
            engine.share_idle_pools(&idle_pools, worker_id);

            if let Some(t) = stats_timeout {
                engine.set_cli_timeout(t);
            }
            if let Some(n) = stats_maxconn {
                engine.set_cli_maxconn(n as usize);
            }
            if let Some((listener, name, file)) = cli_pre {
                if let Some(level) = stats_socket_level {
                    engine.set_cli_level(level);
                }
                // Only an epoll_ctl failure on a fresh descriptor can fail here.
                engine.adopt_cli(listener, name, file).unwrap_or_else(|e| { ibex_rt::stderr_line!("Failed to serve a CLI / stats socket: {e}"); process::exit(1) });
            }
            for (listener, name, file, level) in extra_pre.into_iter().flatten() {
                engine.adopt_extra_cli(listener, name, file, level).unwrap_or_else(|e| { ibex_rt::stderr_line!("Failed to serve a CLI / stats socket: {e}"); process::exit(1) });
            }
            engine.set_lifecycle(lifecycle_clone);
            let _ = ready_tx.send(());
            drop(ready_tx);
            let (lock, cvar) = &*go;
            let mut released = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*released {
                released = cvar.wait(released).unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            drop(released);
            if let Err(err) = engine.run_loop() {
                ibex_rt::stderr_line!("Engine error (worker {}): {}", worker_id, err);
                process::exit(1);
            }
        });
        threads.push(t);
    }

    drop(ready_tx);

    // 13. Only now, with every worker bound, tell the old process to go and tell systemd we
    //     are up. These used to run before the engine was built: a reload signalled the old
    //     process to stop before the new one was listening, so there was always a window
    //     with nothing accepting, and READY=1 reported a service that did not exist yet. A
    //     worker that fails to start exits the process, so this cannot wait forever.
    for _ in 0..nbthread {
        if ready_rx.recv().is_err() {
            break;
        }
    }
    // HAProxy arms its watchdog per thread at thread init (src/wdt.c:246) and does not fail
    // to start without it.
    let warn_after = config.global.as_ref().and_then(|g| g.warn_blocked_traffic_after).unwrap_or(ibex_rt::watchdog::DEFAULT_WARN_AFTER);
    if let Err(e) = ibex_rt::watchdog::start(warn_after, config.global.as_ref().is_some_and(|g| g.ibex_watchdog_warn_only)) {
        ibex_rt::stderr_line!("[WARNING]  ({}) : Failed to start the watchdog thread ({e}), disabling lockup detection.", process::id());
    }
    let unused = ibex_rt::handover::drop_unused_inherited();
    if unused > 0 && !opts.quiet {
        ibex_rt::stderr_line!("[NOTICE] closed {unused} inherited socket(s) that no bind in this configuration uses");
    }
    // `HAProxy`'s order (src/haproxy.c `main`): the pidfile is written before the chroot,
    // the old processes are signalled before the user changes (it may no longer be allowed
    // to), and a chroot or identity that fails exits 1 before anything is served.
    if reload_child {
        if let Some(ref pidfile) = opts.pid_file {
            handle_pid_file(pidfile);
        }
    }
    identity::chroot(&program, &identity);
    if !opts.sf_pids.is_empty() {
        send_signals_to_pids(&opts.sf_pids, Signal::Usr1, opts.quiet);
    }
    if !opts.st_pids.is_empty() {
        send_signals_to_pids(&opts.st_pids, Signal::Term, opts.quiet);
    }
    identity::set_identity(&program, &identity);
    // Every worker is up and nothing is served yet: what is open now is Ibex's own.
    ibex_rt::globalconn::settle_fd_ceiling();
    {
        let (lock, cvar) = &*go;
        *lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        cvar.notify_all();
    }
    if master_dir.is_some() {
        // To the master, on the stderr pipe it reads: loaded (see master.rs).
        ibex_rt::stderr_line!("{}", master::READY_MARK);
    }
    // A reload child does not announce itself: it is not systemd's main PID yet, and under
    // the default `NotifyAccess=main` systemd would drop the message. The process it
    // replaces names it with `MAINPID=` instead (see `supervise`).
    if opts.systemd_notify && !reload_child && master_dir.is_none() {
        // crates/ibex-rt/src/systemd.rs, not a local copy: `Path` cannot address the
        // abstract socket systemd hands out as `@name`, and the module sends the full
        // READY=1/MAINPID/STATUS message HAProxy does (src/cli.c:3087).
        if let Err(e) = ibex_rt::systemd::notify_ready() {
            ibex_rt::stderr_line!("[WARNING] systemd notify failed: {e}");
        }
    }

    let respawn = Respawn { args: raw_args[1..].to_vec(), dir: start_dir };
    // A master's worker leaves reloads to the master, and goes when the master does.
    let master_ppid = master_dir.as_ref().map(|_| rustix::process::Pid::as_raw(rustix::process::getppid()));
    supervise(threads, &lifecycle, opts.master_worker && master_ppid.is_none(), &respawn, opts.quiet, master_ppid);
}

/// How to start the process that replaces this one on reload.
struct Respawn {
    args: Vec<String>,
    dir: Option<PathBuf>,
}

impl Respawn {
    /// The same arguments, less the ones that described *this* start: which process to take
    /// over from, which to stop, and `-D` -- this process is already detached, and a
    /// daemonising child would exit at once, which the supervisor would read as a failed
    /// reload.
    fn child_args(&self, sock: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.args.len() {
            match self.args[i].as_str() {
                "-x" => i += 2,
                "-sf" | "-st" => {
                    i += 1;
                    while i < self.args.len() && !self.args[i].starts_with('-') {
                        i += 1;
                    }
                }
                "-D" => i += 1,
                a => {
                    out.push(a.to_string());
                    i += 1;
                }
            }
        }
        out.extend([
            "-x".to_string(),
            sock.display().to_string(),
            "-sf".to_string(),
            process::id().to_string(),
        ]);
        out
    }

    /// The binary to run. `/proc/self/exe` still names this binary after it has been
    /// replaced on disk, with " (deleted)" appended; the path without that suffix is the
    /// upgraded binary, which is what a reload after an upgrade should run.
    fn exe() -> io::Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let text = exe.to_string_lossy();
        Ok(text.strip_suffix(" (deleted)").map_or(exe.clone(), PathBuf::from))
    }
}

/// One reload in progress: the new process, and the private socket it takes our listening
/// sockets from.
///
/// The socket lives in a fresh 0700 directory rather than the stats socket's path, so a
/// SIGUSR2 reload needs no `expose-fd listeners` in the configuration, and nothing else on
/// the host can connect to it and walk off with the listeners.
struct Reload {
    child: std::process::Child,
    listener: std::os::unix::net::UnixListener,
    dir: PathBuf,
    served: bool,
}

impl Reload {
    fn start(respawn: &Respawn) -> io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ibex-reload-{}-{seq}", process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let sock = dir.join("s");
        let listener = std::os::unix::net::UnixListener::bind(&sock)?;
        listener.set_nonblocking(true)?;

        let mut cmd = std::process::Command::new(Respawn::exe()?);
        cmd.args(respawn.child_args(&sock)).env("IBEX_RELOAD_CHILD", "1");
        if let Some(ref d) = respawn.dir {
            cmd.current_dir(d);
        }
        if let Some(n) = ibex_rt::systemd::notify_socket_env() {
            cmd.env("NOTIFY_SOCKET", n);
        }
        let child = cmd.spawn()?;
        Ok(Self { child, listener, dir, served: false })
    }

    /// Answers the new process's `_getsocks`, once, if it has connected.
    fn serve_pending(&mut self) {
        if self.served {
            return;
        }
        let Ok((stream, _)) = self.listener.accept() else { return };
        self.served = true;
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while let Ok(1) = io::Read::read(&mut &stream, &mut byte) {
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
        if line != b"_getsocks" {
            return;
        }
        if let Err(e) = ibex_rt::handover::serve_getsocks(&stream) {
            ibex_rt::stderr_line!("[ALERT] could not hand the listening sockets over: {e}");
        }
    }
}

impl Drop for Reload {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The main thread, once the workers are running: waits for them, and carries out
/// SIGUSR2 reloads under `-W` / `-Ws`.
///
/// A reload starts a new process on the same arguments. It loads its configuration, takes
/// the listening sockets over from us, and once it is listening sends us `-sf`. That
/// SIGUSR1 is how we know it succeeded: we name it systemd's main PID and soft-stop. If it
/// exits instead, the reload failed -- systemd is told so, and we go on serving, which is
/// the property HAProxy's master-worker mode exists to provide.
fn supervise(
    threads: Vec<std::thread::JoinHandle<()>>,
    lifecycle: &ibex_rt::lifecycle::Lifecycle,
    reloadable: bool,
    respawn: &Respawn,
    quiet: bool,
    master_ppid: Option<i32>,
) -> ! {
    let mut reload: Option<Reload> = None;
    let mut handed_over = false;
    loop {
        if lifecycle.term_requested() {
            // HAProxy's worker is killed by SIGTERM on the spot; the master, which is what
            // systemd supervises, then exits 0. Connections are dropped, not drained.
            ibex_rt::systemd::notify_stopping_once();
            process::exit(0);
        }
        if let Some(pp) = master_ppid {
            if rustix::process::Pid::as_raw(rustix::process::getppid()) != pp {
                // The master is gone; HAProxy's workers leave with it.
                process::exit(0);
            }
            let _ = lifecycle.take_reload_request();
        }
        if lifecycle.take_reload_request() {
            if !reloadable {
                if !quiet {
                    ibex_rt::stderr_line!("[NOTICE] SIGUSR2 ignored: reloading on SIGUSR2 needs -W or -Ws");
                }
            } else if reload.is_none() && !lifecycle.soft_stop_requested() {
                ibex_rt::systemd::notify_reloading();
                ibex_rt::systemd::set_handing_over(true);
                match Reload::start(respawn) {
                    Ok(r) => reload = Some(r),
                    Err(e) => {
                        ibex_rt::stderr_line!("[ALERT] reload failed to start a new process: {e}");
                        ibex_rt::systemd::set_handing_over(false);
                        let _ = ibex_rt::systemd::notify_reload_failed();
                    }
                }
            }
        }

        if let Some(r) = reload.as_mut() {
            r.serve_pending();
            if !handed_over {
                if let Ok(Some(st)) = r.child.try_wait() {
                    ibex_rt::stderr_line!(
                        "[ALERT] reload failed: the new process exited ({st}) before taking over; \
                         still serving on the previous configuration"
                    );
                    ibex_rt::systemd::set_handing_over(false);
                    let _ = ibex_rt::systemd::notify_reload_failed();
                    reload = None;
                }
            }
        }

        // Checked before the workers are, so that a process with nothing to drain -- whose
        // workers may be finished by the time we look -- still names its successor first.
        if !handed_over && lifecycle.soft_stop_requested() {
            handed_over = true;
            if let Some(r) = reload.as_ref() {
                ibex_rt::systemd::notify_handover(r.child.id());
            }
        }

        if threads.iter().all(std::thread::JoinHandle::is_finished) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    for t in threads {
        let _ = t.join();
    }
    process::exit(0);
}
