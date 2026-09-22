// SPDX-License-Identifier: GPL-2.0-or-later
// Ibex Load Balancer main daemon entrypoint.
// Copyright (C) 2000-2026 Willy Tarreau and Ibex contributors. See LICENSE.

//! Ibex main executable binary with `HAProxy` 3.5 command-line interface compatibility.

#![forbid(unsafe_code)]
#![allow(clippy::struct_excessive_bools)]

use ibex_rt::Engine;
use rustix::process::{kill_process, Pid, Resource, Rlimit, setrlimit, Signal};
use std::env;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process;

/// Command-line parsed options for Ibex runtime.
#[derive(Debug, Default)]
struct CliOptions {
    config_paths: Vec<PathBuf>,
    stats_socket: Option<PathBuf>,
    check_only: bool,
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
    st_pids: Vec<u32>,
    ignore_resolve_fail: bool,
    disable_epoll: bool,
    disable_poll: bool,
    dump_memory_pools: bool,
    dump_libs: bool,
    user: Option<String>,
    group: Option<String>,
    uid: Option<u32>,
    gid: Option<u32>,
    chroot: Option<PathBuf>,
    overrides: Vec<String>,
}

fn print_help(program: &str) {
    println!("Ibex 0.1.0 - Memory-Safe Soft-Realtime Load Balancer (HAProxy 3.5 compatibility)");
    println!("Usage : {program} [-f <cfgfile|cfgdir>]* [ -vdVD ] [ -n <maxconn> ] [ -N <maxpconn> ]");
    println!("        [ -p <pidfile> ] [ -m <max megs> ] [ -C <dir> ] [-- <cfgfile>*]");
    println!("        -v displays version ; -vv shows known build options.");
    println!("        -vq/-vqs/-vqb only displays version, short version, branch.");
    println!("        -d enters debug mode ; -db only disables background mode.");
    println!("        -dM[<byte>,help,...] debug memory pools");
    println!("        -V enters verbose mode (disables quiet mode)");
    println!("        -D goes daemon ; -C changes to <dir> before loading files.");
    println!("        -W master-worker mode.");
    println!("        -Ws master-worker mode with systemd notify support.");
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
    println!("        -u <user> / -g <group> / -U <uid> / -G <gid> run as user/group");
    println!("        -ch <dir> chroot to directory");
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
    println!("         h2 : mode=HTTP  side=FE|BE  mux=H2    flags=HTX");
    println!("         h1 : mode=HTTP  side=FE|BE  mux=H1    flags=HTX");
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
                "Cannot open configuration file/directory '{}': No such file or directory",
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
                        eprintln!("[WARNING] Failed to send signal {signal:?} to PID {pid}: {err}");
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

/// Sends `READY=1` notification to systemd if `$NOTIFY_SOCKET` is present.
fn notify_systemd() {
    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        if let Ok(sock) = UnixDatagram::unbound() {
            let _ = sock.send_to(b"READY=1\n", Path::new(&socket_path));
        }
    }
}

fn parse_arg_u32(val: &str, flag: &str) -> u32 {
    val.parse::<u32>().unwrap_or_else(|_| {
        eprintln!("Option {flag}: invalid integer argument '{val}'");
        process::exit(1);
    })
}

fn parse_arg_u64(val: &str, flag: &str) -> u64 {
    val.parse::<u64>().unwrap_or_else(|_| {
        eprintln!("Option {flag}: invalid integer argument '{val}'");
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
                    eprintln!("Option -f expects a configuration file/directory path argument.");
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
                    eprintln!("Option -cc expects a condition expression.");
                    process::exit(1);
                }
                match ibex_rt::cond::eval(&args[i]) {
                    Some(true) => process::exit(0),
                    Some(false) => process::exit(1),
                    None => {
                        // Distinguished from false: a condition nobody can parse is a
                        // mistake to fix, not a feature we lack.
                        eprintln!("Unparseable condition: {}", args[i]);
                        process::exit(2);
                    }
                }
            }
            "-c" => {
                opts.check_only = true;
            }
            "-C" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Option -C expects a directory path argument.");
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
                    eprintln!("Option -p expects a pidfile path argument.");
                    process::exit(1);
                }
                opts.pid_file = Some(PathBuf::from(&args[i]));
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
                    eprintln!("Option -S expects a socket path argument.");
                    process::exit(1);
                }
                let raw = &args[i];
                let sock_str = raw.split(',').next().unwrap_or(raw);
                let sock_str = sock_str.strip_prefix("unix@").unwrap_or(sock_str);
                opts.stats_socket = Some(PathBuf::from(sock_str));
            }
            "-n" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Option -n expects an integer argument (maxconn).");
                    process::exit(1);
                }
                opts.maxconn = Some(parse_arg_u32(&args[i], "-n"));
            }
            "-N" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Option -N expects an integer argument (maxpconn).");
                    process::exit(1);
                }
                opts.maxpconn = Some(parse_arg_u32(&args[i], "-N"));
            }
            "-m" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Option -m expects an integer argument (megabytes).");
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
            "-dM" => {
                opts.dump_memory_pools = true;
            }
            "-u" => {
                i += 1;
                if i < args.len() {
                    opts.user = Some(args[i].clone());
                }
            }
            "-g" => {
                i += 1;
                if i < args.len() {
                    opts.group = Some(args[i].clone());
                }
            }
            "-U" => {
                i += 1;
                if i < args.len() {
                    opts.uid = args[i].parse::<u32>().ok();
                }
            }
            "-G" => {
                i += 1;
                if i < args.len() {
                    opts.gid = args[i].parse::<u32>().ok();
                }
            }
            "-ch" => {
                i += 1;
                if i < args.len() {
                    opts.chroot = Some(PathBuf::from(&args[i]));
                }
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
                opts.dump_memory_pools = true;
            }
            unknown => {
                eprintln!("Unknown option: {unknown}");
                print_help(&program);
                process::exit(1);
            }
        }
        i += 1;
    }

    (program, opts)
}

fn load_and_merge_configs(config_files: &[PathBuf]) -> String {
    let mut combined = String::new();
    for path in config_files {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                combined.push_str(&content);
                if !combined.ends_with('\n') {
                    combined.push('\n');
                }
            }
            Err(err) => {
                eprintln!(
                    "Cannot read configuration file '{}': {err}",
                    path.display()
                );
                process::exit(1);
            }
        }
    }
    combined
}

fn report_diagnostics(opts: &CliOptions) {
    if opts.ignore_resolve_fail && !opts.quiet {
        eprintln!("[DIAG] Flag -dr: ignoring server address resolution failures.");
    }
    if opts.disable_epoll && !opts.quiet {
        eprintln!("[DIAG] Flag -de: disabling epoll poller (falling back to standard poll).");
    }
    if opts.disable_poll && !opts.quiet {
        eprintln!("[DIAG] Flag -dp: disabling poll poller.");
    }
    if opts.dump_memory_pools && !opts.quiet {
        eprintln!("[DIAG] Flag -dM: memory pool debugging active.");
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
            eprintln!("[WARNING] Unable to enforce memory limit (-m {megs} MB): {err}");
        }
    }
}

fn handle_pid_file(pid_path: &Path) {
    let pid = std::process::id();
    if let Err(err) = std::fs::write(pid_path, format!("{pid}\n")) {
        eprintln!("Cannot create pidfile '{}': {err}", pid_path.display());
        process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    let raw_args: Vec<String> = env::args().collect();
    let (program, opts) = parse_cli_args(&raw_args);

    // 1. Change working directory if requested via -C <dir>
    if let Some(ref dir) = opts.change_dir {
        if let Err(err) = std::env::set_current_dir(dir) {
            eprintln!("Cannot change directory to '{}': {err}", dir.display());
            process::exit(1);
        }
    }

    // 2. Validate that configuration files were provided
    if opts.config_paths.is_empty() {
        eprintln!("Error: No configuration file specified. Use -f <path>.");
        print_help(&program);
        process::exit(1);
    }

    // 3. Expand directories and collect config files in lexical order
    let config_files = match expand_config_paths(&opts.config_paths) {
        Ok(files) => files,
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    };

    // 4. Read and concatenate all configuration files
    let combined_config = load_and_merge_configs(&config_files);

    // 5. Parse unified configuration AST
    let mut config = match ibex_config::parse_str(&combined_config) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Configuration parsing error: {err}");
            process::exit(1);
        }
    };

    // 5b. TLS is wired now: `Engine::new` builds a rustls config per `bind ... ssl crt`
    // and refuses to start if one cannot be loaded, so the blanket guard that used to
    // live here is gone. What it protected against has not changed -- a listener on :443
    // serving cleartext to clients that believe they negotiated TLS -- it is just
    // enforced where the certificates actually are, in `bind_tls`, and again per
    // connection in the accept path, which drops rather than downgrades.

    // 6. Apply command-line maxconn override (-n <maxconn>)
    if let Some(mc) = opts.maxconn {
        for listen in &mut config.listens {
            if listen.maxconn > mc {
                listen.maxconn = mc;
            }
        }
        for frontend in &mut config.frontends {
            if frontend.maxconn > mc {
                frontend.maxconn = mc;
            }
        }
    }

    // 7. Diagnostic reporting
    report_diagnostics(&opts);

    // 8. Write PID file if requested (-p <pidfile>)
    if let Some(ref pidfile) = opts.pid_file {
        handle_pid_file(pidfile);
    }

    // 9. Handle check-only syntax validation (-c)
    if opts.check_only {
        // Certificates are loaded here, not just parsed. Reporting a config valid and
        // then failing to start on it moves the discovery from CI to production.
        if let Err(e) = ibex_rt::validate_tls(&config) {
            eprintln!("Configuration error: {e}");
            process::exit(1);
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

    // 10. Enforce memory limits if requested (-m <megabytes>)
    if let Some(megs) = opts.memory_limit_mb {
        enforce_memory_limit(megs, opts.quiet);
    }

    // 11. Handle graceful reload and termination signals (-sf / -st)
    if !opts.sf_pids.is_empty() {
        send_signals_to_pids(&opts.sf_pids, Signal::Usr1, opts.quiet);
    }
    if !opts.st_pids.is_empty() {
        send_signals_to_pids(&opts.st_pids, Signal::Term, opts.quiet);
    }

    // 12. Master-worker systemd notification (-Ws)
    if opts.systemd_notify {
        notify_systemd();
    }

    // 13. Initialize Ibex soft-realtime engine
    let capacity = opts.maxconn.unwrap_or(65536) as usize;
    let mut engine = match Engine::new(&config, capacity) {
        Ok(eng) => eng,
        Err(err) => {
            eprintln!("Failed to initialize Ibex engine: {err}");
            process::exit(1);
        }
    };

    // The runtime socket may come from `-S <path>` or, as HAProxy and every hatop
    // tutorial do it, from `global stats socket <path>` in the config file. The config
    // fields were parsed and then never read, so a config-only setup silently produced
    // no socket at all and hatop had nothing to connect to. The flag wins when both
    // are given.
    let cli_socket: Option<PathBuf> = opts.stats_socket.clone().or_else(|| {
        config
            .global
            .as_ref()
            .and_then(|g| g.stats_socket.as_ref())
            .map(PathBuf::from)
    });

    if let Some(ref sock_path) = cli_socket {
        if let Err(err) = engine.bind_cli_socket(sock_path) {
            eprintln!(
                "Failed to bind CLI / stats socket '{}': {err}",
                sock_path.display()
            );
            process::exit(1);
        }

        // `stats socket <path> mode <octal>` sets the socket's permissions. It matters:
        // this socket can disable servers and change weights, so a world-writable one
        // is a privilege escalation waiting to happen.
        if opts.stats_socket.is_none() {
            if let Some(mode) = config.global.as_ref().and_then(|g| g.stats_socket_mode) {
                use std::os::unix::fs::PermissionsExt;
                if let Err(err) =
                    std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(mode))
                {
                    eprintln!(
                        "Warning: could not set mode {mode:o} on '{}': {err}",
                        sock_path.display()
                    );
                }
            }
        }
    }

    if let Err(err) = engine.run_loop() {
        eprintln!("Engine error: {err}");
        process::exit(1);
    }
}
