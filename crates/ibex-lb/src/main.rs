//! # Ibex Load Balancer Daemon

use clap::Parser;
use ibex_config::ConfigParser;
use ibex_core::error::IbexResult;
use ibex_runtime::{IbexEngine, RcuRoutingTable};
use ibex_stick_table::{StickTable, StickTableConfig};
use ibex_vtest::{VtcParser, VtcRunner};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "ibex", version = "0.1.0", about = "Memory-Safe Soft-Realtime Load Balancer")]
struct CliArgs {
    /// Path to HAProxy-compatible configuration file
    #[arg(short = 'f', long = "config")]
    config_file: Option<PathBuf>,

    /// Check configuration file syntax and exit
    #[arg(short = 'c', long = "check")]
    check_only: bool,

    /// Execute a VTC regression test script
    #[arg(short = 't', long = "test")]
    test_script: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> IbexResult<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let args = CliArgs::parse();

    if let Some(vtc_path) = args.test_script {
        info!("Running VTC test script: {:?}", vtc_path);
        let content = std::fs::read_to_string(&vtc_path)
            .map_err(|e| ibex_core::error::IbexError::Io(e.to_string()))?;
        let script = VtcParser::parse_str(&content)?;
        let report = VtcRunner::run_script(&script).await?;
        info!("Test Result: {:?}", report);
        return Ok(());
    }

    if let Some(config_path) = args.config_file {
        info!("Loading configuration: {:?}", config_path);
        let content = std::fs::read_to_string(&config_path)
            .map_err(|e| ibex_core::error::IbexError::Io(e.to_string()))?;
        let ast = ConfigParser::parse_str(&content)?;
        info!(
            "Configuration successfully validated ({} frontends, {} backends, {} peers)",
            ast.frontends.len(),
            ast.backends.len(),
            ast.peers.len()
        );

        if args.check_only {
            println!("Configuration file {:?} is valid.", config_path);
            return Ok(());
        }

        let rcu_table = Arc::new(RcuRoutingTable::default());
        rcu_table.swap_config(&ast);

        let stick_table = Arc::new(StickTable::new(StickTableConfig::default()));
        let _engine = IbexEngine::new(rcu_table.clone(), stick_table.clone());

        info!("Ibex Load Balancer initialized in soft-realtime mode.");
    } else {
        println!("Ibex 0.1.0 (Soft-Realtime Rust Load Balancer). Use -h for help.");
    }

    Ok(())
}
