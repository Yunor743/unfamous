//! Entry point: mode dispatch and signal handling.

use std::sync::Arc;

use clap::Parser;

use unfamous::cli::{CacheCommand, Cli, Command};
use unfamous::config::Config;
use unfamous::{cache, daemon, dfir, logging, monitor};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let config = match Config::load(&cli.config) {
        Ok(config) => Arc::new(config),
        Err(e) => {
            eprintln!("configuration error: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    logging::init(
        cli.log_level
            .as_deref()
            .unwrap_or(&config.general.log_level),
        config.general.log_format == "json",
    );

    let command = match cli.command {
        Some(Command::Monitor) | None => Command::Monitor,
        Some(other) => other,
    };

    match dispatch(command, config.clone()).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

async fn dispatch(command: Command, config: Arc<Config>) -> anyhow::Result<std::process::ExitCode> {
    match command {
        Command::Monitor => {
            let pipeline = Arc::new(daemon::Pipeline::build(config.clone())?);
            monitor::run_monitor(config, pipeline).await?;
            Ok(std::process::ExitCode::SUCCESS)
        }
        Command::Validate => {
            println!("configuration is valid");
            Ok(std::process::ExitCode::SUCCESS)
        }
        Command::Scan {
            path,
            path_positional,
            depth,
            follow_symlinks,
            single_file,
            no_cache,
        } => {
            let scan_path = path
                .or(path_positional)
                .ok_or_else(|| anyhow::anyhow!("scan requires a path (positional or --path)"))?;
            let pipeline = Arc::new(daemon::Pipeline::build(config)?);
            let options = dfir::ScanOptions {
                path: scan_path,
                single_file,
                no_cache,
                depth_override: depth,
                follow_symlinks_override: follow_symlinks,
            };
            let code = dfir::run_scan(Arc::clone(&pipeline.config), pipeline, options).await?;
            Ok(std::process::ExitCode::from(code as u8))
        }
        Command::Cache { sub } => {
            let path = config.resolve_cache_path();
            match sub {
                CacheCommand::Clear => {
                    let cache = cache::Cache::open(&path)?;
                    cache.clear();
                    println!("cache cleared: {}", path.display());
                    Ok(std::process::ExitCode::SUCCESS)
                }
                CacheCommand::Stats => {
                    let cache = cache::Cache::open(&path)?;
                    let stats = cache.stats();
                    println!("{}", serde_json::to_string_pretty(&stats)?);
                    Ok(std::process::ExitCode::SUCCESS)
                }
            }
        }
    }
}
