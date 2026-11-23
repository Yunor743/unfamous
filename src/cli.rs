//! Command line interface.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Unfamous: Linux file reputation monitor.
#[derive(Debug, Parser)]
#[command(
    name = "unfamous",
    version,
    about = "Hash files, query CTI providers, alert on unknown and malicious files",
    after_help = "Run `unfamous scan --help` for DFIR options."
)]
pub struct Cli {
    /// TOML configuration file.
    #[arg(
        short,
        long,
        global = true,
        value_name = "FILE",
        default_value = "./unfamous.conf"
    )]
    pub config: PathBuf,

    /// Log level override (trace, debug, info, warn, error).
    #[arg(long, global = true, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Subcommand to run. Defaults to continuous monitoring when omitted.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Available commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Continuous filesystem monitoring through fanotify.
    Monitor,

    /// One-shot DFIR scan of a path. No fanotify required.
    Scan {
        /// File or directory to scan. Accepts a positional value or `--path`.
        #[arg(long, value_name = "PATH", conflicts_with = "path_positional")]
        path: Option<PathBuf>,

        /// File or directory to scan (positional form).
        #[arg(value_name = "PATH")]
        path_positional: Option<PathBuf>,

        /// Maximum recursion depth (0 = the path itself only).
        #[arg(long, value_name = "N")]
        depth: Option<usize>,

        /// Follow symbolic links during traversal.
        #[arg(long)]
        follow_symlinks: bool,

        /// Treat PATH as a single file even if it looks like a directory name.
        #[arg(long)]
        single_file: bool,

        /// Ignore cached provider results and force fresh queries.
        #[arg(long)]
        no_cache: bool,
    },

    /// Load and validate the configuration file, then exit.
    Validate,

    /// Cache maintenance.
    Cache {
        #[command(subcommand)]
        sub: CacheCommand,
    },
}

/// Cache subcommands.
#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    /// Remove every cached entry.
    Clear,

    /// Print cache statistics as JSON.
    Stats,
}
