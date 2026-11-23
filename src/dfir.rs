//! One-shot DFIR scanning mode.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tracing::{debug, info};

use crate::config::Config;
use crate::daemon::{FileContext, Pipeline};

/// Exit codes: 0 clean, 1 fatal error, 2 alerts were generated.
pub const EXIT_ALERTS: i32 = 2;

pub struct ScanOptions {
    pub path: PathBuf,
    pub single_file: bool,
    pub no_cache: bool,
    pub depth_override: Option<usize>,
    pub follow_symlinks_override: bool,
}

pub async fn run_scan(
    config: Arc<Config>,
    pipeline: Arc<Pipeline>,
    options: ScanOptions,
) -> anyhow::Result<i32> {
    let started = std::time::Instant::now();
    let scanned = Arc::new(AtomicUsize::new(0));
    let alerts = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));

    let meta = std::fs::metadata(&options.path)
        .map_err(|e| anyhow::anyhow!("cannot access {}: {e}", options.path.display()))?;

    if options.single_file || !meta.is_dir() {
        let ctx = FileContext {
            path: Some(options.path.clone()),
            fd: None,
            pid: None,
            mode: "scan",
            bypass_cache: options.no_cache,
        };
        scanned.fetch_add(1, Ordering::Relaxed);
        let outcome = pipeline.process(&ctx).await?;
        if outcome.alert.is_some() {
            alerts.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        let (tx, rx) = tokio::sync::mpsc::channel::<PathBuf>(config.monitoring.queue_size.max(64));
        let walk_depth = options.depth_override.unwrap_or(config.dfir.max_depth);
        let walk_symlinks = options.follow_symlinks_override || config.dfir.follow_symlinks;

        let walker_path = options.path.clone();
        let excludes: Vec<String> = config.dfir.exclude_paths.clone();
        let walker = tokio::task::spawn_blocking(move || {
            for entry in walkdir::WalkDir::new(&walker_path)
                .max_depth(walk_depth)
                .follow_links(walk_symlinks)
                .into_iter()
                .filter_entry(|e| {
                    // Keep the scan root itself so an explicit scan of an
                    // excluded path still honors the operator's request, but
                    // prune excluded subtrees.
                    e.depth() == 0 || !crate::daemon::is_excluded(e.path(), &excludes)
                })
            {
                match entry {
                    Ok(entry) if entry.file_type().is_file() => {
                        if tx.blocking_send(entry.into_path()).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        debug!(error = %e, "walk error");
                    }
                }
            }
        });

        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        let mut handles = Vec::new();
        for _ in 0..config.dfir.threads.max(1) {
            let pipeline = pipeline.clone();
            let rx = rx.clone();
            let scanned = scanned.clone();
            let alerts = alerts.clone();
            let errors = errors.clone();
            let bypass = options.no_cache;
            handles.push(tokio::spawn(async move {
                loop {
                    let next = {
                        let mut guard = rx.lock().await;
                        guard.recv().await
                    };
                    let Some(path) = next else { break };
                    let count = scanned.fetch_add(1, Ordering::Relaxed) + 1;
                    if count % 500 == 0 {
                        info!(files = count, "scan progress");
                    }
                    let ctx = FileContext {
                        path: Some(path.clone()),
                        fd: None,
                        pid: None,
                        mode: "scan",
                        bypass_cache: bypass,
                    };
                    match pipeline.process(&ctx).await {
                        Ok(outcome) => {
                            if outcome.alert.is_some() {
                                alerts.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(e) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                            debug!(path = %path.display(), error = %e, "scan error");
                        }
                    }
                }
            }));
        }
        let _ = walker.await;
        for handle in handles {
            let _ = handle.await;
        }
    }

    let scanned = scanned.load(Ordering::Relaxed);
    let alerts = alerts.load(Ordering::Relaxed);
    let errors = errors.load(Ordering::Relaxed);
    info!(
        files = scanned,
        alerts,
        errors,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "scan finished"
    );
    Ok(if alerts > 0 { EXIT_ALERTS } else { 0 })
}
