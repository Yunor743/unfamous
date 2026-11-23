//! fanotify monitoring engine.

pub mod fanotify;

use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::daemon::{FileContext, Pipeline};
use fanotify::{Fanotify, FanotifyEvent};

const PERM_MASK: u64 = libc::FAN_OPEN_EXEC_PERM | libc::FAN_OPEN_PERM;

#[derive(Debug)]
struct DroppedEvent {
    fd: RawFd,
    needs_response: bool,
}

/// Start continuous monitoring. Returns after a graceful shutdown.
pub async fn run_monitor(config: Arc<Config>, pipeline: Arc<Pipeline>) -> anyhow::Result<()> {
    let fan = Fanotify::init().map_err(|e| {
        anyhow::anyhow!(
            "fanotify_init failed: {e}. Permission events require CAP_SYS_ADMIN; \
             run unfamous as root or grant the capability (setcap cap_sys_admin+ep)."
        )
    })?;
    let fan = Arc::new(fan);

    let mask = Fanotify::mask_for(
        config.monitoring.execution_monitoring,
        config.monitoring.file_access_monitoring,
        config.monitoring.close_write_monitoring,
    );
    for watch in &config.monitoring.watch_paths {
        let path = PathBuf::from(watch);
        match fan.mark_filesystem(&path, mask) {
            Ok(()) => info!(path = %watch, "watching whole filesystem containing path"),
            Err(e) => anyhow::bail!("cannot watch {watch}: {e}"),
        }
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let (tx, rx) = tokio::sync::mpsc::channel::<FanotifyEvent>(config.monitoring.queue_size);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let (dropped_tx, mut dropped_rx) = tokio::sync::mpsc::channel::<DroppedEvent>(1024);

    let reader_shutdown = shutdown.clone();
    let reader_fan = fan.clone();
    let reader = std::thread::Builder::new()
        .name("fanotify-reader".to_string())
        .spawn(move || {
            reader_loop(&reader_fan, &tx, &dropped_tx, &reader_shutdown);
        })?;

    let worker_shutdown = shutdown.clone();
    let worker_fan = fan.clone();
    let worker_config = config.clone();
    let mut workers = Vec::new();
    for id in 0..config.monitoring.worker_count {
        let pipeline = pipeline.clone();
        let fan = worker_fan.clone();
        let shutdown = worker_shutdown.clone();
        let config = worker_config.clone();
        let rx = rx.clone();
        workers.push(tokio::spawn(async move {
            worker_loop(id, fan, pipeline, shutdown, rx, &config).await;
        }));
    }

    let dropper_fan = fan.clone();
    let dropper = tokio::spawn(async move {
        while let Some(dropped) = dropped_rx.recv().await {
            if dropped.needs_response {
                let _ = dropper_fan.respond(dropped.fd, true);
            }
            unsafe { libc::close(dropped.fd) };
        }
    });

    info!(
        workers = config.monitoring.worker_count,
        queue = config.monitoring.queue_size,
        "monitoring started"
    );

    let signal_shutdown = shutdown.clone();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, shutting down");
        }
        () = wait_sigterm() => {
            info!("SIGTERM received, shutting down");
        }
    }
    signal_shutdown.store(true, Ordering::SeqCst);

    // The reader thread owns the queue senders (it was spawned with a move
    // closure), so joining it closes both channels and lets workers drain.
    let _ = reader.join();
    for worker in workers {
        let _ = worker.await;
    }
    dropper.abort();
    drop(fan);
    info!("monitoring stopped");
    Ok(())
}

async fn wait_sigterm() {
    if let Ok(mut stream) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        stream.recv().await;
    }
}

fn reader_loop(
    fan: &Fanotify,
    tx: &tokio::sync::mpsc::Sender<FanotifyEvent>,
    dropped_tx: &tokio::sync::mpsc::Sender<DroppedEvent>,
    shutdown: &AtomicBool,
) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        // Poll with a timeout so the shutdown flag is honored promptly even
        // while no events arrive.
        let mut poll_fd = libc::pollfd {
            fd: fan.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll_fd, 1, 500) };
        if ready < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            error!(error = %e, "fanotify poll failed");
            return;
        }
        if ready == 0 {
            continue;
        }
        match fan.read_events() {
            Ok(events) => {
                for event in events {
                    if event.fd <= 0 {
                        continue;
                    }
                    let needs_response = event.mask & PERM_MASK != 0;
                    let fd = event.fd;
                    if tx.try_send(event).is_err() {
                        let _ = dropped_tx.try_send(DroppedEvent { fd, needs_response });
                        warn!("event queue full; event dropped fail-open");
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "fanotify read failed");
                return;
            }
        }
    }
}

async fn worker_loop(
    id: usize,
    fan: Arc<Fanotify>,
    pipeline: Arc<Pipeline>,
    shutdown: Arc<AtomicBool>,
    rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<FanotifyEvent>>>,
    config: &Config,
) {
    loop {
        let event = {
            let mut guard = rx.lock().await;
            guard.recv().await
        };
        let Some(event) = event else { break };
        if shutdown.load(Ordering::SeqCst) {
            finish_event(&fan, &event, true);
            continue;
        }
        let needs_response = event.mask & PERM_MASK != 0;
        let path = fd_to_path(event.fd);
        let is_perm = needs_response;

        if is_perm {
            let process_result = tokio::time::timeout(
                Duration::from_millis(config.monitoring.response_timeout_ms),
                pipeline.process(&FileContext {
                    path: path.clone(),
                    fd: Some(event.fd),
                    pid: Some(u32::try_from(event.pid).unwrap_or(0)),
                    mode: "monitor",
                    bypass_cache: false,
                }),
            )
            .await;
            let decision = match process_result {
                Ok(Ok(outcome)) => outcome.decision,
                Ok(Err(e)) => {
                    debug!(worker = id, error = %e, "processing failed");
                    None
                }
                Err(_) => {
                    warn!(worker = id, "processing timed out, responding fail-open");
                    None
                }
            };
            let allow = match decision {
                Some(decision) if decision.block && config.monitoring.block_on_malicious => false,
                _ => config.monitoring.fail_open,
            };
            if let Err(e) = fan.respond(event.fd, allow) {
                debug!(worker = id, error = %e, "failed to answer permission event");
            }
        } else {
            let _ = pipeline
                .process(&FileContext {
                    path,
                    fd: Some(event.fd),
                    pid: Some(u32::try_from(event.pid).unwrap_or(0)),
                    mode: "monitor",
                    bypass_cache: false,
                })
                .await;
        }
        unsafe { libc::close(event.fd) };
    }
    // Channel closed: answer any pending permission events to avoid hangs.
    let mut guard = rx.lock().await;
    while let Ok(event) = guard.try_recv() {
        finish_event(&fan, &event, true);
    }
}

fn finish_event(fan: &Fanotify, event: &FanotifyEvent, allow: bool) {
    if event.mask & PERM_MASK != 0 {
        let _ = fan.respond(event.fd, allow);
    }
    unsafe { libc::close(event.fd) };
}

fn fd_to_path(fd: RawFd) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}
