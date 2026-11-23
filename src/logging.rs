//! Logging setup built on tracing.

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Initialize the global tracing subscriber.
///
/// `level` is a tracing level name such as `info`. `json` selects
/// machine-readable JSON lines for SIEM ingestion; otherwise a compact human
/// format is used. `UNFAMOUS_LOG` overrides the filter when set, which is
/// handy for debugging single modules (`UNFAMOUS_LOG=unfamous::monitor=trace`).
pub fn init(level: &str, json: bool) {
    let filter =
        EnvFilter::try_new(std::env::var("UNFAMOUS_LOG").unwrap_or_else(|_| level.to_string()))
            .unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry().with(filter);
    if json {
        registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(false),
            )
            .init();
    } else {
        registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .compact(),
            )
            .init();
    }
}
