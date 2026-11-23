//! Alert model and JSON / JSONL output with daily rotation.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::hashing::Hashes;
use crate::providers::ProviderOutcome;
use crate::reputation::{Decision, ReputationVerdict};

/// One security alert. Unavailable fields are omitted; API keys and other
/// secrets are never part of this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: String,
    pub timestamp: String,
    pub hostname: String,
    pub file_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_extension: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_file_type: Option<String>,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub reputation: ReputationVerdict,
    pub detection_reason: String,
    #[serde(default)]
    pub provider_results: Vec<ProviderResultAlert>,
    pub cache_status: String,
    pub monitoring_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderResultAlert {
    pub provider: String,
    pub result: ProviderOutcome,
    pub queried_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertFormat {
    Json,
    Jsonl,
}

#[derive(Debug)]
struct AlertWriterState {
    current_path: Option<PathBuf>,
    current_date: Option<String>,
    sequence: u32,
}

/// Thread safe alert writer with daily and size-based rotation.
pub struct AlertWriter {
    directory: PathBuf,
    prefix: String,
    extension: String,
    daily_rotation: bool,
    file_mode: u32,
    max_size_bytes: u64,
    format: AlertFormat,
    state: Mutex<AlertWriterState>,
}

impl AlertWriter {
    #[must_use]
    pub fn from_config(config: &crate::config::Alerts) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let mode =
            u32::from_str_radix(config.file_mode.trim_start_matches('0'), 8).unwrap_or(0o600);
        Some(Self {
            directory: PathBuf::from(&config.directory),
            prefix: config.filename_prefix.clone(),
            extension: if config.format == "jsonl" {
                "jsonl"
            } else {
                "json"
            }
            .to_string(),
            daily_rotation: config.daily_rotation,
            file_mode: mode,
            max_size_bytes: config.max_size_mb.saturating_mul(1024 * 1024),
            format: if config.format == "jsonl" {
                AlertFormat::Jsonl
            } else {
                AlertFormat::Json
            },
            state: Mutex::new(AlertWriterState {
                current_path: None,
                current_date: None,
                sequence: 0,
            }),
        })
    }

    pub fn write(&self, alert: &Alert) -> std::io::Result<PathBuf> {
        let mut state = self.state.lock().expect("alert writer mutex");
        std::fs::create_dir_all(&self.directory)?;
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();

        let needs_new = match (&state.current_path, &state.current_date) {
            (Some(path), Some(current_date)) => {
                let expired = self.daily_rotation && current_date != &date;
                let oversized = self.max_size_bytes > 0
                    && std::fs::metadata(path).is_ok_and(|m| m.len() >= self.max_size_bytes);
                expired || oversized
            }
            _ => true,
        };
        if needs_new {
            if self.daily_rotation && state.current_date.as_deref() == Some(date.as_str()) {
                state.sequence += 1;
            } else {
                state.sequence = 0;
            }
            state.current_date = Some(date.clone());
            let mut seq = state.sequence;
            loop {
                let candidate = self.file_path(&date, seq);
                let reusable = !candidate.exists()
                    || (self.max_size_bytes > 0
                        && std::fs::metadata(&candidate)
                            .is_ok_and(|m| m.len() < self.max_size_bytes));
                if reusable {
                    state.sequence = seq;
                    break;
                }
                seq += 1;
            }
            let path = self.file_path(&date, state.sequence);
            let file = OpenOptions::new().create(true).append(true).open(&path)?;
            file.set_permissions(std::fs::Permissions::from_mode(self.file_mode))?;
            state.current_path = Some(path);
        }

        let path = state.current_path.clone().expect("just created");
        drop(state);
        self.append_alert(&path, alert)
    }

    fn file_path(&self, date: &str, sequence: u32) -> PathBuf {
        let base = if self.daily_rotation {
            format!("{}.{}.{}", self.prefix, date, self.extension)
        } else {
            format!("{}.{}", self.prefix, self.extension)
        };
        let name = if sequence == 0 {
            base
        } else {
            format!("{base}.{sequence}")
        };
        self.directory.join(name)
    }

    fn append_alert(&self, path: &Path, alert: &Alert) -> std::io::Result<PathBuf> {
        match self.format {
            AlertFormat::Jsonl => {
                let mut file = OpenOptions::new().append(true).open(path)?;
                let mut line = serde_json::to_string(alert)?;
                line.push('\n');
                file.write_all(line.as_bytes())?;
            }
            AlertFormat::Json => {
                // The JSON format keeps one real JSON array per file. Each
                // write reparses and rewrites it, which is acceptable for the
                // low alert volumes JSON mode is meant for; JSONL is the
                // default for continuous monitoring precisely because it
                // appends cheaply.
                let content = std::fs::read_to_string(path)?;
                let mut items: Vec<serde_json::Value> = if content.trim().is_empty() {
                    Vec::new()
                } else {
                    serde_json::from_str(&content)?
                };
                items.push(serde_json::to_value(alert)?);
                let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
                file.write_all(serde_json::to_string_pretty(&items)?.as_bytes())?;
                file.write_all(b"\n")?;
            }
        }
        Ok(path.to_path_buf())
    }

    /// Remove alert files older than `retention_days`. Best effort; 0
    /// disables retention.
    pub fn apply_retention(&self, retention_days: u32) -> usize {
        if retention_days == 0 {
            return 0;
        }
        let cutoff = chrono::Utc::now() - chrono::Duration::days(i64::from(retention_days));
        let mut removed = 0;
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return 0;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with(&self.prefix) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let Ok(modified) = meta.modified() else {
                continue;
            };
            let modified: chrono::DateTime<chrono::Utc> = modified.into();
            if modified < cutoff && std::fs::remove_file(entry.path()).is_ok() {
                removed += 1;
            }
        }
        removed
    }
}

/// Build an alert from pipeline results.
#[allow(clippy::too_many_arguments)]
pub fn build_alert(
    hostname: &str,
    path: &str,
    hashes: &Hashes,
    file_size: Option<u64>,
    file_type: Option<&str>,
    decision: &Decision,
    provider_results: Vec<ProviderResultAlert>,
    cache_status: &str,
    mode: &str,
    process: Option<ProcessInfo>,
) -> Alert {
    let extension = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"));
    Alert {
        alert_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        hostname: hostname.to_string(),
        file_path: path.to_string(),
        file_size,
        file_extension: extension,
        detected_file_type: file_type.map(str::to_string),
        sha256: hashes
            .get(crate::hashing::HashAlgo::Sha256)
            .map(str::to_string),
        sha1: hashes
            .get(crate::hashing::HashAlgo::Sha1)
            .map(str::to_string),
        md5: hashes
            .get(crate::hashing::HashAlgo::Md5)
            .map(str::to_string),
        reputation: decision.verdict,
        detection_reason: decision.reasons.join("; "),
        provider_results,
        cache_status: cache_status.to_string(),
        monitoring_mode: mode.to_string(),
        process,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn alert() -> Alert {
        let hashes = Hashes {
            values: [(
                crate::hashing::HashAlgo::Sha256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            )]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        };
        let decision = Decision {
            verdict: ReputationVerdict::Unknown,
            reasons: vec!["unknown to all successful provider(s)".into()],
            should_alert: true,
            action: "alert".into(),
            block: false,
        };
        build_alert(
            "testhost",
            "/tmp/mal.js",
            &hashes,
            Some(1024),
            Some("javascript"),
            &decision,
            vec![ProviderResultAlert {
                provider: "otx".into(),
                result: ProviderOutcome::NotFound,
                queried_at: chrono::Utc::now().to_rfc3339(),
            }],
            "miss",
            "scan",
            Some(ProcessInfo {
                pid: 42,
                exe: Some("/usr/bin/node".into()),
                name: Some("node".into()),
            }),
        )
    }

    #[test]
    fn alert_json_shape() {
        let alert = alert();
        let value = serde_json::to_value(&alert).expect("serialize");
        assert!(value["alert_id"].as_str().is_some());
        assert_eq!(value["reputation"], "UNKNOWN");
        assert_eq!(value["sha256"].as_str().expect("hash").len(), 64);
    }

    #[test]
    fn jsonl_append_and_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = AlertWriter::from_config(&crate::config::Alerts {
            directory: dir.path().display().to_string(),
            format: "jsonl".into(),
            ..Default::default()
        })
        .expect("writer");
        writer.write(&alert()).expect("write 1");
        writer.write(&alert()).expect("write 2");
        let mut entries = std::fs::read_dir(dir.path()).expect("dir");
        let file_path = entries.next().expect("entry").expect("dir entry").path();
        assert!(entries.next().is_none(), "only one file expected");
        let content = std::fs::read_to_string(&file_path).expect("read");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            serde_json::from_str::<Alert>(line).expect("valid json line");
        }
        let meta = std::fs::metadata(&file_path).expect("meta");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn json_array_format_stays_valid_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = AlertWriter::from_config(&crate::config::Alerts {
            directory: dir.path().display().to_string(),
            format: "json".into(),
            ..Default::default()
        })
        .expect("writer");
        writer.write(&alert()).expect("write 1");
        writer.write(&alert()).expect("write 2");
        let file = std::fs::read_dir(dir.path())
            .expect("dir")
            .next()
            .expect("entry")
            .expect("dir entry")
            .path();
        let parsed: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(&file).expect("read"))
                .expect("valid json array");
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn alert_file_name_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = AlertWriter::from_config(&crate::config::Alerts {
            directory: dir.path().display().to_string(),
            ..Default::default()
        })
        .expect("writer");
        assert_eq!(
            writer
                .file_path("2000-01-01", 0)
                .file_name()
                .and_then(|n| n.to_str()),
            Some("alerts.2000-01-01.jsonl")
        );
    }

    #[test]
    fn size_rotation_creates_second_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = AlertWriter {
            directory: dir.path().to_path_buf(),
            prefix: "alerts".into(),
            extension: "jsonl".into(),
            daily_rotation: true,
            file_mode: 0o600,
            max_size_bytes: 1,
            format: AlertFormat::Jsonl,
            state: Mutex::new(AlertWriterState {
                current_path: None,
                current_date: None,
                sequence: 0,
            }),
        };
        writer.write(&alert()).expect("write 1");
        writer.write(&alert()).expect("write 2");
        let count = std::fs::read_dir(dir.path()).expect("dir").count();
        assert!(
            count >= 2,
            "expected rotation into a second file, got {count}"
        );
        assert_ne!(
            writer.file_path("2000-01-01", 0),
            writer.file_path("2000-01-01", 1)
        );
    }

    #[test]
    fn retention_removes_old_files_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = AlertWriter::from_config(&crate::config::Alerts {
            directory: dir.path().display().to_string(),
            ..Default::default()
        })
        .expect("writer");
        writer.write(&alert()).expect("write");
        assert_eq!(writer.apply_retention(0), 0);
        assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 1);
    }
}
