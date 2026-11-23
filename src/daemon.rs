//! Shared enrichment pipeline used by both monitoring and DFIR scanning.

use std::collections::HashMap;
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::alerts::{build_alert, Alert, AlertWriter, ProcessInfo, ProviderResultAlert};
use crate::cache::{Cache, HashGuard};
use crate::config::Config;
use crate::filetype::{category_enabled, classify_file, Classifier};
use crate::hashing::{hash_file_from, open_regular_file, HashAlgo, HashError, Hashes};
use crate::lists::{HashListSet, ListKind};
use crate::providers::{CtiProvider, ProviderOutcome};
use crate::reputation::{
    decide, Decision, ListHits as DecisionLists, Policy, ProviderSummary, ReputationVerdict,
};

/// Where a candidate file came from.
pub struct FileContext {
    /// Best effort path, resolved from the fd when available.
    pub path: Option<PathBuf>,
    /// Open descriptor; when present, hashing reads from it instead of the
    /// path, which removes the classic hash-then-open race.
    pub fd: Option<RawFd>,
    pub pid: Option<u32>,
    /// "monitor" or "scan".
    pub mode: &'static str,
    /// Skip cached provider results (DFIR --no-cache).
    pub bypass_cache: bool,
}

pub struct Pipeline {
    pub config: Arc<Config>,
    pub classifier: Classifier,
    pub allowlist: HashListSet,
    pub denylist: HashListSet,
    pub cache: Option<Arc<Cache>>,
    pub guard: HashGuard,
    pub providers: Vec<Arc<dyn CtiProvider>>,
    pub configured: Vec<ConfiguredProvider>,
    pub policy: Policy,
    pub alerts: Option<AlertWriter>,
    pub hostname: String,
    pub provider_timeouts: HashMap<String, u64>,
}

/// A provider enabled in the configuration. Kept even when the provider is
/// not live (missing key, offline mode) so cached results still feed the
/// reputation engine.
pub struct ConfiguredProvider {
    pub name: String,
    pub algorithms: Vec<HashAlgo>,
}

pub struct PipelineOutcome {
    pub alert: Option<Alert>,
    pub decision: Option<Decision>,
}

/// Component-aware exclusion check: `/foobar` is NOT under `/foo`, and a
/// trailing slash on a root does not matter. An empty root list excludes
/// nothing.
#[must_use]
pub fn is_excluded(path: &Path, roots: &[String]) -> bool {
    roots
        .iter()
        .any(|root| path.starts_with(Path::new(root.trim_end_matches('/'))))
}

impl Pipeline {
    /// Combined exclusion roots: monitoring and DFIR exclusions both apply to
    /// every mode.
    fn exclusions(&self) -> Vec<String> {
        self.config
            .monitoring
            .exclude_paths
            .iter()
            .chain(self.config.dfir.exclude_paths.iter())
            .cloned()
            .collect()
    }

    pub fn build(config: Arc<Config>) -> anyhow::Result<Self> {
        let classifier = Classifier::from_config(&config.file_types);
        let allowlist = HashListSet::from_config(&config.lists.allowlist, ListKind::Allow)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let denylist = HashListSet::from_config(&config.lists.denylist, ListKind::Deny)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if !allowlist.is_empty() {
            info!(count = allowlist.len(), "allowlist loaded");
        }
        if !denylist.is_empty() {
            info!(count = denylist.len(), "denylist loaded");
        }

        let cache = if config.cache.enabled {
            let path = config.resolve_cache_path();
            match Cache::open(&path) {
                Ok(cache) => {
                    let removed = cache.prune_expired();
                    if removed > 0 {
                        info!(removed, "pruned expired cache entries");
                    }
                    enforce_cache_size(&cache, &config);
                    Some(Arc::new(cache))
                }
                Err(e) => {
                    warn!("cache disabled, cannot open {}: {e}", path.display());
                    None
                }
            }
        } else {
            None
        };

        let mut providers: Vec<Arc<dyn CtiProvider>> = Vec::new();
        let mut provider_timeouts = HashMap::new();
        let mut configured: Vec<ConfiguredProvider> = Vec::new();
        {
            let entries = [
                ("virustotal", &config.providers.virustotal),
                ("malwarebazaar", &config.providers.malwarebazaar),
                ("otx", &config.providers.otx),
                ("circl_hashlookup", &config.providers.circl_hashlookup),
            ];
            for (name, cfg) in entries {
                if !cfg.enabled {
                    continue;
                }
                let algorithms: Vec<HashAlgo> = [HashAlgo::Sha256, HashAlgo::Sha1, HashAlgo::Md5]
                    .into_iter()
                    .filter(|algo| match name {
                        "virustotal" | "circl_hashlookup" => true,
                        "malwarebazaar" | "otx" => {
                            matches!(algo, HashAlgo::Sha256 | HashAlgo::Sha1 | HashAlgo::Md5)
                        }
                        _ => true,
                    })
                    .collect();
                configured.push(ConfiguredProvider {
                    name: name.to_string(),
                    algorithms,
                });
                provider_timeouts.insert(
                    name.to_string(),
                    cfg.timeout_seconds * u64::from(cfg.retries + 1) + 5,
                );
                if config.general.offline {
                    continue;
                }
                let built: Option<Arc<dyn CtiProvider>> = match name {
                    "virustotal" => crate::providers::virustotal::VirusTotal::from_config(cfg)
                        .map(|p| Arc::new(p) as Arc<dyn CtiProvider>),
                    "malwarebazaar" => {
                        crate::providers::malwarebazaar::MalwareBazaar::from_config(cfg)
                            .map(|p| Arc::new(p) as Arc<dyn CtiProvider>)
                    }
                    "otx" => crate::providers::otx::Otx::from_config(cfg)
                        .map(|p| Arc::new(p) as Arc<dyn CtiProvider>),
                    "circl_hashlookup" => {
                        crate::providers::circl::CirclHashlookup::from_config(cfg)
                            .map(|p| Arc::new(p) as Arc<dyn CtiProvider>)
                    }
                    _ => None,
                };
                match built {
                    Some(provider) => {
                        info!(provider = name, "provider enabled");
                        providers.push(provider);
                    }
                    None => {
                        warn!(provider = name, "enabled in config but its API key is missing or empty; provider disabled at runtime");
                    }
                }
            }
        }
        if config.general.offline {
            info!("offline mode: providers disabled, relying on cache and local lists");
        }

        let policy = Policy::from_config(&config.reputation, config.lists.denylist_overrides);
        let alerts = AlertWriter::from_config(&config.alerts);
        let hostname = if config.general.hostname.is_empty() {
            system_hostname()
        } else {
            config.general.hostname.clone()
        };

        Ok(Self {
            config,
            classifier,
            allowlist,
            denylist,
            cache,
            guard: HashGuard::default(),
            providers,
            policy,
            alerts,
            hostname,
            provider_timeouts,
            configured,
        })
    }

    /// Full enrichment of one candidate file.
    pub async fn process(&self, ctx: &FileContext) -> anyhow::Result<PipelineOutcome> {
        let fd_holder;
        let owned_file;
        let file: &std::fs::File = if let Some(fd) = ctx.fd {
            fd_holder = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
            &fd_holder
        } else {
            let path = ctx
                .path
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no path and no fd for candidate file"))?;
            owned_file = Some(
                open_regular_file(path, self.config.dfir.follow_symlinks).map_err(
                    |(kind, source)| match kind {
                        crate::hashing::OpenError::Symlink => {
                            anyhow::anyhow!("symlink not followed: {}", path.display())
                        }
                        crate::hashing::OpenError::Io => {
                            anyhow::anyhow!("cannot open {}: {source}", path.display())
                        }
                    },
                )?,
            );
            owned_file.as_ref().expect("just assigned")
        };

        let meta = file.metadata()?;
        if !meta.is_file() {
            return Ok(PipelineOutcome {
                alert: None,
                decision: None,
            });
        }
        let file_size = Some(meta.len());

        let path_display = ctx
            .path
            .as_ref()
            .map_or_else(|| "<unknown path>".to_string(), |p| p.display().to_string());

        // Excluded subtrees are skipped for every mode. With no path (an
        // anonymous fd) the exclusion check cannot apply and the file is
        // processed.
        if let Some(path) = ctx.path.as_ref() {
            if is_excluded(path, &self.exclusions()) {
                debug!(path = %path.display(), "path is excluded, skipping");
                return Ok(PipelineOutcome {
                    alert: None,
                    decision: None,
                });
            }
        }

        let detection = if self.config.hashing.detect_file_type {
            let name = ctx
                .path
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            classify_file(file, name, &self.classifier)?
        } else {
            None
        };

        let Some(detection) = detection else {
            return Ok(PipelineOutcome {
                alert: None,
                decision: None,
            });
        };
        if !category_enabled(&self.classifier, &detection.category) {
            return Ok(PipelineOutcome {
                alert: None,
                decision: None,
            });
        }
        debug!(path = %path_display, category = %detection.category, "matched category");

        let algorithms: Vec<HashAlgo> = self
            .config
            .hashing
            .algorithms
            .iter()
            .filter_map(|a| HashAlgo::parse(a).ok())
            .collect();
        let hashes = match hash_file_from(
            file,
            ctx.path
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("<unknown>")),
            &algorithms,
            self.config.hashing.max_file_size_mb,
        ) {
            Ok(hashes) => hashes,
            Err(HashError::TooLarge { .. }) => {
                return Ok(PipelineOutcome {
                    alert: None,
                    decision: None,
                })
            }
            Err(e) => {
                debug!(path = %path_display, error = %e, "hashing skipped");
                return Ok(PipelineOutcome {
                    alert: None,
                    decision: None,
                });
            }
        };

        let (provider_results, cache_status) = if self.config.privacy.share_hashes {
            // Offline mode still enriches from the cache; enrich() performs
            // no network queries when no provider is live.
            self.enrich(&hashes, ctx.bypass_cache).await
        } else {
            (Vec::new(), "disabled".to_string())
        };

        let outcomes: Vec<ProviderSummary> = provider_results
            .iter()
            .map(|r| ProviderSummary {
                provider: r.provider.clone(),
                outcome: r.result.clone(),
            })
            .collect();

        let decision_lists = DecisionLists {
            allowlisted: self.allowlist.check(&hashes).is_some(),
            denylisted: self.denylist.check(&hashes).is_some(),
            reason: None,
        };
        let decision = decide(
            &self.policy,
            &outcomes,
            &decision_lists,
            self.config.general.offline || !self.config.privacy.share_hashes,
        );

        if !decision.should_alert {
            if decision.verdict == ReputationVerdict::KnownGood {
                debug!(path = %path_display, verdict = decision.verdict.name(), "no alert");
            }
            return Ok(PipelineOutcome {
                alert: None,
                decision: Some(decision),
            });
        }

        let process = ctx.pid.and_then(pid_info);
        let alert = build_alert(
            &self.hostname,
            &path_display,
            &hashes,
            file_size,
            Some(detection.category.as_str()),
            &decision,
            provider_results,
            &cache_status,
            ctx.mode,
            process,
        );

        if let Some(writer) = &self.alerts {
            match writer.write(&alert) {
                Ok(path) => {
                    writer.apply_retention(self.config.alerts.retention_days);
                    debug!(alert_file = %path.display(), "alert written");
                }
                Err(e) => warn!("failed to write alert: {e}"),
            }
        } else {
            info!(path = %path_display, verdict = decision.verdict.name(), "alert suppressed (alerts disabled)");
        }

        info!(
            path = %path_display,
            verdict = decision.verdict.name(),
            alert_id = %alert.alert_id,
            "alert generated"
        );
        Ok(PipelineOutcome {
            alert: Some(alert),
            decision: Some(decision),
        })
    }

    /// Query enabled providers for the computed hashes, honoring the cache
    /// and the per-hash guard that collapses concurrent duplicates.
    async fn enrich(
        &self,
        hashes: &Hashes,
        bypass_cache: bool,
    ) -> (Vec<ProviderResultAlert>, String) {
        let mut results = Vec::new();
        let mut hits = 0usize;
        let mut misses = 0usize;
        let cache_cfg = self.config.cache.clone();
        for (algo, hash) in &hashes.values {
            for configured in &self.configured {
                if !configured.algorithms.contains(algo) {
                    continue;
                }
                let live = self.providers.iter().find(|p| p.name() == configured.name);

                let cached = if bypass_cache {
                    None
                } else {
                    self.cache
                        .as_ref()
                        .and_then(|cache| cache.get(*algo, hash, &configured.name, &cache_cfg))
                };
                if let Some(outcome) = cached {
                    hits += 1;
                    results.push(ProviderResultAlert {
                        provider: configured.name.clone(),
                        result: outcome,
                        queried_at: now_iso(),
                    });
                    continue;
                }

                let Some(provider) = live else {
                    // Configured but not live (missing key, offline mode):
                    // only cached data can be used, no query is possible.
                    continue;
                };

                let timeout_secs = self
                    .provider_timeouts
                    .get(provider.name())
                    .copied()
                    .unwrap_or(30);
                misses += 1;
                let (outcome, from_cache) = self
                    .guard
                    .with_lock(*algo, hash, async {
                        if !bypass_cache {
                            if let Some(cache) = &self.cache {
                                if let Some(outcome) =
                                    cache.get(*algo, hash, provider.name(), &cache_cfg)
                                {
                                    return (outcome, true);
                                }
                            }
                        }
                        let attempt = tokio::time::timeout(
                            Duration::from_secs(timeout_secs),
                            provider.lookup(hash, *algo),
                        )
                        .await;
                        let outcome = match attempt {
                            Ok(outcome) => outcome,
                            Err(_) => ProviderOutcome::Timeout,
                        };
                        if let Some(cache) = &self.cache {
                            cache.put(*algo, hash, provider.name(), &outcome, &cache_cfg);
                        }
                        (outcome, false)
                    })
                    .await;
                if from_cache {
                    hits += 1;
                    misses = misses.saturating_sub(1);
                }
                debug!(provider = %provider.name(), hash = %hash, result = %outcome.short(), "provider result");
                results.push(ProviderResultAlert {
                    provider: provider.name().to_string(),
                    result: outcome,
                    queried_at: now_iso(),
                });
            }
        }
        let status = if hits == 0 && misses == 0 {
            if self.config.general.offline {
                "offline"
            } else {
                "disabled"
            }
        } else if hits == 0 {
            "miss"
        } else if misses == 0 {
            "hit"
        } else {
            "partial"
        };
        (results, status.to_string())
    }
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn system_hostname() -> String {
    let mut buffer = [0u8; 256];
    let ret = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if ret == 0 {
        let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
        if let Ok(name) = std::str::from_utf8(&buffer[..end]) {
            return name.to_string();
        }
    }
    "unknown".to_string()
}

fn pid_info(pid: u32) -> Option<ProcessInfo> {
    if pid == 0 {
        return None;
    }
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .ok();
    if exe.is_none() && name.is_none() {
        return None;
    }
    Some(ProcessInfo {
        pid,
        exe: exe.map(|p| p.display().to_string()),
        name,
    })
}

/// Keep the cache database within the configured size by removing expired
/// rows first, then the soonest-to-expire quarter when still oversized.
fn enforce_cache_size(cache: &Cache, config: &Config) {
    let path = PathBuf::from(&config.cache.database_path);
    let Ok(meta) = std::fs::metadata(&path) else {
        return;
    };
    let max_bytes = config.cache.max_size_mb.saturating_mul(1024 * 1024);
    if max_bytes == 0 || meta.len() <= max_bytes {
        return;
    }
    cache.prune_expired();
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > max_bytes {
            cache.trim_oldest_quarter();
            info!("cache exceeded max_size_mb; trimmed oldest entries");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_excluded_component_aware() {
        let roots = vec!["/nix/store".to_string(), "/var/cache".to_string()];
        assert!(is_excluded(Path::new("/nix/store"), &roots));
        assert!(is_excluded(
            Path::new("/nix/store/somepkg/file.txt"),
            &roots
        ));
        assert!(is_excluded(Path::new("/var/cache/deep/nested"), &roots));
        assert!(!is_excluded(Path::new("/nix/storehouse"), &roots));
        assert!(!is_excluded(Path::new("/root"), &roots));
        assert!(!is_excluded(Path::new("/etc/passwd"), &[]));
        // Trailing slash on the root does not break matching.
        let roots = vec!["/var/cache/".to_string()];
        assert!(is_excluded(Path::new("/var/cache/apt"), &roots));
    }
}
