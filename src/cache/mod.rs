//! Persistent SQLite result cache with TTLs, error-aware writes and
//! duplicate query suppression.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::hashing::HashAlgo;
use crate::providers::ProviderOutcome;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    outcome: ProviderOutcome,
    expires_at: u64,
    first_check: u64,
    last_check: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct CacheStats {
    pub entries: u64,
    pub live_entries: u64,
    pub expired_entries: u64,
}

pub struct Cache {
    conn: Mutex<Connection>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

impl Cache {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS results (
                algo TEXT NOT NULL,
                hash TEXT NOT NULL,
                provider TEXT NOT NULL,
                entry TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (algo, hash, provider)
            );
            CREATE INDEX IF NOT EXISTS idx_results_expiry ON results(expires_at);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn ttl_for(outcome_kind: OutcomeKind, config: &crate::config::Cache) -> u64 {
        match outcome_kind {
            OutcomeKind::Positive => config.default_ttl_seconds,
            OutcomeKind::Negative => config.negative_ttl_seconds,
            OutcomeKind::Error => config.error_ttl_seconds,
        }
    }

    /// Read one provider entry. Expired entries are dropped, not returned.
    pub fn get(
        &self,
        algo: HashAlgo,
        hash: &str,
        provider: &str,
        config: &crate::config::Cache,
    ) -> Option<ProviderOutcome> {
        let conn = self.conn.lock().expect("cache mutex");
        let mut stmt = conn
            .prepare_cached(
                "SELECT entry, expires_at FROM results WHERE algo=?1 AND hash=?2 AND provider=?3",
            )
            .ok()?;
        let row: Result<(String, i64), _> = stmt.query_row([algo.name(), hash, provider], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        });
        let Ok((entry_json, expires_at)) = row else {
            return None;
        };
        let entry: StoredEntry = match serde_json::from_str(&entry_json) {
            Ok(e) => e,
            Err(_) => return None,
        };
        if (expires_at as u64) <= now() {
            drop(stmt);
            let _ = conn.execute(
                "DELETE FROM results WHERE algo=?1 AND hash=?2 AND provider=?3",
                [algo.name(), hash, provider],
            );
            return None;
        }
        let _ = config;
        Some(entry.outcome)
    }

    /// Store an outcome. Error outcomes are cached with the short error TTL
    /// and never overwrite a still valid positive or negative result.
    pub fn put(
        &self,
        algo: HashAlgo,
        hash: &str,
        provider: &str,
        outcome: &ProviderOutcome,
        config: &crate::config::Cache,
    ) {
        let kind = OutcomeKind::of(outcome);
        let ts = now();
        let expires_at = ts + Self::ttl_for(kind, config);
        let entry = StoredEntry {
            outcome: outcome.clone(),
            expires_at,
            first_check: ts,
            last_check: ts,
        };
        let json = serde_json::to_string(&entry).expect("outcome serialization");
        let conn = self.conn.lock().expect("cache mutex");
        if kind == OutcomeKind::Error {
            let _ = conn.execute(
                "INSERT INTO results (algo, hash, provider, entry, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(algo, hash, provider) DO NOTHING",
                rusqlite::params![algo.name(), hash, provider, json, expires_at],
            );
        } else {
            let _ = conn.execute(
                "INSERT INTO results (algo, hash, provider, entry, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(algo, hash, provider) DO UPDATE SET
                    entry = excluded.entry,
                    expires_at = excluded.expires_at",
                rusqlite::params![algo.name(), hash, provider, json, expires_at],
            );
        }
    }

    /// Delete expired rows. Called opportunistically; the index keeps this
    /// cheap.
    pub fn prune_expired(&self) -> usize {
        let conn = self.conn.lock().expect("cache mutex");
        conn.execute("DELETE FROM results WHERE expires_at <= ?1", [now()])
            .unwrap_or(0)
    }

    /// Remove the quarter of rows that expire soonest, used when the
    /// database grows past the configured size limit.
    pub fn trim_oldest_quarter(&self) {
        let conn = self.conn.lock().expect("cache mutex");
        let _ = conn.execute(
            "DELETE FROM results WHERE rowid IN
             (SELECT rowid FROM results ORDER BY expires_at ASC LIMIT
              (SELECT COUNT(*) / 4 FROM results))",
            [],
        );
    }

    pub fn stats(&self) -> CacheStats {
        let conn = self.conn.lock().expect("cache mutex");
        let entries = conn
            .query_row("SELECT COUNT(*) FROM results", [], |r| r.get::<_, u64>(0))
            .unwrap_or(0);
        let live = conn
            .query_row(
                "SELECT COUNT(*) FROM results WHERE expires_at > ?1",
                [now()],
                |r| r.get::<_, u64>(0),
            )
            .unwrap_or(0);
        CacheStats {
            entries,
            live_entries: live,
            expired_entries: entries.saturating_sub(live),
        }
    }

    pub fn clear(&self) {
        let conn = self.conn.lock().expect("cache mutex");
        let _ = conn.execute("DELETE FROM results", []);
        let _ = conn.execute("VACUUM", []);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutcomeKind {
    Positive,
    Negative,
    Error,
}

impl OutcomeKind {
    fn of(outcome: &ProviderOutcome) -> Self {
        match outcome {
            ProviderOutcome::Found(_) => Self::Positive,
            ProviderOutcome::NotFound | ProviderOutcome::UnsupportedHash => Self::Negative,
            _ => Self::Error,
        }
    }
}

/// Serializes enrichment per hash: the first worker to take the lock queries
/// the providers; concurrent workers wait, then observe the refreshed cache.
#[derive(Default)]
pub struct HashGuard {
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl HashGuard {
    pub async fn with_lock<F, T>(&self, algo: HashAlgo, hash: &str, f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        let key = format!("{}:{}", algo.name(), hash);
        let lock = {
            let mut map = self.locks.lock().expect("guard mutex");
            map.entry(key)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;
        f.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Cache as CacheConfig;

    fn test_config(path: &Path) -> CacheConfig {
        CacheConfig {
            database_path: path.display().to_string(),
            ..CacheConfig::default()
        }
    }

    fn not_found() -> ProviderOutcome {
        ProviderOutcome::NotFound
    }

    fn malicious() -> ProviderOutcome {
        ProviderOutcome::Found(crate::providers::ProviderHit {
            verdict: crate::providers::Verdict::Malicious,
            malicious: Some(30),
            suspicious: Some(0),
            harmless: Some(0),
            engines: Some(60),
            first_seen: None,
            last_seen: None,
            tags: vec![],
            family: Some("Adwind".into()),
            confidence: Some(0.9),
            summary: None,
        })
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(&dir.path().join("cache.db")).expect("open");
        let cfg = test_config(dir.path());
        cache.put(HashAlgo::Sha256, "aa", "virustotal", &malicious(), &cfg);
        let got = cache
            .get(HashAlgo::Sha256, "aa", "virustotal", &cfg)
            .expect("hit");
        match got {
            ProviderOutcome::Found(hit) => assert_eq!(hit.family.as_deref(), Some("Adwind")),
            other => panic!("unexpected {other:?}"),
        }
        assert!(cache
            .get(HashAlgo::Sha256, "bb", "virustotal", &cfg)
            .is_none());
    }

    #[test]
    fn expiration_removes_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(&dir.path().join("cache.db")).expect("open");
        let mut cfg = test_config(dir.path());
        cfg.negative_ttl_seconds = 0;
        cache.put(HashAlgo::Sha256, "aa", "virustotal", &not_found(), &cfg);
        assert!(cache
            .get(HashAlgo::Sha256, "aa", "virustotal", &cfg)
            .is_none());
    }

    #[test]
    fn errors_do_not_overwrite_valid_results() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(&dir.path().join("cache.db")).expect("open");
        let cfg = test_config(dir.path());
        cache.put(HashAlgo::Sha256, "aa", "virustotal", &malicious(), &cfg);
        cache.put(
            HashAlgo::Sha256,
            "aa",
            "virustotal",
            &ProviderOutcome::RateLimited,
            &cfg,
        );
        let got = cache
            .get(HashAlgo::Sha256, "aa", "virustotal", &cfg)
            .expect("still valid");
        assert!(matches!(got, ProviderOutcome::Found(_)));
    }

    #[test]
    fn error_entries_cached_short_term() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(&dir.path().join("cache.db")).expect("open");
        let cfg = test_config(dir.path());
        cache.put(
            HashAlgo::Sha256,
            "aa",
            "virustotal",
            &ProviderOutcome::ProviderError {
                message: "down".into(),
            },
            &cfg,
        );
        assert!(cache
            .get(HashAlgo::Sha256, "aa", "virustotal", &cfg)
            .is_some());
        let stats = cache.stats();
        assert_eq!(stats.entries, 1);
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cache.db");
        let cfg = test_config(dir.path());
        {
            let cache = Cache::open(&path).expect("open");
            cache.put(HashAlgo::Md5, "cc", "otx", &malicious(), &cfg);
        }
        let reopened = Cache::open(&path).expect("reopen");
        assert!(reopened.get(HashAlgo::Md5, "cc", "otx", &cfg).is_some());
    }

    #[test]
    fn clear_empties_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(&dir.path().join("cache.db")).expect("open");
        let cfg = test_config(dir.path());
        cache.put(HashAlgo::Sha256, "aa", "virustotal", &malicious(), &cfg);
        cache.clear();
        assert_eq!(cache.stats().entries, 0);
    }

    #[tokio::test]
    async fn guard_serializes_same_hash() {
        let guard = HashGuard::default();
        let g2 = HashGuard::default();
        let _ = g2;
        let counter = std::sync::Arc::new(tokio::sync::Mutex::new(0u32));
        let c1 = counter.clone();
        let c2 = counter.clone();
        let job1 = guard.with_lock(HashAlgo::Sha256, "aa", async move {
            let mut c = c1.lock().await;
            *c += 1;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            *c
        });
        let job2 = guard.with_lock(HashAlgo::Sha256, "aa", async move {
            let mut c = c2.lock().await;
            *c += 10;
            *c
        });
        let (r1, r2) = tokio::join!(job1, job2);
        assert_eq!(r1, 1);
        assert_eq!(r2, 11);
    }
}
