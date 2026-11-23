//! `VirusTotal` file report provider.
//!
//! API: GET <https://www.virustotal.com/api/v3/files/{hash>}, header `x-apikey`.

use serde_json::Value;

use super::http::{build_client, send_with_retry, HttpOutcome, RateLimiter};
use super::{CtiProvider, ProviderHit, ProviderOutcome, Verdict};
use crate::config::ProviderCommon;
use crate::hashing::HashAlgo;

pub struct VirusTotal {
    client: reqwest::Client,
    limiter: RateLimiter,
    retries: u32,
    api_key: String,
}

impl VirusTotal {
    #[must_use]
    pub fn from_config(cfg: &ProviderCommon) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        let api_key = cfg
            .api_key_env
            .as_ref()
            .and_then(|name| std::env::var(name).ok())
            .filter(|v| !v.is_empty())?;
        Some(Self {
            client: build_client(std::time::Duration::from_secs(cfg.timeout_seconds)),
            limiter: RateLimiter::new(cfg.rate_limit_per_minute),
            retries: cfg.retries,
            api_key,
        })
    }
}

#[async_trait::async_trait]
impl CtiProvider for VirusTotal {
    fn name(&self) -> &'static str {
        "virustotal"
    }

    fn supported(&self, _algo: HashAlgo) -> bool {
        true
    }

    async fn lookup(&self, hash: &str, algo: HashAlgo) -> ProviderOutcome {
        if !super::valid_hash(algo, hash) {
            return ProviderOutcome::UnsupportedHash;
        }
        let url = format!("https://www.virustotal.com/api/v3/files/{hash}");
        let api_key = self.api_key.clone();
        let outcome = send_with_retry(&self.limiter, self.retries, || {
            self.client
                .get(&url)
                .header("x-apikey", &api_key)
                .header("accept", "application/json")
        })
        .await;
        match outcome {
            HttpOutcome::Ok(body) => match parse_vt_report(&body) {
                Ok(Some(hit)) => ProviderOutcome::Found(hit),
                Ok(None) => ProviderOutcome::NotFound,
                Err(message) => ProviderOutcome::ProviderError { message },
            },
            HttpOutcome::NotFound => ProviderOutcome::NotFound,
            HttpOutcome::AuthFailure => ProviderOutcome::AuthFailure,
            HttpOutcome::RateLimited => ProviderOutcome::RateLimited,
            HttpOutcome::Transient(message) => ProviderOutcome::ProviderError { message },
            HttpOutcome::Fatal(message) => ProviderOutcome::ProviderError { message },
        }
    }
}

/// Parse a `VirusTotal` file report body. `Ok(None)` means the hash is not in
/// the `VirusTotal` corpus.
pub fn parse_vt_report(body: &[u8]) -> Result<Option<ProviderHit>, String> {
    let value: Value = serde_json::from_slice(body).map_err(|e| format!("malformed JSON: {e}"))?;
    if value.get("error").is_some() && value.get("data").is_none() {
        let code = value["error"]["code"].as_str().unwrap_or_default();
        if code == "not_found" {
            return Ok(None);
        }
        return Err(format!("API error: {code}"));
    }
    let attrs = value
        .pointer("/data/attributes")
        .ok_or_else(|| "missing data.attributes".to_string())?;

    let stats = attrs
        .get("last_analysis_stats")
        .cloned()
        .unwrap_or(Value::Null);
    let get_stat = |key: &str| stats[key].as_u64().unwrap_or(0) as u32;
    let malicious = get_stat("malicious");
    let suspicious = get_stat("suspicious");
    let harmless = get_stat("harmless");
    let engines = malicious + suspicious + harmless + get_stat("undetected") + get_stat("timeout");

    let verdict = if malicious > 0 {
        Verdict::Malicious
    } else if suspicious > 0 {
        Verdict::Suspicious
    } else {
        Verdict::Neutral
    };

    let unix_to_iso = |key: &str| {
        attrs[key]
            .as_i64()
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    };

    let reputation = attrs.get("reputation").and_then(Value::as_i64);
    let confidence = Some(match verdict {
        Verdict::Malicious => {
            let ratio = if engines > 0 {
                malicious as f32 / engines as f32
            } else {
                0.0
            };
            (0.5 + 0.5 * ratio).min(1.0)
        }
        Verdict::Suspicious => 0.6,
        Verdict::Neutral | Verdict::Benign => {
            if reputation.is_some_and(|r| r >= 50) {
                0.7
            } else {
                0.4
            }
        }
    });

    let mut summary = serde_json::Map::new();
    if let Some(reputation) = reputation {
        summary.insert("reputation".into(), Value::from(reputation));
    }
    if let Some(desc) = attrs.get("type_description").and_then(Value::as_str) {
        summary.insert("type_description".into(), Value::from(desc));
    }
    if let Some(ranks) = attrs.get("popularity_ranks").and_then(Value::as_object) {
        let names: Vec<Value> = ranks
            .keys()
            .map(|k| Value::from(k.clone()))
            .take(8)
            .collect();
        summary.insert("popularity_ranks".into(), Value::from(names));
    }

    Ok(Some(ProviderHit {
        verdict,
        malicious: Some(malicious),
        suspicious: Some(suspicious),
        harmless: Some(harmless),
        engines: Some(engines),
        first_seen: unix_to_iso("first_submission_date"),
        last_seen: unix_to_iso("last_submission_date"),
        tags: Vec::new(),
        family: None,
        confidence,
        summary: if summary.is_empty() {
            None
        } else {
            Some(Value::Object(summary))
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(malicious: u64, suspicious: u64, undetected: u64, harmless: u64) -> Vec<u8> {
        format!(
            r#"{{"data":{{"attributes":{{"last_analysis_stats":{{"malicious":{malicious},"suspicious":{suspicious},"undetected":{undetected},"harmless":{harmless},"timeout":0}},"first_submission_date":1600000000,"last_submission_date":1700000000,"reputation":-42,"type_description":"PE executable","popularity_ranks":{{}}}}}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn malicious_report() {
        let hit = parse_vt_report(&report(40, 0, 20, 0))
            .expect("parse")
            .expect("found");
        assert_eq!(hit.verdict, Verdict::Malicious);
        assert_eq!(hit.malicious, Some(40));
        assert_eq!(hit.engines, Some(60));
        assert!(hit
            .first_seen
            .as_deref()
            .is_some_and(|s| s.starts_with("2020-09")));
    }

    #[test]
    fn clean_report_is_neutral_not_benign() {
        let hit = parse_vt_report(&report(0, 0, 70, 0))
            .expect("parse")
            .expect("found");
        assert_eq!(hit.verdict, Verdict::Neutral);
    }

    #[test]
    fn suspicious_report() {
        let hit = parse_vt_report(&report(0, 3, 57, 0))
            .expect("parse")
            .expect("found");
        assert_eq!(hit.verdict, Verdict::Suspicious);
    }

    #[test]
    fn unknown_hash() {
        let body = br#"{"error":{"code":"not_found","message":"File not found"}}"#;
        assert!(parse_vt_report(body).expect("parse").is_none());
    }

    #[test]
    fn malformed_body() {
        assert!(parse_vt_report(b"not json").is_err());
        assert!(parse_vt_report(b"{}").is_err());
    }
}
