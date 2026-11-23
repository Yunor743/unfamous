//! `AlienVault` OTX provider.
//!
//! API: GET <https://otx.alienvault.com/api/v1/indicators/file/{hash}/general>
//! with the optional `X-OTX-API-KEY` header.

use serde_json::Value;

use super::http::{build_client, send_with_retry, HttpOutcome, RateLimiter};
use super::{CtiProvider, ProviderHit, ProviderOutcome, Verdict};
use crate::config::ProviderCommon;
use crate::hashing::HashAlgo;

pub struct Otx {
    client: reqwest::Client,
    limiter: RateLimiter,
    retries: u32,
    api_key: Option<String>,
}

impl Otx {
    #[must_use]
    pub fn from_config(cfg: &ProviderCommon) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        let api_key = cfg
            .api_key_env
            .as_ref()
            .and_then(|name| std::env::var(name).ok())
            .filter(|v| !v.is_empty());
        Some(Self {
            client: build_client(std::time::Duration::from_secs(cfg.timeout_seconds)),
            limiter: RateLimiter::new(cfg.rate_limit_per_minute),
            retries: cfg.retries,
            api_key,
        })
    }
}

#[async_trait::async_trait]
impl CtiProvider for Otx {
    fn name(&self) -> &'static str {
        "otx"
    }

    fn supported(&self, algo: HashAlgo) -> bool {
        matches!(algo, HashAlgo::Sha256 | HashAlgo::Sha1 | HashAlgo::Md5)
    }

    async fn lookup(&self, hash: &str, algo: HashAlgo) -> ProviderOutcome {
        if !super::valid_hash(algo, hash) {
            return ProviderOutcome::UnsupportedHash;
        }
        let url = format!("https://otx.alienvault.com/api/v1/indicators/file/{hash}/general");
        let api_key = self.api_key.clone();
        let outcome = send_with_retry(&self.limiter, self.retries, || {
            let mut request = self.client.get(&url).header("accept", "application/json");
            if let Some(key) = &api_key {
                request = request.header("X-OTX-API-KEY", key);
            }
            request
        })
        .await;
        match outcome {
            HttpOutcome::Ok(body) => parse_otx_response(&body),
            HttpOutcome::NotFound => ProviderOutcome::NotFound,
            HttpOutcome::AuthFailure => ProviderOutcome::AuthFailure,
            HttpOutcome::RateLimited => ProviderOutcome::RateLimited,
            HttpOutcome::Transient(message) => ProviderOutcome::ProviderError { message },
            HttpOutcome::Fatal(message) => ProviderOutcome::ProviderError { message },
        }
    }
}

/// Map an OTX `general` response to an outcome. A hash with zero pulses is
/// reported as not found: pulse presence is the only signal this endpoint
/// gives for hash visibility.
pub fn parse_otx_response(body: &[u8]) -> ProviderOutcome {
    let value: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return ProviderOutcome::ProviderError {
                message: format!("malformed JSON: {e}"),
            }
        }
    };
    if value.get("error").is_some() && value.get("pulse_info").is_none() {
        let message = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("error")
            .to_string();
        return if message.contains("Unauthorized") {
            ProviderOutcome::AuthFailure
        } else {
            ProviderOutcome::ProviderError { message }
        };
    }
    let pulses = value
        .pointer("/pulse_info/pulses")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let count = value
        .pointer("/pulse_info/count")
        .and_then(Value::as_u64)
        .unwrap_or(pulses.len() as u64);
    if count == 0 && pulses.is_empty() {
        return ProviderOutcome::NotFound;
    }

    let mut tags = Vec::new();
    for pulse in &pulses {
        if let Some(pulse_tags) = pulse.get("tags").and_then(Value::as_array) {
            for tag in pulse_tags {
                if let Some(tag) = tag.as_str() {
                    if !tags.iter().any(|t: &String| t.eq_ignore_ascii_case(tag)) && tags.len() < 32
                    {
                        tags.push(tag.to_string());
                    }
                }
            }
        }
    }
    let references: Vec<String> = pulses
        .iter()
        .filter_map(|p| p.get("name").and_then(Value::as_str).map(str::to_string))
        .take(16)
        .collect();

    let summary = serde_json::json!({
        "pulse_count": count,
        "pulse_names": references,
    });

    ProviderOutcome::Found(ProviderHit {
        // Pulses are analyst submissions: visibility, not a malicious verdict.
        verdict: Verdict::Neutral,
        malicious: None,
        suspicious: None,
        harmless: None,
        engines: Some(count as u32),
        first_seen: None,
        last_seen: None,
        tags,
        family: None,
        confidence: Some(0.5),
        summary: Some(summary),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn found_with_pulses() {
        let body = br#"{"sections":["general","analysis"],"type":"sha256","pulse_info":{"count":2,"pulses":[{"name":"Pulse A","tags":["rat","stealer"]},{"name":"Pulse B","tags":["RAT"]}]}}"#;
        match parse_otx_response(body) {
            ProviderOutcome::Found(hit) => {
                assert_eq!(hit.verdict, Verdict::Neutral);
                assert_eq!(hit.engines, Some(2));
                assert_eq!(hit.tags.len(), 2);
            }
            other => panic!("expected found, got {other:?}"),
        }
    }

    #[test]
    fn zero_pulses_is_not_found() {
        let body = br#"{"sections":["general"],"pulse_info":{"count":0,"pulses":[]}}"#;
        assert!(matches!(
            parse_otx_response(body),
            ProviderOutcome::NotFound
        ));
    }

    #[test]
    fn unauthorized() {
        let body = br#"{"error":"Unauthorized"}"#;
        assert!(matches!(
            parse_otx_response(body),
            ProviderOutcome::AuthFailure
        ));
    }

    #[test]
    fn malformed() {
        assert!(matches!(
            parse_otx_response(b"<html>oops"),
            ProviderOutcome::ProviderError { .. }
        ));
    }
}
