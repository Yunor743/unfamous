//! CIRCL Hashlookup provider.
//!
//! API: GET <https://hashlookup.circl.lu/lookup/{algo}/{hash>}, no
//! authentication. The dataset is dominated by NSRL known-file sets, so a
//! hit identifies a known file rather than proving it benign.

use serde_json::Value;

use super::http::{build_client, send_with_retry, HttpOutcome, RateLimiter};
use super::{CtiProvider, ProviderHit, ProviderOutcome, Verdict};
use crate::config::ProviderCommon;
use crate::hashing::HashAlgo;

pub struct CirclHashlookup {
    client: reqwest::Client,
    limiter: RateLimiter,
    retries: u32,
}

impl CirclHashlookup {
    #[must_use]
    pub fn from_config(cfg: &ProviderCommon) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        Some(Self {
            client: build_client(std::time::Duration::from_secs(cfg.timeout_seconds)),
            limiter: RateLimiter::new(cfg.rate_limit_per_minute),
            retries: cfg.retries,
        })
    }
}

fn algo_path(algo: HashAlgo) -> &'static str {
    match algo {
        HashAlgo::Sha256 => "sha256",
        HashAlgo::Sha1 => "sha1",
        HashAlgo::Md5 => "md5",
    }
}

#[async_trait::async_trait]
impl CtiProvider for CirclHashlookup {
    fn name(&self) -> &'static str {
        "circl_hashlookup"
    }

    fn supported(&self, _algo: HashAlgo) -> bool {
        true
    }

    async fn lookup(&self, hash: &str, algo: HashAlgo) -> ProviderOutcome {
        let path = algo_path(algo);
        if !super::valid_hash(algo, hash) {
            return ProviderOutcome::UnsupportedHash;
        }
        let url = format!("https://hashlookup.circl.lu/lookup/{path}/{hash}");
        let outcome = send_with_retry(&self.limiter, self.retries, || {
            self.client.get(&url).header("accept", "application/json")
        })
        .await;
        match outcome {
            HttpOutcome::Ok(body) => parse_hashlookup_response(&body),
            HttpOutcome::NotFound => ProviderOutcome::NotFound,
            HttpOutcome::AuthFailure => ProviderOutcome::AuthFailure,
            HttpOutcome::RateLimited => ProviderOutcome::RateLimited,
            HttpOutcome::Transient(message) => ProviderOutcome::ProviderError { message },
            HttpOutcome::Fatal(message) => ProviderOutcome::ProviderError { message },
        }
    }
}

/// Map a hashlookup response to an outcome.
pub fn parse_hashlookup_response(body: &[u8]) -> ProviderOutcome {
    let value: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return ProviderOutcome::ProviderError {
                message: format!("malformed JSON: {e}"),
            }
        }
    };
    if let Some(message) = value.get("message").and_then(Value::as_str) {
        return if message.contains("Unknown hash value") {
            ProviderOutcome::NotFound
        } else {
            ProviderOutcome::ProviderError {
                message: message.to_string(),
            }
        };
    }
    let product = value
        .pointer("/ProductCode/ProductName")
        .and_then(Value::as_str);
    let version = value
        .pointer("/ProductCode/ProductVersion")
        .and_then(Value::as_str);
    let package_id = value.get("RDS:package_id").cloned();

    let mut tags = Vec::new();
    if let Some(pid) = package_id.as_ref().and_then(Value::as_str) {
        tags.push(format!("rds:{pid}"));
    }
    if let Some(os) = value
        .pointer("/OpSystemCode/OpSystemName")
        .and_then(Value::as_str)
    {
        tags.push(format!("os:{os}"));
    }

    let summary = serde_json::json!({
        "file_name": value.get("FileName").cloned(),
        "file_size": value.get("FileSize").cloned(),
        "product_name": product,
        "product_version": version,
        "package_id": package_id,
    });

    ProviderOutcome::Found(ProviderHit {
        // Known file: strong signal for known-good system software, but the
        // dataset also contains other files, so confidence stays moderate.
        verdict: Verdict::Benign,
        malicious: None,
        suspicious: None,
        harmless: None,
        engines: None,
        first_seen: None,
        last_seen: None,
        tags,
        family: None,
        confidence: Some(0.7),
        summary: Some(summary),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_file() {
        let body = br#"{"CRC32":"00000000","FileName":"requires.txt","FileSize":"0","MD5":"D41D8CD98F00B204E9800998ECF8427E","ProductCode":{"ApplicationType":"Graphic/Drawing","ProductVersion":"4.0.1"},"RDS:package_id":"304062","OpSystemCode":{"OpSystemName":"TBD"},"SHA-256":"E3B0"}"#;
        match parse_hashlookup_response(body) {
            ProviderOutcome::Found(hit) => {
                assert_eq!(hit.verdict, Verdict::Benign);
                assert_eq!(hit.tags[0], "rds:304062");
                assert!(hit.summary.is_some());
            }
            other => panic!("expected found, got {other:?}"),
        }
    }

    #[test]
    fn unknown_hash() {
        let body = br#"{"message":"Unknown hash value"}"#;
        assert!(matches!(
            parse_hashlookup_response(body),
            ProviderOutcome::NotFound
        ));
    }

    #[test]
    fn malformed() {
        assert!(matches!(
            parse_hashlookup_response(b"<!doctype html>"),
            ProviderOutcome::ProviderError { .. }
        ));
    }
}
