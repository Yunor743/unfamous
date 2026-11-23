//! Common CTI provider interface and normalized result model.

pub mod circl;
pub mod http;
pub mod malwarebazaar;
pub mod otx;
pub mod virustotal;

use serde::{Deserialize, Serialize};

use crate::hashing::HashAlgo;

/// Provider side verdict class. Providers only assert what their API
/// actually supports; a missing field stays `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Malicious,
    Suspicious,
    Benign,
    Neutral,
}

/// Normalized provider hit, independent of the upstream API shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHit {
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malicious: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspicious: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harmless: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engines: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<serde_json::Value>,
}

/// What a provider returned for one hash. Not-found is its own state and
/// must never be read as a negative verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProviderOutcome {
    Found(ProviderHit),
    NotFound,
    ProviderError { message: String },
    RateLimited,
    AuthFailure,
    Timeout,
    UnsupportedHash,
}

impl ProviderOutcome {
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            ProviderOutcome::ProviderError { .. }
                | ProviderOutcome::RateLimited
                | ProviderOutcome::AuthFailure
                | ProviderOutcome::Timeout
        )
    }

    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ProviderOutcome::RateLimited | ProviderOutcome::Timeout
        ) || matches!(self, ProviderOutcome::ProviderError { message }
            if message.contains("timeout") || message.contains("connection failure"))
    }

    #[must_use]
    pub fn short(&self) -> String {
        match self {
            ProviderOutcome::Found(hit) => format!("found:{:?}", hit.verdict),
            ProviderOutcome::NotFound => "not_found".to_string(),
            ProviderOutcome::ProviderError { message } => format!("error:{message}"),
            ProviderOutcome::RateLimited => "rate_limited".to_string(),
            ProviderOutcome::AuthFailure => "auth_failure".to_string(),
            ProviderOutcome::Timeout => "timeout".to_string(),
            ProviderOutcome::UnsupportedHash => "unsupported_hash".to_string(),
        }
    }
}

#[async_trait::async_trait]
pub trait CtiProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn supported(&self, algo: HashAlgo) -> bool;
    async fn lookup(&self, hash: &str, algo: HashAlgo) -> ProviderOutcome;
}

/// Validate that a hash string has the right shape for its algorithm.
#[must_use]
pub fn valid_hash(algo: HashAlgo, hash: &str) -> bool {
    algo.is_valid_hex(hash)
}
