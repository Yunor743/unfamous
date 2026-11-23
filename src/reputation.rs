//! Reputation decision engine: aggregate provider outcomes and local lists
//! into a final verdict and an action.

use serde::{Deserialize, Serialize};

use crate::providers::{ProviderHit, ProviderOutcome, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReputationVerdict {
    KnownGood,
    KnownBad,
    Unknown,
    Rare,
    Suspicious,
    InsufficientData,
    ProviderError,
}

impl ReputationVerdict {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ReputationVerdict::KnownGood => "KNOWN_GOOD",
            ReputationVerdict::KnownBad => "KNOWN_BAD",
            ReputationVerdict::Unknown => "UNKNOWN",
            ReputationVerdict::Rare => "RARE",
            ReputationVerdict::Suspicious => "SUSPICIOUS",
            ReputationVerdict::InsufficientData => "INSUFFICIENT_DATA",
            ReputationVerdict::ProviderError => "PROVIDER_ERROR",
        }
    }
}

/// Aggregated view of one provider's outcome for the deciding engine.
#[derive(Debug, Clone)]
pub struct ProviderSummary {
    pub provider: String,
    pub outcome: ProviderOutcome,
}

#[derive(Debug, Clone, Default)]
pub struct ListHits {
    pub allowlisted: bool,
    pub denylisted: bool,
    pub reason: Option<String>,
}

/// Final decision for one file.
#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: ReputationVerdict,
    pub reasons: Vec<String>,
    pub should_alert: bool,
    pub action: String,
    /// True when the decision authorizes a blocking response (fanotify DENY).
    pub block: bool,
}

pub struct Policy {
    pub alert_on_unknown: bool,
    pub alert_on_known_bad: bool,
    pub alert_on_rare: bool,
    pub alert_on_suspicious: bool,
    pub minimum_malicious_providers: u32,
    pub detection_ratio_threshold: Option<f64>,
    pub rare_max_providers: u32,
    pub unknown_action: String,
    pub malicious_action: String,
    pub suspicious_action: String,
    pub rare_action: String,
    pub denylist_overrides: bool,
}

impl Policy {
    #[must_use]
    pub fn from_config(reputation: &crate::config::Reputation, denylist_overrides: bool) -> Self {
        Self {
            alert_on_unknown: reputation.alert_on_unknown,
            alert_on_known_bad: reputation.alert_on_known_bad,
            alert_on_rare: reputation.alert_on_rare,
            alert_on_suspicious: reputation.alert_on_suspicious,
            minimum_malicious_providers: reputation.minimum_malicious_providers,
            detection_ratio_threshold: reputation.detection_ratio_threshold,
            rare_max_providers: reputation.rare_max_providers,
            unknown_action: reputation.unknown_action.clone(),
            malicious_action: reputation.malicious_action.clone(),
            suspicious_action: reputation.suspicious_action.clone(),
            rare_action: reputation.rare_action.clone(),
            denylist_overrides,
        }
    }
}

/// Decide the reputation for one file from provider outcomes and list hits.
///
/// Ordering matters: local denylist first, then malicious consensus, then
/// detection ratios, then allowlist, then knowledge-based verdicts. A file
/// no provider knows is UNKNOWN, which is deliberately distinct from
/// malicious.
#[must_use]
pub fn decide(
    policy: &Policy,
    outcomes: &[ProviderSummary],
    lists: &ListHits,
    _offline: bool,
) -> Decision {
    let reasons = Vec::new();

    let malicious = |hit: &ProviderHit| hit.verdict == Verdict::Malicious;
    let malicious_hits: Vec<&ProviderSummary> = outcomes
        .iter()
        .filter(|s| matches!(&s.outcome, ProviderOutcome::Found(h) if malicious(h)))
        .collect();
    let successful: Vec<&ProviderSummary> = outcomes
        .iter()
        .filter(|s| {
            matches!(
                &s.outcome,
                ProviderOutcome::Found(_) | ProviderOutcome::NotFound
            )
        })
        .collect();
    let errored: Vec<&ProviderSummary> = outcomes.iter().filter(|s| s.outcome.is_error()).collect();
    let not_found: Vec<&ProviderSummary> = outcomes
        .iter()
        .filter(|s| matches!(s.outcome, ProviderOutcome::NotFound))
        .collect();

    let finish = |verdict, action: &str, reasons: Vec<String>| {
        let should_alert = match verdict {
            ReputationVerdict::KnownBad => policy.alert_on_known_bad && action == "alert",
            ReputationVerdict::Unknown => policy.alert_on_unknown && action == "alert",
            ReputationVerdict::Rare => policy.alert_on_rare && action == "alert",
            ReputationVerdict::Suspicious => policy.alert_on_suspicious && action == "alert",
            ReputationVerdict::KnownGood
            | ReputationVerdict::InsufficientData
            | ReputationVerdict::ProviderError => false,
        };
        let block = verdict == ReputationVerdict::KnownBad && action == "alert_block";
        Decision {
            verdict,
            reasons,
            should_alert,
            action: action.to_string(),
            block,
        }
    };

    if lists.denylisted && (policy.denylist_overrides || !lists.allowlisted) {
        let reason = lists
            .reason
            .clone()
            .unwrap_or_else(|| "hash matched a local denylist entry".to_string());
        return finish(
            ReputationVerdict::KnownBad,
            &policy.malicious_action,
            push(reasons, reason),
        );
    }

    if malicious_hits.len() as u32 >= policy.minimum_malicious_providers.max(1) {
        let names: Vec<String> = malicious_hits.iter().map(|s| s.provider.clone()).collect();
        return finish(
            ReputationVerdict::KnownBad,
            &policy.malicious_action,
            push(
                reasons,
                format!("flagged as malicious by {}", names.join(", ")),
            ),
        );
    }

    if let Some(threshold) = policy.detection_ratio_threshold {
        for summary in outcomes {
            if let ProviderOutcome::Found(hit) = &summary.outcome {
                if let (Some(mal), Some(eng)) = (hit.malicious, hit.engines) {
                    if eng > 0 {
                        let ratio = f64::from(mal) / f64::from(eng);
                        if ratio >= threshold {
                            return finish(
                                ReputationVerdict::Suspicious,
                                &policy.suspicious_action,
                                push(
                                    reasons,
                                    format!(
                                        "{} detection ratio {ratio:.2} >= {threshold}",
                                        summary.provider
                                    ),
                                ),
                            );
                        }
                    }
                }
            }
        }
    }

    if !malicious_hits.is_empty() {
        let names: Vec<String> = malicious_hits.iter().map(|s| s.provider.clone()).collect();
        return finish(
            ReputationVerdict::Suspicious,
            &policy.suspicious_action,
            push(
                reasons,
                format!(
                    "flagged as malicious by {} but the minimum is {} provider(s)",
                    names.join(", "),
                    policy.minimum_malicious_providers.max(1)
                ),
            ),
        );
    }

    if lists.allowlisted {
        return finish(
            ReputationVerdict::KnownGood,
            "log",
            push(reasons, "local allowlist match".to_string()),
        );
    }

    if successful.is_empty() {
        if !errored.is_empty() {
            return finish(
                ReputationVerdict::ProviderError,
                "log",
                push(reasons, "no provider returned a usable result".to_string()),
            );
        }
        // No provider ran at all (offline mode, no cache hit): nothing is
        // known about the file.
        return finish(
            ReputationVerdict::Unknown,
            &policy.unknown_action,
            push(reasons, "no provider results available".to_string()),
        );
    }

    let found_hits: Vec<&ProviderSummary> = outcomes
        .iter()
        .filter(|s| matches!(s.outcome, ProviderOutcome::Found(_)))
        .collect();
    if found_hits.is_empty() {
        if not_found.len() == successful.len() {
            return finish(
                ReputationVerdict::Unknown,
                &policy.unknown_action,
                push(
                    reasons,
                    format!("unknown to all {} successful provider(s)", successful.len()),
                ),
            );
        }
        return finish(
            ReputationVerdict::InsufficientData,
            "log",
            push(
                reasons,
                "mixed provider results without a clear verdict".to_string(),
            ),
        );
    }

    if found_hits.len() as u32 <= policy.rare_max_providers {
        let names: Vec<String> = found_hits.iter().map(|s| s.provider.clone()).collect();
        return finish(
            ReputationVerdict::Rare,
            &policy.rare_action,
            push(
                reasons,
                format!(
                    "known to {} provider(s) ({}), which is at or below the rare threshold {}",
                    found_hits.len(),
                    names.join(", "),
                    policy.rare_max_providers
                ),
            ),
        );
    }
    let names: Vec<String> = found_hits.iter().map(|s| s.provider.clone()).collect();
    finish(
        ReputationVerdict::KnownGood,
        "log",
        push(reasons, format!("known file: {}", names.join(", "))),
    )
}

fn push(mut reasons: Vec<String>, reason: String) -> Vec<String> {
    reasons.push(reason);
    reasons
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(verdict: Verdict, malicious: u32, engines: u32) -> ProviderOutcome {
        ProviderOutcome::Found(ProviderHit {
            verdict,
            malicious: Some(malicious),
            suspicious: Some(0),
            harmless: Some(0),
            engines: Some(engines),
            first_seen: None,
            last_seen: None,
            tags: vec![],
            family: None,
            confidence: None,
            summary: None,
        })
    }

    fn summary(name: &str, outcome: ProviderOutcome) -> ProviderSummary {
        ProviderSummary {
            provider: name.to_string(),
            outcome,
        }
    }

    fn policy() -> Policy {
        Policy {
            alert_on_unknown: true,
            alert_on_known_bad: true,
            alert_on_rare: true,
            alert_on_suspicious: true,
            minimum_malicious_providers: 1,
            detection_ratio_threshold: None,
            rare_max_providers: 1,
            unknown_action: "alert".into(),
            malicious_action: "alert".into(),
            suspicious_action: "alert".into(),
            rare_action: "alert".into(),
            denylist_overrides: true,
        }
    }

    fn no_lists() -> ListHits {
        ListHits::default()
    }

    #[test]
    fn denylist_wins() {
        let d = decide(
            &policy(),
            &[],
            &ListHits {
                allowlisted: false,
                denylisted: true,
                reason: Some("test".into()),
            },
            false,
        );
        assert_eq!(d.verdict, ReputationVerdict::KnownBad);
        assert!(d.should_alert);
    }

    #[test]
    fn single_malicious_provider() {
        let outcomes = vec![summary("virustotal", hit(Verdict::Malicious, 30, 60))];
        let d = decide(&policy(), &outcomes, &no_lists(), false);
        assert_eq!(d.verdict, ReputationVerdict::KnownBad);
        assert!(d.reasons[0].contains("virustotal"));
    }

    #[test]
    fn minimum_malicious_providers_two() {
        let mut p = policy();
        p.minimum_malicious_providers = 2;
        let one = vec![summary("virustotal", hit(Verdict::Malicious, 30, 60))];
        let d = decide(&p, &one, &no_lists(), false);
        assert_eq!(d.verdict, ReputationVerdict::Suspicious);
        let two = vec![
            summary("virustotal", hit(Verdict::Malicious, 30, 60)),
            summary("malwarebazaar", hit(Verdict::Malicious, 0, 0)),
        ];
        let d = decide(&p, &two, &no_lists(), false);
        assert_eq!(d.verdict, ReputationVerdict::KnownBad);
    }

    #[test]
    fn detection_ratio_threshold() {
        let mut p = policy();
        p.detection_ratio_threshold = Some(0.5);
        let outcomes = vec![summary("virustotal", hit(Verdict::Neutral, 40, 60))];
        let d = decide(&p, &outcomes, &no_lists(), false);
        assert_eq!(d.verdict, ReputationVerdict::Suspicious);
    }

    #[test]
    fn unknown_to_all_providers() {
        let outcomes = vec![
            summary("virustotal", ProviderOutcome::NotFound),
            summary("circl_hashlookup", ProviderOutcome::NotFound),
        ];
        let d = decide(&policy(), &outcomes, &no_lists(), false);
        assert_eq!(d.verdict, ReputationVerdict::Unknown);
        assert!(d.should_alert);
        assert_ne!(d.reasons[0], "malicious");
    }

    #[test]
    fn unknown_is_not_malicious() {
        let outcomes = vec![summary("malwarebazaar", ProviderOutcome::NotFound)];
        let d = decide(&policy(), &outcomes, &no_lists(), false);
        assert_eq!(d.verdict, ReputationVerdict::Unknown);
        assert!(!matches!(d.verdict, ReputationVerdict::KnownBad));
    }

    #[test]
    fn rare_when_known_by_one_provider() {
        let outcomes = vec![
            summary("circl_hashlookup", hit(Verdict::Benign, 0, 0)),
            summary("virustotal", ProviderOutcome::NotFound),
        ];
        let d = decide(&policy(), &outcomes, &no_lists(), false);
        assert_eq!(d.verdict, ReputationVerdict::Rare);
    }

    #[test]
    fn known_good_when_widely_known() {
        let outcomes = vec![
            summary("circl_hashlookup", hit(Verdict::Benign, 0, 0)),
            summary("otx", hit(Verdict::Neutral, 0, 3)),
            summary("virustotal", ProviderOutcome::NotFound),
        ];
        let d = decide(&policy(), &outcomes, &no_lists(), false);
        assert_eq!(d.verdict, ReputationVerdict::KnownGood);
    }

    #[test]
    fn all_providers_errored() {
        let outcomes = vec![summary("virustotal", ProviderOutcome::RateLimited)];
        let d = decide(&policy(), &outcomes, &no_lists(), false);
        assert_eq!(d.verdict, ReputationVerdict::ProviderError);
        assert!(!d.should_alert);
    }

    #[test]
    fn mixed_error_and_not_found() {
        let outcomes = vec![
            summary(
                "virustotal",
                ProviderOutcome::ProviderError {
                    message: "down".into(),
                },
            ),
            summary("circl_hashlookup", ProviderOutcome::NotFound),
        ];
        let d = decide(&policy(), &outcomes, &no_lists(), false);
        assert_eq!(d.verdict, ReputationVerdict::Unknown);
    }

    #[test]
    fn no_providers_at_all_is_unknown() {
        let d = decide(&policy(), &[], &no_lists(), true);
        assert_eq!(d.verdict, ReputationVerdict::Unknown);
        assert!(d.should_alert);
    }

    #[test]
    fn allowlist_gives_known_good() {
        let d = decide(
            &policy(),
            &[],
            &ListHits {
                allowlisted: true,
                denylisted: false,
                reason: None,
            },
            false,
        );
        assert_eq!(d.verdict, ReputationVerdict::KnownGood);
    }

    #[test]
    fn offline_mode_follows_policy() {
        let d = decide(&policy(), &[], &no_lists(), true);
        assert_eq!(d.verdict, ReputationVerdict::Unknown);
        assert!(d.should_alert);
        let mut quiet = policy();
        quiet.unknown_action = "none".into();
        let d = decide(&quiet, &[], &no_lists(), true);
        assert!(!d.should_alert);
    }
}
