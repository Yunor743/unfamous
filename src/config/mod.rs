//! TOML configuration model, loading and validation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const ALGORITHMS: [&str; 3] = ["sha256", "sha1", "md5"];

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct General {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_log_format")]
    pub log_format: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub offline: bool,
}

fn default_mode() -> String {
    "monitor".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "human".to_string()
}

impl Default for General {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            log_level: default_log_level(),
            log_format: default_log_format(),
            hostname: String::new(),
            offline: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Monitoring {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub fanotify: bool,
    #[serde(default = "default_true")]
    pub execution_monitoring: bool,
    #[serde(default)]
    pub file_access_monitoring: bool,
    #[serde(default = "default_true")]
    pub close_write_monitoring: bool,
    #[serde(default = "default_queue_size")]
    pub queue_size: usize,
    #[serde(default = "default_worker_count")]
    pub worker_count: usize,
    #[serde(default = "default_watch_paths")]
    pub watch_paths: Vec<String>,
    #[serde(default = "default_true")]
    pub fail_open: bool,
    #[serde(default = "default_response_timeout_ms")]
    pub response_timeout_ms: u64,
    #[serde(default = "default_block_on_malicious")]
    pub block_on_malicious: bool,
}

impl Default for Monitoring {
    fn default() -> Self {
        Self {
            enabled: true,
            fanotify: true,
            execution_monitoring: true,
            file_access_monitoring: false,
            close_write_monitoring: true,
            queue_size: default_queue_size(),
            worker_count: default_worker_count(),
            watch_paths: default_watch_paths(),
            fail_open: true,
            response_timeout_ms: default_response_timeout_ms(),
            block_on_malicious: false,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_queue_size() -> usize {
    4096
}
fn default_worker_count() -> usize {
    4
}
fn default_watch_paths() -> Vec<String> {
    vec!["/".to_string()]
}
fn default_response_timeout_ms() -> u64 {
    3000
}
fn default_block_on_malicious() -> bool {
    false
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hashing {
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    #[serde(default = "default_max_file_size")]
    pub max_file_size_mb: u64,
    #[serde(default = "default_true")]
    pub detect_file_type: bool,
}

impl Default for Hashing {
    fn default() -> Self {
        Self {
            algorithms: default_algorithms(),
            max_file_size_mb: default_max_file_size(),
            detect_file_type: true,
        }
    }
}

fn default_algorithms() -> Vec<String> {
    vec!["sha256".to_string()]
}
fn default_max_file_size() -> u64 {
    512
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileTypes {
    #[serde(default = "default_true")]
    pub pe: bool,
    #[serde(default = "default_true")]
    pub elf: bool,
    #[serde(default = "default_true")]
    pub shared_objects: bool,
    #[serde(default = "default_true")]
    pub javascript: bool,
    #[serde(default = "default_true")]
    pub hta: bool,
    #[serde(default = "default_true")]
    pub vba: bool,
    #[serde(default = "default_true")]
    pub cpl: bool,
    #[serde(default)]
    pub shell_scripts: bool,
    #[serde(default)]
    pub python: bool,
    #[serde(default)]
    pub powershell: bool,
    #[serde(default)]
    pub custom: BTreeMap<String, CustomType>,
}

impl Default for FileTypes {
    fn default() -> Self {
        Self {
            pe: true,
            elf: true,
            shared_objects: true,
            javascript: true,
            hta: true,
            vba: true,
            cpl: true,
            shell_scripts: false,
            python: false,
            powershell: false,
            custom: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustomType {
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub magic_hex: Vec<String>,
    #[serde(default = "default_true")]
    pub require_magic: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderCommon {
    pub enabled: bool,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
    #[serde(default = "default_retries")]
    pub retries: u32,
}

impl Default for ProviderCommon {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key_env: None,
            timeout_seconds: default_timeout(),
            rate_limit_per_minute: default_rate_limit(),
            retries: default_retries(),
        }
    }
}

fn default_timeout() -> u64 {
    15
}
fn default_rate_limit() -> u32 {
    240
}
fn default_retries() -> u32 {
    2
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Providers {
    #[serde(default)]
    pub virustotal: ProviderCommon,
    #[serde(default)]
    pub malwarebazaar: ProviderCommon,
    #[serde(default)]
    pub otx: ProviderCommon,
    #[serde(default = "default_circl")]
    pub circl_hashlookup: ProviderCommon,
}

fn default_circl() -> ProviderCommon {
    ProviderCommon {
        enabled: true,
        ..ProviderCommon::default()
    }
}

impl Default for Providers {
    fn default() -> Self {
        Self {
            virustotal: ProviderCommon::default(),
            malwarebazaar: ProviderCommon::default(),
            otx: ProviderCommon::default(),
            circl_hashlookup: default_circl(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Reputation {
    #[serde(default = "default_true")]
    pub alert_on_unknown: bool,
    #[serde(default = "default_true")]
    pub alert_on_known_bad: bool,
    #[serde(default)]
    pub alert_on_rare: bool,
    #[serde(default = "default_true")]
    pub alert_on_suspicious: bool,
    #[serde(default = "default_min_malicious")]
    pub minimum_malicious_providers: u32,
    #[serde(default)]
    pub detection_ratio_threshold: Option<f64>,
    #[serde(default = "default_rare_max")]
    pub rare_max_providers: u32,
    #[serde(default = "default_unknown_action")]
    pub unknown_action: String,
    #[serde(default = "default_malicious_action")]
    pub malicious_action: String,
    #[serde(default = "default_suspicious_action")]
    pub suspicious_action: String,
    #[serde(default = "default_unknown_action")]
    pub rare_action: String,
}

impl Default for Reputation {
    fn default() -> Self {
        Self {
            alert_on_unknown: true,
            alert_on_known_bad: true,
            alert_on_rare: false,
            alert_on_suspicious: true,
            minimum_malicious_providers: 1,
            detection_ratio_threshold: None,
            rare_max_providers: 1,
            unknown_action: "alert".to_string(),
            malicious_action: "alert".to_string(),
            suspicious_action: "alert".to_string(),
            rare_action: "alert".to_string(),
        }
    }
}

fn default_min_malicious() -> u32 {
    1
}
fn default_rare_max() -> u32 {
    1
}
fn default_unknown_action() -> String {
    "alert".to_string()
}
fn default_malicious_action() -> String {
    "alert".to_string()
}
fn default_suspicious_action() -> String {
    "alert".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct HashList {
    #[serde(default)]
    pub sha256: Vec<String>,
    #[serde(default)]
    pub sha1: Vec<String>,
    #[serde(default)]
    pub md5: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Lists {
    #[serde(default)]
    pub allowlist: HashList,
    #[serde(default)]
    pub denylist: HashList,
    /// When true, a denylist hit wins over any positive reputation.
    #[serde(default = "default_true")]
    pub denylist_overrides: bool,
}

impl Default for Lists {
    fn default() -> Self {
        Self {
            allowlist: HashList::default(),
            denylist: HashList::default(),
            denylist_overrides: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default = "default_db_path")]
    pub database_path: String,
    #[serde(default = "default_ttl")]
    pub default_ttl_seconds: u64,
    #[serde(default = "default_negative_ttl")]
    pub negative_ttl_seconds: u64,
    #[serde(default = "default_error_ttl")]
    pub error_ttl_seconds: u64,
    #[serde(default = "default_cache_max")]
    pub max_size_mb: u64,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: "sqlite".to_string(),
            database_path: "/var/lib/unfamous/cache.db".to_string(),
            default_ttl_seconds: 86400,
            negative_ttl_seconds: 3600,
            error_ttl_seconds: 300,
            max_size_mb: 512,
        }
    }
}

fn default_backend() -> String {
    "sqlite".to_string()
}
fn default_db_path() -> String {
    "/var/lib/unfamous/cache.db".to_string()
}
fn default_ttl() -> u64 {
    86400
}
fn default_negative_ttl() -> u64 {
    3600
}
fn default_error_ttl() -> u64 {
    300
}
fn default_cache_max() -> u64 {
    512
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Alerts {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_alert_dir")]
    pub directory: String,
    #[serde(default = "default_prefix")]
    pub filename_prefix: String,
    #[serde(default = "default_alert_format")]
    pub format: String,
    #[serde(default = "default_true")]
    pub daily_rotation: bool,
    #[serde(default = "default_retention")]
    pub retention_days: u32,
    #[serde(default = "default_file_mode")]
    pub file_mode: String,
    #[serde(default = "default_alert_max_size")]
    pub max_size_mb: u64,
}

impl Default for Alerts {
    fn default() -> Self {
        Self {
            enabled: true,
            directory: "/var/log".to_string(),
            filename_prefix: "alerts".to_string(),
            format: "jsonl".to_string(),
            daily_rotation: true,
            retention_days: 30,
            file_mode: "0600".to_string(),
            max_size_mb: 64,
        }
    }
}

fn default_alert_dir() -> String {
    "/var/log".to_string()
}
fn default_prefix() -> String {
    "alerts".to_string()
}
fn default_alert_format() -> String {
    "jsonl".to_string()
}
fn default_retention() -> u32 {
    30
}
fn default_file_mode() -> String {
    "0600".to_string()
}
fn default_alert_max_size() -> u64 {
    64
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Dfir {
    #[serde(default = "default_dfir_depth")]
    pub max_depth: usize,
    #[serde(default)]
    pub follow_symlinks: bool,
    #[serde(default = "default_dfir_threads")]
    pub threads: usize,
}

impl Default for Dfir {
    fn default() -> Self {
        Self {
            max_depth: default_dfir_depth(),
            follow_symlinks: false,
            threads: default_dfir_threads(),
        }
    }
}

fn default_dfir_depth() -> usize {
    16
}
fn default_dfir_threads() -> usize {
    4
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Privacy {
    #[serde(default)]
    pub upload_files: bool,
    #[serde(default = "default_true")]
    pub share_hashes: bool,
}

impl Default for Privacy {
    fn default() -> Self {
        Self {
            upload_files: false,
            share_hashes: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
#[derive(Default)]
pub struct Config {
    pub general: General,
    pub monitoring: Monitoring,
    pub hashing: Hashing,
    pub file_types: FileTypes,
    pub providers: Providers,
    pub reputation: Reputation,
    pub lists: Lists,
    pub cache: Cache,
    pub alerts: Alerts,
    pub dfir: Dfir,
    pub privacy: Privacy,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config file {}: {e}", path.display()))?;
        let config: Config = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("invalid configuration in {}: {e}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !matches!(self.general.mode.as_str(), "monitor" | "scan") {
            anyhow::bail!(
                "general.mode must be \"monitor\" or \"scan\", got {:?}",
                self.general.mode
            );
        }
        if !matches!(
            self.general.log_level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error"
        ) {
            anyhow::bail!("general.log_level must be one of trace|debug|info|warn|error");
        }
        if !matches!(self.general.log_format.as_str(), "human" | "json") {
            anyhow::bail!("general.log_format must be \"human\" or \"json\"");
        }
        if self.monitoring.queue_size == 0 || self.monitoring.queue_size > 1_048_576 {
            anyhow::bail!("monitoring.queue_size must be between 1 and 1048576");
        }
        if self.monitoring.worker_count == 0 || self.monitoring.worker_count > 256 {
            anyhow::bail!("monitoring.worker_count must be between 1 and 256");
        }
        if self.monitoring.enabled
            && self.monitoring.fanotify
            && !self.monitoring.execution_monitoring
            && !self.monitoring.file_access_monitoring
            && !self.monitoring.close_write_monitoring
        {
            anyhow::bail!("monitoring: enable at least one of execution_monitoring, file_access_monitoring or close_write_monitoring");
        }
        if self.monitoring.watch_paths.is_empty() {
            anyhow::bail!("monitoring.watch_paths must contain at least one path");
        }
        if self.hashing.algorithms.is_empty() {
            anyhow::bail!("hashing.algorithms must not be empty");
        }
        for algo in &self.hashing.algorithms {
            if !ALGORITHMS.contains(&algo.as_str()) {
                anyhow::bail!(
                    "hashing.algorithms contains unknown algorithm {algo:?}; supported: {ALGORITHMS:?}"
                );
            }
        }
        if self.hashing.max_file_size_mb == 0 || self.hashing.max_file_size_mb > 1_048_576 {
            anyhow::bail!("hashing.max_file_size_mb must be between 1 and 1048576");
        }
        for (name, custom) in &self.file_types.custom {
            if custom.extensions.is_empty() && custom.magic_hex.is_empty() {
                anyhow::bail!(
                    "file_types.custom.{name} needs at least one extension or magic signature"
                );
            }
            for ext in &custom.extensions {
                if !ext.starts_with('.') {
                    anyhow::bail!(
                        "file_types.custom.{name}: extension {ext:?} must start with '.'"
                    );
                }
            }
            for magic in &custom.magic_hex {
                if magic.len() < 2 || magic.len() % 2 != 0 {
                    anyhow::bail!("file_types.custom.{name}: magic signature {magic:?} must be an even-length hex string");
                }
                if hex::decode(magic).is_err() {
                    anyhow::bail!(
                        "file_types.custom.{name}: magic signature {magic:?} is not valid hex"
                    );
                }
            }
        }
        for provider in ["virustotal", "malwarebazaar", "otx", "circl_hashlookup"] {
            let section = self.provider(provider);
            if section.enabled && section.timeout_seconds == 0 {
                anyhow::bail!("providers.{provider}.timeout_seconds must be greater than 0");
            }
        }
        if self.provider("virustotal").enabled && self.provider("virustotal").api_key_env.is_none()
        {
            anyhow::bail!("providers.virustotal is enabled but api_key_env is not set");
        }
        if self.reputation.minimum_malicious_providers > 16 {
            anyhow::bail!("reputation.minimum_malicious_providers must be 16 or less");
        }
        if let Some(ratio) = self.reputation.detection_ratio_threshold {
            if !(0.0..=1.0).contains(&ratio) {
                anyhow::bail!("reputation.detection_ratio_threshold must be between 0.0 and 1.0");
            }
        }
        for (key, value) in [
            ("unknown_action", &self.reputation.unknown_action),
            ("malicious_action", &self.reputation.malicious_action),
            ("suspicious_action", &self.reputation.suspicious_action),
            ("rare_action", &self.reputation.rare_action),
        ] {
            let allowed = if key == "malicious_action" {
                matches!(value.as_str(), "alert" | "alert_block" | "log" | "none")
            } else {
                matches!(value.as_str(), "alert" | "log" | "none")
            };
            if !allowed {
                anyhow::bail!(
                    "reputation.{key} must be \"alert\", \"log\" or \"none\"{}",
                    if key == "malicious_action" { " (or \"alert_block\" to answer FAN_DENY)" } else { "" }
                );
            }
        }
        if !self.lists.allowlist.files.is_empty() || !self.lists.denylist.files.is_empty() {
            for file in self
                .lists
                .allowlist
                .files
                .iter()
                .chain(self.lists.denylist.files.iter())
            {
                if file.is_empty() {
                    anyhow::bail!("lists: list file paths must not be empty");
                }
            }
        }
        if self.cache.enabled && self.cache.backend != "sqlite" {
            anyhow::bail!("cache.backend: only \"sqlite\" is supported");
        }
        if self.cache.database_path.is_empty() {
            anyhow::bail!("cache.database_path must not be empty");
        }
        if !matches!(self.alerts.format.as_str(), "json" | "jsonl") {
            anyhow::bail!("alerts.format must be \"json\" or \"jsonl\"");
        }
        let mode = u32::from_str_radix(self.alerts.file_mode.trim_start_matches('0'), 8)
            .map_err(|_| anyhow::anyhow!("alerts.file_mode must be an octal mode such as 0600"))?;
        if mode > 0o777 {
            anyhow::bail!("alerts.file_mode must be a three-digit octal permission mode");
        }
        if self.dfir.threads == 0 || self.dfir.threads > 64 {
            anyhow::bail!("dfir.threads must be between 1 and 64");
        }
        if self.privacy.upload_files {
            anyhow::bail!(
                "privacy.upload_files=true is not supported: unfamous never uploads file contents"
            );
        }
        Ok(())
    }

    fn provider(&self, name: &str) -> &ProviderCommon {
        match name {
            "virustotal" => &self.providers.virustotal,
            "malwarebazaar" => &self.providers.malwarebazaar,
            "otx" => &self.providers.otx,
            "circl_hashlookup" => &self.providers.circl_hashlookup,
            _ => unreachable!("unknown provider name"),
        }
    }

    /// At least one provider is enabled, or offline mode is active.
    #[must_use]
    pub fn any_provider_enabled(&self) -> bool {
        self.general.offline
            || self.providers.virustotal.enabled
            || self.providers.malwarebazaar.enabled
            || self.providers.otx.enabled
            || self.providers.circl_hashlookup.enabled
    }
}

impl Config {
    #[must_use]
    pub fn alert_file_extension(&self) -> &'static str {
        if self.alerts.format == "jsonl" {
            ".jsonl"
        } else {
            ".json"
        }
    }

    /// Absolute config-relative resolution for cache and alert paths.
    #[must_use]
    pub fn resolve_cache_path(&self) -> PathBuf {
        PathBuf::from(&self.cache.database_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Config {
        Config::default()
    }

    #[test]
    fn default_config_is_valid() {
        valid().validate().expect("default config must validate");
    }

    #[test]
    fn alert_block_allowed_only_for_malicious_action() {
        let mut config = valid();
        config.reputation.malicious_action = "alert_block".into();
        config.validate().expect("alert_block is valid for malicious_action");
        config.reputation.unknown_action = "alert_block".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn actions_validated() {
        let mut config = valid();
        config.reputation.unknown_action = "explode".into();
        assert!(config.validate().is_err());
        config.reputation.unknown_action = "alert".into();
        config.reputation.malicious_action = "explode".into();
        assert!(config.validate().is_err());
        config.reputation.malicious_action = "alert".into();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn algorithms_validated() {
        let mut config = valid();
        config.hashing.algorithms = vec!["crc32".into()];
        assert!(config.validate().is_err());
        config.hashing.algorithms = vec!["sha256".into(), "md5".into()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn virustotal_needs_key_env() {
        let mut config = valid();
        config.providers.virustotal.enabled = true;
        config.providers.virustotal.api_key_env = None;
        assert!(config.validate().is_err());
        config.providers.virustotal.api_key_env = Some("UNFAMOUS_VT_API_KEY".into());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn upload_files_rejected() {
        let mut config = valid();
        config.privacy.upload_files = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn file_mode_validated() {
        let mut config = valid();
        config.alerts.file_mode = "0999".into();
        assert!(config.validate().is_err());
        config.alerts.file_mode = "0640".into();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn queue_bounds_validated() {
        let mut config = valid();
        config.monitoring.queue_size = 0;
        assert!(config.validate().is_err());
        config.monitoring.queue_size = 4096;
        config.monitoring.worker_count = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn custom_type_validated() {
        let mut config = valid();
        config.file_types.custom.insert(
            "bad".into(),
            CustomType { extensions: vec![], magic_hex: vec!["zz".into()], require_magic: true },
        );
        assert!(config.validate().is_err());
        config.file_types.custom.get_mut("bad").expect("entry").magic_hex = vec!["deadbeef".into()];
        config.file_types.custom.get_mut("bad").expect("entry").extensions = vec![".fw".into()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn unknown_top_level_key_rejected() {
        let raw = r#"
[general]
mode = "monitor"
[no_such_section]
key = 1
"#;
        let result: Result<Config, _> = toml::from_str(raw);
        assert!(result.is_err());
    }

    #[test]
    fn minimal_config_parses() {
        let raw = r#"
[monitoring]
watch_paths = ["/root"]
"#;
        let config: Config = toml::from_str(raw).expect("minimal config");
        assert_eq!(config.monitoring.watch_paths, vec!["/root".to_string()]);
    }
}
