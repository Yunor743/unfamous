# Configuration reference

Unfamous reads a TOML configuration file. The default path is
`./unfamous.conf`; override it with `--config`. Every key is optional and has
a default unless stated otherwise. Unknown keys are rejected, and invalid
values abort startup with a specific error message.

Validate a configuration without running anything:

```console
$ unfamous --config ./unfamous.conf validate
```

A complete example ships as `unfamous.conf.example`.

## [general]

| Key | Default | Description |
| --- | --- | --- |
| `mode` | `monitor` | `monitor` for continuous watching, `scan` for one-shot runs. The `scan` subcommand overrides this. |
| `log_level` | `info` | `trace`, `debug`, `info`, `warn` or `error`. |
| `log_format` | `human` | `human` for console output, `json` for JSON lines (SIEM friendly). The `UNFAMOUS_LOG` environment variable overrides the filter for debugging. |
| `hostname` | `""` | Hostname written into alerts. Empty uses the system hostname. |
| `offline` | `false` | Disables every provider. Verdicts come from the cache and local lists only. |

## [monitoring]

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Master switch for the monitoring mode. |
| `fanotify` | `true` | fanotify is the only monitoring backend. |
| `execution_monitoring` | `true` | Watch executions with `FAN_OPEN_EXEC_PERM`. |
| `file_access_monitoring` | `false` | Watch every file open with `FAN_OPEN_PERM`. Noisy; enable deliberately. |
| `close_write_monitoring` | `true` | Watch completed writes with `FAN_CLOSE_WRITE` to catch newly written files. |
| `queue_size` | `4096` | Bounded event queue between the reader and the workers. |
| `worker_count` | `4` | Worker tasks processing events concurrently. |
| `watch_paths` | `["/"]` | Paths to watch. `/` is marked as a mount; other paths are marked as directories and cover their whole tree. |
| `fail_open` | `true` | Answer `FAN_ALLOW` when processing fails or times out. Setting this to false answers `FAN_DENY` on failure, which can make a system unusable when a provider outage coincides with a burst of executions. |
| `response_timeout_ms` | `3000` | Maximum enrichment time before a permission event is answered per `fail_open`. |
| `block_on_malicious` | `false` | Answer `FAN_DENY` for `KNOWN_BAD` verdicts. Explicit opt-in for enforcement; the default policy only alerts. |

## [hashing]

| Key | Default | Description |
| --- | --- | --- |
| `algorithms` | `["sha256"]` | Any subset of `sha256`, `sha1`, `md5`. SHA-1 and MD5 are for provider compatibility only; never treat them as integrity guarantees. |
| `max_file_size_mb` | `512` | Files larger than this are skipped. |
| `detect_file_type` | `true` | Classify by magic bytes before hashing. |

## [file_types]

Booleans select which categories are monitored: `pe`, `elf`,
`shared_objects`, `javascript`, `hta`, `vba`, `cpl` (default true except
where noted), plus `shell_scripts`, `python` and `powershell` (default
false).

Extensions are weak signals. Binary categories are confirmed by magic bytes;
text categories may match on content heuristics, and extension-only matches
are recorded as such in alerts.

Custom categories:

```toml
[file_types.custom.firmware]
extensions = [".fw"]
magic_hex = ["deadbeef"]
require_magic = true
```

`require_magic = true` means the signature bytes must be present; the
extension alone never selects the category.

## [providers.*]

Each provider has the same shape:

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | provider specific | Enables the provider. VirusTotal additionally requires an API key; a provider whose key is missing is disabled at runtime with a warning. |
| `api_key_env` | none | Name of the environment variable holding the key. Keys are never read from the configuration file. |
| `timeout_seconds` | `15` | Per-request timeout. |
| `rate_limit_per_minute` | `240` | Client side request limit. Set it at or below the provider quota. |
| `retries` | `2` | Retries for transient failures (network errors, 5xx, 429) with exponential backoff and jitter. |

Provider specifics are described in [providers.md](providers.md).

## [reputation]

| Key | Default | Description |
| --- | --- | --- |
| `alert_on_unknown` | `true` | Alert when no successful provider knows the file. |
| `alert_on_known_bad` | `true` | Alert on `KNOWN_BAD`. |
| `alert_on_rare` | `false` | Alert on `RARE`. |
| `alert_on_suspicious` | `true` | Alert on `SUSPICIOUS`. |
| `minimum_malicious_providers` | `1` | Providers that must flag a hash as malicious for `KNOWN_BAD`. Fewer malicious hits produce `SUSPICIOUS`. |
| `detection_ratio_threshold` | none | When set (0.0 to 1.0), a provider detection ratio at or above it produces `SUSPICIOUS`. |
| `rare_max_providers` | `1` | A file known to at most this many providers counts as `RARE`. |
| `unknown_action` | `alert` | Action for the `UNKNOWN` verdict: `alert`, `log` or `none`. |
| `malicious_action` | `alert` | Action for `KNOWN_BAD`. |
| `suspicious_action` | `alert` | Action for `SUSPICIOUS`. |
| `rare_action` | `alert` | Action for `RARE`. |

## [lists]

| Key | Default | Description |
| --- | --- | --- |
| `denylist_overrides` | `true` | A denylist hit wins over allowlist entries and provider verdicts. When false, an allowlist hit wins. |

### [lists.allowlist] and [lists.denylist]

| Key | Description |
| --- | --- |
| `sha256`, `sha1`, `md5` | Inline hash entries. |
| `files` | Files with one hash per line; `#` comments and blank lines are ignored. |

Entries are validated at startup; a malformed hash aborts startup.

## [cache]

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Master switch. |
| `backend` | `sqlite` | Only `sqlite` is implemented. |
| `database_path` | `/var/lib/unfamous/cache.db` | SQLite database file. The directory is created if missing. |
| `default_ttl_seconds` | `86400` | Expiry for found and not-found results. |
| `negative_ttl_seconds` | `3600` | Expiry for unsupported-hash results. |
| `error_ttl_seconds` | `300` | Short expiry for provider errors, so outages are retried soon. Errors never overwrite a still-valid result. |
| `max_size_mb` | `512` | Expired rows are pruned at startup; if the database still exceeds the limit, the soonest-to-expire quarter is removed. |

## [alerts]

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Master switch. When disabled, triggered detections are logged but not written to files. |
| `directory` | `/var/log` | Alert directory. Created with mode 0700 when missing. |
| `filename_prefix` | `alerts` | Alert files are named `{prefix}.{YYYY-MM-DD}.{json|jsonl}`. |
| `format` | `jsonl` | `jsonl` writes one JSON object per line; `json` rewrites a JSON array per alert. JSONL is preferred for monitoring. |
| `daily_rotation` | `true` | Start a new file per UTC day. |
| `retention_days` | `30` | Delete alert files older than this. `0` disables retention. |
| `file_mode` | `0600` | Octal permission mode for alert files. |
| `max_size_mb` | `64` | Rotate when the current file reaches this size. `0` disables size rotation. |

## [dfir]

| Key | Default | Description |
| --- | --- | --- |
| `max_depth` | `16` | Maximum recursion depth for `scan`. The `--depth` flag overrides it. |
| `follow_symlinks` | `false` | Follow symbolic links while scanning and when opening files. |
| `threads` | `4` | Parallel scan workers. |

## [privacy]

| Key | Default | Description |
| --- | --- | --- |
| `upload_files` | `false` | Must stay false. Unfamous never uploads file contents; setting true fails validation. |
| `share_hashes` | `true` | Set false to skip every provider query; hashes stay local and only cache and list data is used. |

## Secrets

API keys are read from the environment variables named by each provider's
`api_key_env`. They never appear in configuration files, logs, or alerts. The
systemd unit loads them from an `EnvironmentFile`.
