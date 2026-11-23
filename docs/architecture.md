# Unfamous architecture

Unfamous is a Linux file reputation monitor. It hashes files observed on the
filesystem, queries external Cyber Threat Intelligence (CTI) providers for
those hashes, applies a configurable reputation policy, and writes structured
alerts. It runs in two modes: continuous monitoring built on fanotify, and a
one-shot DFIR scanner that walks a directory tree without requiring any
kernel facility.

## Component layout

```
unfamous (single crate)
src/
  main.rs          entry point, mode dispatch, signal handling
  cli.rs           clap command line interface
  config/          TOML configuration model, loading, validation
  logging.rs       tracing setup (human or JSON output)
  filetype.rs      magic byte / extension based file classification
  hashing.rs       streaming SHA-256 / SHA-1 / MD5 with TOCTOU checks
  providers/       CTI provider trait + VirusTotal, MalwareBazaar,
                   AlienVault OTX, CIRCL Hashlookup implementations
  reputation.rs    aggregation of provider results into a verdict
  lists.rs         local allowlist / denylist handling
  cache/           SQLite backed result cache with TTL and deduplication
  alerts.rs        JSON / JSONL alert writing with rotation
  monitor/         fanotify event loop, worker pool, pipeline
  dfir.rs          one-shot recursive scanning
  daemon.rs        long-running orchestration shared by both modes
```

## Pipeline

Both modes share the same enrichment pipeline. A candidate file (from
fanotify or from the DFIR walker) flows through:

1. **Classification**: a quick magic-byte check decides whether the file
   belongs to a configured, enabled category. Files that match no enabled
   category are dropped before hashing.
2. **Hashing**: one open file descriptor is used for classification, hashing
   and identity verification. Before hashing and before enrichment, the
   (device, inode) identity and size are re-checked against the original
   stat. If the file changed underneath us, the result is discarded.
3. **Cache lookup**: per (hash, algorithm, provider) result lookup. A cached
   aggregated verdict is used directly when all required providers have
   non-expired entries. Concurrent workers querying the same hash wait on a
   single in-flight query instead of issuing duplicates.
4. **Provider queries**: enabled providers are queried concurrently with
   per-provider timeouts, rate limiting and retry with exponential backoff
   and jitter. A provider failure never fails the pipeline; it produces a
   `PROVIDER_ERROR` partial result.
5. **Reputation decision**: the configured policy aggregates provider
   results, local allowlist and denylist entries into a verdict
   (`KNOWN_GOOD`, `KNOWN_BAD`, `UNKNOWN`, `RARE`, `SUSPICIOUS`,
   `INSUFFICIENT_DATA`, `PROVIDER_ERROR`).
6. **Alerting**: if the policy triggers, a JSON or JSONL alert is appended to
   the configured alert file with daily rotation and restrictive permissions.

## fanotify monitoring

The monitoring engine uses `fanotify_init` with `FAN_CLASS_CONTENT` so that
permission events can be used. The event mask is configurable:

- `FAN_OPEN_EXEC_PERM`: fires before an `execve` completes. Unfamous answers
  the permission event (`FAN_ALLOW`) after deciding whether to alert. The
  default policy alerts on suspicious files but never blocks; deny is
  available as an explicit, opt-in configuration with a fail-open timeout.
- `FAN_OPEN_PERM` and `FAN_CLOSE_WRITE`: optional, for access and
  modification monitoring of configured categories.

Key constraints that shape the design:

- Permission events must be answered quickly; a slow CTI provider must not
  stall the monitored application indefinitely. The response is sent after a
  bounded wait, and `fail_open` behavior is the default.
- `fanotify_init` with `FAN_CLASS_CONTENT` requires `CAP_SYS_ADMIN`. The
  daemon therefore needs `CAP_SYS_ADMIN` (not full root) when started from
  systemd.
- fanotify does not report file creation or rename events by itself. The
  close-write event is used to catch newly written files of interest.

A dedicated reader thread reads `fanotify_event_metadata` structures from the
fanotify file descriptor and feeds a bounded queue. Worker threads take
events, duplicate-suppress by (inode, hash), and run the pipeline. Shutdown
is cooperative: SIGINT/SIGTERM close the queue and the reader thread answers
any pending permission events before exit.

## Caching

SQLite is the cache backend (via `rusqlite`, bundled SQLite). The schema
stores one row per (hash algorithm, hash, provider): verdict data, raw
summary, first/last analysis timestamps and a per-row expiry. Negative and
error results get shorter TTLs than positive ones, both configurable. A
provider that is temporarily unavailable never overwrites an existing valid
row.

## CTI providers

Every provider implements the same trait and maps its API into a normalized
`ProviderVerdict`. The result model distinguishes found/not-found, verdict
class, detection statistics, tags, family, first/last seen, confidence and
provider-specific metadata. API endpoints used are the documented public
ones:

- VirusTotal: `GET /api/v3/files/{hash}` with the `x-apikey` header.
- MalwareBazaar: `POST https://mb-api.abuse.ch/api/v1/` form data
  `query=get_info&hash=...` with the `Auth-Key` header.
- AlienVault OTX: `GET /api/v1/indicators/file/{hash}/general`, optional
  `X-OTX-API-KEY` header.
- CIRCL Hashlookup: `GET /lookup/{algo}/{hash}`, no authentication.

API keys are read from environment variables, never from the configuration
file.

## Concurrency and failure model

- Bounded queues everywhere; the fanotify reader drops counters rather than
  growing memory.
- Per-provider semaphores for rate limiting, configurable.
- Retries only for transient failures (network, 5xx, 429), with jittered
  exponential backoff and a retry budget.
- Any provider outage degrades to `PROVIDER_ERROR` for that provider; the
  service stays up.
- Offline mode: providers disabled or unreachable; cache and local lists
  still produce verdicts.

## Deployment

- `contrib/unfamous.service`: systemd unit running with `CAP_SYS_ADMIN` for
  fanotify, hardened with `ProtectSystem=strict`, `NoNewPrivileges`, and
  writable paths limited to cache and alert directories.
- Nix flake with crane packaging, checks, dev shell, and a NixOS module
  exposing `services.unfamous` with enable, package, configuration and
  hardening options.

## Testing

Unit tests cover hashing (including modification-during-hash detection and
permission errors), file classification, provider response parsing (mocked
HTTP bodies), reputation policy combinations, cache TTL and dedup, alert
rotation, and DFIR traversal. Provider integration tests never touch the
network; HTTP behavior is exercised through a local test server. fanotify
functionality is smoke-tested manually when the environment permits, and its
event parsing is unit tested with synthetic event buffers.
