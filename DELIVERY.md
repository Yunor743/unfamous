# Unfamous delivery report

Date: 2026-11-23
Repository: https://github.com/Yunor743/unfamous (commit a9c9b50, branch main)
Reference project studied: https://github.com/Yunor743/JIT-Hater (Apache-2.0; only architectural
ideas were taken, no source code copied)

## Implemented features

- Continuous monitoring through fanotify (`FAN_CLASS_CONTENT`): `FAN_OPEN_EXEC_PERM`
  for executions, optional `FAN_OPEN_PERM`, and `FAN_CLOSE_WRITE` for written files.
  Permission events are always answered, with a configurable timeout and fail-open
  default; explicit `FAN_DENY` blocking is an opt-in flag.
- One-shot DFIR scanner (`unfamous ... scan /path` or `scan --path /path`) with depth
  control, symlink policy, parallel workers, cache reuse, progress logging and
  automation-friendly exit codes (0 clean, 1 error, 2 alerts).
- Streaming SHA-256, SHA-1, MD5 hashing (any combination), with
  device/inode/size/mtime identity verified before and after reading so files changed
  during hashing produce no verdict. Configurable size cap. Symlinks are rejected by
  default in scan mode.
- File classification by magic bytes (PE32/PE32+ incl. optional-header check, ELF
  exec vs shared object, OLE compound files) and content heuristics for JavaScript,
  HTA, shell, Python, PowerShell, CPL, plus user-defined custom categories with
  optional magic enforcement. Misleading extensions never select a binary category.
- CTI providers with a shared trait and normalized result model: VirusTotal
  (`GET /api/v3/files/{hash}`), MalwareBazaar (`POST mb-api.abuse.ch/api/v1/`,
  `query=get_info`), AlienVault OTX (`GET /api/v1/indicators/file/{hash}/general`),
  CIRCL Hashlookup (`GET /lookup/{algo}/{hash}`). Each provider is independently
  configurable with timeout, client-side rate limiting and jittered exponential-backoff
  retries for transient failures. Endpoints verified against provider documentation and
  live services during development; no invented fields.
- Reputation engine producing `KNOWN_GOOD`, `KNOWN_BAD`, `UNKNOWN`, `RARE`,
  `SUSPICIOUS`, `INSUFFICIENT_DATA`, `PROVIDER_ERROR` with configurable thresholds
  (minimum malicious providers, detection-ratio threshold, rare threshold) and
  per-verdict actions. Unknown is never treated as malicious.
- Local SHA-256/SHA-1/MD5 allowlist and denylist, inline or from files, with
  configurable denylist priority.
- Persistent SQLite cache (bundled SQLite): per (algorithm, hash, provider) rows,
  per-class TTLs (positive/negative/error), error results never overwrite valid ones,
  startup pruning and size management, concurrent duplicate-query collapse per hash.
- Alerts in JSONL (default, append-friendly) or JSON (array per file), daily and
  size-based rotation, retention, 0600 file modes, full alert body (id, UTC timestamp,
  hostname, path, size, extension, detected type, all hashes, verdict, reason,
  per-provider results with timestamps, cache status, mode, process info). API keys
  never appear in logs or alerts.
- TOML configuration (`unfamous.conf`) with full validation, a complete example file,
  environment-variable secrets, and an offline mode.
- systemd unit (`contrib/unfamous.service`) with `CAP_SYS_ADMIN` as the only
  capability plus a standard hardening set; Nix flake (package, dev shell, checks) and
  a NixOS module (`services.unfamous`) with generated config, environment file and
  hardening.
- 77 tests (71 unit, 6 integration) covering hashing, classification, provider
  parsing, reputation policy, cache, alerts, fanotify event parsing and the full
  offline pipeline. Tests never touch the network.

## Architecture overview

Single Rust crate (`src/lib.rs` + binary). A shared pipeline
(`src/daemon.rs`) serves both modes: classify -> hash from the fanotify file
descriptor or an opened path -> cache lookup -> provider enrichment -> local lists ->
policy decision -> alert. Monitoring (`src/monitor/`) runs a fanotify reader thread
polling the descriptor, feeding a bounded queue processed by worker tasks; the reader
thread owns the queue senders so a shutdown flag plus channel closure produces a clean
drain, and any pending permission events are answered `FAN_ALLOW` on exit.

## CTI providers implemented

VirusTotal, MalwareBazaar, AlienVault OTX, CIRCL Hashlookup. Candidates evaluated but
not implemented (documented in docs/providers.md): Google Threat Intelligence
(commercial), NIST NSRL (bulk dataset, better consumed via a local hashlookup), MISP
(deployment-specific).

## Linux kernel requirements

- Linux with fanotify; `FAN_OPEN_EXEC_PERM` needs kernel 5.11+.
- `CAP_SYS_ADMIN` for permission-event monitoring (monitoring mode only). Scanning
  needs no privileges.

## Build and test results (executed on this machine)

- `cargo test`: 71 unit + 6 integration tests, all passing.
- `cargo clippy --all-targets`: zero warnings (pedantic enabled with a documented,
  targeted allowlist in Cargo.toml).
- `cargo fmt --check`: clean.
- `cargo build --release`: success (Rust 1.99.0 via Nix).
- `nix flake check`: all checks passed (package, clippy with `--deny warnings`,
  fmt check, test suite).
- Live smoke test on this machine: `validate`, `scan` over a fixture directory with a
  denylist hash produced a correct `KNOWN_BAD` JSONL alert (`alerts.YYYY-MM-DD.jsonl`),
  an unknown JS file produced an `UNKNOWN` alert, exit codes 2, and `cache stats`
  reported correctly. Alerts file permissions verified 0600.
- Live fanotify validation in a NixOS microvm (`test/microvm/`, following the
  Yunor743/coruscant pattern): a NixOS 26.11 qemu/KVM microvm booted with the
  unfamous NixOS module in monitor mode. Verified with real kernel events:
  `FAN_OPEN_EXEC_PERM` fired on script execution, a denylisted script was answered
  `FAN_DENY` (execution refused, no hang), a benign script executed normally
  (fail-open), and `KNOWN_BAD` plus `UNKNOWN` JSONL alerts were written inside the
  guest. The microvm run exposed and drove out two real bugs (an invalid
  `malicious_action = "alert_block"` validation rule and missing directory-mark event
  delivery on the initramfs rootfs, fixed with `FAN_MARK_FILESYSTEM`).

## NixOS validation results

`nix flake check` passes on x86_64-linux: the package builds, clippy check passes with
warnings denied, formatting is clean, and the test suite passes inside the Nix build.
The NixOS module evaluates (`nix flake lock` succeeded; module wiring follows standard
`systemd.services` patterns). It has not been activated on a running NixOS system.

## Known limitations

- Monitoring mode is validated live inside a NixOS microvm
  (`test/microvm/README.md`); event parsing and permission-event answering are
  additionally unit-tested with synthetic kernel-format buffers.
- fanotify cannot report create/rename events directly; new files are caught through
  `FAN_CLOSE_WRITE`.
- Hash-based detection cannot see packed or polymorphic payloads; unfamous
  complements rather than replaces behavioral EDR.
- `alerts.format = "json"` rewrites the whole array file on each alert; JSONL is the
  recommended default.
- No provider was queried with real API keys during development (no keys available);
  provider request building and response parsing are verified against documented
  response shapes and live unauthenticated endpoints where possible (hashlookup and
  OTX responded live during development; VirusTotal and MalwareBazaar require keys and
  were verified against their documented contracts only).

## Repository and push status

- Local repository: clean, single commit `a9c9b50` on `main` containing the full
  project (source, tests, docs, example config, systemd unit, flake, flake.lock).
- Push to https://github.com/Yunor743/unfamous: NOT completed. No GitHub credentials
  exist on this machine (no `gh` CLI, no git credential helper, no SSH key); push
  fails with "could not read Username". The repository is left in a clean committed
  state, per the specification. Once credentials are available, `git push origin main`
  publishes the release.
