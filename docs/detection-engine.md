# Detection engine

The detection engine turns a file observation into a reputation verdict and,
when the policy triggers, an alert. This document describes each stage and
its limits.

## File discovery

Two modes produce candidate files:

- **Monitoring** reads fanotify events. `FAN_OPEN_EXEC_PERM` fires before an
  execution completes, `FAN_OPEN_PERM` on every file open, and
  `FAN_CLOSE_WRITE` when a file opened for writing is closed. Permission
  events carry an open file descriptor, which the engine reads directly.
- **DFIR scanning** walks a directory tree and opens each matching file.

fanotify reports opens, executions and writes. It does not report file
creation or rename events by itself, and close-write coverage only catches
files that were actually opened for writing. This is why the engine hashes
the descriptor instead of trusting a path: between the event and the read,
the path may already point somewhere else.

## Classification

Files are classified against the enabled categories before any hashing:

- Binary formats are confirmed by magic bytes: `MZ` with a valid `PE\0\0`
  signature (with the PE32+ optional header check), the ELF magic with the
  `e_type` field, and the OLE compound file signature for VBA-capable
  documents.
- Text formats (JavaScript, HTA, shell, Python, PowerShell) combine
  extensions with light content heuristics such as shebang lines or HTML
  markers.
- A `.exe` file that does not contain a PE signature is not classified as
  PE. Misleading extensions never select a binary category on their own.
- Custom categories come from `[file_types.custom.*]` with optional
  `require_magic` enforcement.

Files matching no enabled category are dropped without hashing. This keeps
the engine off unrelated traffic unless `file_access_monitoring` is enabled,
in which case every open is a candidate.

## Hashing

Hashing reads the file in 64 KiB buffers through all configured hashers at
once (SHA-256, SHA-1, MD5). The file's identity, taken as
`(device, inode, size, mtime)`, is captured before and after reading. If the
two snapshots differ, the file was modified while being read: no hash is
produced and no reputation is computed. A file that grows past
`max_file_size_mb` is skipped. Permission errors and vanished files are
logged at debug level and skipped.

Symlink handling is explicit. Monitoring reads the descriptor fanotify
already opened, which follows whatever the monitored process opened. DFIR
scanning rejects symlinks unless `follow_symlinks` (or `--follow-symlinks`)
is set, so evidence trees are not silently dereferenced.

## Enrichment

Computed hashes are looked up in the cache per (algorithm, hash, provider).
Missing entries are queried through the provider interface. A per-hash lock
collapses concurrent workers: the first worker queries, others wait and then
read the refreshed cache instead of issuing duplicate requests.

Each provider query runs under a total timeout of
`timeout_seconds * (retries + 1) + 5` seconds, a client-side rate limiter,
and retry with exponential backoff and jitter for transient failures. Provider
outages produce `PROVIDER_ERROR` results; the pipeline continues with the
remaining providers and the service stays up.

## Reputation policy

The decision engine evaluates, in order:

1. Local denylist hit: `KNOWN_BAD` (with `denylist_overrides` it wins over
   everything, otherwise an allowlist hit wins).
2. Malicious consensus: at least `minimum_malicious_providers` providers
   flagged the hash malicious: `KNOWN_BAD`.
3. Detection ratio: any provider's malicious/engine ratio at or above
   `detection_ratio_threshold` (when configured): `SUSPICIOUS`.
4. Lone malicious hits below the minimum: `SUSPICIOUS`.
5. Local allowlist hit: `KNOWN_GOOD`.
6. No provider returned a usable result: `PROVIDER_ERROR` when at least one
   provider errored. When no provider ran at all (offline mode, no cache
   hit) the file is `UNKNOWN`, because nothing is known about it.
7. Known to few providers: `RARE` when the file is known (benign verdict) to
   at most `rare_max_providers` providers.
8. Unknown to every successful provider: `UNKNOWN`.
9. Everything else: `INSUFFICIENT_DATA`.

`UNKNOWN` is deliberately distinct from malicious. The default policy alerts
on unknown files because never-before-seen executables are the interesting
cases, but the alert is a detection event, not an accusation.

Each verdict maps to an action (`alert`, `log`, `none`) configured per
verdict family. Only `alert` writes an alert file. With fanotify permission
events, `block_on_malicious = true` additionally answers `FAN_DENY` for
`KNOWN_BAD` verdicts; the default is to always answer `FAN_ALLOW` (detection
and enforcement stay separate).

## Alert contents

Alerts include the alert id, UTC timestamp, hostname, path, size, extension,
detected type, all computed hashes, the verdict, the decision reason,
per-provider results with query timestamps, cache status, monitoring mode,
and process information (pid, executable, name) when fanotify provided a
pid. See docs/architecture.md for the pipeline overview and
docs/configuration.md for every knob.
