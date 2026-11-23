# Security notes and limitations

Unfamous is a security tool, so its own security posture matters. This page
documents the relevant decisions and the honest limitations.

## What unfamous does not do

- It never deletes, quarantines, modifies, or blocks files by default. Even
  with `block_on_malicious = true`, only the single execution that triggered
  a `KNOWN_BAD` verdict is denied at the fanotify level.
- It never uploads file contents. `privacy.upload_files = true` is rejected
  at startup. Only hashes cross the network.
- It does not treat unknown as malicious. The `UNKNOWN` verdict is separate
  from `KNOWN_BAD` and stays separate.

## Secrets

- API keys are read from environment variables named by `api_key_env`. They
  are never read from, or written to, the configuration file.
- Keys are not logged and not included in alerts.
- The recommended environment file has mode 0600 and is loaded by systemd.

## Files and permissions

- Alert files are created with `[alerts] file_mode` (default 0600) inside a
  directory created with 0700 when it does not exist. Alerts contain file
  paths and hashes, which are sensitive in their own right.
- The cache database sits in a state directory with the same recommendation
  (`/var/lib/unfamous`, 0700).
- List files and configuration are read at startup; a malformed list entry
  aborts startup rather than silently degrading.

## TOCTOU handling

Monitoring hashes the file descriptor fanotify provides for the observed
open, so the bytes hashed are the bytes the monitored process touched, not
whatever the path points to later. Scanning re-verifies
`(device, inode, size, mtime)` before and after reading; a file that changed
while being read yields no verdict. Symlinks are not followed during scans
unless explicitly configured.

## Service hardening

The systemd unit and NixOS module run with:

- `CAP_SYS_ADMIN` only (fanotify requirement), no other capabilities,
- `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`,
- protected kernel interfaces, clock, hostname and control groups,
- restricted address families and namespaces,
- writable paths limited to the cache and alert directories.

Root is still required because fanotify permission events cannot be delegated
to an unprivileged user.

## External service exposure

Hash lookups tell each provider which files your systems execute. Consider:

- Use providers whose data policy you accept; read their terms.
- Rate limits and quotas are visible in docs/providers.md.
- For sensitive hosts, set `offline = true` or `share_hashes = false` and
  rely on cache plus local lists.

## Known limitations

- fanotify only reports opens, executions and close-writes. Creation and
  rename events are not observed directly; a written file is caught when it
  is closed.
- `FAN_OPEN_PERM` monitoring of everything is expensive and noisy; the
  default watches executions and close-writes.
- Hash-based detection cannot see packed or polymorphic payloads whose
  on-disk hash is new. Unfamous complements, not replaces, behavioral EDR.
- Provider coverage is heterogeneous: VirusTotal dominance does not prove a
  file benign, and MalwareBazaar only contains confirmed malware.
- SHA-1 and MD5 exist for provider compatibility. They are not secure
  integrity guarantees and are never used for anything security-critical
  beyond lookups.
- The reputation engine is additive rule evaluation, not machine learning.
  It is intentionally simple and auditable.
