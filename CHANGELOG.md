# Changelog

## 0.1.0

Initial release.

- Continuous monitoring through fanotify (`FAN_OPEN_EXEC_PERM`,
  `FAN_OPEN_PERM`, `FAN_CLOSE_WRITE`) with permission-event responses and
  fail-open behavior.
- One-shot DFIR scanning mode with depth control, symlink policy and
  parallel processing.
- SHA-256, SHA-1 and MD5 hashing with file-change detection.
- CTI providers: VirusTotal, MalwareBazaar, AlienVault OTX, CIRCL
  Hashlookup.
- Configurable reputation policy with local allowlist and denylist.
- SQLite result cache with TTLs, deduplication and size management.
- JSON and JSONL alert output with rotation and retention.
- systemd service unit, Nix flake and NixOS module.
