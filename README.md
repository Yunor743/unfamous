# Unfamous

Unfamous is a Linux file reputation monitor. It hashes files observed on the
filesystem, queries external Cyber Threat Intelligence (CTI) providers for
those hashes, applies a configurable reputation policy, and writes structured
alerts. Its core model is simple: a file is known good, known bad, unknown, or
rare.

Unfamous is a detection and intelligence enrichment tool. It does not remove,
quarantine, or modify files, and an unknown file is never treated as malware
by default.

## Features

- Continuous monitoring through fanotify, including `FAN_OPEN_EXEC_PERM` so
  files can be inspected before execution.
- One-shot DFIR scanning of files, directories and forensic images. No
  fanotify or root privileges required for scanning.
- Streaming SHA-256, SHA-1 and MD5 hashing with change detection: a file
  modified while being hashed produces no reputation verdict.
- CTI providers: VirusTotal, MalwareBazaar, AlienVault OTX and CIRCL
  Hashlookup. Each provider is optional and independently configurable.
- Local allowlist and denylist with configurable priority.
- Persistent SQLite cache with per-result expiration, deduplicated concurrent
  queries, and short-lived caching of provider errors.
- JSON Lines or JSON alert output with daily rotation, size rotation,
  retention and restrictive file permissions.
- Configurable reputation policy: alert thresholds, detection ratio
  thresholds, rare-file thresholds, and per-verdict actions.
- systemd service unit and a NixOS module with hardening.

## Requirements

- Linux with fanotify support (kernel 5.9 or newer for
  `FAN_OPEN_EXEC_PERM`).
- `CAP_SYS_ADMIN` for monitoring with permission events. Scanning needs no
  special privileges.
- Rust 1.75 or newer to build, or Nix with flakes to build and deploy.

## Quick start

Build and run a one-shot scan:

```console
$ cargo build --release
$ cp unfamous.conf.example unfamous.conf
$ ./target/release/unfamous --config ./unfamous.conf validate
$ ./target/release/unfamous --config ./unfamous.conf scan --path /tmp/suspicious
```

Continuous monitoring (requires CAP_SYS_ADMIN):

```console
$ sudo setcap cap_sys_admin+ep ./target/release/unfamous
$ ./target/release/unfamous --config ./unfamous.conf
```

Provider API keys come from environment variables:

```console
$ export UNFAMOUS_VT_API_KEY="..."     # VirusTotal
$ export UNFAMOUS_MB_AUTH_KEY="..."    # MalwareBazaar
$ export UNFAMOUS_OTX_API_KEY="..."    # AlienVault OTX (optional)
```

See [docs/installation.md](docs/installation.md) for full build, install and
deployment instructions, and [docs/configuration.md](docs/configuration.md)
for every configuration key.

## How a file flows through unfamous

1. The file is observed (fanotify event or DFIR walk) and classified against
   the enabled file categories by magic bytes and name.
2. Matching files are hashed with the configured algorithms.
3. Hashes are looked up in the cache, then queried against every enabled
   provider that supports the hash algorithm.
4. The reputation engine aggregates provider results and local lists into a
   verdict: `KNOWN_GOOD`, `KNOWN_BAD`, `UNKNOWN`, `RARE`, `SUSPICIOUS`,
   `INSUFFICIENT_DATA` or `PROVIDER_ERROR`.
5. If the policy triggers, an alert is written to the alert directory.

Unknown is not malicious. A file no provider has ever seen produces an
`UNKNOWN` alert by default, which is what makes unfamous useful for spotting
fresh implants, but the two states are never conflated.

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration reference](docs/configuration.md)
- [CTI providers](docs/providers.md)
- [Detection engine](docs/detection-engine.md)
- [Cache behavior](docs/cache.md)
- [Installation](docs/installation.md)
- [NixOS deployment](docs/nixos.md)
- [DFIR usage](docs/dfir.md)
- [MicroVM live testing](test/microvm/README.md)
- [Security notes and limitations](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)

## Development

```console
$ nix develop            # or use your own Rust toolchain
$ cargo test
$ cargo clippy --all-targets
$ cargo fmt --check
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
