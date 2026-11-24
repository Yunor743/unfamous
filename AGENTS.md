# AGENTS.md

Guidance for AI agents (and human contributors) working on Unfamous: a Linux
file reputation monitor written in Rust. It hashes files observed through
fanotify or found by the DFIR scanner, queries CTI providers by hash, applies
a configurable reputation policy, and writes JSON/JSONL alerts.

## TL;DR

- Single Rust crate: `src/lib.rs` (library) plus `src/main.rs` (the
  `unfamous` binary). Library modules are shared by both binaries and the
  integration tests.
- Two modes share one pipeline: continuous fanotify monitoring and a one-shot
  DFIR scanner.
- Four CTI providers behind one trait: VirusTotal, MalwareBazaar, AlienVault
  OTX, CIRCL Hashlookup.
- Configuration is TOML (`unfamous.conf`); every key is validated at startup
  and unknown keys are rejected.
- Repository also contains a hardened systemd unit, a Nix flake with a NixOS
  module, and a microvm-based live test harness.

## Build, test, lint

This workstation has no system rustc: run cargo through a nix-shell.

```bash
nix-shell -p rustc cargo clippy rustfmt pkg-config --run 'cargo test'
nix-shell -p rustc cargo clippy rustfmt pkg-config --run 'cargo clippy --all-targets'
nix-shell -p rustc cargo rustfmt pkg-config --run 'cargo fmt --check'
nix-shell -p rustc cargo pkg-config --run 'cargo build --release'
nix flake check   # package, clippy (deny warnings), fmt, tests
```

Do not claim a feature works without running the relevant tests. Unit tests
live next to the code; end-to-end pipeline tests live in
`tests/integration.rs`; provider tests use canned response bodies and never
touch the network.

## Architecture

### Pipeline (src/daemon.rs)

`Pipeline::build` wires configuration, classifier, hash lists, cache,
providers, policy and the alert writer. `Pipeline::process` runs every
candidate file through: exclusion check, classification, hashing, cache
lookup, provider enrichment, local lists, reputation decision, alert.

- `FileContext` carries either a path (DFIR) or a file descriptor (fanotify).
  With an fd, hashing reads the descriptor itself, which removes the
  hash-then-open race.
- Enrichment consults the SQLite cache per (algorithm, hash, provider) and
  serializes concurrent queries for the same hash through `HashGuard`.

### Monitoring (src/monitor/)

- `fanotify.rs` is the FFI layer: init with `FAN_CLASS_CONTENT`, marks,
  event parsing from raw bytes, and permission responses.
- `mod.rs` runs a reader thread feeding a bounded tokio mpsc queue consumed
  by worker tasks. The reader thread owns the queue senders; shutdown is a
  flag plus thread join, and pending permission events are answered allow on
  drain.

Rules that must not be broken:

- Every permission event is answered exactly once. `fail_open = true` is the
  default; a processing failure or timeout answers `FAN_ALLOW`.
- Marks use `FAN_MARK_FILESYSTEM`. Directory marks do not deliver events on
  the initramfs rootfs a microvm boots from; filesystem marks do (verified
  with fatrace in the microvm test).
- A provider outage degrades to `PROVIDER_ERROR`; it must never fail the
  pipeline or the service.

### Reputation (src/reputation.rs)

Verdicts: `KNOWN_GOOD`, `KNOWN_BAD`, `UNKNOWN`, `RARE`, `SUSPICIOUS`,
`INSUFFICIENT_DATA`, `PROVIDER_ERROR`. Decision order: denylist, malicious
consensus, detection ratio, lone malicious hits, allowlist, no-result cases,
rare threshold, unknown. `UNKNOWN` is deliberately distinct from malicious.
Actions are `alert`, `log`, `none`, and `alert_block` (only valid for
`malicious_action`).

### Providers (src/providers/)

Each provider implements `CtiProvider` and maps its API into the normalized
`ProviderOutcome`. Only documented public APIs are implemented; the
VirusTotal web UI is not an API and must not be scraped. Keyless coverage
comes from OTX (anonymous) and CIRCL Hashlookup (no auth).

### Configuration (src/config/mod.rs)

All defaults live in serde `default = ...` functions and `Default` impls.
Validation happens in `Config::validate`. Any new option must come with:

1. a serde field with a default,
2. a validation rule (fail loudly on nonsense),
3. a row in `docs/configuration.md`,
4. an entry in `unfamous.conf.example`,
5. a unit test in `src/config/mod.rs`.

### Path exclusions (monitoring.exclude_paths, dfir.exclude_paths)

`daemon::is_excluded` is component-aware: `/nix/store` does not exclude
`/nix/storehouse`. The check runs inside `Pipeline::process` so both modes
honor it; the DFIR walker additionally prunes excluded subtrees (the scan
root itself is always kept so an explicit scan wins).

## Testing rules

- Provider response parsing is tested with recorded bodies, including
  not-found, unauthorized and malformed cases. Never write a test that calls
  a real CTI service.
- fanotify behavior is covered by `test/microvm/` (see its README): boot the
  microvm, execute a denylisted script, expect `FAN_DENY` and a `KNOWN_BAD`
  alert; execute a benign script, expect allow plus an `UNKNOWN` alert.
  After changing unfamous source, run `nix flake update unfamous` inside
  `test/microvm/` first: `path` inputs are snapshotted in flake.lock, so the
  guest otherwise runs a stale binary.
- Keep tests deterministic: no network, no sleeps unless timing itself is
  under test.

## Documentation rules

- English, short sentences, no em dashes, no marketing language.
- `docs/configuration.md` documents every configuration key; keep it in sync.
- Never document functionality that does not exist. Planned features say so
  explicitly.

## Commit style

Short imperative summaries (`fanotify: handle EINTR in reader loop`), body
explains why when the change is not obvious. One logical change per commit.
