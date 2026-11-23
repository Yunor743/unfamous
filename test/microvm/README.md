# MicroVM live testing

The unit and integration tests verify logic, but fanotify event delivery and
permission-event answering only happen for real against a running kernel.
`test/microvm/` boots a NixOS microvm (qemu, KVM) in which unfamous runs in
monitor mode as root with `CAP_SYS_ADMIN`, generates real file and execution
events, and asserts on the resulting alerts.

Requirements: a Nix flake-capable host with `/dev/kvm`.

## What the test does

The guest runs the `services.unfamous` NixOS module from this flake with a
test configuration:

- offline mode (no provider traffic),
- execution (`FAN_OPEN_EXEC_PERM`) and close-write (`FAN_CLOSE_WRITE`)
  monitoring of the filesystem containing `/root` and `/tmp`,
- a denylist entry whose SHA-256 equals the baked-in `evil.sh` fixture
  (computed at evaluation time with `builtins.hashString`),
- `malicious_action = "alert_block"` and `block_on_malicious = true`, so a
  `KNOWN_BAD` verdict is answered with `FAN_DENY`.

The driver then verifies inside the guest:

1. the service reaches `active`,
2. a denylisted script's execution is denied (`FAN_DENY`, no `PWNED_MARKER`,
   no hang),
3. a benign script still executes (fail-open behavior for unknown files),
4. `KNOWN_BAD` and `UNKNOWN` JSONL alerts exist with the correct verdicts,
   `cache_status = "offline"` and `monitoring_mode = "monitor"`.

## Running it

```console
$ cd test/microvm
$ nix run .#
```

The command builds the VM (first run downloads a NixOS closure), boots it,
waits for sshd (forwarded to host port 2222, password `unfamous`), runs the
assertions and shuts the VM down. Exit code 0 means every assertion passed.

Note: the guest system is built from the flake input `unfamous`. If you
changed the source, refresh the input so the guest picks it up:

```console
$ nix flake update unfamous
```

## Files

| File | Purpose |
| --- | --- |
| `flake.nix` | VM configuration, test driver app, assertions |
| `vm.nix` | Guest system: microvm settings, unfamous service, test config |

## Debugging a failure

The driver prints the guest journal tail, the effective configuration, the
hash of the fixture and the alert contents on failure. The VM serial console
is written to a temp file whose path the driver prints at start. To poke at a
running guest manually:

```console
$ sshpass -p unfamous ssh -p 2222 root@127.0.0.1
```

The VM also ships `strace` and `fatrace`; `fatrace` is useful to confirm the
kernel itself is delivering fanotify events when the service appears silent.
