# Troubleshooting

## fanotify_init failed

Monitoring with permission events requires `CAP_SYS_ADMIN`.

```console
$ sudo setcap cap_sys_admin+ep ./unfamous
```

or run the systemd unit / NixOS service, which grants the capability. Verify
with `getcap ./unfamous`. Containers need the capability passed through
(e.g. `--cap-add SYS_ADMIN` with Docker), which is rarely advisable.

## Cannot watch /: Device or resource busy

`fanotify_mark` with `FAN_MARK_MOUNT` fails on pseudo filesystems. Remove
problematic entries from `watch_paths` or watch specific directories instead
of `/`.

## No alerts are written

Check, in order:

1. `[alerts] enabled = true` and `directory` points where you expect.
2. The verdict triggered: with default settings only `UNKNOWN`,
   `KNOWN_BAD` and `SUSPICIOUS` alert; `RARE` requires
   `alert_on_rare = true`.
3. The file matched a category: enable `debug` logging
   (`UNFAMOUS_LOG=debug`) and look for `matched category`.
4. The file is within `[hashing] max_file_size_mb`.

## Every provider reports auth failure

- VirusTotal and MalwareBazaar require keys. Check that the environment
  variable is set in the service context: `systemctl show unfamous -p Environment`.
  For the systemd unit, keys go into the `EnvironmentFile`, not the unit file.
- A provider whose key is missing is disabled at runtime with a warning at
  startup.

## Rate limited responses

Set `rate_limit_per_minute` at or below your actual quota (VirusTotal public
tier: 4 per minute for file lookups). The cache absorbs repeat queries; with
`default_ttl_seconds` at its default 24 h, repeat executions of the same
binary cost nothing.

## High CPU or event floods

- Keep `file_access_monitoring = false` unless you need it.
- Increase `worker_count` for many-core hosts, or lower it to reduce CPU.
- Narrow `watch_paths` to risky directories (e.g. `/tmp`, `/home`) instead
  of the whole root.
- Raise `max_file_size_mb` limits only if large binaries matter to you.

## Permission event hangs a process

This should not happen: permission events are always answered, and after
`response_timeout_ms` they are answered `FAN_ALLOW` when `fail_open` is
true. If you see a hang, file a bug with the debug log
(`UNFAMOUS_LOG=unfamous::monitor=trace`).

## Cache file issues

- `unfamous cache stats` shows entry counts.
- `unfamous cache clear` resets the cache; the database is recreated.
- The cache directory must be writable by the user running unfamous. Under
  systemd, `StateDirectory=unfamous` handles this for
  `/var/lib/unfamous`.

## Scanning a forensic image is slow

- Raise `[dfir] threads`.
- Point `[cache]` at a persistent path so repeat scans reuse results.
- Use `--no-cache` only when you need fresh verdicts; it is slower.

## Debug logging

```console
$ UNFAMOUS_LOG=debug ./unfamous --config ./unfamous.conf scan --path /tmp
$ UNFAMOUS_LOG=unfamous::providers=trace ./unfamous --config ./unfamous.conf
```

JSON logs for SIEM ingestion: `[general] log_format = "json"`.
