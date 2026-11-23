# DFIR mode

The `scan` subcommand runs a one-shot scan without fanotify and without root
privileges. It works on live directories, copied evidence trees, and mounted
forensic images. It never modifies the files it reads.

```console
$ unfamous --config ./unfamous.conf scan --path /mnt/evidence
$ unfamous --config ./unfamous.conf scan --path /var/tmp/case42 --depth 4
$ unfamous --config ./unfamous.conf scan --path sample.exe --single-file
$ unfamous --config ./unfamous.conf scan --path /mnt/evidence --no-cache
```

## Options

| Option | Config equivalent | Description |
| --- | --- | --- |
| `--depth N` | `[dfir] max_depth` | Maximum recursion depth (0 = the path itself only). |
| `--follow-symlinks` | `[dfir] follow_symlinks` | Follow symbolic links. Off by default so evidence trees are not silently dereferenced. |
| `--single-file` | none | Treat the path as a single file even if it is a directory name. |
| `--no-cache` | none | Ignore cached provider results and force fresh queries. |

The same file categories, hashing, providers, reputation policy and alerts
are used as in monitoring mode, so a scan and a monitor run agree on what is
suspicious.

## Behavior

- Matching files are processed in parallel by `[dfir] threads` workers.
- Every 500 processed files a progress line is logged.
- Cache entries are reused across scans and monitoring; `--no-cache` bypasses
  reads but still writes fresh results.
- A summary with file, alert and error counts is logged at the end.

## Exit status

| Code | Meaning |
| --- | --- |
| 0 | Scan completed, no alerts. |
| 1 | Fatal error (bad configuration, inaccessible path). |
| 2 | Scan completed, at least one alert was generated. |

This makes automation straightforward:

```console
$ unfamous --config ./unfamous.conf scan --path /mnt/evidence
$ echo $?
2
```

## Provider caution

A scan queries providers with the hashes of evidence files. That is usually
desirable for triage, but it tells the providers which files you are
investigating. For sensitive cases run with `offline = true` (cache and local
lists only) or `share_hashes = false` (no provider queries at all).
