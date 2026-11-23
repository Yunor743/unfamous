# Cache

The cache prevents repeated CTI requests for files that were already
analyzed. It is a SQLite database (bundled SQLite via rusqlite, no system
dependency) stored at `cache.database_path`, by default
`/var/lib/unfamous/cache.db`.

## What is stored

One row per (algorithm, hash, provider):

- the normalized provider outcome (`found`, `not_found`, errors) serialized
  as JSON,
- the expiry timestamp,
- the creation timestamp.

Aggregated verdicts are not cached separately; they are recomputed from the
per-provider rows, which keeps policy changes effective immediately.

## Expiration

Each outcome class has its own TTL:

| Outcome class | Config key | Default |
| --- | --- | --- |
| Found, not found | `default_ttl_seconds` | 86400 (24 h) |
| Unsupported hash | `negative_ttl_seconds` | 3600 |
| Errors (unavailable, rate limited, auth, timeout) | `error_ttl_seconds` | 300 |

Error results are cached only briefly so an outage is retried soon instead
of being remembered as a permanent failure. An error result never overwrites
a still-valid found or not-found result.

## Deduplication

Workers that need results for the same hash at the same time share one
query: a per-hash lock lets the first worker query the providers while the
others wait, and they then read the freshly written cache rows instead of
issuing duplicate requests.

## Size management

At startup, expired rows are deleted. If the database file still exceeds
`max_size_mb`, the quarter of rows that expire soonest is removed. The
`expires_at` index keeps both operations cheap.

## Offline behavior

In offline mode (`general.offline = true`) providers are not queried but the
cache still answers: previously fetched provider results remain usable until
they expire, and local lists apply as usual.

## Maintenance

```console
$ unfamous --config ./unfamous.conf cache stats   # entry counts as JSON
$ unfamous --config ./unfamous.conf cache clear   # delete everything
```

Deleting the database file is also safe; it is recreated on the next start.
