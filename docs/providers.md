# CTI providers

Unfamous queries external providers by hash only. File contents are never
transmitted. Every provider is optional, configured under `[providers.*]`,
and failures in one provider never affect the others.

The normalized result model distinguishes:

- `found`: the provider returned a record. The record's verdict class
  (`malicious`, `suspicious`, `benign`, `neutral`) is provider specific.
- `not_found`: the provider does not know the hash. This is not a negative
  verdict.
- `provider_error`, `rate_limited`, `auth_failure`, `timeout`: query
  problems. These are cached briefly and retried later.
- `unsupported_hash`: the provider does not accept this algorithm.

## VirusTotal

- Endpoint: `GET https://www.virustotal.com/api/v3/files/{hash}` with the
  `x-apikey` header.
- Authentication: required. Free API keys are available at
  <https://www.virustotal.com/gui/my-apikey>.
- Data extracted: last analysis statistics (malicious, suspicious, harmless,
  engine count), first and last submission dates, reputation, file type
  description, popularity ranks.
- Verdict mapping: any malicious detection is `malicious`; suspicious
  detections without malicious ones are `suspicious`; a report with neither
  is `neutral` because VirusTotal coverage is not proof of quality.
- Quota: the public API allows 4 requests per minute for file lookups. Set
  `rate_limit_per_minute` accordingly and expect the cache to do most of the
  work.

```toml
[providers.virustotal]
enabled = true
api_key_env = "UNFAMOUS_VT_API_KEY"
rate_limit_per_minute = 4
```

There is no keyless VirusTotal API. The `virustotal.com/gui/file/{hash}` page
is a browser UI backed by undocumented internal endpoints that are not
licensed for programmatic use; unfamous therefore does not implement it. If
you do not have a VirusTotal key, set `enabled = false` and use the keyless
providers instead: MalwareBazaar needs a free key, but OTX works anonymously
and CIRCL Hashlookup needs no authentication at all.

## MalwareBazaar (abuse.ch)

- Endpoint: `POST https://mb-api.abuse.ch/api/v1/` with form data
  `query=get_info&hash={hash}` and the `Auth-Key` header.
- Authentication: required. Free auth keys are available at
  <https://auth.abuse.ch/>.
- Data extracted: malware family (`signature`), tags, file type and MIME
  type, first and last seen timestamps, origin country.
- Verdict mapping: MalwareBazaar only hosts confirmed malware samples, so
  every hit is `malicious` with high confidence.
- Supports SHA-256, SHA-1 and MD5 lookups.

```toml
[providers.malwarebazaar]
enabled = true
api_key_env = "UNFAMOUS_MB_AUTH_KEY"
```

## AlienVault OTX

- Endpoint: `GET https://otx.alienvault.com/api/v1/indicators/file/{hash}/general`
  with the optional `X-OTX-API-KEY` header.
- Authentication: optional. Anonymous queries work but are rate limited.
- Data extracted: pulse count, pulse names and tags. Pulses are analyst
  submitted threat reports.
- Verdict mapping: pulse presence is community visibility, not a malicious
  verdict, so hits are `neutral`. OTX is best used as context enrichment.
- A hash with zero pulses is reported as not found.

```toml
[providers.otx]
enabled = true
api_key_env = "UNFAMOUS_OTX_API_KEY"
```

## CIRCL Hashlookup

- Endpoint: `GET https://hashlookup.circl.lu/lookup/{algo}/{hash}` for
  `sha256`, `sha1` and `md5`. No authentication.
- Data extracted: known file name, size, product name and version, NSRL
  package id, operating system name.
- Verdict mapping: a hit means the file is a known file in the hashlookup
  datasets, which are dominated by NSRL known-file sets. This is a strong
  known-good signal for system files but the dataset also contains other
  content, so confidence is moderate rather than absolute.
- A public community service: keep `rate_limit_per_minute` polite (60 is a
  reasonable default).

```toml
[providers.circl_hashlookup]
enabled = true
```

## Other providers

The provider interface (`CtiProvider` in `src/providers/mod.rs`) is designed
for extension. Candidates worth considering, not implemented in this
release:

- Google Threat Intelligence: commercial, requires an account and terms
  review.
- NIST NSRL: bulk RDS datasets, better consumed through a local database
  than an HTTP API. A hashlookup instance already exposes NSRL data.
- MISP instances: useful inside organizations that already run one; the
  feed format varies per deployment.

Add a provider only when it offers a documented, stable API and a clear
verdict signal. See CONTRIBUTING.md for the implementation checklist.

## Privacy notes

Hash lookups reveal to each provider that your system encountered a specific
file. For most environments this is acceptable and is the entire point of
file reputation. For sensitive environments, disable providers (`offline =
true` or `share_hashes = false`) and rely on the cache and local lists.
