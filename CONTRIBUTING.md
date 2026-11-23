# Contributing to Unfamous

## Development setup

A Nix flake dev shell is provided:

```console
$ nix develop
```

Without Nix, install a Rust toolchain (1.75+) and run the usual commands.

## Code style

- Run `cargo fmt` before committing.
- `cargo clippy --all-targets` must stay warning-free.
- Public items carry doc comments; the crate builds with `missing_docs`
  warnings enabled.
- No em dashes in code comments or documentation.

## Tests

Every pull request should come with tests for the behavior it adds:

- Unit tests live next to the code they cover.
- End to end pipeline tests live in `tests/integration.rs` and must not
  require network access.
- Provider response parsing is tested against recorded response bodies;
  never write a test that calls a real CTI service.

Run the full suite before pushing:

```console
$ cargo test
$ cargo build --release
$ nix flake check   # when Nix is available
```

## Adding a CTI provider

1. Add a configuration section under `providers` in `src/config/mod.rs`.
2. Implement the `CtiProvider` trait in a new module under `src/providers/`.
   Map the upstream API into the normalized `ProviderOutcome` model; do not
   invent fields the API does not return.
3. Wire the provider into `Pipeline::build`.
4. Add parse tests with realistic response bodies, including the not-found,
   unauthorized and malformed cases.

## Adding a file category

File categories are defined in `src/filetype.rs` and configured in the
`[file_types]` section. Magic-byte detection is preferred over extension
matching; extension-only matches are reported with lower confidence.

## Commit messages

Write short imperative summaries, for example `fanotify: handle EINTR in
reader loop`. Explain why in the body when the change is not obvious.
