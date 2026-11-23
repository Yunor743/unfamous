# NixOS deployment

Unfamous ships a Nix flake with a package, checks, a dev shell and a NixOS
module.

## Flake outputs

| Output | Description |
| --- | --- |
| `packages.<system>.default` | The unfamous package. |
| `apps.<system>.default` | Run the package directly (`nix run .`). |
| `devShells.<system>.default` | Rust toolchain, clippy, rustfmt, rust-analyzer. |
| `checks.<system>.unfamous-tests` | `cargo test`. |
| `checks.<system>.unfamous-clippy` | `cargo clippy` with warnings denied. |
| `checks.<system>.unfamous-fmt` | `cargo fmt --check`. |
| `nixosModules.default` | The `services.unfamous` module. |

```console
$ nix flake check
$ nix build
```

## Module usage

Minimal setup with a generated configuration:

```nix
{
  services.unfamous = {
    enable = true;
    package = pkgs.unfamous; # or unfamous.packages.${pkgs.system}.default
  };
}
```

With your own configuration file and API keys:

```nix
{
  services.unfamous = {
    enable = true;
    package = pkgs.unfamous;
    configFile = /etc/unfamous/unfamous.conf;
    environmentFile = "/etc/unfamous/env";
    watchPaths = [ "/" ];
    alertDirectory = "/var/log";
    cacheDirectory = "/var/lib/unfamous";
  };
}
```

The environment file is loaded by systemd; put provider keys there, for
example:

```
UNFAMOUS_VT_API_KEY=...
UNFAMOUS_MB_AUTH_KEY=...
```

## Module options

| Option | Default | Description |
| --- | --- | --- |
| `enable` | false | Enable the service. |
| `package` | the flake package | Package providing `bin/unfamous`. |
| `configFile` | null | Path to an existing `unfamous.conf`. When null, a minimal TOML file is generated from the options below. |
| `watchPaths` | `["/"]` | Paths passed to `[monitoring] watch_paths`. |
| `alertDirectory` | `/var/log` | Passed to `[alerts] directory`. |
| `cacheDirectory` | `/var/lib/unfamous` | The cache database is placed at `cacheDirectory/cache.db`. |
| `extraConfig` | `""` | TOML text appended to the generated configuration (ignored when `configFile` is set). |
| `environmentFile` | null | systemd `EnvironmentFile` for API keys. |

## Service hardening

The generated systemd service runs as root with only `CAP_SYS_ADMIN`
(needed for fanotify permission events), `NoNewPrivileges=true`,
`ProtectSystem=strict`, read-only home, protected kernel interfaces,
restricted address families and namespaces, and writable paths limited to
the alert and cache directories.

## Notes

- `configFile` and `extraConfig` are mutually exclusive ways to configure
  the service; prefer `configFile` for production systems so the deployed
  file is explicit.
- The flake builds with crane and only depends on nixpkgs, flake-utils and
  crane itself.
