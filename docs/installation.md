# Installation

## From source

Requirements: Linux, Rust 1.75 or newer.

```console
$ git clone https://github.com/Yunor743/unfamous.git
$ cd unfamous
$ cargo build --release
```

The binary is `target/release/unfamous`. There are no runtime library
dependencies: TLS is provided by rustls and SQLite is bundled.

## From Nix

```console
$ nix build .          # or: nix run . -- --help
```

## Setup

```console
$ sudo install -Dm755 target/release/unfamous /usr/local/bin/unfamous
$ sudo install -Dm644 unfamous.conf.example /etc/unfamous/unfamous.conf
$ sudoedit /etc/unfamous/unfamous.conf
```

Create the state directories and put API keys in an environment file readable
only by root:

```console
$ sudo install -dm700 /var/lib/unfamous
$ sudo sh -c 'umask 077; printf "UNFAMOUS_VT_API_KEY=%s\n" "your-key" > /etc/unfamous/env'
```

Validate the configuration:

```console
$ unfamous --config /etc/unfamous/unfamous.conf validate
```

## Capabilities

| Operation | Requirement |
| --- | --- |
| DFIR scanning | none |
| Cache and alerts in user-writable paths | none |
| fanotify monitoring with permission events | `CAP_SYS_ADMIN` |

`fanotify_init` with `FAN_CLASS_CONTENT` (needed for
`FAN_OPEN_EXEC_PERM`/`FAN_OPEN_PERM`) requires `CAP_SYS_ADMIN`. The service
unit grants exactly that capability. Two ways to run the binary directly:

```console
# As root (the unit effectively does this with a reduced capability set):
$ sudo ./unfamous --config ./unfamous.conf

# Or grant the single capability to the binary:
$ sudo setcap cap_sys_admin+ep ./target/release/unfamous
$ ./unfamous --config ./unfamous.conf
```

## systemd

The template unit is in `contrib/unfamous.service`. Install it:

```console
$ sudo install -Dm644 contrib/unfamous.service /etc/systemd/system/unfamous.service
$ sudo sed -i 's|@bindir@|/usr/local/bin|; s|@config@|/etc/unfamous|; s|@statedir@|/var/lib/unfamous|; s|@logdir@|/var/log|' /etc/systemd/system/unfamous.service
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now unfamous
```

The unit runs as root with `CAP_SYS_ADMIN` as the only capability,
`ProtectSystem=strict`, and writable paths limited to the cache and alert
directories. See the unit file for the full hardening set.

On NixOS use the module instead, see [nixos.md](nixos.md).

## Uninstallation

```console
$ sudo systemctl disable --now unfamous
$ sudo rm /etc/systemd/system/unfamous.service
$ sudo systemctl daemon-reload
$ sudo rm /usr/local/bin/unfamous
$ sudo rm -rf /var/lib/unfamous /etc/unfamous   # optional: removes cache and keys
```

Alert files under `[alerts] directory` are only removed if you delete them
yourself.
