{
  description = "Unfamous: Linux file reputation monitor (fanotify + CTI providers)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, flake-utils, crane }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        craneLib = crane.mkLib pkgs;

        src = craneLib.cleanCargoSource (craneLib.path ./.);

        commonArgs = {
          inherit src;
          strictDeps = true;
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        unfamous = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "unfamous";
          meta = with pkgs.lib; {
            description = "Linux file reputation monitor: hash files, query CTI providers, alert on unknown and malicious files";
            homepage = "https://github.com/Yunor743/unfamous";
            license = licenses.asl20;
            platforms = platforms.linux;
            mainProgram = "unfamous";
          };
        });
      in
      {
        packages = {
          inherit unfamous;
          default = unfamous;
        };

        apps.default = flake-utils.lib.mkApp { drv = unfamous; };

        devShells.default = craneLib.devShell {
          inherit cargoArtifacts;
          packages = with pkgs; [
            rust-analyzer
            clippy
            rustfmt
          ];
        };

        checks = {
          unfamous-tests = craneLib.cargoTest (commonArgs // {
            inherit cargoArtifacts;
          });
          unfamous-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });
          unfamous-fmt = craneLib.cargoFmt (commonArgs // {
            inherit cargoArtifacts;
          });
        };
      }
    )
    // {
      nixosModules.default =
        { config, lib, pkgs, ... }:
        let
          cfg = config.services.unfamous;
          generatedConfig = pkgs.writeText "unfamous.conf" ''
            [general]
            mode = "monitor"
            log_format = "json"

            [monitoring]
            enabled = true
            watch_paths = [${lib.concatMapStringsSep ", " (p: ''"${p}"'') cfg.watchPaths}]

            [cache]
            database_path = "${cfg.cacheDirectory}/cache.db"

            [alerts]
            directory = "${cfg.alertDirectory}"

            # Append operator provided configuration last so it wins.
            ${cfg.extraConfig}
          '';
          configFile = if cfg.configFile == null then generatedConfig else cfg.configFile;
        in
        {
          options.services.unfamous = {
            enable = lib.mkEnableOption "unfamous file reputation monitoring";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.default;
              defaultText = lib.literalExpression "unfamous.packages.''${pkgs.system}.default";
              description = "The unfamous package to use.";
            };

            configFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = ''
                Path to an unfamous.conf file. When null, a minimal
                configuration is generated from the module options.
              '';
            };

            watchPaths = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ "/" ];
              description = "Paths to watch with fanotify.";
            };

            alertDirectory = lib.mkOption {
              type = lib.types.str;
              default = "/var/log";
              description = "Directory alerts are written to.";
            };

            cacheDirectory = lib.mkOption {
              type = lib.types.str;
              default = "/var/lib/unfamous";
              description = "Directory holding the SQLite cache.";
            };

            extraConfig = lib.mkOption {
              type = lib.types.lines;
              default = "";
              description = "Extra TOML appended to the generated configuration.";
            };

            environmentFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              example = "/etc/unfamous/env";
              description = ''
                Environment file loaded by the service; use it for provider
                API keys (UNFAMOUS_VT_API_KEY, UNFAMOUS_MB_AUTH_KEY, ...).
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.unfamous = {
              description = "Unfamous file reputation monitor";
              after = [ "local-fs.target" "network-online.target" ];
              wants = [ "network-online.target" ];
              wantedBy = [ "multi-user.target" ];
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/unfamous --config ${configFile}";
                Restart = "on-failure";
                RestartSec = "5s";
                User = "root";
                NoNewPrivileges = true;
                CapabilityBoundingSet = [ "CAP_SYS_ADMIN" ];
                AmbientCapabilities = [ "CAP_SYS_ADMIN" ];
                ProtectSystem = "strict";
                ProtectHome = "read-only";
                PrivateTmp = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                ProtectClock = true;
                ProtectHostname = true;
                RestrictAddressFamilies = [
                  "AF_UNIX"
                  "AF_NETLINK"
                  "AF_INET"
                  "AF_INET6"
                ];
                RestrictNamespaces = true;
                LockPersonality = true;
                RestrictRealtime = true;
                SystemCallArchitectures = "native";
                ReadWritePaths = [
                  cfg.alertDirectory
                  cfg.cacheDirectory
                ];
                StateDirectory = "unfamous";
                EnvironmentFile = lib.mkIf (cfg.environmentFile != null) cfg.environmentFile;
              };
            };
          };
        };
    };
}
