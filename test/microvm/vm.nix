{
  config,
  lib,
  pkgs,
  unfamous,
  evilContent,
  evilHash,
  ...
}: let
  testConfig = pkgs.writeText "unfamous.conf" ''
    [general]
    mode = "monitor"
    log_level = "debug"
    log_format = "human"
    offline = true

    [monitoring]
    enabled = true
    execution_monitoring = true
    close_write_monitoring = true
    watch_paths = ["/root", "/tmp"]
    fail_open = true
    response_timeout_ms = 2000
    block_on_malicious = true

    [hashing]
    algorithms = ["sha256"]

    [file_types]
    shell_scripts = true

    [reputation]
    malicious_action = "alert_block"

    [lists.denylist]
    sha256 = ["${evilHash}"]

    [cache]
    database_path = "/var/lib/unfamous/cache.db"

    [alerts]
    directory = "/var/log"
    filename_prefix = "alerts"
    format = "jsonl"
    file_mode = "0600"
  '';
in {
  imports = [
    unfamous.nixosModules.default
  ];

  networking.hostName = "unfamous-testvm";

  system.stateVersion = "25.05";

  microvm = {
    hypervisor = "qemu";
    mem = 3072;
    vcpu = 2;

    interfaces = [ { type = "user"; id = "net0"; mac = "02:00:00:01:01:01"; } ];

    forwardPorts = [
      { from = "host"; host.port = 2222; guest.port = 22; }
    ];
  };

  services.openssh = {
    enable = true;
    settings.PermitRootLogin = "yes";
  };
  networking.firewall.allowedTCPPorts = [ 22 ];

  users.users.root.initialPassword = "unfamous";

  environment.etc."unfamous/evil.sh" = {
    text = evilContent;
    mode = "0755";
  };

  environment.systemPackages = with pkgs; [
    strace
    fatrace
  ];

  services.unfamous = {
    enable = true;
    package = unfamous.packages.${pkgs.system}.default;
    configFile = testConfig;
  };
}
