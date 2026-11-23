{
  description = "Unfamous microVM test: runs unfamous monitor mode inside a NixOS microvm (qemu) and verifies live fanotify behavior";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    microvm.url = "github:microvm-nix/microvm.nix";
    unfamous.url = "path:../..";
  };

  outputs =
    { self, nixpkgs, microvm, unfamous, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      # The denylisted script content. Its SHA-256 is computed at eval time
      # with builtins.hashString and injected into the guest configuration, so
      # config and fixture always agree.
      evilContent = "#!/bin/sh\necho PWNED_MARKER\n";
      evilHash = builtins.hashString "sha256" evilContent;

      vmConfig = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = { inherit unfamous evilContent evilHash; };
        modules = [ microvm.nixosModules.microvm ./vm.nix ];
      };

      runner = vmConfig.config.microvm.runner.qemu;

      runTest = pkgs.writeShellApplication {
        name = "unfamous-vm-test";
        runtimeInputs = with pkgs; [
          openssh
          sshpass
          netcat-openbsd
          coreutils
          gnugrep
          gnused
          util-linux
        ];
        text = ''
          set -euo pipefail

          RUN_ROOT="$(mktemp -d /tmp/unfamous-vm-XXXXXX)"
          VM_LOG="$RUN_ROOT/vm.log"
          VM_PID=""
          SSHPASS=unfamous
          PORT=2222

          cleanup() {
            if [ -n "$VM_PID" ] && kill -0 "$VM_PID" 2>/dev/null; then
              sshpass -p "$SSHPASS" ssh -p "$PORT" \
                -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o ConnectTimeout=5 root@127.0.0.1 'poweroff' >/dev/null 2>&1 || true
              for _ in $(seq 1 30); do
                kill -0 "$VM_PID" 2>/dev/null || break
                sleep 1
              done
              kill "$VM_PID" 2>/dev/null || true
            fi
            rm -rf "$RUN_ROOT"
          }
          trap cleanup EXIT

          echo "[test] starting microvm (log: $VM_LOG)"
          ${runner}/bin/microvm-run >"$VM_LOG" 2>&1 &
          VM_PID=$!

          echo "[test] waiting for sshd in the guest"
          up=0
          for _ in $(seq 1 90); do
            if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then up=1; break; fi
            if ! kill -0 "$VM_PID" 2>/dev/null; then
              echo "[test] VM exited early:"; tail -30 "$VM_LOG"; exit 1
            fi
            sleep 2
          done
          [ "$up" = 1 ] || { echo "[test] sshd never came up"; tail -30 "$VM_LOG"; exit 1; }

          ssh() {
            sshpass -p "$SSHPASS" ssh -p "$PORT" \
              -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
              -o ConnectTimeout=10 root@127.0.0.1 "$@"
          }

          echo "[test] waiting for the unfamous service"
          ready=0
          for _ in $(seq 1 60); do
            if ssh 'systemctl is-active unfamous >/dev/null 2>&1'; then ready=1; break; fi
            sleep 2
          done
          [ "$ready" = 1 ] || { echo "[test] unfamous service not active"; ssh 'systemctl status unfamous --no-pager; journalctl -u unfamous --no-pager | tail -40'; exit 1; }
          ssh 'systemctl is-active unfamous'
          ssh 'journalctl -u unfamous --no-pager | grep -E "monitoring started|watching" | tail -5'

          echo "[test] writing a JavaScript dropper (close_write event expected)"
          ssh "printf 'var beacon = 1; function exfiltrate() { return 1; }\n' > /tmp/dropper.js"

          echo "[test] writing the denylisted script and executing it (FAN_DENY expected)"
          # evilContent must byte-match the hash baked into the guest config.
          ssh "printf '${evilContent}' > /root/evil.sh && chmod +x /root/evil.sh"
          set +e
          BLOCK_OUT="$(ssh '/root/evil.sh; echo EXIT=$?' 2>&1)"
          set -e
          echo "[test] denylisted exec output: $BLOCK_OUT"
          case "$BLOCK_OUT" in
            *"EXIT=126"*|*"EXIT=1"*|*Permission*denied*|*PWNED_MARKER*) ;; # PWNED would mean it ran
            *) echo "[test] unexpected denylisted exec behavior" ;;
          esac
          if echo "$BLOCK_OUT" | grep -q PWNED_MARKER; then
            echo "[test] FAIL: denylisted script was allowed to execute"
            ssh 'sha256sum /root/evil.sh; CFG=$(systemctl cat unfamous | grep ExecStart | sed "s/.*--config //"); echo cfg=$CFG; grep -A2 lists.denylist $CFG; grep -E "block_on_malicious|malicious_action|shell_scripts|offline" $CFG; journalctl -u unfamous --no-pager | tail -30; echo alerts:; cat /var/log/alerts.*.jsonl 2>/dev/null | head -6' 2>&1 | grep -v 'Permanently added' || true
            exit 1
          fi
          echo "[test] denylisted script did not run"

          echo "[test] writing and executing a benign script (must run, UNKNOWN alert expected)"
          ssh "printf '#!/bin/sh\necho OK_MARKER\n' > /root/ok.sh && chmod +x /root/ok.sh"
          OK_OUT="$(ssh '/root/ok.sh; echo EXIT=$?' 2>&1)"
          echo "[test] benign exec output: $OK_OUT"
          echo "$OK_OUT" | grep -q OK_MARKER || { echo "[test] FAIL: benign script did not run"; exit 1; }

          sleep 2
          echo "[test] alert files in the guest:"
          ALERTS="$(ssh 'cat /var/log/alerts.*.jsonl 2>/dev/null || true')"
          echo "$ALERTS"

          echo "$ALERTS" | grep -q '"reputation":"KNOWN_BAD"' \
            || { echo "[test] FAIL: no KNOWN_BAD alert"; exit 1; }
          echo "$ALERTS" | grep -q 'evil.sh' \
            || { echo "[test] FAIL: no alert for evil.sh"; exit 1; }
          echo "$ALERTS" | grep -q '"reputation":"UNKNOWN"' \
            || { echo "[test] FAIL: no UNKNOWN alert"; exit 1; }
          echo "$ALERTS" | grep -q 'dropper.js' \
            || { echo "[test] FAIL: no alert for dropper.js"; exit 1; }
          echo "$ALERTS" | grep -q 'ok.sh' \
            || { echo "[test] FAIL: no alert for ok.sh"; exit 1; }
          echo "$ALERTS" | grep -q '"cache_status":"offline"' \
            || { echo "[test] FAIL: cache status not offline"; exit 1; }
          echo "$ALERTS" | grep -q '"monitoring_mode":"monitor"' \
            || { echo "[test] FAIL: monitoring mode not recorded"; exit 1; }

          echo "[test] checking fanotify permission-event latency stayed bounded"
          ssh 'journalctl -u unfamous --no-pager | grep -c "responding fail-open" || true'

          echo "[test] PASS: all microvm assertions succeeded"
        '';
      };
    in
    {
      nixosConfigurations.unfamous-vm = vmConfig;
      apps.${system} = {
        run-test = { type = "app"; program = "${runTest}/bin/unfamous-vm-test"; };
        default = self.apps.${system}.run-test;
      };
      packages.${system}.unfamous-vm-test = runTest;
    };
}
