{ ... }@parts:
{
  perSystem =
    {
      lib,
      pkgs,
      config,
      ...
    }:
    let
      linux-tpm-fido2-smoke = pkgs.writeShellApplication {
        name = "linux-tpm-fido2-smoke";
        runtimeInputs = with pkgs; [
          coreutils
          (python3.withPackages (ps: [
            ps.cbor2
            ps.fido2
          ]))
        ];
        text = lib.readFile ./fido-smoke.sh;
      };
    in
    {
      checks.nixos-polkit = pkgs.testers.runNixOSTest {
        name = "linux-tpm-fido2-polkit";

        nodes.machine = {
          imports = [ ./nixos-module.nix ];

          virtualisation.memorySize = 1536;
          virtualisation.tpm.enable = true;

          users.users.alice = {
            isNormalUser = true;
            password = "alice";
          };

          services.linux-tpm-fido2 = {
            enable = true;
            package = config.packages.default;
            tpmPath = "/dev/tpm0";
            uhidPath = "/dev/uhid";
          };

          systemd.services.linux-tpm-fido2.serviceConfig.Environment = [
            "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=test-recovery-passphrase"
          ];

          # Start the daemon after the test creates Alice's real logind
          # session, rather than supplying a non-existent session ID.
          systemd.services.linux-tpm-fido2.wantedBy = lib.mkForce [ ];

          security.polkit.extraConfig = ''
            polkit.addRule(function(action, subject) {
              if (action.id == "io.github.pineapplehunter.linux-tpm-fido2.approve"
                  && subject.user == "alice") {
                return polkit.Result.YES;
              }
            });
          '';

          environment.systemPackages = with pkgs; [
            linux-tpm-fido2-smoke
            tpm2-tools
          ];
        };

        testScript = ''
          def login_alice():
              machine.send_key("ctrl-alt-f1")
              machine.wait_until_tty_matches("1", "login:")
              machine.send_chars("alice\n")
              machine.wait_until_tty_matches("1", "Password:")
              machine.send_chars("alice\n")
              machine.wait_until_tty_matches("1", "alice@")

          machine.wait_for_unit("getty@tty1.service")
          login_alice()
          machine.succeed("systemctl start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")

          # register and assert should succeed via polkit authorization
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke register")
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")

          # regression test for tpm session exhaustion
          for _ in range(20):
            machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")

          # regression check for reboot persistence
          machine.shutdown()
          machine.wait_for_unit("getty@tty1.service")
          login_alice()
          machine.succeed("systemctl start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")

          # PCR update works through the same credential created with Polkit approval.
          machine.succeed("tpm2_pcrextend 7:sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
          machine.fail("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")
          credential_id = machine.succeed("od -An -v -tx1 /tmp/linux-tpm-fido2-smoke/credential.id | tr -d ' \\n'").strip()
          machine.systemctl("stop linux-tpm-fido2")
          machine.succeed(
              "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=test-recovery-passphrase "
              + "linux-tpm-fido2 --store-dir /var/lib/linux-tpm-fido2 "
              + "--tpm-path /dev/tpm0 --update-pcr-policy " + credential_id
          )
          machine.systemctl("start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")

          # Rewrap the recovery key, reject the old passphrase, and recover with the new one.
          machine.systemctl("stop linux-tpm-fido2")
          machine.succeed(
              "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=test-recovery-passphrase "
              + "LINUX_TPM_FIDO2_NEW_RECOVERY_PASSPHRASE=new-recovery-passphrase "
              + "linux-tpm-fido2 --store-dir /var/lib/linux-tpm-fido2 "
              + "--tpm-path /dev/tpm0 --change-recovery-passphrase " + credential_id
          )
          machine.fail(
              "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=test-recovery-passphrase "
              + "linux-tpm-fido2 --store-dir /var/lib/linux-tpm-fido2 "
              + "--tpm-path /dev/tpm0 --update-pcr-policy " + credential_id
          )
          machine.succeed("tpm2_pcrextend 7:sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
          machine.succeed(
              "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=new-recovery-passphrase "
              + "linux-tpm-fido2 --store-dir /var/lib/linux-tpm-fido2 "
              + "--tpm-path /dev/tpm0 --update-pcr-policy " + credential_id
          )
          machine.systemctl("start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")
        '';
      };
    };
}
