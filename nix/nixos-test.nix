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
      linux-tpm-fido2 = config.packages.default.overrideAttrs (old: {
        cargoBuildFlags = (old.cargoBuildFlags or [ ]) ++ [
          "--features"
          "auto-approve"
        ];
      });
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
      checks.nixos = pkgs.testers.runNixOSTest {
        name = "linux-tpm-fido2";

        nodes.machine = {
          imports = [ ./nixos-module.nix ];

          virtualisation.memorySize = 1536;
          virtualisation.tpm.enable = true;

          services.linux-tpm-fido2 = {
            enable = true;
            package = linux-tpm-fido2;
            tpmPath = "/dev/tpm0";
            uhidPath = "/dev/uhid";
          };

          systemd.services.linux-tpm-fido2.serviceConfig.Environment = [
            "LINUX_TPM_FIDO2_AUTO_APPROVE=1"
            "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=test-recovery-passphrase"
            "RUST_LOG=debug"
          ];

          environment.systemPackages = with pkgs; [
            linux-tpm-fido2-smoke
            tpm2-tools
          ];
        };

        testScript = ''
          machine.wait_for_unit("linux-tpm-fido2")

          # test if a normal register and login procedure works
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke register")
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")

          # regression test for tpm storage exhaustion
          for _ in range(20):
            machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")

          # regression check for reboot persistance
          machine.shutdown()
          machine.wait_for_unit("linux-tpm-fido2")
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")

          # PCR update scenario: extend PCR 7, verify assertion fails, then update policy
          machine.succeed("tpm2_pcrextend 7:sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
          machine.fail("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")

          # read credential ID and update PCR policy; must stop daemon first so it does not hold TPM exclusivity
          credential_id = machine.succeed("od -An -v -tx1 /tmp/linux-tpm-fido2-smoke/credential.id | tr -d ' \\n'").strip()
          machine.systemctl("stop linux-tpm-fido2")
          machine.succeed(
              "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=test-recovery-passphrase "
              + "linux-tpm-fido2 --store-dir /var/lib/linux-tpm-fido2 "
              + "--tpm-path /dev/tpm0 --uhid-path /dev/uhid "
              + "--update-pcr-policy " + credential_id
          )
          machine.systemctl("start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")

          # swtpm resets PCR 7 at reboot. The update for the extended value must no
          # longer authorize an assertion, then recovery approves the boot PCR again.
          machine.shutdown()
          machine.wait_for_unit("linux-tpm-fido2")
          machine.fail("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")
          machine.systemctl("stop linux-tpm-fido2")
          machine.succeed(
              "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=test-recovery-passphrase "
              + "linux-tpm-fido2 --store-dir /var/lib/linux-tpm-fido2 "
              + "--tpm-path /dev/tpm0 --update-pcr-policy " + credential_id
          )
          machine.systemctl("start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")

          # passphrase change scenario: change recovery passphrase and verify new one works
          machine.systemctl("stop linux-tpm-fido2")
          credential_id = machine.succeed("od -An -v -tx1 /tmp/linux-tpm-fido2-smoke/credential.id | tr -d ' \\n'").strip()
          # change passphrase from test-recovery-passphrase to new-recovery-passphrase
          machine.succeed(
              "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=test-recovery-passphrase "
              + "LINUX_TPM_FIDO2_NEW_RECOVERY_PASSPHRASE=new-recovery-passphrase "
              + "linux-tpm-fido2 --store-dir /var/lib/linux-tpm-fido2 "
              + "--tpm-path /dev/tpm0 --uhid-path /dev/uhid "
              + "--change-recovery-passphrase " + credential_id
          )
          # verify old passphrase is rejected
          machine.fail(
              "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=test-recovery-passphrase "
              + "linux-tpm-fido2 --store-dir /var/lib/linux-tpm-fido2 "
              + "--tpm-path /dev/tpm0 --uhid-path /dev/uhid "
              + "--update-pcr-policy " + credential_id
          )
          # extend PCR again to force a new update, then use new passphrase
          machine.succeed("tpm2_pcrextend 7:sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
          machine.succeed(
              "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=new-recovery-passphrase "
              + "linux-tpm-fido2 --store-dir /var/lib/linux-tpm-fido2 "
              + "--tpm-path /dev/tpm0 --uhid-path /dev/uhid "
              + "--update-pcr-policy " + credential_id
          )
          machine.systemctl("start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")
        '';
      };
    };
}
