{
  perSystem =
    { pkgs, config, ... }:
    let
      linux-tpm-fido2 = config.packages.default.overrideAttrs (old: {
        cargoBuildFlags = (old.cargoBuildFlags or [ ]) ++ [
          "--features"
          "auto-approve"
        ];
      });
    in
    {
      checks.nixos = pkgs.testers.runNixOSTest {
        name = "linux-tpm-fido2";

        nodes.machine = { pkgs, ... }: {
          imports = [ ./nixos-module.nix ];

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
            fido2-manage
            libfido2
            tpm2-tools
            (python3.withPackages (ps: [
              ps.cbor2
              ps.fido2
            ]))
          ];
        };

        testScript = ''
          machine.wait_for_unit("linux-tpm-fido2")

          # test if a normal register and login procedure works
          machine.succeed("mkdir -p /tmp/linux-tpm-fido2-smoke")
          machine.succeed("python3 ${./tests/smoke_register.py} /tmp/linux-tpm-fido2-smoke login.example.test alice user-123 'make credential challenge' false")
          machine.succeed("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")

          # regression test for tpm storage exhaustion
          for _ in range(20):
            machine.succeed("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")

          # regression check for reboot persistance
          machine.shutdown()
          machine.wait_for_unit("linux-tpm-fido2")
          machine.succeed("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")

          # PCR update scenario: extend PCR 7, verify assertion fails, then update policy
          machine.succeed("tpm2_pcrextend 7:sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
          machine.fail("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")

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
          machine.succeed("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")

          # swtpm resets PCR 7 at reboot. The update for the extended value must no
          # longer authorize an assertion, then recovery approves the boot PCR again.
          machine.shutdown()
          machine.wait_for_unit("linux-tpm-fido2")
          machine.fail("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")
          machine.systemctl("stop linux-tpm-fido2")
          machine.succeed(
              "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=test-recovery-passphrase "
              + "linux-tpm-fido2 --store-dir /var/lib/linux-tpm-fido2 "
              + "--tpm-path /dev/tpm0 --update-pcr-policy " + credential_id
          )
          machine.systemctl("start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")
          machine.succeed("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")

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
          machine.succeed("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")

          # credential deletion via CTAP2 credential management
          delete_workdir = "/tmp/linux-tpm-fido2-delete"
          machine.succeed(f"mkdir -p {delete_workdir}")
          machine.succeed(
              "python3 ${./tests/smoke_register.py} "
              + delete_workdir + " delete-test.example.test alice user-123 'make credential challenge' true"
          )
          delete_credential_b64 = machine.succeed(
              f"base64 -w0 {delete_workdir}/credential.id"
          ).strip()
          # Single invocation: set PIN, delete credential via CTAP2
          # credential management, and verify.
          machine.succeed(
              "python3 ${./tests/test_delete_credential.py} " + delete_credential_b64
          )
          machine.fail(
              "python3 ${./tests/smoke_assert.py} "
              + delete_workdir + " delete-test.example.test 'assert credential challenge'"
          )
        '';
      };
    };
}
