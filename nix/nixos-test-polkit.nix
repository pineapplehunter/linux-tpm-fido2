{
  perSystem =
    {
      lib,
      pkgs,
      config,
      ...
    }:
    {
      checks.nixos-polkit = pkgs.testers.runNixOSTest {
        name = "linux-tpm-fido2-polkit";

        nodes.machine = {
          imports = [ ./nixos-module.nix ];

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
            fido2-manage
            expect
            tpm2-tools
            (python3.withPackages (ps: [
              ps.cbor2
              ps.fido2
            ]))
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

          # -- fido2-manage subcommands (no PIN needed) --
          output = machine.succeed("fido2-manage -list")
          print("fido2-manage -list output:")
          print(output)
          assert "FIDO2" in output or "1209" in output or "linux-tpm" in output.lower(), (
              f"Expected device listing, got: {output}"
          )

          output = machine.succeed("fido2-manage -info -device 1")
          print("fido2-manage -info output:")
          print(output)
          assert "FIDO_2_1" in output, f"Expected FIDO2 version info, got: {output}"
          assert "rk" in output, f"Expected resident key support info, got: {output}"

          # -- register and assert via polkit authorization --
          machine.succeed("mkdir -p /tmp/linux-tpm-fido2-smoke")
          machine.succeed("python3 ${./tests/smoke_register.py} /tmp/linux-tpm-fido2-smoke login.example.test alice user-123 'make credential challenge' false")
          machine.succeed("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")

          # -- regression test for tpm session exhaustion --
          for _ in range(20):
            machine.succeed("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")

          # -- regression check for reboot persistence --
          machine.shutdown()
          machine.wait_for_unit("getty@tty1.service")
          login_alice()
          machine.succeed("systemctl start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")
          machine.succeed("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")

          # -- PCR update works through the same credential created with Polkit approval --
          machine.succeed("tpm2_pcrextend 7:sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
          machine.fail("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")
          credential_id = machine.succeed("od -An -v -tx1 /tmp/linux-tpm-fido2-smoke/credential.id | tr -d ' \\n'").strip()
          machine.systemctl("stop linux-tpm-fido2")
          machine.succeed(
              "LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE=test-recovery-passphrase "
              + "linux-tpm-fido2 --store-dir /var/lib/linux-tpm-fido2 "
              + "--tpm-path /dev/tpm0 --update-pcr-policy " + credential_id
          )
          machine.systemctl("start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")
          machine.succeed("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")

          # -- Rewrap the recovery key, reject the old passphrase, and recover with the new one --
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
          machine.succeed("python3 ${./tests/smoke_assert.py} /tmp/linux-tpm-fido2-smoke login.example.test 'assert credential challenge'")

          # -- fido2-manage PIN-dependent subcommands (daemon has no PIN at this point) --
          machine.succeed(
              "expect -c '"
              'spawn fido2-manage -setPIN -device 1; '
              'expect "Enter new PIN"; '
              'send "1234\\r"; '
              'expect "Enter the same PIN again"; '
              'send "1234\\r"; '
              'expect eof'
              "'"
          )

          machine.succeed(
              "expect -c '"
              'spawn fido2-manage -storage -device 1; '
              'expect "Enter PIN"; '
              'send "1234\\r"; '
              'expect eof'
              "'"
          )

          machine.succeed(
              "expect -c '"
              'spawn fido2-manage -changePIN -device 1; '
              'expect "Enter current PIN"; '
              'send "1234\\r"; '
              'expect "Enter new PIN"; '
              'send "5678\\r"; '
              'expect "Enter the same PIN again"; '
              'send "5678\\r"; '
              'expect eof'
              "'"
          )
        '';
      };
    };
}
