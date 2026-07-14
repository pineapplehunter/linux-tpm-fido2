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

        nodes.machine =
          { ... }:
          {
            imports = [ ./module.nix ];

            virtualisation.memorySize = 1536;
            virtualisation.tpm.enable = true;

            services.linux-tpm-fido2 = {
              enable = true;
              package = linux-tpm-fido2;
              tpmPath = "/dev/tpm0";
              uhidPath = "/dev/uhid";
              storeDir = "/tmp/linux-tpm-fido2-smoke/store";
            };

            systemd.services.linux-tpm-fido2.serviceConfig.Environment = "LINUX_TPM_FIDO2_AUTO_APPROVE=1";

            environment.systemPackages = [
              linux-tpm-fido2-smoke
            ];
          };

        testScript = ''
          start_all()

          machine.succeed("mkdir -p /tmp/linux-tpm-fido2-smoke/store")

          machine.wait_until_succeeds("systemctl is-active linux-tpm-fido2")
          machine.wait_until_succeeds("sh -c 'set -- /dev/hidraw*; [ $# -ge 2 ]'")

          machine.succeed("sh -euc 'WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke register || { journalctl -u linux-tpm-fido2 --no-pager; exit 1; }'")
          machine.succeed("sh -euc 'WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert || { journalctl -u linux-tpm-fido2 --no-pager; exit 1; }'")

          machine.succeed("systemctl stop linux-tpm-fido2")
          machine.wait_until_succeeds("! systemctl is-active linux-tpm-fido2")

          machine.succeed("systemctl start linux-tpm-fido2")
          machine.wait_until_succeeds("systemctl is-active linux-tpm-fido2")
          machine.wait_until_succeeds("sh -c 'set -- /dev/hidraw*; [ $# -ge 2 ]'")

          machine.succeed("sh -euc 'WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert || { journalctl -u linux-tpm-fido2 --no-pager; exit 1; }'")
        '';
      };
    };
}
