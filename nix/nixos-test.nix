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
            };

            systemd.services.linux-tpm-fido2.serviceConfig.Environment = "LINUX_TPM_FIDO2_AUTO_APPROVE=1";

            environment.systemPackages = [
              linux-tpm-fido2-smoke
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
        '';
      };
    };
}
