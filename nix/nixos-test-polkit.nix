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
          imports = [ ./module.nix ];

          virtualisation.memorySize = 1536;
          virtualisation.tpm.enable = true;

          services.linux-tpm-fido2 = {
            enable = true;
            package = config.packages.default;
            tpmPath = "/dev/tpm0";
            uhidPath = "/dev/uhid";
          };

          systemd.services.linux-tpm-fido2.serviceConfig.Environment = "XDG_SESSION_ID=1";

          security.polkit.extraConfig = ''
            polkit.addRule(function(action, subject) {
              if (action.id == "io.github.pineapplehunter.linux-tpm-fido2.approve") {
                return polkit.Result.YES;
              }
            });
          '';

          environment.systemPackages = [
            linux-tpm-fido2-smoke
          ];
        };

        testScript = ''
          machine.wait_for_unit("linux-tpm-fido2")

          # register and assert should succeed via polkit authorization
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke register")
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")

          # regression test for tpm session exhaustion
          for _ in range(20):
            machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")

          # regression check for reboot persistence
          machine.shutdown()
          machine.wait_for_unit("linux-tpm-fido2")
          machine.succeed("WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test linux-tpm-fido2-smoke assert")
        '';
      };
    };
}
