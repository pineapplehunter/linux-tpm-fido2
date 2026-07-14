{
  perSystem =
    {
      lib,
      pkgs,
      config,
      ...
    }:
    {
      checks.nixos =
        let
          linux-tpm-fido2 = config.packages.default;
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
        pkgs.testers.runNixOSTest {
          name = "linux-tpm-fido2";

          nodes.machine = {
            environment.systemPackages = [
              pkgs.kmod
              pkgs.swtpm
            ];

            virtualisation.memorySize = 1536;
          };

          testScript = ''
            start_all()

            machine.succeed("mkdir -p /tmp/linux-tpm-fido2-smoke/swtpm /tmp/linux-tpm-fido2-smoke/store")
            machine.succeed("modprobe cuse")
            machine.succeed("nohup swtpm cuse --name=tpm0 --tpm2 --tpmstate dir=/tmp/linux-tpm-fido2-smoke/swtpm --flags startup-clear >/tmp/linux-tpm-fido2-smoke/swtpm.log 2>&1 &")
            machine.wait_until_succeeds("test -e /dev/tpm0")

            machine.succeed("nohup sh -c 'export RUST_LOG=debug; yes y | ${linux-tpm-fido2}/bin/linux-tpm-fido2 --tpm-path /dev/tpm0 --store-dir /tmp/linux-tpm-fido2-smoke/store' >/tmp/linux-tpm-fido2-smoke/daemon.log 2>&1 & echo $! >/tmp/linux-tpm-fido2-smoke/daemon.pid")
            machine.wait_until_succeeds("sh -c 'set -- /dev/hidraw*; [ $# -ge 2 ]'")

            machine.succeed("sh -euc 'WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test ${linux-tpm-fido2-smoke}/bin/linux-tpm-fido2-smoke register || { cat /tmp/linux-tpm-fido2-smoke/daemon.log; exit 1; }'")
            machine.succeed("sh -euc 'WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test ${linux-tpm-fido2-smoke}/bin/linux-tpm-fido2-smoke assert || { cat /tmp/linux-tpm-fido2-smoke/daemon.log; exit 1; }'")

            machine.succeed("kill $(cat /tmp/linux-tpm-fido2-smoke/daemon.pid)")
            machine.wait_until_succeeds("! kill -0 $(cat /tmp/linux-tpm-fido2-smoke/daemon.pid)")
            machine.succeed("pkill -x linux-tpm-fido2 || true")

            machine.succeed("nohup sh -c 'export RUST_LOG=debug; yes y | ${linux-tpm-fido2}/bin/linux-tpm-fido2 --tpm-path /dev/tpm0 --store-dir /tmp/linux-tpm-fido2-smoke/store' >/tmp/linux-tpm-fido2-smoke/daemon-restart.log 2>&1 & echo $! >/tmp/linux-tpm-fido2-smoke/daemon.pid")
            machine.wait_until_succeeds("sh -c 'set -- /dev/hidraw*; [ $# -ge 2 ]'")

            machine.succeed("sh -euc 'WORKDIR=/tmp/linux-tpm-fido2-smoke RP_ID=login.example.test ${linux-tpm-fido2-smoke}/bin/linux-tpm-fido2-smoke assert || { cat /tmp/linux-tpm-fido2-smoke/daemon-restart.log; exit 1; }'")
          '';
        };
    };
}
