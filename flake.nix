{
  description = "A basic shell";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  inputs.flake-parts.url = "github:hercules-ci/flake-parts";
  inputs.treefmt-nix = {
    url = "github:numtide/treefmt-nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay?ref=stable";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ inputs.treefmt-nix.flakeModule ];

      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];

      perSystem =
        {
          pkgs,
          system,
          lib,
          ...
        }:
        let
          linux-tpm-fido2 = pkgs.rustPlatform.buildRustPackage {
            pname = "linux-tpm-fido2";
            version = "0.1.0";
            src = ./.;

            _structuredAttrs = true;
            strictDeps = true;

            cargoLock.lockFile = ./Cargo.lock;

            env.SQLX_OFFLINE = "true";

            nativeBuildInputs = with pkgs; [
              pkg-config
              rustPlatform.bindgenHook
            ];

            buildInputs = with pkgs; [
              gtk4
              tpm2-tss
            ];
          };

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

          linux-tpm-fido2-nixos-test = pkgs.testers.runNixOSTest {
            name = "linux-tpm-fido2";

            nodes.machine =
              { ... }:
              {
                environment.systemPackages = [
                  linux-tpm-fido2
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
        in
        {
          packages.default = linux-tpm-fido2;

          checks.nixos = linux-tpm-fido2-nixos-test;

          treefmt = {
            projectRootFile = "flake.nix";

            programs = {
              nixfmt.enable = true;
              rustfmt.enable = true;
              taplo.enable = true;
            };
          };

          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              inputs.rust-overlay.overlays.default
              # Add overlays as needed
            ];
          };

          devShells.default = pkgs.mkShell {
            env.SQLX_OFFLINE = "true";

            packages = with pkgs; [
              gtk4
              pkg-config
              rustPlatform.bindgenHook
              sqlx-cli
              tpm2-tss
              (rust-bin.stable.latest.default.override {
                extensions = [
                  "rust-src"
                  "rust-analyzer"
                ];
                targets = [ ];
              })
            ];
          };

          # Uncomment to build any package with `nix build .#package`
          #legacyPackages = pkgs;
        };
    };
}
