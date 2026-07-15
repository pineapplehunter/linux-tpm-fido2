{ ... }@parts:
{
  flake.nixosModules.default =
    { ... }:
    {
      imports = [ ./nixos-module.nix ];

      nixpkgs.overlays = [ parts.config.flake.overlays.default ];
    };
}
