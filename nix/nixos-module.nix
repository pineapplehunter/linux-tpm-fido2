{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    types
    mkIf
    mkEnableOption
    mkOption
    ;
  cfg = config.services.linux-tpm-fido2;
in
{
  options.services.linux-tpm-fido2 = {
    enable = mkEnableOption "TPM-backed FIDO2 authenticator daemon";

    package = lib.mkPackageOption pkgs "linux-tpm-fido2" { };

    tpmPath = mkOption {
      type = types.str;
      default = "/dev/tpmrm0";
      description = "TPM device path";
    };

    uhidPath = mkOption {
      type = types.str;
      default = "/dev/uhid";
      description = "UHID device path";
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    services.udev.packages = [ cfg.package ];

    security.polkit.enable = true;

    systemd.services.linux-tpm-fido2 = {
      description = "TPM-backed FIDO2 authenticator";
      after = [
        "systemd-logind.service"
        "polkit.service"
      ];
      requires = [ "systemd-logind.service" ];
      wants = [ "polkit.service" ];
      wantedBy = [ "multi-user.target" ];

      unitConfig = {
        ConditionPathExists = [
          cfg.uhidPath
          cfg.tpmPath
        ];
      };

      path = [ cfg.package ];

      script = ''
        exec linux-tpm-fido2 daemon --store-dir /var/lib/linux-tpm-fido2 --tpm-path "${cfg.tpmPath}" --uhid-path "${cfg.uhidPath}"
      '';

      serviceConfig = {
        NoNewPrivileges = true;
        PrivateDevices = false;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        Restart = "on-failure";
        RestartSec = 2;
        RuntimeDirectory = "linux-tpm-fido2";
        RuntimeDirectoryMode = "0777";
        StateDirectory = "linux-tpm-fido2";
        StateDirectoryMode = "0700";
        Type = "simple";
      };
    };
  };
}
