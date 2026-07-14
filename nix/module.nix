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

    storeDir = mkOption {
      type = types.str;
      default = "/var/lib/linux-tpm-fido2";
      description = "Directory for credential storage";
    };

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
      wantedBy = [ "multi-user.target" ];

      unitConfig = {
        ConditionPathExists = [
          cfg.uhidPath
          cfg.tpmPath
        ];
      };

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/linux-tpm-fido2 --store-dir ${cfg.storeDir} --tpm-path ${cfg.tpmPath} --uhid-path ${cfg.uhidPath}";
        StateDirectory = lib.strings.removePrefix "/var/lib/" cfg.storeDir;
        StateDirectoryMode = "0700";
        Restart = "on-failure";
        RestartSec = 2;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = false;
      };
    };
  };
}
