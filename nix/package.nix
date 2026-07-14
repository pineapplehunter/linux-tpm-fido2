{
  lib,
  rustPlatform,
  pkg-config,
  libadwaita,
  gtk4,
  tpm2-tss,
}:
rustPlatform.buildRustPackage {
  pname = "linux-tpm-fido2";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../.sqlx
      ../Cargo.lock
      ../Cargo.toml
      ../assets
      ../migrations
      ../src
    ];
  };

  _structuredAttrs = true;
  strictDeps = true;

  cargoLock.lockFile = ../Cargo.lock;

  env.SQLX_OFFLINE = "true";

  nativeBuildInputs = [
    pkg-config
    rustPlatform.bindgenHook
  ];

  buildInputs = [
    libadwaita
    gtk4
    tpm2-tss
  ];

  postPatch = ''
    substituteInPlace assets/tpm-fido2.service \
      --replace-fail "/usr/bin" "$out/bin"
  '';

  postInstall = ''
    install -D -m 0644 assets/tpm-fido2.rules "$out/lib/udev/rules.d/tpm-fido2.rules"
    install -D -m 0644 assets/tpm-fido2.service "$out/lib/systemd/system/tpm-fido2.service"
    install -D -m 0644 assets/tpm-fido2.policy "$out/share/polkit-1/actions/tpm-fido2.policy"
  '';
}
