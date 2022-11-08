with import <nixpkgs> {};
let
  basePackages = [
    libpcap
    libtool
    pkg-config
    rustc
    cargo
    gcc
  ];

  

in mkShell {
  buildInputs = inputs;
  nativeBuildInputs = with pkgs; [ rustc cargo gcc libpcap];
  shellHook = hooks;
  RUST_SRC_PATH="${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
  PKG_CONFIG_PATH="${pkgs.libpcap}/lib/pkgconfig";
  LIBPCAP_LIBDIR="${pkgs.libpcap}/lib";
}

